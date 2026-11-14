//! Sockets and nothing else: the I/O shell around `Conn`, over `std.Io`.
//!
//! `Conn` takes bytes and a clock and hands back bytes; every buffer is the
//! caller's and no call blocks. This file is the other half a program needs:
//! a UDP socket, a receive that waits, and a flush that sends until nothing is
//! owed. It owns no policy — no stream framing, no retry, no timers of its own
//! — so the rules of the machine above it stay the rules here.
//!
//! What it does own is one decision the machine cannot make: which address a
//! datagram goes to. A client knows its peer before the first packet; a server
//! takes it from the first datagram and then stops looking. A datagram from
//! anywhere else is dropped, not followed: migration is only legal once the new
//! path is validated (§9.3 of RFC 9000), and this layer does not validate
//! paths. A server behind a NAT that rebinds its port therefore goes quiet
//! rather than guessing.
//!
//! Like `Conn`, a `Connection` must not move after `init`: the machine inside it
//! records its own address and refuses a later move, so build one in place.
//!
//! A server cannot build its `Conn` before it has met its client: the client's
//! connection IDs seed the Initial keys (§5.2 of RFC 9001), and they arrive in
//! the first Initial. So a server's `Connection` starts listening, with no
//! `Conn` at all, and `accept` builds the machine in place from that first
//! datagram, without moving anything.
//!
//! Entropy and the clock stay the caller's: `flush` takes `now`, and the socket
//! cannot block longer than the timeout the caller passes to `receive`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const quic = @import("quic");
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const frame = quic.frame;
const TransportParameters = quic.TransportParameters;

const Io = std.Io;

pub const Error = Conn.Error ||
    TransportParameters.Error ||
    Io.net.Socket.ReceiveTimeoutError ||
    Io.net.Socket.SendError ||
    error{
        /// The connection is still listening: `accept` has not met its client, so
        /// there is no machine to flush or to receive for.
        NotOpen,
    };

/// One connection, its socket, and the buffers the machine writes into.
pub const Connection = struct {
    io: Io,
    socket: Io.net.Socket,
    /// Where packets go. A server sets it from the first datagram; a client is
    /// given it.
    peer: Io.net.IpAddress,
    /// Valid only once `state` is `.open`. A client's is built by `init`; a
    /// server's by `accept`, in this very field, because a `Conn` refuses to move.
    conn: Conn = undefined,
    state: State,
    /// Where `accept` copies the client's two connection IDs. The `Conn` borrows
    /// them for its whole life, so this stays the caller's and stays put.
    connection_ids: []u8,
    datagram: []u8,
    /// Scratch for the frames a packet carries. Distinct from `datagram`: the
    /// machine composes a frame here and then copies it into the packet it
    /// seals, and the same bytes cannot be both.
    write_frames: []u8,
    plaintext: []u8,
    frames: []frame.Frame,
    stream_events: []Conn.StreamEvent,
    recovery_events: *Recovery.Events,
    /// The datagram being walked, one packet at a time. One datagram may carry
    /// several packets (§12.2 of RFC 9000), and every one of them belongs to
    /// the machine, not just the first.
    walk: Conn.Datagram,
    walking: bool = false,
    /// When the datagram being walked arrived. Every packet in it shares one
    /// arrival time, so an RTT sample does not drift down the datagram.
    received_at: Conn.Duration = 0,
    /// Whether `peer` is settled. A client is given it; a server takes it from
    /// the first datagram and keeps it.
    peer_settled: bool,
    /// What this endpoint's own send loop still owes, per packet number space.
    owed: [3]Conn.SpaceId = undefined,

    /// Whether the machine exists yet. Two states and one transition, `accept`:
    /// a client is born open.
    pub const State = enum { listening, open };

    pub const Config = struct {
        io: Io,
        socket: Io.net.Socket,
        peer: ?Io.net.IpAddress = null,
        /// A client's configuration, and a server's when it already knows its
        /// client's connection IDs. Null is a server that has not met its client:
        /// `accept` builds the machine later, from `Accepting`.
        conn: ?Conn.Config,
        /// Where `accept` keeps the client's two connection IDs. A version 1
        /// connection ID is at most 20 bytes, so 40 holds any pair; `accept`
        /// returns `error.NoSpace` for a pair that does not fit. Unused, and may
        /// be empty, when `conn` is given.
        connection_ids: []u8 = &.{},
        /// One datagram, in and out. The machine's `max_send_size` is the
        /// caller's; this is the buffer it is written into.
        datagram: []u8,
        /// Scratch the machine writes a packet's frames into before sealing.
        /// An Initial datagram is padded to 1200 bytes (RFC 9000 §14.1) and the
        /// padding lives here, so this must hold a whole Initial payload.
        write_frames: []u8,
        plaintext: []u8,
        frames: []frame.Frame,
        stream_events: []Conn.StreamEvent,
        recovery_events: *Recovery.Events,
    };

    /// What `accept` needs to build a server's machine once it has met its
    /// client.
    pub const Accepting = struct {
        /// The server's configuration: its own `source_connection_id`, the loss
        /// state, the driver, the streams, everything but the client's names.
        /// `original_destination_connection_id`, `destination_connection_id`, and
        /// `transport_parameters` are overwritten, so what they hold is ignored.
        conn: Conn.Config,
        /// The server's limits. §7.3: its transport parameters name the
        /// connection ID the client first addressed and the server's own, and
        /// the first is unknown until the Initial arrives, so `accept` fills in
        /// `original_destination_connection_id` and `initial_source_connection_id`
        /// and encodes the rest. They must agree with `conn`, as `Conn` asserts.
        parameters: TransportParameters,
        /// Where the encoded parameters live; the `Conn` points at them for its
        /// whole life. `error.NoSpace` when they do not fit.
        parameter_storage: []u8,
    };

    pub fn init(config: Config) Connection {
        // A listener has no peer to be given, and nowhere to put the client's
        // names without a buffer.
        assert(config.conn != null or (config.peer == null and config.connection_ids.len > 0));
        var self: Connection = .{
            .io = config.io,
            .socket = config.socket,
            .peer = config.peer orelse .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
            .state = if (config.conn == null) .listening else .open,
            .connection_ids = config.connection_ids,
            .datagram = config.datagram,
            .write_frames = config.write_frames,
            .plaintext = config.plaintext,
            .frames = config.frames,
            .stream_events = config.stream_events,
            .recovery_events = config.recovery_events,
            .walk = .init(config.datagram),
            .peer_settled = config.peer != null,
        };
        if (config.conn) |conn| self.conn = .init(conn);
        return self;
    }

    /// Wait up to `timeout` for a client's first Initial, learn its connection
    /// IDs from it, build the machine in place, and return the Initial's first
    /// packet, as `receive` would.
    ///
    /// §7.2: the Destination Connection ID of the first Initial names this
    /// endpoint and seeds the Initial keys, and its Source Connection ID is where
    /// answers go. `Conn.Opening` copies both into `connection_ids`, and the
    /// `Conn` is built from them; only then is the datagram walked, by the same
    /// code `receive` uses, so the rest of its packets come from `receive`.
    ///
    /// Null is either the wait expiring, with `state` still `.listening`, or the
    /// machine now existing while no packet of the datagram opened. The caller
    /// tells them apart by `state`, and calls `accept` again only in the first.
    /// `accept` on a connection that is open is a bug, not an error: a second
    /// client is not this layer's to serve.
    ///
    /// A datagram that does not start a connection returns the error
    /// `Conn.Opening.fromDatagram` gives and builds nothing: `error.NotInitial`,
    /// `error.InvalidConnectionId`, `error.NoSpace`, and `error.UnsupportedVersion`.
    /// After any of them `peer` is where the datagram came from and `datagram`
    /// still holds it, so the caller can answer an unsupported version with a
    /// Version Negotiation packet (§6 of RFC 9000, `quic.connection_setup`);
    /// whether to is the caller's policy. `peer_settled` stays false, so the next `accept` takes
    /// a fresh sender.
    ///
    /// `now` dates the datagram, as in `receive`.
    pub fn accept(
        self: *Connection,
        accepting: Accepting,
        now: Conn.Duration,
        timeout: Io.Timeout,
    ) Error!?Conn.Opened {
        assert(self.state == .listening);
        assert(!self.walking);
        assert(accepting.conn.role == .server);

        const message = self.socket.receiveTimeout(self.io, self.datagram, timeout) catch |err| switch (err) {
            error.Timeout => return null,
            else => return err,
        };
        self.peer = message.from;
        const opening = try Conn.Opening.fromDatagram(message.data, self.connection_ids);

        var conn = accepting.conn;
        conn.original_destination_connection_id = opening.destination_connection_id;
        conn.destination_connection_id = opening.source_connection_id;
        var parameters = accepting.parameters;
        parameters.original_destination_connection_id = opening.destination_connection_id;
        parameters.initial_source_connection_id = conn.source_connection_id;
        var writer: quic.Writer = .init(accepting.parameter_storage);
        try TransportParameters.encode(&writer, parameters, .server);
        conn.transport_parameters = writer.written();

        // In place: the `Conn` is assigned into the field it will live in, and
        // is first used, and so pinned, after that.
        self.conn = .init(conn);
        self.state = .open;
        self.peer_settled = true;
        return self.beginWalk(message.data, now);
    }

    /// Return the next packet the machine has, waiting up to `timeout` for a
    /// datagram when the last one is used up.
    ///
    /// The caller loops until it gets null, and every packet reports its own
    /// frames; that is the whole contract. A datagram that carries several
    /// packets (§12.2) is handed over one at a time, and the wait only happens
    /// when the previous datagram is exhausted, so a coalesced flight cannot
    /// lose its tail.
    ///
    /// Null means the wait expired with nothing to do, which is the caller's
    /// timer firing, not an error. A datagram whose every packet fails to open
    /// also returns null: the machine counted them, and there is nothing to
    /// report.
    pub fn receive(self: *Connection, now: Conn.Duration, timeout: Io.Timeout) Error!?Conn.Opened {
        if (self.state != .open) return error.NotOpen;
        while (self.walking) {
            if (try self.nextPacket()) |opened| return opened;
        }
        const message = self.socket.receiveTimeout(self.io, self.datagram, timeout) catch |err| switch (err) {
            error.Timeout => return null,
            else => return err,
        };
        // §9: the peer is where the first datagram came from, and where the
        // answers go. A later datagram from somewhere else is not a migration
        // to follow; it is the start of one this endpoint cannot validate, so
        // the path stays where it is and the datagram is dropped.
        if (!self.peer_settled) {
            self.peer = message.from;
            self.peer_settled = true;
        } else if (!self.peer.eql(&message.from)) {
            return null;
        }
        return self.beginWalk(message.data, now);
    }

    /// Start walking a datagram that arrived at `now`, and return its first
    /// packet. Shared by `receive` and `accept`, so a server's first Initial is
    /// opened by the code every later packet is.
    fn beginWalk(self: *Connection, data: []u8, now: Conn.Duration) Error!?Conn.Opened {
        assert(self.state == .open);
        self.received_at = now;
        self.walk = .init(data);
        self.walking = true;
        return self.nextPacket();
    }

    /// Open the next packet of the datagram being walked, or mark the walk
    /// finished. `walk.next` leaves the cursor after the packet it returned, so
    /// a second call reads the next one rather than the same one again.
    fn nextPacket(self: *Connection) Error!?Conn.Opened {
        const opened = try self.walk.next(
            &self.conn,
            self.plaintext,
            self.frames,
            self.stream_events,
            self.recovery_events,
            self.received_at,
        );
        if (opened == null) self.walking = false;
        return opened;
    }

    /// Send everything the machine owes right now: handshake messages, then an
    /// acknowledgment in each space that has one pending.
    ///
    /// Returns how many datagrams went out. `error.NoSpace` from the machine
    /// means the CRYPTO buffer is full, which is fatal by design; a socket that
    /// refuses a datagram is not retried here, because the packet has already
    /// been recorded in flight (§6 of RFC 9002) and loss recovery will bring it
    /// back.
    pub fn flush(self: *Connection, now: Conn.Duration) Error!usize {
        if (self.state != .open) return error.NotOpen;
        var sent: usize = 0;
        while (try self.conn.writeHandshake(self.write_frames, self.datagram, now)) |length| {
            try self.socket.send(self.io, &self.peer, self.datagram[0..length]);
            sent += 1;
        }
        for (self.conn.acksOwed(&self.owed)) |id| {
            const length = try self.conn.writeAck(id, self.datagram, now);
            if (length == 0) continue;
            try self.socket.send(self.io, &self.peer, self.datagram[0..length]);
            sent += 1;
        }
        return sent;
    }

    /// Whether the handshake is finished in both directions: our TLS handshake
    /// completed and the peer has confirmed what it must.
    ///
    /// §4.1.2 of RFC 9001: a client finishes when a HANDSHAKE_DONE frame lands,
    /// a server when its own handshake does. A server still listening has no
    /// handshake, so it is not established.
    pub fn established(self: *const Connection) bool {
        if (self.state != .open) return false;
        return self.conn.handshakeConfirmed() and (self.conn.app != null);
    }
};

// -- Tests -------------------------------------------------------------------
//
// Two real sockets on the loopback interface, driven the way a program drives
// them: seal a packet with the machine, send it with the socket, wait for the
// other side. No TLS, because Initial keys come from the connection ID (§5.2 of
// RFC 9001), and these are tests of the socket layer, not of the handshake.

const Loss = struct {
    shared: Recovery = .{},
    spaces: [3]Recovery.Space = undefined,
    sent_initial: [16]Recovery.SentPacket = undefined,
    sent_handshake: [16]Recovery.SentPacket = undefined,
    sent_app: [16]Recovery.SentPacket = undefined,

    fn value(self: *Loss) Conn.Loss {
        return .{
            .shared = &self.shared,
            .spaces = &self.spaces,
            .sent_initial = &self.sent_initial,
            .sent_handshake = &self.sent_handshake,
            .sent_app = &self.sent_app,
        };
    }
};

/// A bound on every wait, so a regression fails the test instead of hanging CI.
const test_timeout: Io.Timeout = .{ .duration = .{
    .raw = .{ .nanoseconds = 2 * std.time.ns_per_s },
    .clock = .awake,
} };

/// Bind 127.0.0.1 until a port is free. A test cannot ask for port 0 and learn
/// the port back, so it walks a small range instead.
fn bindLoopback(io: Io) !struct { socket: Io.net.Socket, address: Io.net.IpAddress } {
    var port: u16 = 47301;
    while (port < 47351) : (port += 1) {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const socket = Io.net.IpAddress.bind(&address, io, .{ .mode = .dgram, .protocol = .udp }) catch continue;
        return .{ .socket = socket, .address = address };
    }
    return error.NoFreePort;
}

/// Two connections on real sockets, with every buffer they need. Built in place
/// because a `Connection` must not move after `init`.
const Harness = struct {
    threaded: Io.Threaded = undefined,
    io: Io = undefined,
    server_socket: Io.net.Socket = undefined,
    server_address: Io.net.IpAddress = undefined,
    client_socket: Io.net.Socket = undefined,
    client_address: Io.net.IpAddress = undefined,
    dcid: [3]u8 = .{ 0x11, 0x22, 0x33 },
    client_loss: Loss = .{},
    server_loss: Loss = .{},
    client_datagram: [1200]u8 = undefined,
    client_write_frames: [1500]u8 = undefined,
    client_plaintext: [1200]u8 = undefined,
    client_recovery: [8]Recovery.SentPacket = undefined,
    client_lost: [8]Recovery.SentPacket = undefined,
    client_events: Recovery.Events = undefined,
    client_parsed: [8]frame.Frame = undefined,
    client_streams: [8]Conn.StreamEvent = undefined,
    server_datagram: [1200]u8 = undefined,
    server_write_frames: [1500]u8 = undefined,
    server_plaintext: [1200]u8 = undefined,
    server_recovery: [8]Recovery.SentPacket = undefined,
    server_lost: [8]Recovery.SentPacket = undefined,
    server_events: Recovery.Events = undefined,
    server_parsed: [8]frame.Frame = undefined,
    server_streams: [8]Conn.StreamEvent = undefined,
    server_ids: [40]u8 = undefined,
    server_parameters: [128]u8 = undefined,
    client: Connection = undefined,
    server: Connection = undefined,

    fn init(self: *Harness) !void {
        self.threaded = .init(testing.allocator, .{});
        self.io = self.threaded.io();
        const server = try bindLoopback(self.io);
        self.server_socket = server.socket;
        self.server_address = server.address;
        const client = try bindLoopback(self.io);
        self.client_socket = client.socket;
        self.client_address = client.address;

        self.client_events = .init(&self.client_recovery, &self.client_lost);
        self.server_events = .init(&self.server_recovery, &self.server_lost);

        self.client = .init(.{
            .io = self.io,
            .socket = self.client_socket,
            .peer = self.server_address,
            .conn = .{
                .role = .client,
                .loss = self.client_loss.value(),
                .original_destination_connection_id = &self.dcid,
                .destination_connection_id = &self.dcid,
                .source_connection_id = &.{0x44},
            },
            .datagram = &self.client_datagram,
            .write_frames = &self.client_write_frames,
            .plaintext = &self.client_plaintext,
            .frames = &self.client_parsed,
            .stream_events = &self.client_streams,
            .recovery_events = &self.client_events,
        });
        self.server = .init(.{
            .io = self.io,
            .socket = self.server_socket,
            .peer = null,
            .conn = .{
                .role = .server,
                .loss = self.server_loss.value(),
                .original_destination_connection_id = &self.dcid,
                .destination_connection_id = &.{0x44},
                .source_connection_id = &self.dcid,
            },
            .datagram = &self.server_datagram,
            .write_frames = &self.server_write_frames,
            .plaintext = &self.server_plaintext,
            .frames = &self.server_parsed,
            .stream_events = &self.server_streams,
            .recovery_events = &self.server_events,
        });
    }

    /// Replace the server with one that has not met its client: no `Conn`, and
    /// a buffer for the client's names.
    fn listen(self: *Harness) void {
        self.server = .init(.{
            .io = self.io,
            .socket = self.server_socket,
            .conn = null,
            .connection_ids = &self.server_ids,
            .datagram = &self.server_datagram,
            .write_frames = &self.server_write_frames,
            .plaintext = &self.server_plaintext,
            .frames = &self.server_parsed,
            .stream_events = &self.server_streams,
            .recovery_events = &self.server_events,
        });
    }

    /// What a server accepts with: the name the client already addresses it by, so
    /// the client needs no storage to adopt a new one.
    fn accepting(self: *Harness) Connection.Accepting {
        return .{
            .conn = .{
                .role = .server,
                .loss = self.server_loss.value(),
                .original_destination_connection_id = "",
                .destination_connection_id = "",
                .source_connection_id = &self.dcid,
            },
            .parameters = .{},
            .parameter_storage = &self.server_parameters,
        };
    }

    fn deinit(self: *Harness) void {
        self.server_socket.close(self.io);
        self.client_socket.close(self.io);
        self.threaded.deinit();
        self.* = undefined;
    }

    /// Seal one PING in an Initial at `out`, returning its length.
    fn sealPing(self: *Harness, out: []u8) !u32 {
        var payload: [8]u8 = undefined;
        var writer: quic.Writer = .init(&payload);
        try frame.write(&writer, .{ .ping = {} });
        return self.client.conn.writeFrames(.initial, writer.written(), out, .data(0));
    }
};

test "RFC 9001 §5.2, two sockets exchange an Initial and its acknowledgment" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();

    // The client seals a PING in an Initial and sends it with the socket, the
    // way an application would.
    const sealed = try h.sealPing(&h.client_datagram);
    try h.client.socket.send(h.io, &h.server_address, h.client_datagram[0..sealed]);

    // The server waits for it, then answers with the acknowledgment the machine
    // owes; `flush` is what turns that into a datagram.
    const opened = (try h.server.receive(0, test_timeout)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Conn.SpaceId.initial, opened.space);
    try testing.expectEqual(@as(usize, 1), opened.frames.len);
    try testing.expectEqual(1, try h.server.flush(0));

    // And the client learns its packet arrived.
    _ = (try h.client.receive(0, test_timeout)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), h.client_events.ackedPackets().len);
}

test "RFC 9000 §12.2, a coalesced datagram yields every packet it carries" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();

    // Two Initials, back to back in one datagram. A client's first flight does
    // exactly this with Initial and Handshake, which is why the shell may not
    // stop at the first packet it opens.
    const first = try h.sealPing(h.client_datagram[0..]);
    const second = try h.sealPing(h.client_datagram[first..]);
    try h.client.socket.send(h.io, &h.server_address, h.client_datagram[0 .. first + second]);

    const one = (try h.server.receive(0, test_timeout)) orelse return error.TestUnexpectedResult;
    const two = (try h.server.receive(0, test_timeout)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), one.frames.len);
    try testing.expectEqual(@as(usize, 1), two.frames.len);
    try testing.expectEqual(one.packet_number + 1, two.packet_number);
    try testing.expectEqual(first + second, one.packet_len + two.packet_len);
}

test "RFC 9000 §9.3, a datagram from another address is not a migration" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();

    const sealed = try h.sealPing(h.client_datagram[0..]);
    try h.client.socket.send(h.io, &h.server_address, h.client_datagram[0..sealed]);
    _ = (try h.server.receive(0, test_timeout)) orelse return error.TestUnexpectedResult;

    // The same connection ID from a different port: the server has validated
    // no path there, so the datagram is dropped rather than followed.
    const stranger = try bindLoopback(h.io);
    defer stranger.socket.close(h.io);
    const second = try h.sealPing(h.client_datagram[0..]);
    try stranger.socket.send(h.io, &h.server_address, h.client_datagram[0..second]);

    const nothing = try h.server.receive(0, test_timeout);
    try testing.expect(nothing == null);
    try testing.expect(h.server.peer_settled);
    try testing.expect(h.server.peer.eql(&h.client_address));
}

test "RFC 9000 §7.2, accept builds the connection from the first Initial's connection IDs" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    h.listen();

    // The client's IDs are the harness's: the server was built knowing neither.
    const sealed = try h.sealPing(&h.client_datagram);
    try h.client.socket.send(h.io, &h.server_address, h.client_datagram[0..sealed]);

    const opened = (try h.server.accept(h.accepting(), 0, test_timeout)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Conn.SpaceId.initial, opened.space);
    try testing.expectEqual(Connection.State.open, h.server.state);
    try testing.expectEqualSlices(u8, &h.dcid, h.server_ids[0..h.dcid.len]);
    try testing.expectEqualSlices(u8, &.{0x44}, h.server.conn.destination_connection_id);
    try testing.expect(h.server.peer.eql(&h.client_address));

    // And the machine it built works: it owes an acknowledgment, which the
    // client reads.
    try testing.expectEqual(1, try h.server.flush(0));
    _ = (try h.client.receive(0, test_timeout)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), h.client_events.ackedPackets().len);
}

test "RFC 9000 §7.2, an unsupported version is refused before a connection exists" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    h.listen();

    // §17.2: the version follows the first byte. Version 0x1a2a3a4a is one of
    // the reserved ones that no endpoint implements (§15).
    const sealed = try h.sealPing(&h.client_datagram);
    @memcpy(h.client_datagram[1..5], &[_]u8{ 0x1a, 0x2a, 0x3a, 0x4a });
    try h.client.socket.send(h.io, &h.server_address, h.client_datagram[0..sealed]);

    try testing.expectError(error.UnsupportedVersion, h.server.accept(h.accepting(), 0, test_timeout));
    try testing.expectEqual(Connection.State.listening, h.server.state);
    try testing.expect(!h.server.peer_settled);
    // The caller can still answer: the sender and the datagram are kept.
    try testing.expect(h.server.peer.eql(&h.client_address));
    try testing.expectError(error.NotOpen, h.server.flush(0));
}

test "RFC 9000 §7.2, a server that has not accepted has no connection to flush" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    h.listen();

    try testing.expectError(error.NotOpen, h.server.flush(0));
    try testing.expectError(error.NotOpen, h.server.receive(0, test_timeout));
    try testing.expect(!h.server.established());
}
