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
//! learns it from the first datagram that opens, and uses it for everything
//! after. It also learns the peer's address on every datagram, because a
//! connection can migrate (§9 of RFC 9000) and the machine below has already
//! said which one it believes.
//!
//! Like `Conn`, a `Connection` must not move after `init`: the machine inside it
//! records its own address and refuses a later move, so build one in place.
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

const Io = std.Io;

pub const Error = Conn.Error ||
    Io.net.Socket.ReceiveTimeoutError ||
    Io.net.Socket.SendError;

/// One connection, its socket, and the buffers the machine writes into.
pub const Connection = struct {
    io: Io,
    socket: Io.net.Socket,
    /// Where packets go. A server sets it from the first datagram; a client is
    /// given it.
    peer: Io.net.IpAddress,
    conn: Conn,
    datagram: []u8,
    /// Scratch for the frames a packet carries. Distinct from `datagram`: the
    /// machine composes a frame here and then copies it into the packet it
    /// seals, and the same bytes cannot be both.
    write_frames: []u8,
    plaintext: []u8,
    frames: []frame.Frame,
    stream_events: []Conn.StreamEvent,
    recovery_events: *Recovery.Events,
    /// What this endpoint's own send loop still owes, per packet number space.
    owed: [3]Conn.SpaceId = undefined,

    pub const Config = struct {
        io: Io,
        socket: Io.net.Socket,
        peer: ?Io.net.IpAddress = null,
        conn: Conn.Config,
        /// One datagram, in and out. The machine's `max_send_size` is the
        /// caller's; this is the buffer it is written into.
        datagram: []u8,
        /// Scratch the machine writes a packet's frames into before sealing.
        write_frames: []u8,
        plaintext: []u8,
        frames: []frame.Frame,
        stream_events: []Conn.StreamEvent,
        recovery_events: *Recovery.Events,
    };

    pub fn init(config: Config) Connection {
        return .{
            .io = config.io,
            .socket = config.socket,
            .peer = config.peer orelse .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
            .conn = .init(config.conn),
            .datagram = config.datagram,
            .write_frames = config.write_frames,
            .plaintext = config.plaintext,
            .frames = config.frames,
            .stream_events = config.stream_events,
            .recovery_events = config.recovery_events,
        };
    }

    /// Wait up to `timeout` for one datagram and feed it to the machine.
    ///
    /// Null means the wait expired with nothing to do, which is a caller's
    /// timer firing, not an error. A datagram that does not open is not an
    /// error either: the machine counts it and returns null.
    pub fn receive(self: *Connection, now: Conn.Duration, timeout: Io.Timeout) Error!?Conn.Opened {
        const message = self.socket.receiveTimeout(self.io, self.datagram, timeout) catch |err| switch (err) {
            error.Timeout => return null,
            else => return err,
        };
        // §9: the address the machine believes is the one the last datagram
        // came from, and it is also where replies go.
        self.peer = message.from;
        const opened = try self.conn.feed(
            message.data,
            self.plaintext,
            self.frames,
            self.stream_events,
            self.recovery_events,
            now,
        );
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
    /// a server when its own handshake does.
    pub fn established(self: *const Connection) bool {
        return self.conn.handshakeConfirmed() and (self.conn.app != null);
    }
};

// -- Tests -------------------------------------------------------------------
//
// One datagram each way over a real socket: the machine seals an Initial, the
// shell sends it, the other shell receives it, and its acknowledgment comes
// back. No TLS, because Initial keys are the connection ID's (§5.2 of RFC
// 9001) and this is a test of the socket layer, not the handshake.

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

test "RFC 9001 §5.2, two sockets exchange an Initial and its acknowledgment" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_bound = try bindLoopback(io);
    defer server_bound.socket.close(io);
    const client_bound = try bindLoopback(io);
    defer client_bound.socket.close(io);

    const dcid = [_]u8{ 0x11, 0x22, 0x33 };
    var client_loss: Loss = .{};
    var server_loss: Loss = .{};

    var client_datagram: [1200]u8 = undefined;
    var client_frames: [64]u8 = undefined;
    var client_plaintext: [1200]u8 = undefined;
    var client_recovery: [8]Recovery.SentPacket = undefined;
    var client_lost: [8]Recovery.SentPacket = undefined;
    var client_events: Recovery.Events = .init(&client_recovery, &client_lost);
    var client_parsed: [8]frame.Frame = undefined;
    var client_streams: [8]Conn.StreamEvent = undefined;

    var server_datagram: [1200]u8 = undefined;
    var server_frames: [64]u8 = undefined;
    var server_plaintext: [1200]u8 = undefined;
    var server_recovery: [8]Recovery.SentPacket = undefined;
    var server_lost: [8]Recovery.SentPacket = undefined;
    var server_events: Recovery.Events = .init(&server_recovery, &server_lost);
    var server_parsed: [8]frame.Frame = undefined;
    var server_streams: [8]Conn.StreamEvent = undefined;

    var client: Connection = .init(.{
        .io = io,
        .socket = client_bound.socket,
        .peer = server_bound.address,
        .conn = .{
            .role = .client,
            .loss = client_loss.value(),
            .original_destination_connection_id = &dcid,
            .destination_connection_id = &dcid,
            .source_connection_id = &.{0x44},
        },
        .datagram = &client_datagram,
        .write_frames = &client_frames,
        .plaintext = &client_plaintext,
        .frames = &client_parsed,
        .stream_events = &client_streams,
        .recovery_events = &client_events,
    });
    var server: Connection = .init(.{
        .io = io,
        .socket = server_bound.socket,
        .peer = null,
        .conn = .{
            .role = .server,
            .loss = server_loss.value(),
            .original_destination_connection_id = &dcid,
            .destination_connection_id = &.{0x44},
            .source_connection_id = &dcid,
        },
        .datagram = &server_datagram,
        .write_frames = &server_frames,
        .plaintext = &server_plaintext,
        .frames = &server_parsed,
        .stream_events = &server_streams,
        .recovery_events = &server_events,
    });

    // The client seals a PING in an Initial and sends it with the socket, the
    // way an application would.
    var payload: [8]u8 = undefined;
    var writer: quic.Writer = .init(&payload);
    try frame.write(&writer, .{ .ping = {} });
    const sealed = try client.conn.writeFrames(.initial, writer.written(), &client_datagram, .data(0));
    try client.socket.send(io, &server_bound.address, client_datagram[0..sealed]);

    // The server waits for it, then answers with the acknowledgment the machine
    // owes; `flush` is what turns that into a datagram.
    const opened = (try server.receive(0, .none)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Conn.SpaceId.initial, opened.space);
    try testing.expectEqual(@as(usize, 1), opened.frames.len);
    try testing.expectEqual(1, try server.flush(0));

    // And the client learns its packet arrived.
    _ = (try client.receive(0, .none)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), client_events.ackedPackets().len);
}
