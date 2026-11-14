//! What `hq_server.zig` and `hq_client.zig` share: one endpoint's storage, wired
//! to a real TLS 1.3 driver and a real UDP socket, and the two loops both need.
//!
//! hq-interop is HTTP/0.9 over QUIC: one bidirectional stream per request, the
//! request `GET /path\r\n`, the response the body and a FIN. It is the smallest
//! application that proves a handshake carried bytes both ways.
//!
//! Everything here is a fixed buffer. An `Endpoint` is a file-scope `var` in
//! each example and is built in place by `start`: the machine records its own
//! address and the driver is pointed at by the machine, so neither may move.
//!
//! Neither end agrees on a connection ID beforehand. A client invents the name
//! it gives the server and its own, from the platform's entropy; a server
//! learns both from the client's first Initial (`Connection.accept`) and picks
//! its own the same way. So a foreign client works as well as `hq_client`.

const std = @import("std");
const quic = @import("quic");
const quic_io = @import("quic-io");
const driver = @import("quic-tls");
const tls = @import("tls");

const Io = std.Io;
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const TransportParameters = quic.TransportParameters;

/// The application protocol both ends name in the handshake.
pub const alpn = "hq-interop";

/// The only stream: the first client-initiated bidirectional one (RFC 9000 §2.1).
pub const request_stream: u64 = 0;

/// What the server answers, as the client expects to read it back.
pub const body = "hello from baskingspot/quic\n";

/// How long an endpoint waits for the whole exchange before it gives up, so a
/// stuck handshake fails instead of hanging.
pub const exchange_limit_ns: u64 = 5 * std.time.ns_per_s;

/// The most one stream holds in either direction, and the size of its ring.
const stream_bytes = 1024;

/// §7.2: the least a client's first Destination Connection ID may be.
const original_id_len = 8;
const own_id_len = 4;

/// The limits each end advertises in the handshake (RFC 9001 §8.2), which the
/// peer's `Conn` adopts: one bidirectional stream of `stream_bytes`. The caller
/// adds the connection IDs, which differ per connection (§7.3).
fn limits(identity: TransportParameters) TransportParameters {
    var parameters = identity;
    parameters.initial_max_data = 4096;
    parameters.initial_max_stream_data_bidi_local = stream_bytes;
    parameters.initial_max_stream_data_bidi_remote = stream_bytes;
    parameters.initial_max_streams_bidi = 1;
    return parameters;
}

/// When the exchange started and when it must be over.
pub const Deadline = struct {
    io: Io,
    start: Io.Timestamp,

    pub fn init(io: Io) Deadline {
        return .{ .io = io, .start = Io.Timestamp.now(io, .awake) };
    }

    /// Nanoseconds since `init`, which is the clock the machine is handed.
    pub fn now(self: Deadline) u64 {
        const elapsed = self.start.durationTo(Io.Timestamp.now(self.io, .awake));
        return @intCast(@max(elapsed.nanoseconds, 0));
    }

    /// The wait that is left, or null when the exchange has run out of time.
    fn timeout(self: Deadline) ?Io.Timeout {
        const elapsed = self.now();
        if (elapsed >= exchange_limit_ns) return null;
        return .{ .duration = .{
            .raw = .fromNanoseconds(exchange_limit_ns - elapsed),
            .clock = .awake,
        } };
    }
};

pub const Error = quic_io.Error || driver.Error || error{Timeout};

/// One endpoint's caller-owned state.
pub const Endpoint = struct {
    loss_state: Recovery = .{},
    spaces: [3]Recovery.Space = undefined,
    sent_initial: [16]Recovery.SentPacket = undefined,
    sent_handshake: [16]Recovery.SentPacket = undefined,
    sent_app: [16]Recovery.SentPacket = undefined,
    acked: [32]Recovery.SentPacket = undefined,
    lost: [32]Recovery.SentPacket = undefined,
    events: Recovery.Events = undefined,

    // The driver's storage, one buffer per job (`driver.Storage`).
    tls_slots: [16]tls.level.Output = undefined,
    tls_out: [4096]u8 = undefined,
    peer_initial: [2048]u8 = undefined,
    peer_handshake: [4096]u8 = undefined,
    peer_app: [512]u8 = undefined,
    peer_shares: [tls.handshake_core.peer_share_storage_len]u8 = undefined,
    extension_slots: [1]tls.extension_type.ExtraExtension = undefined,
    our_parameters: [512]u8 = undefined,
    peer_parameters: [512]u8 = undefined,
    selected_alpn: [64]u8 = undefined,
    server_hello: [256]u8 = undefined,

    // The machine's own: CRYPTO reassembly and replay, per level, then streams.
    crypto_initial: [2048]u8 = undefined,
    crypto_handshake: [4096]u8 = undefined,
    sent_crypto_initial: [2048]u8 = undefined,
    sent_crypto_handshake: [4096]u8 = undefined,
    adopted_id: [20]u8 = undefined,
    /// The names. A client's `original_id` is what it first addresses the server
    /// as, and `own_id` is what either end calls itself. A server's
    /// `client_ids` is where `accept` copies the client's pair.
    original_id: [original_id_len]u8 = undefined,
    own_id: [own_id_len]u8 = undefined,
    client_ids: [40]u8 = undefined,
    parameter_bytes: [128]u8 = undefined,
    accepting: quic_io.Connection.Accepting = undefined,
    slots: [2]quic.StreamTable.Slot = undefined,
    send_bytes: [2][stream_bytes]u8 = undefined,
    recv_bytes: [2][stream_bytes]u8 = undefined,
    streams: [2]Conn.Stream = undefined,

    // The shell's scratch, sized for one datagram.
    datagram: [1500]u8 = undefined,
    write_frames: [1500]u8 = undefined,
    plaintext: [1500]u8 = undefined,
    parsed: [16]quic.frame.Frame = undefined,
    stream_events: [16]Conn.StreamEvent = undefined,

    tls_driver: driver.Tls = undefined,
    connection: quic_io.Connection = undefined,

    fn loss(self: *Endpoint) Conn.Loss {
        return .{
            .shared = &self.loss_state,
            .spaces = &self.spaces,
            .sent_initial = &self.sent_initial,
            .sent_handshake = &self.sent_handshake,
            .sent_app = &self.sent_app,
        };
    }

    fn storage(self: *Endpoint) driver.Storage {
        return .{
            .slots = &self.tls_slots,
            .out = &self.tls_out,
            .peer_bytes = .{
                .initial = &self.peer_initial,
                .handshake = &self.peer_handshake,
                .app = &self.peer_app,
            },
            .peer_shares = &self.peer_shares,
            .extension_slots = &self.extension_slots,
            .our_parameters = &self.our_parameters,
            .peer_parameters = &self.peer_parameters,
            .alpn = &self.selected_alpn,
            .server_hello = &self.server_hello,
        };
    }

    /// Build the driver and the connection in place. A server passes no `peer`
    /// and learns it from the first datagram, and builds its machine in
    /// `accept`; a client is given the peer and builds its machine here.
    ///
    /// The TLS random fields, the ephemeral keys, and the connection IDs come
    /// from the platform, never from a constant.
    pub fn start(
        self: *Endpoint,
        io: Io,
        socket: Io.net.Socket,
        peer: ?Io.net.IpAddress,
        tls_config: driver.Config,
    ) driver.Error!void {
        self.events = .init(&self.acked, &self.lost);
        // `Conn.init` asserts that no two buffers overlap, so each stream has
        // its own pair.
        for (&self.streams, &self.send_bytes, &self.recv_bytes) |*stream, *send, *recv| {
            stream.* = .{ .send_buffer = send, .recv_buffer = recv, .recv_limit_bytes = stream_bytes };
        }

        var random: [32]u8 = undefined;
        io.random(&random);
        self.tls_driver = try driver.Tls.init(self.storage(), tls_config, random);
        io.random(&self.original_id);
        io.random(&self.own_id);

        // A server's names are the client's, which it has not met: `accept`
        // fills them in, and what is written here is ignored.
        var conn: Conn.Config = switch (tls_config) {
            .client => Conn.clientConfig(&self.original_id, &self.own_id, self.loss()),
            .server => .{
                .role = .server,
                .loss = self.loss(),
                .original_destination_connection_id = "",
                .destination_connection_id = "",
                .source_connection_id = &self.own_id,
            },
        };
        conn.tls = self.tls_driver.driver();
        conn.crypto = .{ .initial = &self.crypto_initial, .handshake = &self.crypto_handshake };
        conn.crypto_sent = .{
            .initial = &self.sent_crypto_initial,
            .handshake = &self.sent_crypto_handshake,
        };
        conn.connection_id_storage = &self.adopted_id;
        conn.stream_slots = &self.slots;
        conn.streams = &self.streams;
        conn.receive_limit = 4096;
        conn.max_streams_bidi = 1;

        switch (tls_config) {
            .client => {
                // §7.3: a client names itself in its parameters.
                var writer: quic.Writer = .init(&self.parameter_bytes);
                TransportParameters.encode(&writer, limits(.{
                    .initial_source_connection_id = &self.own_id,
                }), .client) catch unreachable;
                conn.transport_parameters = writer.written();
            },
            .server => self.accepting = .{
                .conn = conn,
                .parameters = limits(.{}),
                .parameter_storage = &self.parameter_bytes,
            },
        }

        self.connection = .init(.{
            .io = io,
            .socket = socket,
            .peer = peer,
            .conn = switch (tls_config) {
                .client => conn,
                .server => null,
            },
            .connection_ids = &self.client_ids,
            .datagram = &self.datagram,
            .write_frames = &self.write_frames,
            .plaintext = &self.plaintext,
            .frames = &self.parsed,
            .stream_events = &self.stream_events,
            .recovery_events = &self.events,
        });
    }

    pub fn deinit(self: *Endpoint) void {
        self.tls_driver.deinit();
        self.* = undefined;
    }

    /// Send what the machine owes without waiting for anything: a client's
    /// first Initial goes out here.
    pub fn flush(self: *Endpoint, deadline: Deadline) Error!void {
        _ = try self.connection.flush(deadline.now());
    }

    /// A server waits for its client's first Initial, builds its machine from
    /// it, and answers. Returns once the machine exists, or `error.Timeout`.
    pub fn accept(self: *Endpoint, deadline: Deadline) Error!void {
        while (self.connection.state == .listening) {
            const timeout = deadline.timeout() orelse return error.Timeout;
            _ = try self.connection.accept(self.accepting, deadline.now(), timeout);
        }
        _ = try self.connection.flush(deadline.now());
    }

    /// Wait for one packet and answer it, or give up when the deadline passes.
    /// A datagram that opens nothing is not progress and not an error: the
    /// caller's loop asks again, and the clock is what ends it.
    pub fn step(self: *Endpoint, deadline: Deadline) Error!void {
        const timeout = deadline.timeout() orelse return error.Timeout;
        _ = try self.connection.receive(deadline.now(), timeout);
        _ = try self.connection.flush(deadline.now());
    }

    /// Send every STREAM frame the stream has ready.
    pub fn sendStream(self: *Endpoint, deadline: Deadline) Error!void {
        const offers = [_]Conn.Offer{.{ .stream_id = request_stream, .length = stream_bytes }};
        var written: [offers.len]Conn.Written = undefined;
        while (try self.connection.conn.writeStreams(.{
            .offers = &offers,
            .frames = self.connection.write_frames,
            .out = self.connection.datagram,
            .written = &written,
            .max_payload = 1200,
            .now = deadline.now(),
        })) |packet| {
            try self.connection.socket.send(
                self.connection.io,
                &self.connection.peer,
                self.connection.datagram[0..packet.length],
            );
        }
    }

    /// End the connection with an application NO_ERROR (RFC 9000 §10.2.3).
    pub fn closeNoError(self: *Endpoint, deadline: Deadline) Error!void {
        const length = try self.connection.conn.close(
            .{ .error_code = 0, .application = true },
            self.connection.write_frames,
            self.connection.datagram,
            deadline.now(),
        );
        try self.connection.socket.send(
            self.connection.io,
            &self.connection.peer,
            self.connection.datagram[0..length],
        );
    }
};

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

/// File scope: an `Endpoint` is tens of kilobytes, and the machine points into
/// it, so it is built in place and stays put.
var test_client: Endpoint = undefined;
var test_server: Endpoint = undefined;

test "RFC 9000 §7.2, a server learns the client's connection IDs from its first Initial" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The server is bound first, on a port the client is then told. The client
    // binds anywhere: the server learns where from the first datagram.
    var server_address: Io.net.IpAddress = undefined;
    const server_socket = bound: {
        var port: u16 = 47401;
        while (port < 47451) : (port += 1) {
            server_address = .{ .ip4 = .loopback(port) };
            break :bound Io.net.IpAddress.bind(&server_address, io, .{ .mode = .dgram }) catch continue;
        }
        return error.NoFreePort;
    };
    defer server_socket.close(io);
    const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const client_socket = try local.bind(io, .{ .mode = .dgram });
    defer client_socket.close(io);

    // The fixture's own certificate, as `tls_loopback.zig` uses it.
    const cert_pem = @embedFile("tls_server_crt");
    var der: [cert_pem.len]u8 = undefined;
    var chain_slots: [1][]const u8 = undefined;
    const chain = try tls.certificate_chain.CertificateChain.fromPem(cert_pem, &der, &chain_slots);
    var key = try tls.signature.PrivateKey.fromPemAuto(@embedFile("tls_server_key"));
    defer key.deinit();
    var policy: tls.certificate.Policy = .init;
    policy.insecure_no_chain_anchor = true;

    try test_client.start(io, client_socket, server_address, .{ .client = .{
        .policy = policy,
        .alpn = &.{alpn},
    } });
    defer test_client.deinit();
    try test_server.start(io, server_socket, null, .{ .server = .{
        .credentials = .{ .chain = chain, .signer = key.signer() },
        .alpn = &.{alpn},
    } });
    defer test_server.deinit();

    // Nothing tells the server who the client is until its first Initial lands.
    try testing.expectEqual(quic_io.Connection.State.listening, test_server.connection.state);

    const deadline: Deadline = .init(io);
    try test_client.flush(deadline);
    try test_server.accept(deadline);
    try testing.expectEqual(quic_io.Connection.State.open, test_server.connection.state);

    // What the server learned is what the client invented: its first
    // Destination Connection ID, then its Source Connection ID.
    const learned = test_server.connection.connection_ids;
    try testing.expectEqualSlices(u8, &test_client.original_id, learned[0..original_id_len]);
    try testing.expectEqualSlices(u8, &test_client.own_id, learned[original_id_len..][0..own_id_len]);

    // The handshake completes on both ends: the client sees its own driver
    // finish and the 1-RTT keys, the server its confirmation.
    while (!(test_client.tls_driver.done() and test_client.connection.conn.app != null)) {
        try test_client.step(deadline);
    }
    while (!test_server.connection.established()) try test_server.step(deadline);

    // And a byte crosses a stream.
    const stream = try test_client.connection.conn.openStream(request_stream);
    try stream.send.write("Q");
    try stream.send.finish();
    try test_client.sendStream(deadline);

    var received: [8]u8 = undefined;
    var length: usize = 0;
    while (true) {
        if (test_server.connection.conn.stream(request_stream)) |arrived| {
            length += try arrived.recv.readInto(received[length..]);
            if (arrived.recv.isTerminal()) break;
        }
        try test_server.step(deadline);
    }
    try testing.expectEqualStrings("Q", received[0..length]);
}
