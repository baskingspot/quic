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
//! The connection IDs are the examples' own convention, not a protocol rule. A
//! server is built before any datagram arrives, so it cannot read the client's
//! IDs out of the first Initial (`Conn.Opening`), and the pair therefore agree
//! on them here. A foreign client picks its own, and serving one needs a way to
//! build the connection after the first datagram, which `quic-io` does not yet
//! have.

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

/// The name the client gives the server in its first Initial, which also seeds
/// the Initial keys (RFC 9001 §5.2). §7.2 asks for at least eight bytes.
const original_destination_id = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
/// What the server calls itself, which the client adopts from the server's first
/// Initial (§7.2).
const server_id = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
const client_id = [_]u8{ 0xc1, 0xc2 };

/// The most one stream holds in either direction, and the size of its ring.
const stream_bytes = 1024;

/// What the handshake carries opaquely (RFC 9001 §8.2), and what each `Conn`
/// adopts as the peer's limits: one bidirectional stream of `stream_bytes`.
fn encodeParameters(comptime sender: TransportParameters.Role, comptime identity: TransportParameters) []const u8 {
    const bytes = comptime blk: {
        var buffer: [128]u8 = undefined;
        var writer: quic.Writer = .init(&buffer);
        var parameters = identity;
        parameters.initial_max_data = 4096;
        parameters.initial_max_stream_data_bidi_local = stream_bytes;
        parameters.initial_max_stream_data_bidi_remote = stream_bytes;
        parameters.initial_max_streams_bidi = 1;
        TransportParameters.encode(&writer, parameters, sender) catch unreachable;
        const written = buffer[0..writer.written().len].*;
        break :blk written;
    };
    return &bytes;
}

/// §7.3: a client names itself, and a server also echoes the connection ID the
/// client first addressed.
const client_parameters = encodeParameters(.client, .{
    .initial_source_connection_id = &client_id,
});
const server_parameters = encodeParameters(.server, .{
    .original_destination_connection_id = &original_destination_id,
    .initial_source_connection_id = &server_id,
});

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
    /// and learns it from the first datagram; a client is given it.
    ///
    /// The TLS random fields and ephemeral keys come from the platform, never
    /// from a constant.
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

        var conn: Conn.Config = switch (tls_config) {
            .client => Conn.clientConfig(&original_destination_id, &client_id, self.loss()),
            .server => .{
                .role = .server,
                .loss = self.loss(),
                .original_destination_connection_id = &original_destination_id,
                .destination_connection_id = &client_id,
                .source_connection_id = &server_id,
            },
        };
        conn.tls = self.tls_driver.driver();
        conn.transport_parameters = switch (tls_config) {
            .client => client_parameters,
            .server => server_parameters,
        };
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

        self.connection = .init(.{
            .io = io,
            .socket = socket,
            .peer = peer,
            .conn = conn,
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
