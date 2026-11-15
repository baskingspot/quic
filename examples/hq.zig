//! What `hq_server.zig` and `hq_client.zig` share: the protocol's few
//! constants, the endpoint type, and the TLS driver's storage, which is the
//! program's and not `quic-io`'s (the module takes a ready driver).
//!
//! hq-interop is HTTP/0.9 over QUIC: one bidirectional stream per request, the
//! request `GET /path\r\n`, the response the body and a FIN. It is the smallest
//! application that proves a handshake carried bytes both ways.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;

const driver = @import("quic-tls");
const quic = @import("quic");
const quic_io = @import("quic-io");
const tls = @import("tls");

/// The application protocol both ends name in the handshake.
pub const alpn = "hq-interop";

/// What the server answers, as the client expects to read it back.
pub const body = "hello from baskingspot/quic\n";

/// One connection's storage, with the module's default limits.
pub const Endpoint = quic_io.Endpoint(quic_io.Sizing(.{}));

/// §10.1: five seconds of silence ends the connection, which is also what
/// bounds a handshake that goes nowhere.
pub const parameters: quic.TransportParameters = .{ .max_idle_timeout = 5000 };

/// The TLS driver and every buffer it writes into (`driver.Storage`). Built in
/// place, because the machine holds a pointer to the driver.
pub const Tls = struct {
    slots: [16]tls.level.Output = undefined,
    out: [4096]u8 = undefined,
    peer_initial: [2048]u8 = undefined,
    peer_handshake: [4096]u8 = undefined,
    peer_app: [512]u8 = undefined,
    peer_shares: [tls.handshake_core.peer_share_storage_len]u8 = undefined,
    extension_slots: [1]tls.extension_type.ExtraExtension = undefined,
    our_parameters: [512]u8 = undefined,
    peer_parameters: [512]u8 = undefined,
    selected_alpn: [64]u8 = undefined,
    server_hello: [256]u8 = undefined,
    engine: driver.Tls = undefined,

    /// Build the driver. The TLS random fields and the ephemeral keys come
    /// from the platform, never from a constant.
    pub fn start(self: *Tls, io: Io, config: driver.Config) driver.Error!quic.handshake.Driver {
        var random: [32]u8 = undefined;
        io.random(&random);
        self.engine = try .init(.{
            .slots = &self.slots,
            .out = &self.out,
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
        }, config, random);
        return self.engine.driver();
    }

    pub fn deinit(self: *Tls) void {
        self.engine.deinit();
        self.* = undefined;
    }
};

/// Read a whole stream into `buffer`, until the peer's FIN.
pub fn readAll(stream: quic_io.Stream, io: Io, buffer: []u8) (quic_io.Stream.ReadError || error{TooLong})![]u8 {
    var length: usize = 0;
    while (true) {
        if (length == buffer.len) return error.TooLong;
        var vector = [_][]u8{buffer[length..]};
        const count = try stream.read(io, &vector);
        if (count == 0) return buffer[0..length];
        length += count;
    }
}

/// Write all of `bytes`, which must fit the stream's send buffer.
pub fn writeAll(stream: quic_io.Stream, io: Io, bytes: []const u8) quic_io.Stream.WriteError!void {
    var sent: usize = 0;
    while (sent < bytes.len) sent += try stream.write(io, bytes[sent..]);
}

// -- Tests -------------------------------------------------------------------
//
// A server and a client from this file, in one process, over loopback UDP and
// a real TLS 1.3 handshake: what `just interop-hq` runs as two processes, plus
// what only a test can arrange.

/// File scope: an endpoint is tens of kilobytes and must not move.
var test_client: Endpoint = undefined;
var test_server: Endpoint = undefined;
var client_tls: Tls = undefined;
var server_tls: Tls = undefined;

const Pair = struct {
    threaded: Io.Threaded,
    io: Io,
    server_address: Io.net.IpAddress,
    key: tls.signature.PrivateKey,
    der: [cert_pem.len]u8 = undefined,
    chain_slots: [1][]const u8 = undefined,

    const cert_pem = @embedFile("tls_server_crt");

    /// Bind the server, start listening, and build the client's driver. The
    /// client's `connect` is the test's to call.
    fn init(self: *Pair) !void {
        self.threaded = .init(testing.allocator, .{});
        self.io = self.threaded.io();
        const io = self.io;
        const socket = bound: {
            var port: u16 = 47401;
            while (port < 47451) : (port += 1) {
                self.server_address = .{ .ip4 = .loopback(port) };
                break :bound self.server_address.bind(io, .{ .mode = .dgram }) catch continue;
            }
            return error.NoFreePort;
        };
        const chain: tls.certificate_chain.CertificateChain = try .fromPem(cert_pem, &self.der, &self.chain_slots);
        self.key = try .fromPemAuto(@embedFile("tls_server_key"));
        const server_driver = try server_tls.start(io, .{ .server = .{
            .credentials = .{ .chain = chain, .signer = self.key.signer() },
            .alpn = &.{alpn},
        } });
        test_server.listen(.{ .io = io, .socket = socket, .driver = server_driver, .parameters = parameters });
    }

    fn connect(self: *Pair) !quic_io.Connection {
        const io = self.io;
        var policy: tls.certificate.Policy = .init;
        policy.insecure_no_chain_anchor = true;
        const client_driver = try client_tls.start(io, .{ .client = .{ .policy = policy, .alpn = &.{alpn} } });
        const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        return test_client.connect(.{
            .io = io,
            .socket = try local.bind(io, .{ .mode = .dgram }),
            .peer = self.server_address,
            .driver = client_driver,
            .parameters = parameters,
        });
    }

    /// `deinit` both endpoints, which must return with their tasks running.
    fn deinit(self: *Pair, client_started: bool) void {
        const io = self.io;
        if (client_started) {
            test_client.deinit(io);
            client_tls.deinit();
        }
        test_server.deinit(io);
        server_tls.deinit();
        self.key.deinit();
        self.threaded.deinit();
        self.* = undefined;
    }
};

/// The server half of an exchange: accept, read the request to its FIN,
/// answer, and wait for the client to close.
fn serveOne(io: Io) !void {
    const connection = try test_server.accept(io);
    const stream = try connection.acceptStream(io);
    defer stream.close(io);
    var request: [64]u8 = undefined;
    try testing.expectEqualStrings("GET /index.html\r\n", try readAll(stream, io, &request));
    try writeAll(stream, io, body);
    try stream.shutdown(io, .send);
    try testing.expectError(error.ConnectionClosed, connection.acceptStream(io));
}

test "RFC 9000 §2, a request and its response cross a stream, and the client closes" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit(true);
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();

    const stream = try connection.openStream(io, .bidi);
    try writeAll(stream, io, "GET /index.html\r\n");
    try stream.shutdown(io, .send);
    var response: [64]u8 = undefined;
    try testing.expectEqualStrings(body, try readAll(stream, io, &response));

    // The handle is spent once closed, and stays spent when its slot is reused.
    stream.close(io);
    var vector = [_][]u8{&response};
    try testing.expectError(error.StreamClosed, stream.read(io, &vector));
    try testing.expectError(error.StreamClosed, stream.write(io, "x"));

    connection.close(io);
    try serving.await(io);
    try testing.expectError(error.ConnectionClosed, connection.openStream(io, .bidi));
}

/// Accept, take the stream, and never answer.
fn acceptSilently(io: Io) !void {
    const connection = try test_server.accept(io);
    const stream = try connection.acceptStream(io);
    _ = stream;
    try io.sleep(.fromSeconds(10), .awake);
}

test "a read waiting on a silent peer is canceled like any Io wait, and deinit stops the tasks" {
    var pair: Pair = undefined;
    try pair.init();
    // Both endpoints are torn down with their tasks still running.
    defer pair.deinit(true);
    const io = pair.io;

    var serving = try io.concurrent(acceptSilently, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const stream = try connection.openStream(io, .bidi);
    try writeAll(stream, io, "GET /\r\n");

    var response: [16]u8 = undefined;
    var vector = [_][]u8{&response};
    var reading = try io.concurrent(quic_io.Stream.read, .{ stream, io, &vector });
    try testing.expectError(error.Canceled, reading.cancel(io));
}
