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

// -- Tests -------------------------------------------------------------------
//
// A server and a client from this file, in one process, over loopback UDP and
// a real TLS 1.3 handshake: what `just interop-hq` runs as two processes, plus
// what only a test can arrange.

/// Read a whole stream into `buffer`, until the peer's FIN, with `read`
/// itself: the side of a test that checks an adapter against the stream.
fn readAll(stream: quic_io.Stream, io: Io, buffer: []u8) (quic_io.Stream.ReadError || error{TooLong})![]u8 {
    var length: usize = 0;
    while (true) {
        if (length == buffer.len) return error.TooLong;
        var vector = [_][]u8{buffer[length..]};
        const count = try stream.read(io, &vector);
        if (count == 0) return buffer[0..length];
        length += count;
    }
}

/// Write all of `bytes` with `write` itself. They must fit the send buffer.
fn writeAll(stream: quic_io.Stream, io: Io, bytes: []const u8) quic_io.Stream.WriteError!void {
    var sent: usize = 0;
    while (sent < bytes.len) sent += try stream.write(io, bytes[sent..]);
}

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
    /// Whether `connect` got far enough that `test_client` and `client_tls`
    /// are built, and so are `deinit`'s to tear down.
    client_started: bool,

    const cert_pem = @embedFile("tls_server_crt");

    /// Bind the server and start listening. The client's `connect` is the
    /// test's to call.
    ///
    /// The kernel names the port, so no two tests, and no two processes, share
    /// one. A fixed port is shared by all of them, and whatever reaches it (a
    /// client of another process, a straggler for the last test's server)
    /// arrives as this server's first datagram and takes its one connection
    /// (§8.1).
    fn init(self: *Pair) !void {
        self.threaded = .init(testing.allocator, .{});
        self.io = self.threaded.io();
        self.client_started = false;
        const io = self.io;
        const any: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const socket = try any.bind(io, .{ .mode = .dgram });
        self.server_address = socket.address;
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
        const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const socket = try local.bind(io, .{ .mode = .dgram });
        const client_driver = client_tls.start(io, .{ .client = .{ .policy = policy, .alpn = &.{alpn} } }) catch |err| {
            socket.close(io);
            return err;
        };
        // From here the endpoint owns the socket, and `connect` failing still
        // leaves it for `deinit`.
        self.client_started = true;
        return test_client.connect(.{
            .io = io,
            .socket = socket,
            .peer = self.server_address,
            .driver = client_driver,
            .parameters = parameters,
        });
    }

    /// `deinit` both endpoints, which must return with their tasks running.
    /// The client only if `connect` started it: tearing down an endpoint that
    /// was never built is a `Group.cancel` on whatever the last test left.
    fn deinit(self: *Pair) void {
        const io = self.io;
        if (self.client_started) {
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
    defer pair.deinit();
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
    defer pair.deinit();
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

// -- Stream.Reader and Stream.Writer -------------------------------------------
//
// Each adapter is checked against the plain `read` or `write` on the other end,
// so what crosses the wire is the stream's and not the adapter's own echo.

/// A client stream that has sent the request `serveOne` expects, with its FIN.
fn sendRequest(connection: quic_io.Connection, io: Io) !quic_io.Stream {
    const stream = try connection.openStream(io, .bidi);
    try writeAll(stream, io, "GET /index.html\r\n");
    try stream.shutdown(io, .send);
    return stream;
}

test "RFC 9000 §19.8, a Stream.Reader yields the stream's bytes, then EndOfStream at the FIN" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const stream = try sendRequest(connection, io);

    var buffer: [64]u8 = undefined;
    var reader: quic_io.Stream.Reader = .init(stream, io, &buffer);
    try testing.expectEqualStrings(body, try reader.interface.take(body.len));
    // The FIN bit ends the stream at the final size (§4.5), and a read past it
    // is the end of the reader too, not a wait.
    try testing.expectError(error.EndOfStream, reader.interface.takeByte());
    try testing.expectEqual(null, reader.err);

    stream.close(io);
    connection.close(io);
    try serving.await(io);
}

test "RFC 9000 §2.2, a Stream.Reader smaller than the data reads it in order across many reads" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const stream = try sendRequest(connection, io);

    var buffer: [4]u8 = undefined;
    var reader: quic_io.Stream.Reader = .init(stream, io, &buffer);
    var got: [64]u8 = undefined;
    var length: usize = 0;
    var reads: usize = 0;
    while (true) {
        const chunk = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return reader.err.?,
        };
        try testing.expect(chunk.len <= buffer.len);
        @memcpy(got[length..][0..chunk.len], chunk);
        length += chunk.len;
        reader.interface.toss(chunk.len);
        reads += 1;
    }
    try testing.expectEqualStrings(body, got[0..length]);
    try testing.expect(reads >= body.len / buffer.len);

    stream.close(io);
    connection.close(io);
    try serving.await(io);
}

test "RFC 9000 §19.8, what a Stream.Writer drains crosses as STREAM frames, byte for byte" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const stream = try connection.openStream(io, .bidi);

    // A buffer shorter than the request, so `print` drains mid-line and the
    // flush drains the rest. `serveOne` reads it with plain `read`.
    var buffer: [8]u8 = undefined;
    var writer: quic_io.Stream.Writer = .init(stream, io, &buffer);
    try writer.interface.print("GET {s}\r\n", .{"/index.html"});
    try writer.interface.flush();
    try testing.expectEqual(null, writer.err);
    try stream.shutdown(io, .send);

    var response: [64]u8 = undefined;
    try testing.expectEqualStrings(body, try readAll(stream, io, &response));
    stream.close(io);
    connection.close(io);
    try serving.await(io);
}

/// Accept, read the request to its FIN, and reset the stream rather than
/// answer it.
fn resetOne(io: Io) !void {
    const connection = try test_server.accept(io);
    const stream = try connection.acceptStream(io);
    defer stream.close(io);
    var line: [64]u8 = undefined;
    _ = try readAll(stream, io, &line);
    try stream.shutdown(io, .both);
    try testing.expectError(error.ConnectionClosed, connection.acceptStream(io));
}

test "RFC 9000 §19.4, a RESET_STREAM fails a Stream.Reader, and err says so" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(resetOne, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const stream = try sendRequest(connection, io);

    var buffer: [64]u8 = undefined;
    var reader: quic_io.Stream.Reader = .init(stream, io, &buffer);
    try testing.expectError(error.ReadFailed, reader.interface.takeByte());
    try testing.expectEqual(error.StreamReset, reader.err.?);

    stream.close(io);
    connection.close(io);
    try serving.await(io);
}

// -- Forged first datagrams ----------------------------------------------------
//
// §8.1: an endpoint has one connection to give, so what a stranger can do with
// one datagram decides whether anyone else gets it.

/// How long a test waits for a server task to have received a datagram that
/// was already sent. It cannot be observed from here: a dropped datagram
/// leaves no trace, which is the point.
const settle_ms = 250;

/// A Version 1 Initial whose header reads true and whose ciphertext is random
/// (§17.2.2): the packet number and everything after it is noise, so no tag
/// verifies. `claimed_extra` is how many bytes past the datagram's end the
/// Length field claims, so 0 is a well-formed header and anything else is not.
fn forgedInitial(io: Io, out: *[1200]u8, dcid_len: u8, claimed_extra: u14) void {
    io.random(out);
    out[0..5].* = .{ 0xc3, 0, 0, 0, 1 };
    var at: usize = 5;
    out[at] = dcid_len;
    at += 1 + dcid_len;
    out[at] = 8;
    at += 1 + 8;
    out[at] = 0; // No token.
    at += 1;
    const claimed: u14 = @intCast(out.len - at - 2 + claimed_extra);
    out[at] = 0x40 | @as(u8, @intCast(claimed >> 8));
    out[at + 1] = @truncate(claimed);
}

/// A bound UDP socket of someone who is not the client.
fn bindStranger(io: Io) !Io.net.Socket {
    const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    return local.bind(io, .{ .mode = .dgram });
}

/// The server has dropped everything so far: still listening, no peer.
fn expectUncommitted(io: Io) !void {
    try io.sleep(.fromMilliseconds(settle_ms), .awake);
    const nowhere: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
    try testing.expectEqual(.listening, test_server.core.phase);
    try testing.expect(test_server.core.peer.eql(&nowhere));
}

/// The client's request and the server's answer, and the server's peer is the
/// client rather than whoever spoke first.
fn expectExchange(connection: quic_io.Connection, io: Io) !void {
    const stream = try sendRequest(connection, io);
    var response: [64]u8 = undefined;
    try testing.expectEqualStrings(body, try readAll(stream, io, &response));
    try testing.expect(test_server.core.peer.eql(&test_client.core.socket.address));
    stream.close(io);
    connection.close(io);
}

test "RFC 9000 §8.1, a forged Initial does not take the one connection, and the client after it does" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};

    const stranger = try bindStranger(io);
    defer stranger.close(io);
    var datagram: [1200]u8 = undefined;
    forgedInitial(io, &datagram, 8, 0);
    try stranger.send(io, &pair.server_address, &datagram);
    try expectUncommitted(io);

    try expectExchange(try pair.connect(), io);
    try serving.await(io);
}

test "RFC 9000 §8.1, a first datagram that is malformed does not take the one connection either" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};

    const stranger = try bindStranger(io);
    defer stranger.close(io);
    var datagram: [1200]u8 = undefined;
    // A Length field that reaches past the datagram (§17.2), a Destination
    // Connection ID of no bytes (§7.2), and one longer than version 1 allows
    // (§17.2).
    const shapes = [_]struct { dcid_len: u8, claimed_extra: u14 }{
        .{ .dcid_len = 8, .claimed_extra = 2800 },
        .{ .dcid_len = 0, .claimed_extra = 0 },
        .{ .dcid_len = 21, .claimed_extra = 0 },
    };
    for (shapes) |shape| {
        forgedInitial(io, &datagram, shape.dcid_len, shape.claimed_extra);
        try stranger.send(io, &pair.server_address, &datagram);
    }
    try expectUncommitted(io);

    try expectExchange(try pair.connect(), io);
    try serving.await(io);
}

test "RFC 9000 §8.1, a genuine first datagram opens on the first accept, from its own address" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};
    try expectExchange(try pair.connect(), io);
    try serving.await(io);
}
