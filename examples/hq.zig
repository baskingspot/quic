//! What `hq_server.zig` and `hq_client.zig` share: the protocol's few
//! constants and the endpoint type. The TLS handshake is `quic-io`'s: a server
//! is handed a certificate and key, a client a trust decision.
//!
//! hq-interop is HTTP/0.9 over QUIC: one bidirectional stream per request, the
//! request `GET /path\r\n`, the response the body and a FIN. It is the smallest
//! application that proves a handshake carried bytes both ways.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const testing = std.testing;

const quic = @import("quic");
const quic_io = @import("quic-io");

/// The application protocol both ends name in the handshake.
pub const alpn = "hq-interop";

/// What the server answers, as the client expects to read it back.
pub const body = "hello from baskingspot/quic\n";

/// One connection's storage, handshake included, with the module's default
/// limits and two stream slots preheated: a client's one request and the slot
/// it keeps for the stream the server may open, and a server's one request and
/// the slot accepting it grants the client for another. So neither end
/// allocates once it runs.
pub const Sizing = quic_io.Sizing(.{ .preheat = 2 });
pub const Endpoint = quic_io.Endpoint(Sizing);

/// §10.1: five seconds of silence ends the connection, which is also what
/// bounds a handshake that goes nowhere.
pub const parameters: quic.TransportParameters = .{ .max_idle_timeout = 5000 };

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

/// A server listening and a client to connect, over the endpoints `client` and
/// `server`, which are file-scope variables because an endpoint must not move.
fn PairOf(comptime E: type, comptime client: *E, comptime server: *E) type {
    return struct {
        const Self = @This();

        threaded: Io.Threaded,
        io: Io,
        /// What the client's streams come from; the server's is `init`'s.
        client_allocator: std.mem.Allocator,
        server_address: Io.net.IpAddress,
        /// Whether `connect` got far enough that `client` is built, and so
        /// is `deinit`'s to tear down.
        client_started: bool,

        /// Bind the server and start listening. The client's `connect` is the
        /// test's to call.
        ///
        /// The kernel names the port, so no two tests, and no two processes,
        /// share one. A fixed port is shared by all of them, and whatever
        /// reaches it (a client of another process, a straggler for the last
        /// test's server) arrives as this server's first datagram and takes its
        /// one connection (§8.1).
        fn init(self: *Self) !void {
            return self.initWith(testing.allocator, testing.allocator);
        }

        /// `init`, with the allocator each endpoint's streams come from.
        fn initWith(self: *Self, client_allocator: std.mem.Allocator, server_allocator: std.mem.Allocator) !void {
            self.threaded = .init(testing.allocator, .{});
            self.io = self.threaded.io();
            self.client_allocator = client_allocator;
            self.client_started = false;
            const io = self.io;
            const any: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
            const socket = try any.bind(io, .{ .mode = .dgram });
            self.server_address = socket.address;
            try server.listen(server_allocator, .{
                .io = io,
                .socket = socket,
                .certificate = @embedFile("tls_server_crt"),
                .key = @embedFile("tls_server_key"),
                .alpn = &.{alpn},
                .parameters = parameters,
            });
        }

        fn connect(self: *Self) !quic_io.Connection {
            const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
            const socket = try local.bind(self.io, .{ .mode = .dgram });
            return self.connectFrom(socket, self.server_address);
        }

        /// Connect from `socket`, which the client then owns, to `peer`: the
        /// server, or something that forwards to it.
        fn connectFrom(self: *Self, socket: Io.net.Socket, peer: Io.net.IpAddress) !quic_io.Connection {
            // From here the endpoint owns the socket, and `connect` failing still
            // leaves it for `deinit`.
            self.client_started = true;
            return client.connect(self.client_allocator, .{
                .io = self.io,
                .socket = socket,
                .peer = peer,
                .alpn = &.{alpn},
                .trust = .insecure,
                .parameters = parameters,
            });
        }

        /// `deinit` both endpoints, which must return with their tasks
        /// running. The client only if `connect` started it: tearing down an
        /// endpoint that was never built is a `Group.cancel` on whatever the
        /// last test left.
        fn deinit(self: *Self) void {
            const io = self.io;
            if (self.client_started) {
                client.deinit(io);
            }
            server.deinit(io);
            self.threaded.deinit();
            self.* = undefined;
        }
    };
}

const Pair = PairOf(Endpoint, &test_client, &test_server);

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

// -- Real loss -------------------------------------------------------------------
//
// The exchange above through a UDP relay this test owns, which drops datagrams
// in both directions by their place in each direction's sequence. Never at
// random, so a failure replays the same pattern.
//
// The timers are the shipped ones. `parameters` sets a 5 s idle timeout, and
// the PTO starts from RFC 9002's 333 ms initial RTT (about 1 s) and falls to a
// few milliseconds once loopback yields a sample. A loss repaired by a probe
// costs about a second during the handshake and milliseconds after it, inside
// the idle timeout, and a loss nothing repairs ends in `error.IdleTimeout`
// within seconds instead of a hang.

/// The loss tests' endpoints: a stream ring big enough that one response
/// leaves in more full datagrams, back to back, than either pattern below lets
/// through between two drops. Each pattern is then sure to drop response data.
const LossSizing = quic_io.Sizing(.{ .stream_ring = 16384 });
const LossEndpoint = quic_io.Endpoint(LossSizing);
var loss_client: LossEndpoint = undefined;
var loss_server: LossEndpoint = undefined;
const LossPair = PairOf(LossEndpoint, &loss_client, &loss_server);

/// What the server answers under loss: the whole stream ring, and no byte
/// equal to its neighbor, so a range delivered twice or at the wrong offset
/// does not compare equal.
const loss_body: [LossSizing.limits.stream_ring]u8 = bytes: {
    var bytes: [LossSizing.limits.stream_ring]u8 = undefined;
    @setEvalBranchQuota(4 * bytes.len);
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index % 251);
    break :bytes bytes;
};

/// A short-header datagram this long is response data. A 1-RTT packet in this
/// shell is never padded, and the ones without STREAM data (ACK, PING,
/// HANDSHAKE_DONE, the MAX_* frames, RESET_STREAM, STOP_SENDING,
/// CONNECTION_CLOSE) are tens of bytes.
const bulk = 1000;

/// What one direction of the relay passed on and dropped.
const Tally = struct {
    forwarded: u32 = 0,
    dropped: u32 = 0,
    /// Dropped datagrams that were one 1-RTT packet of at least `bulk` bytes.
    dropped_bulk: u32 = 0,
};

/// A UDP relay between the client and the server: the client talks to
/// `client_side`, the server hears from `server_side`, and datagram `n` of
/// either direction, counting from 0, is dropped when `drop[n % drop.len]`.
const Relay = struct {
    client_side: Io.net.Socket,
    server_side: Io.net.Socket,
    drop: []const bool,
    upstream: Tally = .{},
    downstream: Tally = .{},
    group: Io.Group = .init,

    fn bind(io: Io, drop: []const bool) !Relay {
        // A pattern that drops everything is a partition, not loss.
        assert(std.mem.findScalar(bool, drop, false) != null);
        const any: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const client_side = try any.bind(io, .{ .mode = .dgram });
        errdefer client_side.close(io);
        const server_side = try any.bind(io, .{ .mode = .dgram });
        return .{ .client_side = client_side, .server_side = server_side, .drop = drop };
    }

    /// Forward both directions between `client` and `server` until `stop`.
    fn run(self: *Relay, io: Io, client: Io.net.IpAddress, server: Io.net.IpAddress) Io.ConcurrentError!void {
        const up = .{ self, io, self.client_side, self.server_side, client, server, &self.upstream };
        try self.group.concurrent(io, forward, up);
        errdefer self.group.cancel(io);
        const down = .{ self, io, self.server_side, self.client_side, server, client, &self.downstream };
        try self.group.concurrent(io, forward, down);
    }

    /// Stop both tasks, then close both sockets. The tallies stay readable.
    fn stop(self: *Relay, io: Io) void {
        self.group.cancel(io);
        self.client_side.close(io);
        self.server_side.close(io);
    }

    /// One direction: what `source` sends `from` leaves `to` for `destination`.
    fn forward(
        self: *Relay,
        io: Io,
        from: Io.net.Socket,
        to: Io.net.Socket,
        source: Io.net.IpAddress,
        destination: Io.net.IpAddress,
        tally: *Tally,
    ) Io.Cancelable!void {
        var buffer: [2048]u8 = undefined;
        while (true) {
            const message = from.receive(io, &buffer) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                // Lost on the way in: one more loss, which the test is about.
                else => continue,
            };
            // A stranger's datagram is not the pair's to count.
            if (!message.from.eql(&source)) continue;
            const index = tally.forwarded + tally.dropped;
            if (self.drop[index % self.drop.len]) {
                tally.dropped += 1;
                // §17.3.1: the header form bit is outside header protection.
                if (message.data.len >= bulk and message.data[0] & 0x80 == 0) tally.dropped_bulk += 1;
                continue;
            }
            tally.forwarded += 1;
            to.send(io, &destination, message.data) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                // A refused send is one more loss, which is the test's point.
                else => {},
            };
        }
    }
};

/// The server half under loss: `serveOne`, answering with `loss_body`.
///
/// The client's CONNECTION_CLOSE is the one packet nobody sends twice (§10.2),
/// so when the relay drops it this waits out the idle timeout. The test cancels
/// it instead once the client has read the whole body: by then the server has
/// done everything the exchange needs from it.
fn serveBulk(io: Io) !void {
    const connection = try loss_server.accept(io);
    const stream = try connection.acceptStream(io);
    defer stream.close(io);
    var request: [64]u8 = undefined;
    try testing.expectEqualStrings("GET /index.html\r\n", try readAll(stream, io, &request));
    try writeAll(stream, io, &loss_body);
    try stream.shutdown(io, .send);
    if (connection.acceptStream(io)) |_| return error.UnexpectedStream else |err| switch (err) {
        error.ConnectionClosed => {},
        else => return err,
    }
}

/// The hq exchange through `relay`: the request, the whole of `loss_body`
/// back, intact and ended by the server's FIN, and the client's close.
fn exchangeThrough(pair: *LossPair, relay: *Relay) !void {
    const io = pair.io;
    var serving = try io.concurrent(serveBulk, .{io});
    defer serving.cancel(io) catch {};
    const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try local.bind(io, .{ .mode = .dgram });
    relay.run(io, socket.address, pair.server_address) catch |err| {
        socket.close(io);
        return err;
    };
    const connection = try pair.connectFrom(socket, relay.client_side.address);
    const stream = try sendRequest(connection, io);
    // One byte over, so a longer response is `error.TooLong`, not a match.
    var response: [loss_body.len + 1]u8 = undefined;
    try testing.expectEqualSlices(u8, &loss_body, try readAll(stream, io, &response));
    // The server's peer is the relay, which is where all its packets went.
    try testing.expect(loss_server.core.peer.eql(&relay.server_side.address));
    stream.close(io);
    connection.close(io);
    serving.cancel(io) catch |err| switch (err) {
        error.Canceled => {},
        else => return err,
    };
}

/// Run the exchange through a relay dropping by `drop`, and require that the
/// drops hit both directions and that the body needed a resend.
fn expectRecovery(drop: []const bool) !void {
    var pair: LossPair = undefined;
    try pair.init();
    defer pair.deinit();
    var relay: Relay = try .bind(pair.io, drop);
    {
        defer relay.stop(pair.io);
        try exchangeThrough(&pair, &relay);
    }
    try testing.expect(relay.upstream.dropped > 0);
    try testing.expect(relay.downstream.dropped > 0);
    // Response bytes the relay dropped, and a body that arrived whole anyway:
    // this shell sends a STREAM range a second time only when the machine
    // marks it lost (§13.3), and a probe is a PING, so those bytes reached the
    // client in a retransmission.
    try testing.expect(relay.downstream.dropped_bulk > 0);
}

test "RFC 9002 §6 and RFC 9000 §13.3, the exchange survives two datagrams of every five dropped each way" {
    try expectRecovery(&.{ false, true, false, true, false });
}

test "RFC 9002 §6 and RFC 9000 §13.3, the exchange survives every seventh datagram dropped each way" {
    try expectRecovery(&.{ false, false, false, false, false, false, true });
}

// -- Pooled streams --------------------------------------------------------------
//
// A stream's buffers come from its endpoint's pool, which takes them from the
// allocator `listen` or `connect` was handed. These pin when it does: never
// once a preheated pool runs, never again for a slot a closed stream gave back,
// never because of what a peer sends, and never with a failure the connection
// does not survive.

/// The streams `endpoint`'s machine holds open, read under its mutex.
fn openStreams(endpoint: *Endpoint, io: Io) usize {
    endpoint.core.mutex.lockUncancelable(io);
    defer endpoint.core.mutex.unlock(io);
    var count: usize = 0;
    for (endpoint.core.storage.streams) |*entry| count += @intFromBool(entry.isOpen());
    return count;
}

/// How many slots `endpoint`'s pool has taken from its allocator.
fn poolCapacity(endpoint: *Endpoint, io: Io) u32 {
    endpoint.core.mutex.lockUncancelable(io);
    defer endpoint.core.mutex.unlock(io);
    return endpoint.pool_capacity;
}

/// Wait until neither endpoint holds a stream open. A closed stream's slot
/// comes free once both halves are over (§3.1, §3.2), which is the peer's
/// acknowledgment arriving, not the close.
fn awaitNoStreams(io: Io) !void {
    for (0..2000) |_| {
        if (openStreams(&test_client, io) + openStreams(&test_server, io) == 0) return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.StreamsStillOpen;
}

/// Read one request off `stream`, answer it with `body` and a FIN, and close.
fn answer(stream: quic_io.Stream, io: Io) !void {
    defer stream.close(io);
    var request: [64]u8 = undefined;
    try testing.expectEqualStrings("GET /index.html\r\n", try readAll(stream, io, &request));
    try writeAll(stream, io, body);
    try stream.shutdown(io, .send);
}

/// `serveOne` for `count` streams in turn.
fn serveMany(io: Io, count: usize) !void {
    const connection = try test_server.accept(io);
    for (0..count) |_| try answer(try connection.acceptStream(io), io);
    try testing.expectError(error.ConnectionClosed, connection.acceptStream(io));
}

/// Accept the next stream on `connection` and answer it.
fn answerNext(connection: quic_io.Connection, io: Io) !void {
    try answer(try connection.acceptStream(io), io);
}

/// One request, its whole response, and both ends' streams freed.
fn fetchOne(connection: quic_io.Connection, io: Io) !void {
    const stream = try sendRequest(connection, io);
    var response: [64]u8 = undefined;
    try testing.expectEqualStrings(body, try readAll(stream, io, &response));
    stream.close(io);
    try awaitNoStreams(io);
}

/// §4.6: the client has no credit for another stream, so an open waits for
/// it until canceled.
fn expectNoCredit(connection: quic_io.Connection, io: Io) !void {
    var opening = try io.concurrent(quic_io.Connection.openStream, .{ connection, io, .bidi });
    try io.sleep(.fromMilliseconds(settle_ms), .awake);
    try testing.expectError(error.Canceled, opening.cancel(io));
}

/// Each endpoint's own memory, `fixed_buffer_bytes` exactly, for the tests
/// that hold an endpoint to it. An endpoint's allocator is its alone.
var client_memory: [Sizing.fixed_buffer_bytes]u8 = undefined;
var server_memory: [Sizing.fixed_buffer_bytes]u8 = undefined;

test "RFC 9000 §2, endpoints on a FixedBufferAllocator and a preheated pool exchange without allocating" {
    var client_fixed: std.heap.FixedBufferAllocator = .init(&client_memory);
    var server_fixed: std.heap.FixedBufferAllocator = .init(&server_memory);
    // Counting every call, and failing none.
    var client_counted: testing.FailingAllocator = .init(client_fixed.allocator(), .{});
    var server_counted: testing.FailingAllocator = .init(server_fixed.allocator(), .{});
    var pair: Pair = undefined;
    try pair.initWith(client_counted.allocator(), server_counted.allocator());
    defer pair.deinit();
    const io = pair.io;
    const server_preheated = server_counted.allocated_bytes;
    const server_calls = server_counted.allocations;
    try testing.expect(server_calls > 0);

    var serving = try io.concurrent(serveOne, .{io});
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const client_preheated = client_counted.allocated_bytes;
    const client_calls = client_counted.allocations;
    try testing.expect(client_calls > 0);
    try expectExchange(connection, io);
    try serving.await(io);

    // Not a byte after the preheat: not for the stream the client opened, the
    // one the server accepted, or the credit accepting it granted (§4.6).
    try testing.expectEqual(client_calls, client_counted.allocations);
    try testing.expectEqual(server_calls, server_counted.allocations);
    try testing.expectEqual(client_preheated, client_counted.allocated_bytes);
    try testing.expectEqual(server_preheated, server_counted.allocated_bytes);
    // And the reserve `fixed_buffer_bytes` names is what was used, but for
    // alignment.
    try testing.expect(Sizing.fixed_buffer_bytes - client_fixed.end_index < 64);
    try testing.expect(Sizing.fixed_buffer_bytes - server_fixed.end_index < 64);
}

test "RFC 9000 §2.1, four streams in turn reuse the pool's slots rather than growing it" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveMany, .{ io, 4 });
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    for (0..4) |_| try fetchOne(connection, io);
    connection.close(io);
    try serving.await(io);

    // Two slots at most in use at once on either end: the live stream, and
    // the one held for the stream the peer may open next (§4.6). Four
    // streams, and the pool never held more.
    try testing.expectEqual(@as(u32, 2), poolCapacity(&test_client, io));
    try testing.expectEqual(@as(u32, 2), poolCapacity(&test_server, io));
}

test "RFC 9000 §2.1, a handle to a closed stream is StreamClosed, even once its slot is another stream's" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveMany, .{ io, 2 });
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    const first = try sendRequest(connection, io);
    var response: [64]u8 = undefined;
    try testing.expectEqualStrings(body, try readAll(first, io, &response));
    first.close(io);
    try awaitNoStreams(io);

    // The same slot, recycled, under a new generation.
    const second = try sendRequest(connection, io);
    try testing.expectEqual(first.index, second.index);
    try testing.expect(first.generation != second.generation);
    var vector = [_][]u8{&response};
    try testing.expectError(error.StreamClosed, first.read(io, &vector));
    try testing.expectError(error.StreamClosed, first.write(io, "x"));
    try testing.expectError(error.StreamClosed, first.shutdown(io, .both));
    // A no-op, which leaves the stream now in the slot alone.
    first.close(io);
    try testing.expectEqualStrings(body, try readAll(second, io, &response));
    second.close(io);
    connection.close(io);
    try serving.await(io);
}

test "RFC 9000 §4.6, an open the pool cannot back is OutOfMemory, and the connection goes on" {
    var client_fixed: std.heap.FixedBufferAllocator = .init(&client_memory);
    var pair: Pair = undefined;
    try pair.initWith(client_fixed.allocator(), testing.allocator);
    defer pair.deinit();
    const io = pair.io;

    var serving = try io.concurrent(serveMany, .{ io, 2 });
    defer serving.cancel(io) catch {};
    const connection = try pair.connect();
    // Two slots preheated: one held for the stream the server may open, one
    // for this stream. The memory has room for no third.
    const first = try sendRequest(connection, io);
    try testing.expectError(error.OutOfMemory, connection.openStream(io, .bidi));

    var response: [64]u8 = undefined;
    try testing.expectEqualStrings(body, try readAll(first, io, &response));
    first.close(io);
    try awaitNoStreams(io);
    // The slot it gave back is the next stream's.
    try fetchOne(connection, io);
    connection.close(io);
    try serving.await(io);
}

test "RFC 9000 §4.6, an accept the pool cannot back grants no credit, and the connection goes on" {
    var server_fixed: std.heap.FixedBufferAllocator = .init(&server_memory);
    var pair: Pair = undefined;
    try pair.initWith(testing.allocator, server_fixed.allocator());
    defer pair.deinit();
    const io = pair.io;

    var accepting = try io.concurrent(Endpoint.accept, .{ &test_server, io });
    defer _ = accepting.cancel(io) catch {};
    const connection = try pair.connect();
    const server = try accepting.await(io);

    // The server's one credit, then the one its first accept granted from the
    // preheated pool. Its second accept finds the pool empty and the memory
    // full, so it grants nothing, and the client's next open waits.
    const first = try sendRequest(connection, io);
    const one = try server.acceptStream(io);
    const second = try sendRequest(connection, io);
    const two = try server.acceptStream(io);
    try expectNoCredit(connection, io);

    try answer(one, io);
    try answer(two, io);
    var response: [64]u8 = undefined;
    for ([_]quic_io.Stream{ first, second }) |stream| {
        try testing.expectEqualStrings(body, try readAll(stream, io, &response));
        stream.close(io);
    }
    try awaitNoStreams(io);
    // The two streams freed give their credit back, on the slots they free.
    var answering = try io.concurrent(answerNext, .{ server, io });
    defer answering.cancel(io) catch {};
    try fetchOne(connection, io);
    try answering.await(io);
    connection.close(io);
}

test "RFC 9000 §4.6, a peer that opens what it may and closes nothing cannot make the endpoint allocate" {
    var server_counted: testing.FailingAllocator = .init(testing.allocator, .{});
    var pair: Pair = undefined;
    try pair.initWith(testing.allocator, server_counted.allocator());
    defer pair.deinit();
    const io = pair.io;
    const listened = server_counted.allocated_bytes;

    var accepting = try io.concurrent(Endpoint.accept, .{ &test_server, io });
    defer _ = accepting.cancel(io) catch {};
    const connection = try pair.connect();
    const server = try accepting.await(io);

    // The client spends its one credit, keeps the stream open, and asks for
    // more. Nothing it does moves the server's allocator.
    _ = try sendRequest(connection, io);
    try expectNoCredit(connection, io);
    try testing.expectEqual(listened, server_counted.allocated_bytes);
    try testing.expectEqual(@as(u32, 2), poolCapacity(&test_server, io));

    // Each accept grants one more, its slot first: from the preheat, then
    // from the allocator. The pool is the peer's backlog plus what the
    // application took, never what the peer asked for.
    _ = try server.acceptStream(io);
    _ = try sendRequest(connection, io);
    try expectNoCredit(connection, io);
    try testing.expectEqual(listened, server_counted.allocated_bytes);
    try testing.expectEqual(@as(u32, 2), poolCapacity(&test_server, io));

    _ = try server.acceptStream(io);
    _ = try sendRequest(connection, io);
    // Three streams and the slot kept for one the server may open fill the
    // client's table of four, so this time its own limit stops it.
    try testing.expectError(error.StreamLimit, connection.openStream(io, .bidi));
    try io.sleep(.fromMilliseconds(settle_ms), .awake);
    try testing.expectEqual(@as(u32, 3), poolCapacity(&test_server, io));
    connection.close(io);
}
