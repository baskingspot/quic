//! An hq-interop server: one TLS 1.3 handshake over loopback UDP, one request,
//! one response.
//!
//! Usage: `hq_server <cert.pem> <key.pem> <port>`. It binds 127.0.0.1:<port>,
//! accepts one connection, reads the line `GET /<path>\r\n` off the first
//! stream the client opens, answers on the same stream with a fixed body and a
//! FIN, waits for the client to close the connection, and exits. It never
//! accepts a second connection, which is why every buffer is static, the
//! handshake's and the streams' included: they come from a
//! `FixedBufferAllocator` over `memory`.
//!
//! The idle timeout bounds every wait: a handshake that goes nowhere, or a
//! client that goes quiet, prints `hq_server: TIMEOUT` and exits 1.
//!
//! Run it with `just interop-hq`, against `hq_client`.

const std = @import("std");
const Io = std.Io;
const print = std.debug.print;
const assert = std.debug.assert;
const mem = std.mem;

const quic_io = @import("quic-io");

const hq = @import("hq.zig");

/// Static, because the machine and the driver point into it for the life of the
/// process.
var endpoint: hq.Endpoint = undefined;
/// The certificate is read at run time, so this is enough for one as long as
/// the sizing allows: `allocation_bytes`, not `listenBytes` of the one in use.
var memory: [hq.Sizing.allocation_bytes]u8 align(hq.Sizing.allocation_alignment) = undefined;
var request: [256]u8 = undefined;

/// A file larger than this is not a certificate or a key: reading stops with
/// `error.StreamTooLong`, not with a cut-off chain.
const max_pem = 64 * 1024;

const usage = "usage: hq_server <cert.pem> <key.pem> <port>\n";

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 4) {
        print(usage, .{});
        return 2;
    }
    const port = std.fmt.parseInt(u16, args[3], 10) catch {
        print(usage, .{});
        return 2;
    };
    const io = init.io;

    const certificate = try Io.Dir.cwd().readFileAlloc(io, args[1], arena, .limited(max_pem));
    const key = try Io.Dir.cwd().readFileAlloc(io, args[2], arena, .limited(max_pem));

    const address: Io.net.IpAddress = try .parseIp4("127.0.0.1", port);
    const socket = try address.bind(io, .{ .mode = .dgram });
    // The endpoint owns the socket from `listen` on, failed or not.
    defer endpoint.deinit(io);
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    try endpoint.listen(fixed.allocator(), .{
        .io = io,
        .socket = socket,
        .certificate = certificate,
        .key = key,
        .alpn = &.{hq.alpn},
        .parameters = hq.parameters,
    });

    serve(io) catch |err| switch (err) {
        error.IdleTimeout => {
            print("hq_server: TIMEOUT\n", .{});
            return 1;
        },
        else => return err,
    };
    return 0;
}

fn serve(io: Io) !void {
    const connection = try endpoint.accept(io);
    const stream = try connection.acceptStream(io);
    defer stream.close(io);

    var reader: quic_io.Stream.Reader = .init(stream, io, &request);
    const line = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.EndOfStream, error.StreamTooLong => return error.BadRequest,
    };
    if (!mem.startsWith(u8, line, "GET /") or !mem.endsWith(u8, line, "\r\n")) {
        return error.BadRequest;
    }
    print("hq_server: request {s}\n", .{line[0 .. line.len - 2]});

    // Unbuffered: the body goes to the stream in one write, with no flush.
    var writer: quic_io.Stream.Writer = .init(stream, io, &.{});
    writer.interface.writeAll(hq.body) catch return writer.err.?;
    try stream.shutdown(io, .send);

    // The client closes once it has read the response. Closing first could
    // race the response: a peer may drop stream bytes it has not read yet when
    // a CONNECTION_CLOSE lands. Until then the shell resends what is lost.
    while (true) {
        const extra = connection.acceptStream(io) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        extra.close(io);
    }
    print("hq_server: answered {d} bytes\n", .{hq.body.len});
}
