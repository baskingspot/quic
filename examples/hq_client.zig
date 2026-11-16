//! An hq-interop client: one TLS 1.3 handshake over loopback UDP, one request,
//! one response.
//!
//! Usage: `hq_client <port> <path>`. It connects to 127.0.0.1:<port>, trusts the
//! server's self-signed certificate (`.trust = .insecure`: this is a loopback
//! demonstration, not a policy to copy), sends `GET <path>\r\n` on a
//! new bidirectional stream with a FIN, copies the response to stdout until the
//! server's FIN, closes with NO_ERROR, and exits.
//!
//! The idle timeout bounds every wait: a handshake that goes nowhere prints
//! `hq_client: TIMEOUT` and exits 1.
//!
//! Run it with `just interop-hq`, against `hq_server`.

const std = @import("std");
const Io = std.Io;
const print = std.debug.print;

const quic_io = @import("quic-io");

const hq = @import("hq.zig");

/// Static, because the machine and the driver point into it for the life of the
/// process.
var endpoint: hq.Endpoint = undefined;
/// Where the streams' buffers come from: no heap, as in `hq_server`.
var memory: [hq.Sizing.fixed_buffer_bytes]u8 = undefined;
var request: [256]u8 = undefined;
var response: [1024]u8 = undefined;

const usage = "usage: hq_client <port> <path>\n";

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        print(usage, .{});
        return 2;
    }
    const port = std.fmt.parseInt(u16, args[1], 10) catch {
        print(usage, .{});
        return 2;
    };
    const path = args[2];
    const io = init.io;
    const server: Io.net.IpAddress = try .parseIp4("127.0.0.1", port);

    fetch(io, server, path) catch |err| switch (err) {
        error.IdleTimeout => {
            print("hq_client: TIMEOUT\n", .{});
            return 1;
        },
        else => return err,
    };
    return 0;
}

fn fetch(io: Io, server: Io.net.IpAddress, path: []const u8) !void {
    // Port 0 asks for any free one: the server learns where to answer from the
    // first datagram.
    const local: Io.net.IpAddress = try .parseIp4("127.0.0.1", 0);
    const socket = try local.bind(io, .{ .mode = .dgram });
    // The endpoint owns the socket from `connect` on, failed or not.
    defer endpoint.deinit(io);
    var streams: std.heap.FixedBufferAllocator = .init(&memory);
    const connection = try endpoint.connect(streams.allocator(), .{
        .io = io,
        .socket = socket,
        .peer = server,
        .alpn = &.{hq.alpn},
        .trust = .insecure,
        .parameters = hq.parameters,
    });

    const stream = try connection.openStream(io, .bidi);
    var writer: quic_io.Stream.Writer = .init(stream, io, &request);
    writer.interface.print("GET {s}\r\n", .{path}) catch return writer.err.?;
    writer.interface.flush() catch return writer.err.?;
    try stream.shutdown(io, .send);

    // Unbuffered: `streamRemaining` reads straight into stdout's buffer.
    var reader: quic_io.Stream.Reader = .init(stream, io, &.{});
    var stdout = Io.File.stdout().writerStreaming(io, &response);
    _ = reader.interface.streamRemaining(&stdout.interface) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.WriteFailed => return stdout.err orelse err,
    };
    stdout.interface.flush() catch |err| return stdout.err orelse err;
    stream.close(io);
    connection.close(io);
}
