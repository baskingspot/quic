//! An hq-interop client: one TLS 1.3 handshake over loopback UDP, one request,
//! one response.
//!
//! Usage: `hq_client <port> <path>`. It connects to 127.0.0.1:<port>, trusts the
//! server's self-signed certificate (`insecure_no_chain_anchor`: this is a
//! loopback demonstration, not a policy to copy), sends `GET <path>\r\n` on
//! stream 0 with a FIN, reads the response until the server's FIN, prints it to
//! stdout, closes with NO_ERROR, and exits.
//!
//! Every wait is bounded by one deadline: a handshake that goes nowhere prints
//! `hq_client: TIMEOUT` and exits 1.
//!
//! Run it with `just interop-hq`, against `hq_server`.

const std = @import("std");
const tls = @import("tls");

const hq = @import("hq.zig");

const Io = std.Io;

/// Static, because the machine and the driver point into it for the life of the
/// process.
var endpoint: hq.Endpoint = undefined;
var request: [256]u8 = undefined;
var response: [1024]u8 = undefined;

const usage = "usage: hq_client <port> <path>\n";

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    const port = std.fmt.parseInt(u16, args[1], 10) catch {
        std.debug.print(usage, .{});
        std.process.exit(2);
    };
    const path = args[2];
    const io = init.io;

    // Port 0 asks for any free one: the server learns where to answer from the
    // first datagram.
    const local = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = try local.bind(io, .{ .mode = .dgram });
    defer socket.close(io);
    const server = try Io.net.IpAddress.parseIp4("127.0.0.1", port);

    var policy: tls.certificate.Policy = .init;
    policy.insecure_no_chain_anchor = true;
    try endpoint.start(io, socket, server, .{ .client = .{
        .policy = policy,
        .alpn = &.{hq.alpn},
    } });
    defer endpoint.deinit();

    fetch(io, path) catch |err| switch (err) {
        error.Timeout => {
            std.debug.print("hq_client: TIMEOUT\n", .{});
            std.process.exit(1);
        },
        else => return err,
    };
}

fn fetch(io: Io, path: []const u8) !void {
    const deadline: hq.Deadline = .init(io);

    // The first Initial, then the handshake. A client is confirmed by a
    // HANDSHAKE_DONE frame (RFC 9001 §4.1.2) and `Conn` has no writer for one,
    // so the server here never sends it and `established` would never turn
    // true. The client waits on what it can see instead: its own driver is
    // finished and the 1-RTT keys exist.
    try endpoint.flush(deadline);
    while (!(endpoint.tls_driver.done() and endpoint.connection.conn.app != null)) {
        try endpoint.step(deadline);
    }

    const line = try std.mem.print(&request, "GET {s}\r\n", .{path});
    const stream = try endpoint.connection.conn.openStream(hq.request_stream);
    try stream.send.write(line);
    try stream.send.finish();
    try endpoint.sendStream(deadline);

    var length: usize = 0;
    while (true) {
        length += try stream.recv.readInto(response[length..]);
        if (stream.recv.isTerminal()) break;
        if (length == response.len) return error.ResponseTooLong;
        try endpoint.step(deadline);
    }
    try endpoint.closeNoError(deadline);

    const stdout = Io.File.stdout();
    try stdout.writeStreamingAll(io, response[0..length]);
    if (length == 0 or response[length - 1] != '\n') try stdout.writeStreamingAll(io, "\n");
}
