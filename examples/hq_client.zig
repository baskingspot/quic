//! An hq-interop client: one TLS 1.3 handshake over loopback UDP, one request,
//! one response.
//!
//! Usage: `hq_client <port> <path>`. It connects to 127.0.0.1:<port>, trusts the
//! server's self-signed certificate (`insecure_no_chain_anchor`: this is a
//! loopback demonstration, not a policy to copy), sends `GET <path>\r\n` on a
//! new bidirectional stream with a FIN, reads the response until the server's
//! FIN, prints it to stdout, closes with NO_ERROR, and exits.
//!
//! The idle timeout bounds every wait: a handshake that goes nowhere prints
//! `hq_client: TIMEOUT` and exits 1.
//!
//! Run it with `just interop-hq`, against `hq_server`.

const std = @import("std");
const quic = @import("quic");
const tls = @import("tls");

const hq = @import("hq.zig");

const Io = std.Io;

/// Static, because the machine and the driver point into them for the life of
/// the process.
var endpoint: hq.Endpoint = undefined;
var handshake: hq.Tls = undefined;
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
    const server = try Io.net.IpAddress.parseIp4("127.0.0.1", port);

    var policy: tls.certificate.Policy = .init;
    policy.insecure_no_chain_anchor = true;
    const driver = try handshake.start(io, .{ .client = .{ .policy = policy, .alpn = &.{hq.alpn} } });
    defer handshake.deinit();

    fetch(io, server, driver, path) catch |err| switch (err) {
        error.IdleTimeout => {
            std.debug.print("hq_client: TIMEOUT\n", .{});
            std.process.exit(1);
        },
        else => return err,
    };
}

fn fetch(io: Io, server: Io.net.IpAddress, driver: quic.handshake.Driver, path: []const u8) !void {
    // Port 0 asks for any free one: the server learns where to answer from the
    // first datagram.
    const local = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = try local.bind(io, .{ .mode = .dgram });
    // The endpoint owns the socket from `connect` on, failed or not.
    defer endpoint.deinit(io);
    const connection = try endpoint.connect(.{
        .io = io,
        .socket = socket,
        .peer = server,
        .driver = driver,
        .parameters = hq.parameters,
    });

    const stream = try connection.openStream(io, .bidi);
    try hq.writeAll(stream, io, try std.mem.print(&request, "GET {s}\r\n", .{path}));
    try stream.shutdown(io, .send);
    const body = try hq.readAll(stream, io, &response);
    stream.close(io);
    connection.close(io);

    const stdout = Io.File.stdout();
    try stdout.writeStreamingAll(io, body);
    if (body.len == 0 or body[body.len - 1] != '\n') try stdout.writeStreamingAll(io, "\n");
}
