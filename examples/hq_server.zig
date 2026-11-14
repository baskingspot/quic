//! An hq-interop server: one TLS 1.3 handshake over loopback UDP, one request,
//! one response.
//!
//! Usage: `hq_server <cert.pem> <key.pem> <port>`. It binds 127.0.0.1:<port>,
//! learns its peer from the first datagram, finishes the handshake, reads
//! `GET /<path>\r\n` off stream 0 until the client's FIN, answers on the same
//! stream with a fixed body and a FIN, closes with NO_ERROR, and exits. It never
//! accepts a second connection, which is why every buffer is static.
//!
//! Every wait is bounded by one deadline: a handshake that goes nowhere prints
//! `hq_server: TIMEOUT` and exits 1.
//!
//! Run it with `just interop-hq`, against `hq_client`.

const std = @import("std");
const tls = @import("tls");

const hq = @import("hq.zig");

const Io = std.Io;

/// Static, because the machine and the driver point into it for the life of the
/// process.
var endpoint: hq.Endpoint = undefined;
var cert_pem: [4096]u8 = undefined;
var key_pem: [1024]u8 = undefined;
var cert_der: [4096]u8 = undefined;
var chain_slots: [1][]const u8 = undefined;
var request: [256]u8 = undefined;

const usage = "usage: hq_server <cert.pem> <key.pem> <port>\n";

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 4) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    const port = std.fmt.parseInt(u16, args[3], 10) catch {
        std.debug.print(usage, .{});
        std.process.exit(2);
    };
    const io = init.io;

    const cert = try Io.Dir.cwd().readFile(io, args[1], &cert_pem);
    const key_bytes = try Io.Dir.cwd().readFile(io, args[2], &key_pem);
    // A file that fills its buffer may have been cut off, and a cut chain fails
    // later with a message about the chain, not the buffer.
    std.debug.assert(cert.len < cert_pem.len);
    std.debug.assert(key_bytes.len < key_pem.len);
    const chain = try tls.certificate_chain.CertificateChain.fromPem(cert, &cert_der, &chain_slots);
    var key = try tls.signature.PrivateKey.fromPemAuto(key_bytes);
    defer key.deinit();

    const address = try Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const socket = try address.bind(io, .{ .mode = .dgram });
    defer socket.close(io);

    try endpoint.start(io, socket, null, .{ .server = .{
        .credentials = .{ .chain = chain, .signer = key.signer() },
        .alpn = &.{hq.alpn},
    } });
    defer endpoint.deinit();

    serve(io) catch |err| switch (err) {
        error.Timeout => {
            std.debug.print("hq_server: TIMEOUT\n", .{});
            std.process.exit(1);
        },
        else => return err,
    };
}

fn serve(io: Io) !void {
    const deadline: hq.Deadline = .init(io);

    // The handshake, driven by the client's datagrams.
    while (!endpoint.connection.established()) try endpoint.step(deadline);

    // The request: bytes on stream 0 until the client's FIN.
    var length: usize = 0;
    while (true) {
        if (endpoint.connection.conn.stream(hq.request_stream)) |stream| {
            length += try stream.recv.readInto(request[length..]);
            if (stream.recv.isTerminal()) break;
            if (length == request.len) return error.RequestTooLong;
        }
        try endpoint.step(deadline);
    }
    const line = request[0..length];
    if (!std.mem.startsWith(u8, line, "GET /") or !std.mem.endsWith(u8, line, "\r\n")) {
        return error.BadRequest;
    }
    std.debug.print("hq_server: request {s}\n", .{line[0 .. line.len - 2]});

    // The answer goes out on the other half of the stream the client opened.
    const stream = try endpoint.connection.conn.joinStream(hq.request_stream);
    try stream.send.write(hq.body);
    try stream.send.finish();
    try endpoint.sendStream(deadline);
    try endpoint.closeNoError(deadline);
    std.debug.print("hq_server: answered {d} bytes\n", .{hq.body.len});
}
