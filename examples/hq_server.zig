//! An hq-interop server: one TLS 1.3 handshake over loopback UDP, one request,
//! one response.
//!
//! Usage: `hq_server <cert.pem> <key.pem> <port>`. It binds 127.0.0.1:<port>,
//! accepts one connection, reads the line `GET /<path>\r\n` off the first
//! stream the client opens, answers on the same stream with a fixed body and a
//! FIN, waits for the client to close the connection, and exits. It never
//! accepts a second connection, which is why every buffer is static.
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
const tls = @import("tls");

const hq = @import("hq.zig");

/// Static, because the machine and the driver point into them for the life of
/// the process.
var endpoint: hq.Endpoint = undefined;
var handshake: hq.Tls = undefined;
var cert_pem: [4096]u8 = undefined;
var key_pem: [1024]u8 = undefined;
var cert_der: [4096]u8 = undefined;
var chain_slots: [1][]const u8 = undefined;
var request: [256]u8 = undefined;

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

    const cert = try Io.Dir.cwd().readFile(io, args[1], &cert_pem);
    const key_bytes = try Io.Dir.cwd().readFile(io, args[2], &key_pem);
    // A file that fills its buffer may have been cut off, and a cut chain fails
    // later with a message about the chain, not the buffer.
    assert(cert.len < cert_pem.len);
    assert(key_bytes.len < key_pem.len);
    const chain: tls.certificate_chain.CertificateChain = try .fromPem(cert, &cert_der, &chain_slots);
    var key: tls.signature.PrivateKey = try .fromPemAuto(key_bytes);
    defer key.deinit();

    const address: Io.net.IpAddress = try .parseIp4("127.0.0.1", port);
    const socket = try address.bind(io, .{ .mode = .dgram });
    const driver = try handshake.start(io, .{ .server = .{
        .credentials = .{ .chain = chain, .signer = key.signer() },
        .alpn = &.{hq.alpn},
    } });
    defer handshake.deinit();
    endpoint.listen(.{ .io = io, .socket = socket, .driver = driver, .parameters = hq.parameters });
    defer endpoint.deinit(io);

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
