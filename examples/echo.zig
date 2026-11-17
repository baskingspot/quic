//! Hello, QUIC: the first file to read. A server and a client in one process
//! over loopback UDP, a real TLS 1.3 handshake with the fixture certificate,
//! one connection, one stream, and the client's bytes echoed back.
//!
//! `quic-io` reads like `std.Io.net`: an `Endpoint` listens or connects, a
//! `Connection` opens and accepts streams, and a `Stream` is read and written
//! through `std.Io.Reader` and `std.Io.Writer`. Every buffer is in the
//! endpoint, sized by `Sizing`, or comes from the allocator `listen` and
//! `connect` are handed. `examples/hq_server.zig` is the same API serving a
//! real client; `examples/machine.zig` is the sans-I/O machine underneath.
//!
//! Run it with `just example`.

const std = @import("std");
const Io = std.Io;
const print = std.debug.print;

const quic = @import("quic");
const quic_io = @import("quic-io");

const Endpoint = quic_io.Endpoint(quic_io.Sizing(.{}));
const alpn = "echo";
/// §10.1: five quiet seconds end a connection, a handshake that stalls too.
const parameters: quic.TransportParameters = .{ .max_idle_timeout = 5000 };

/// File scope: an endpoint is built in place and must not move.
var server: Endpoint = undefined;
var client: Endpoint = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const loopback: Io.net.IpAddress = .{ .ip4 = .loopback(0) };

    // Port 0: the kernel picks one, and the client learns it from the socket.
    const server_socket = try loopback.bind(io, .{ .mode = .dgram });
    defer server.deinit(io);
    try server.listen(init.gpa, .{
        .io = io,
        .socket = server_socket,
        .certificate = @embedFile("server_crt"),
        .key = @embedFile("server_key"),
        .alpn = &.{alpn},
        .parameters = parameters,
    });
    var serving = try io.concurrent(serve, .{io});
    defer serving.cancel(io) catch {};

    // `.insecure` because the fixture is self-signed: not a policy to copy.
    const client_socket = try loopback.bind(io, .{ .mode = .dgram });
    defer client.deinit(io);
    const connection = try client.connect(init.gpa, .{
        .io = io,
        .socket = client_socket,
        .peer = server_socket.address,
        .alpn = &.{alpn},
        .trust = .insecure,
        .parameters = parameters,
    });
    const stream = try connection.openStream(io, .bidi);
    var writer: quic_io.Stream.Writer = .init(stream, io, &.{});
    writer.interface.writeAll("hello, QUIC") catch return writer.err.?;
    try stream.shutdown(io, .send);

    var echoed: [64]u8 = undefined;
    var reader: quic_io.Stream.Reader = .init(stream, io, &.{});
    const count = reader.interface.readSliceShort(&echoed) catch return reader.err.?;
    print("client: echoed back \"{s}\"\n", .{echoed[0..count]});

    stream.close(io);
    connection.close(io);
    try serving.await(io);
}

/// Accept one connection and its first stream, copy what arrives back until
/// the client's FIN, then wait for the client to close.
fn serve(io: Io) !void {
    const connection = try server.accept(io);
    const stream = try connection.acceptStream(io);
    defer stream.close(io);

    // The reader streams into the writer's buffer, so the writer needs one.
    var buffer: [64]u8 = undefined;
    var reader: quic_io.Stream.Reader = .init(stream, io, &.{});
    var writer: quic_io.Stream.Writer = .init(stream, io, &buffer);
    const count = reader.interface.streamRemaining(&writer.interface) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.WriteFailed => return writer.err.?,
    };
    writer.interface.flush() catch return writer.err.?;
    try stream.shutdown(io, .send);
    print("server: echoed {d} bytes\n", .{count});

    // Closing first could race the echo: the client closes once it has read.
    _ = connection.acceptStream(io) catch |err| switch (err) {
        error.ConnectionClosed => return,
        else => return err,
    };
    return error.UnexpectedStream;
}
