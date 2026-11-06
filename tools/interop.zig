//! External interop: answer a foreign client's first Initial and check what it
//! sends back.
//!
//! This is the one test in the package where the peer is not us. It is
//! deliberately narrow: both scenarios happen before any crypto, so neither
//! needs a handshake. What it proves is that a foreign stack accepts the bytes
//! we produce.
//!
//! Usage: `interop retry <port>` and `interop vn <port>`, with `quiche-client`
//! pointed at 127.0.0.1:<port> by the caller (`just interop` does that).
//!
//! Every assertion is about a datagram the peer sent, never about our own log:
//! the token in its second Initial, the connection ID it addressed, the version
//! it would not change.

const std = @import("std");
const quic = @import("quic");

const Io = std.Io;

const token = "interop-token";
const retry_scid = [_]u8{ 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) return usage();
    const mode = args[1];
    const port = std.fmt.parseInt(u16, args[2], 10) catch return usage();
    const io = init.io;

    const address = try Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const socket = try address.bind(io, .{ .mode = .dgram });
    defer socket.close(io);

    const ok = if (std.mem.eql(u8, mode, "retry"))
        try retryScenario(io, &socket)
    else if (std.mem.eql(u8, mode, "vn"))
        try versionScenario(io, &socket)
    else
        return usage();

    if (!ok) std.process.exit(1);
}

fn usage() error{Usage} {
    std.debug.print("usage: interop retry <port> | interop vn <port>\n", .{});
    return error.Usage;
}

const Received = struct {
    bytes: []const u8,
    from: Io.net.IpAddress,
};

/// Wait up to two seconds for the next datagram, or null.
fn receive(io: Io, socket: *const Io.net.Socket, buffer: []u8) !?Received {
    const timeout: Io.Timeout = .{ .duration = .{
        .raw = .fromNanoseconds(2 * std.time.ns_per_s),
        .clock = .awake,
    } };
    const message = socket.receiveTimeout(io, buffer, timeout) catch |err| switch (err) {
        error.Timeout => return null,
        else => return err,
    };
    return .{ .bytes = message.data, .from = message.from };
}

fn send(io: Io, socket: *const Io.net.Socket, bytes: []const u8, to: *const Received) !void {
    try socket.send(io, &to.from, bytes);
}

/// RFC 9000 §17.2.5: answer the first Initial with a Retry, then require the
/// client's next Initial to name our connection ID and carry our token.
fn retryScenario(io: Io, socket: *const Io.net.Socket) !bool {
    var buffer: [2048]u8 = undefined;
    const first = (try receive(io, socket, &buffer)) orelse {
        std.debug.print("interop retry: no Initial arrived\n", .{});
        return false;
    };

    const invariant = quic.packet.parseInvariant(first.bytes) catch |err| {
        std.debug.print("interop retry: the first datagram is not a long header: {t}\n", .{err});
        return false;
    };
    const kind: quic.packet.Kind = @fromBackingInt(@intCast((invariant.first >> 4) & 0x03));
    if (kind != .initial) {
        std.debug.print("interop retry: expected an Initial, got {t}\n", .{kind});
        return false;
    }

    var out: [1024]u8 = undefined;
    const retry_length = quic.connection_setup.Retry.write(&out, invariant.destination_connection_id, .{
        .destination_connection_id = invariant.source_connection_id,
        .source_connection_id = &retry_scid,
        .token = token,
    }) catch |err| {
        std.debug.print("interop retry: could not build a Retry: {t}\n", .{err});
        return false;
    };
    try send(io, socket, out[0..retry_length], &first);

    // The client must answer with a new Initial. Nothing else counts.
    const second = (try receive(io, socket, &buffer)) orelse {
        std.debug.print("interop retry: the client sent nothing after the Retry\n", .{});
        return false;
    };
    const second_long = quic.packet.parseLong(second.bytes) catch |err| {
        std.debug.print("interop retry: the reply is not a long header: {t}\n", .{err});
        return false;
    };

    if (second_long.kind != .initial) {
        std.debug.print("interop retry: the reply is {t}, not an Initial\n", .{second_long.kind});
        return false;
    }
    if (!std.mem.eql(u8, second_long.token, token)) {
        std.debug.print(
            "interop retry: FAIL the client's token is {d} bytes, not ours\n",
            .{second_long.token.len},
        );
        return false;
    }
    if (!std.mem.eql(u8, second_long.destination_connection_id, &retry_scid)) {
        std.debug.print("interop retry: FAIL the client did not address our connection ID\n", .{});
        return false;
    }

    std.debug.print(
        "interop retry: PASS quiche validated our tag, echoed our {d}-byte token, and addressed our SCID\n",
        .{token.len},
    );
    return true;
}

/// RFC 9000 §6.2: a client must not change version in response to a Version
/// Negotiation packet. The assertion is on what arrives: if any packet with a
/// version other than 1 comes back, the peer negotiated, and that is the bug.
fn versionScenario(io: Io, socket: *const Io.net.Socket) !bool {
    var buffer: [2048]u8 = undefined;
    const first = (try receive(io, socket, &buffer)) orelse {
        std.debug.print("interop vn: no Initial arrived\n", .{});
        return false;
    };

    const invariant = quic.packet.parseInvariant(first.bytes) catch |err| {
        std.debug.print("interop vn: the first datagram is not a long header: {t}\n", .{err});
        return false;
    };

    var out: [128]u8 = undefined;
    var writer: quic.Writer = .init(&out);
    const unsupported = [_]quic.packet.Version{@fromBackingInt(@intCast(0xfa0a0a0a))};
    try quic.connection_setup.VersionNegotiation.write(&writer, &invariant, &unsupported);
    try send(io, socket, writer.written(), &first);

    // Wait for anything else. Same-version retransmissions are legal and are
    // ignored; a different version is the failure.
    while (try receive(io, socket, &buffer)) |next| {
        const next_invariant = quic.packet.parseInvariant(next.bytes) catch continue;
        if (next_invariant.version == .v1) continue;
        std.debug.print(
            "interop vn: FAIL the client changed to version 0x{x:0>8}\n",
            .{@backingInt(next_invariant.version)},
        );
        return false;
    }

    std.debug.print("interop vn: PASS the client did not change version\n", .{});
    return true;
}
