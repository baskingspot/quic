//! An echo endpoint on top of `quic.Conn`: one process, a client and a server,
//! and a handshake faked by `handshake.Stub`.
//!
//! This is not QUIC done well; it is the first code in the tree that calls the
//! machine the way an application would. The handshake is a lie (two stub
//! drivers agree on secrets and on nothing else), there is no congestion
//! controller, and the loop is a fixed ping-pong rather than a reactor. What it
//! does do is exercise the real contract: buffers the caller owns, a clock the
//! caller reads, events the caller acts on, and packets the caller frames.
//!
//! Run it with `just example`.

const std = @import("std");
const quic = @import("quic");

const Io = std.Io;
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const frame = quic.frame;
const handshake = quic.handshake;
const protection = quic.protection;
const StreamTable = quic.StreamTable;

/// One sent-packet table per space, and the report storage the machine fills.
const tables_max = 16;

/// One endpoint's caller-owned state. It is created in the arena and never
/// moved, because `Conn` holds pointers into it.
const Endpoint = struct {
    recovery: Recovery = .{},
    sent_initial: [tables_max]Recovery.SentPacket = undefined,
    sent_handshake: [tables_max]Recovery.SentPacket = undefined,
    sent_app: [tables_max]Recovery.SentPacket = undefined,
    acked: [tables_max]Recovery.SentPacket = undefined,
    lost: [tables_max]Recovery.SentPacket = undefined,
    events: Recovery.Events = undefined,

    crypto_in_initial: [512]u8 = undefined,
    crypto_in_handshake: [512]u8 = undefined,
    crypto_out_initial: [512]u8 = undefined,
    crypto_out_handshake: [512]u8 = undefined,

    /// One ring and one send buffer per stream. `Conn.init` asserts that no two
    /// share storage, so a `@splat` over these is a panic on the first packet
    /// rather than one stream's bytes landing in another's.
    ring_a: [1024]u8 = undefined,
    ring_b: [1024]u8 = undefined,
    send_a: [1024]u8 = undefined,
    send_b: [1024]u8 = undefined,
    slots: [2]StreamTable.Slot = undefined,
    streams: [2]Conn.Stream = undefined,

    conn: Conn = undefined,
    plaintext: [1500]u8 = undefined,
    parsed: [16]frame.Frame = undefined,

    fn loss(self: *Endpoint) Conn.Loss {
        return .{
            .shared = &self.recovery,
            .sent_initial = &self.sent_initial,
            .sent_handshake = &self.sent_handshake,
            .sent_app = &self.sent_app,
        };
    }

    fn start(self: *Endpoint, config: Conn.Config) void {
        self.events = .init(&self.acked, &self.lost);
        self.streams = .{
            .{ .send_buffer = &self.send_a, .recv_buffer = &self.ring_a, .recv_limit_bytes = 1024 },
            .{ .send_buffer = &self.send_b, .recv_buffer = &self.ring_b, .recv_limit_bytes = 1024 },
        };
        self.conn = .init(config);
    }

    /// One call per packet, which is the whole of what a caller must give the
    /// machine to read one.
    fn feed(self: *Endpoint, bytes: []u8, at: u64) !Conn.Opened {
        return self.conn.feed(bytes, &self.plaintext, &self.parsed, &self.events, at);
    }
};

var clock_start: Io.Timestamp = undefined;

fn now(io: Io) u64 {
    const elapsed = clock_start.durationTo(Io.Timestamp.now(io, .awake));
    return @intCast(@max(elapsed.nanoseconds, 0));
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    clock_start = Io.Timestamp.now(io, .awake);

    const server_id = [_]u8{ 0x5e, 0x5e, 0x5e, 0x5e };
    const client_id = [_]u8{ 0xc1, 0xc2 };

    // Two stub drivers that agree on secrets and on nothing else. The machine
    // installs the traffic spaces from these and never asks how they were
    // negotiated.
    const client_secret: [protection.secret_length]u8 = @splat(0x11);
    const server_secret: [protection.secret_length]u8 = @splat(0x22);
    const secrets: handshake.Secrets = .{ .client = &client_secret, .server = &server_secret };
    var client_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ClientHello, faked" }},
        .handshake_secrets = secrets,
        .app_secrets = secrets,
    };
    var server_stub: handshake.Stub = .{
        .handshake_secrets = secrets,
        .app_secrets = secrets,
    };

    const client = try arena.create(Endpoint);
    const server = try arena.create(Endpoint);
    client.start(.{
        .role = .client,
        .loss = client.loss(),
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &server_id,
        .source_connection_id = &client_id,
        .tls = client_stub.driver(),
        .transport_parameters = "client parameters",
        .crypto = .{ .initial = &client.crypto_in_initial, .handshake = &client.crypto_in_handshake },
        .crypto_sent = .{ .initial = &client.crypto_out_initial, .handshake = &client.crypto_out_handshake },
        .stream_slots = &client.slots,
        .streams = &client.streams,
        .receive_limit = 4096,
        .send_limit = 4096,
        .max_streams_bidi = 1,
    });
    server.start(.{
        .role = .server,
        .loss = server.loss(),
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &client_id,
        .source_connection_id = &server_id,
        .tls = server_stub.driver(),
        .transport_parameters = "server parameters",
        .crypto = .{ .initial = &server.crypto_in_initial, .handshake = &server.crypto_in_handshake },
        .crypto_sent = .{ .initial = &server.crypto_out_initial, .handshake = &server.crypto_out_handshake },
        .stream_slots = &server.slots,
        .streams = &server.streams,
        .receive_limit = 4096,
        .send_limit = 4096,
        .max_streams_bidi = 1,
    });

    var wire: [1500]u8 = undefined;
    var frames: [512]u8 = undefined;

    // The client's handshake flight, and the server's call that writes nothing
    // but installs the spaces its driver reported secrets for.
    const flight = (try client.conn.writeHandshake(&frames, &wire, now(io))) orelse
        return error.NoHandshakeWritten;
    const first_server_packet = try server.feed(wire[0..flight], now(io));
    std.debug.assert(first_server_packet.space == .initial);
    try std.testing.expect((try server.conn.writeHandshake(&frames, &wire, now(io))) == null);
    std.debug.print("server: 1-RTT keys from the faked handshake: {}\n", .{server.conn.app != null});

    // The client asks for a stream, writes, and offers it to the packetizer. The
    // offer is how much this packet may carry, not how much was written.
    const stream = try client.conn.openStream(0, 4096);
    // `write` takes all of it or returns `error.NoSpace`: there is no short
    // write to check, and so no way to publish a truncated stream by accident.
    const message = "hello from the client";
    try stream.send.write(message);
    try stream.send.finish();

    var client_written: [1]Conn.Written = undefined;
    const sent = (try client.conn.writeStreams(.{
        .offers = &.{.{ .stream_id = 0, .length = 1024 }},
        .frames = &frames,
        .out = &wire,
        .written = &client_written,
        .max_payload = 1200,
        .now = now(io),
    })) orelse return error.NothingToSend;
    std.debug.print("client: packet {d}, {d} bytes on the wire, took {d} offers\n", .{
        sent.number,
        sent.length,
        sent.consumed.taken,
    });

    // The server reads the packet. The machine consumed the STREAM frame and
    // told nobody which stream it was for, so the application goes looking.
    _ = try server.feed(wire[0..sent.length], now(io));
    var echoed: u32 = 0;
    for (server.conn.stream_table.iterator()) |slot| {
        const recv = slot.recv orelse continue;
        var read: [1024]u8 = undefined;
        const count = try recv.readInto(&read);
        if (count == 0) continue;
        std.debug.print("server: stream {d} had {d} bytes\n", .{ recv.id, count });

        // A bidirectional stream the peer opened is not writable until this
        // endpoint opens its own half of it, which reads like creating a stream
        // rather than joining one.
        const back = try server.conn.openStream(recv.id, 4096);
        try back.send.write(read[0..count]);
        try back.send.finish();
        var server_written: [1]Conn.Written = undefined;
        const reply = (try server.conn.writeStreams(.{
            .offers = &.{.{ .stream_id = recv.id, .length = 1024 }},
            .frames = &frames,
            .out = &wire,
            .written = &server_written,
            .max_payload = 1200,
            .now = now(io),
        })) orelse return error.NothingToSend;
        echoed = reply.length;
        std.debug.print("server: echoed in packet {d}\n", .{reply.number});
    }

    // The client reads the echo the same way: scan, read, and nothing told it
    // which stream to look at.
    _ = try client.feed(wire[0..echoed], now(io));
    const reply = client.conn.stream(0) orelse return error.NotOpen;
    var read_back: [1024]u8 = undefined;
    const count = try reply.recv.readInto(&read_back);
    std.debug.print("client: read back \"{s}\"\n", .{read_back[0..count]});

    // Nothing here ever acknowledged a packet, so both ends still hold
    // everything in flight. A real loop asks `ackOwed`/`writeAck` and runs
    // `RecoveryDriver`; this one just shows the bill.
    std.debug.print("client: {d} in flight, server: {d} in flight\n", .{
        client.conn.app.?.recovery.inFlight().len,
        server.conn.app.?.recovery.inFlight().len,
    });
}
