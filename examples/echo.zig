//! The machine driven directly: a client and a server in one process, calling
//! `quic.Conn` with no socket shell around it and a handshake faked by
//! `handshake.Stub`.
//!
//! This is the path to take to embed `Conn` in another I/O layer, to write a
//! different driver, or to test a connection without crypto. The caller owns
//! every buffer, reads the clock, acts on the events `feed` returns, and frames
//! the packets itself. Nothing here is a reactor: the loop is a fixed
//! ping-pong, and the clock is real except where a wait is skipped by telling
//! the machine that time went by.
//!
//! What it shows: the stub's secrets and transport parameters becoming the
//! spaces and limits of both peers, the server's HANDSHAKE_DONE confirming the
//! client, and a lost packet that the machine sends again from the stream's own
//! buffer once the caller's loss timer declares it.
//!
//! What it does not prove: the handshake is a lie (two stubs agree on secrets
//! and on nothing else, so no certificate, no ALPN, no key schedule and no
//! authentication are exercised), nothing crosses a network, and there is no
//! congestion controller, pacing or idle timer. A passing run says the
//! machine's contract holds, not that this is a working QUIC peer.
//!
//! For the real thing, a TLS 1.3 handshake over UDP through `quic-io`'s
//! `Endpoint`, read `examples/hq_server.zig`.
//!
//! Run it with `just example`.

const std = @import("std");
const Io = std.Io;
const print = std.debug.print;
const assert = std.debug.assert;

const quic = @import("quic");
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const RecoveryDriver = quic.RecoveryDriver;
const frame = quic.frame;
const handshake = quic.handshake;
const protection = quic.protection;
const StreamTable = quic.StreamTable;
const TransportParameters = quic.TransportParameters;

/// One sent-packet table per space, and the report storage the machine fills.
const tables_max = 16;

/// One peer's caller-owned state. It is created in the arena and never
/// moved, because `Conn` holds pointers into it.
const Node = struct {
    recovery: Recovery = .{},
    /// The per-space loss state, outside the connection so a `RecoveryDriver`
    /// can hold it without holding a pointer into the connection.
    spaces: [3]Recovery.Space = undefined,
    sent_initial: [tables_max]Recovery.SentPacket = undefined,
    sent_handshake: [tables_max]Recovery.SentPacket = undefined,
    sent_app: [tables_max]Recovery.SentPacket = undefined,
    /// The STREAM ranges each 1-RTT packet carried, one per `sent_app` slot, so
    /// a lost one is sent again from the stream's own buffer.
    sent_streams: [tables_max]Conn.SentStreams = undefined,
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
    stream_events: [16]Conn.StreamEvent = undefined,
    /// Where the client copies the server's name out of its first packet.
    adopted_cid: [20]u8 = undefined,

    fn loss(self: *Node) Conn.Loss {
        return .{
            .shared = &self.recovery,
            .spaces = &self.spaces,
            .sent_initial = &self.sent_initial,
            .sent_handshake = &self.sent_handshake,
            .sent_app = &self.sent_app,
            .sent_streams = &self.sent_streams,
        };
    }

    /// Storage whose address the connection will point at, set up before the
    /// configuration can name it.
    fn prepare(self: *Node) void {
        self.events = .init(&self.acked, &self.lost);
        self.streams = .{
            .{ .send_buffer = &self.send_a, .recv_buffer = &self.ring_a, .recv_limit_bytes = 1024 },
            .{ .send_buffer = &self.send_b, .recv_buffer = &self.ring_b, .recv_limit_bytes = 1024 },
        };
    }

    fn start(self: *Node, config: Conn.Config) void {
        self.conn = .init(config);
    }

    /// One call per packet, which is the whole of what a caller must give the
    /// machine to read one.
    fn feed(self: *Node, bytes: []u8, at: u64) !Conn.Opened {
        return self.conn.feed(
            bytes,
            &self.plaintext,
            &self.parsed,
            &self.stream_events,
            &self.events,
            at,
        );
    }
};

var clock_start: Io.Timestamp = undefined;
/// Time the example skips instead of sleeping, added to every reading so the
/// clock the machine sees never runs backwards.
var clock_skipped: u64 = 0;

/// What an endpoint tells the other in the handshake (RFC 9000 §18.2), as bytes
/// a driver carries. The numbers are this example's own configuration: the
/// receive window, the stream credit, and the size of the rings, which is also
/// each stream's window.
fn encodeParameters(
    buffer: []u8,
    sender: TransportParameters.Role,
    identity: TransportParameters,
) ![]const u8 {
    var parameters = identity;
    parameters.initial_max_data = 4096;
    parameters.initial_max_stream_data_bidi_local = 1024;
    parameters.initial_max_stream_data_bidi_remote = 1024;
    parameters.initial_max_streams_bidi = 1;
    var writer: quic.Writer = .init(buffer);
    try TransportParameters.encode(&writer, parameters, sender);
    return writer.written();
}

fn now(io: Io) u64 {
    const elapsed = clock_start.durationTo(.now(io, .awake));
    return @as(u64, @intCast(@max(elapsed.nanoseconds, 0))) + clock_skipped;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    clock_start = .now(io, .awake);

    // The client invents the server's name, and §7.2 asks for eight bytes: it is
    // also the seed of the Initial keys (RFC 9001 §5.2).
    const named_server = [_]u8{ 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e };
    // What the server calls itself. A real server generates this from its own
    // entropy; the example fixes it so the transcript reads the same every run.
    // Four bytes, while the name the client invented is eight: §7.2 makes the
    // client adopt this one, and a short header has to know the length without
    // a field for it (§17.3.1).
    const server_local_id = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const client_id = [_]u8{ 0xc1, 0xc2 };

    // Two stub drivers that agree on secrets and on nothing else. The machine
    // installs the traffic spaces from these and never asks how they were
    // negotiated.
    const client_secret: [protection.secret_length]u8 = @splat(0x11);
    const server_secret: [protection.secret_length]u8 = @splat(0x22);
    const secrets: handshake.Secrets = .{ .client = &client_secret, .server = &server_secret };
    // Both ends send real transport parameters. §7.3 has each name itself, and
    // the server echo the name the client first used for it.
    var client_parameters_buffer: [128]u8 = undefined;
    var server_parameters_buffer: [128]u8 = undefined;
    const client_parameters = try encodeParameters(&client_parameters_buffer, .client, .{
        .initial_source_connection_id = &client_id,
    });
    const server_parameters = try encodeParameters(&server_parameters_buffer, .server, .{
        .original_destination_connection_id = &named_server,
        .initial_source_connection_id = &server_local_id,
    });
    // The client has neither the server's parameters nor the 1-RTT secrets until
    // the server's first flight arrives, as with a real driver; the machine
    // refuses 1-RTT without the parameters (RFC 9001 §8.2).
    var client_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ClientHello, faked" }},
        .handshake_secrets = secrets,
    };
    var server_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ServerHello, faked" }},
        .handshake_secrets = secrets,
        .app_secrets = secrets,
        .peer_parameters = client_parameters,
    };

    const client = try arena.create(Node);
    const server = try arena.create(Node);
    client.prepare();
    server.prepare();
    // The client's identity is the name it makes up for the server, which is
    // also the seed of its Initial keys, and the constructor is what pairs them.
    var client_config = Conn.clientConfig(&named_server, &client_id, client.loss());
    client_config.tls = client_stub.driver();
    client_config.transport_parameters = client_parameters;
    client_config.crypto = .{
        .initial = &client.crypto_in_initial,
        .handshake = &client.crypto_in_handshake,
    };
    client_config.crypto_sent = .{
        .initial = &client.crypto_out_initial,
        .handshake = &client.crypto_out_handshake,
    };
    client_config.stream_slots = &client.slots;
    client_config.streams = &client.streams;
    client_config.receive_limit = 4096;
    client_config.connection_id_storage = &client.adopted_cid;
    client_config.max_streams_bidi = 1;
    client.start(client_config);
    var wire: [1500]u8 = undefined;
    // §14.1: an Initial datagram is padded to 1200 bytes, and the padding is
    // written into this scratch.
    var frames: [1500]u8 = undefined;

    // The client's handshake flight.
    const flight = (try client.conn.writeHandshake(&frames, &wire, now(io))) orelse
        return error.NoHandshakeWritten;

    // The server is built from that datagram: the client's Destination
    // Connection ID is the seed of the Initial keys and the client's Source
    // Connection ID is where every reply goes, and the constructor is what
    // pairs them with the right one. The IDs are copied out of the receive
    // buffer, which is about to be reused.
    var server_ids: [40]u8 = undefined;
    const opening: Conn.Opening = try .fromDatagram(wire[0..flight], &server_ids);
    var server_config = opening.serverConfig(&server_local_id, server.loss());
    server_config.tls = server_stub.driver();
    server_config.transport_parameters = server_parameters;
    server_config.crypto = .{
        .initial = &server.crypto_in_initial,
        .handshake = &server.crypto_in_handshake,
    };
    server_config.crypto_sent = .{
        .initial = &server.crypto_out_initial,
        .handshake = &server.crypto_out_handshake,
    };
    server_config.stream_slots = &server.slots;
    server_config.streams = &server.streams;
    server_config.receive_limit = 4096;
    server_config.max_streams_bidi = 1;
    server.start(server_config);

    // The server reads the flight and installs the spaces its driver reported
    // secrets for; that is what makes its 1-RTT keys exist. The stub also says
    // the handshake is complete, which is what a server's confirmation is
    // (§4.1.2 of RFC 9001) and what owes the client a HANDSHAKE_DONE.
    const first_server_packet = try server.feed(wire[0..flight], now(io));
    assert(first_server_packet.space == .initial);
    server_stub.confirmed = true;
    try server.conn.installSpaces();
    print("server: 1-RTT keys from the faked handshake: {}\n", .{server.conn.app != null});

    // Its answer is also what names it: §7.2 makes the client adopt the Source
    // Connection ID of the server's first Initial, and a short header has no
    // length field to disagree about.
    const hello = (try server.conn.writeHandshake(&frames, &wire, now(io))) orelse
        return error.NoHandshakeWritten;
    _ = try client.feed(wire[0..hello], now(io));

    // The server's flight is what carries its parameters and finishes the
    // handshake, so this is when the driver has both. The machine adopts the
    // parameters as the limits it opens streams under: one stream's credit, and
    // a window of 4096 bytes.
    client_stub.peer_parameters = server_parameters;
    client_stub.app_secrets = secrets;
    try client.conn.installSpaces();
    print("client: the server allows {d} bytes and {d} stream\n", .{
        client.conn.peer.?.max_data,
        client.conn.peer.?.max_streams.bidi,
    });
    print("server: the client allows {d} bytes and {d} stream\n", .{
        server.conn.peer.?.max_data,
        server.conn.peer.?.max_streams.bidi,
    });
    // The adopted limit is enforced, not just printed: the second client
    // stream, id 4, is past the one the server allows (§4.6).
    assert(client.conn.openStream(4) == error.NoStreamCredit);
    print("client: sends to {d} bytes named by the server\n", .{
        client.conn.destination_connection_id.len,
    });

    // §4.1.2 of RFC 9001: the client is not confirmed until the server says so,
    // and the server's frame is a packet of its own.
    assert(!client.conn.handshakeConfirmed());
    const done = (try server.conn.writeConfirmation(&wire, now(io))) orelse
        return error.NothingToSend;
    _ = try client.feed(wire[0..done], now(io));
    print("client: handshake confirmed by HANDSHAKE_DONE: {}\n", .{client.conn.handshakeConfirmed()});
    assert(client.conn.handshakeConfirmed());

    // The client asks for a stream, writes, and offers it to the packetizer. The
    // offer is how much this packet may carry, not how much was written.
    const stream = try client.conn.openStream(0);
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
    print("client: packet {d}, {d} bytes on the wire, took {d} offers\n", .{
        sent.number,
        sent.length,
        sent.consumed.taken,
    });

    // The datagram is lost: it is never delivered. The machine cannot tell, and
    // it is not told until a later packet is acknowledged and the caller's loss
    // timer fires (RFC 9002 §6.1.2). A PING that does arrive is that packet.
    const ping = [_]u8{0x01};
    const ping_number = client.conn.app.?.next_packet_number;
    const later = try client.conn.writeFrames(.app, &ping, &wire, .data(now(io)));
    _ = try server.feed(wire[0..later], now(io));
    const ack = try server.conn.writeAck(.app, &wire, now(io));

    // Instead of sleeping through the loss delay, say that it passed.
    clock_skipped += Recovery.ms(100);
    _ = try client.feed(wire[0..ack], now(io));
    var recovery_spaces = [_]*Recovery.Space{ &client.spaces[0], &client.spaces[1], &client.spaces[2] };
    var timers: RecoveryDriver = .init(&client.recovery, &recovery_spaces);
    const options = client.conn.recoveryOptions();
    const due = timers.deadline(options);
    assert(due.kind == .loss);
    const fired = (try timers.poll(due.at, options, .client, &client.events)) orelse
        return error.NoTimerFired;
    assert(fired.kind == .loss);
    assert(client.events.lostPackets()[0].packet_number == sent.number);
    print("client: packet {d} declared lost after the ack of packet {d}\n", .{
        sent.number,
        ping_number,
    });

    // A timer's losses are the caller's to hand over. The machine then owes the
    // stream's bytes again, and the same offer sends them in a new packet.
    client.conn.onPacketsLost(.app, client.events.lostPackets());
    const resent = (try client.conn.writeStreams(.{
        .offers = &.{.{ .stream_id = 0, .length = 1024 }},
        .frames = &frames,
        .out = &wire,
        .written = &client_written,
        .max_payload = 1200,
        .now = now(io),
    })) orelse return error.NothingToSend;
    assert(resent.number != sent.number);
    print("client: resent the same bytes in packet {d}\n", .{resent.number});

    // The server reads the packet. The machine says which streams the packet
    // made readable, so the application does not scan its own table.
    const at_server = try server.feed(wire[0..resent.length], now(io));
    var echoed: u32 = 0;
    for (at_server.streams) |changed| {
        const incoming = server.conn.stream(changed.stream_id) orelse continue;
        var read: [1024]u8 = undefined;
        const count = try incoming.recv.readInto(&read);
        if (count == 0) continue;
        print("server: stream {d} had {d} bytes\n", .{ changed.stream_id, count });

        // A bidirectional stream the peer opened is not writable until this
        // endpoint joins it, which is a different act from opening one: nothing
        // is created, and the limit is the peer's.
        const back = try server.conn.joinStream(changed.stream_id);
        try back.send.write(read[0..count]);
        try back.send.finish();
        var server_written: [1]Conn.Written = undefined;
        const reply = (try server.conn.writeStreams(.{
            .offers = &.{.{ .stream_id = changed.stream_id, .length = 1024 }},
            .frames = &frames,
            .out = &wire,
            .written = &server_written,
            .max_payload = 1200,
            .now = now(io),
        })) orelse return error.NothingToSend;
        echoed = reply.length;
        print("server: echoed in packet {d}\n", .{reply.number});
    }

    // The client reads the echo the same way: the same report, on its side.
    const at_client = try client.feed(wire[0..echoed], now(io));
    for (at_client.streams) |changed| {
        const echoed_back = client.conn.stream(changed.stream_id) orelse continue;
        var read_back: [1024]u8 = undefined;
        const count = try echoed_back.recv.readInto(&read_back);
        print("client: read back \"{s}\"\n", .{read_back[0..count]});
    }

    // Only the client's PING was ever acknowledged, so both ends still hold the
    // rest in flight: the client the echo, the server its HANDSHAKE_DONE and the
    // echo. A real loop asks `ackOwed`/`writeAck` and polls `RecoveryDriver` on
    // every wake; this one just shows the bill.
    print("client: {d} in flight, server: {d} in flight\n", .{
        client.conn.app.?.recovery.inFlight().len,
        server.conn.app.?.recovery.inFlight().len,
    });
}
