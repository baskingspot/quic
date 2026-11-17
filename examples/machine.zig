//! For someone embedding `quic.Conn` in their own I/O layer, writing a driver,
//! or testing without crypto: the bare machine, a client and a server in one
//! process, with no socket and a handshake faked by `handshake.Stub`. To use
//! QUIC rather than build on it, start with `examples/echo.zig`.
//!
//! Every buffer is a `quic.Storage`; the caller keeps the clock, carries each
//! datagram, acts on what `feed` reports, and services the loss timer. It
//! shows the stubs' secrets and parameters becoming keys and limits,
//! HANDSHAKE_DONE confirming the client, and a lost packet resent.
//!
//! What it does not prove: two stubs agree on secrets and nothing else, so no
//! certificate or key schedule runs, nothing crosses a network, and there is
//! no congestion control, pacing, or idle timer.
//!
//! Run it with `just machine`.

const std = @import("std");
const print = std.debug.print;
const assert = std.debug.assert;

const quic = @import("quic");
const Conn = quic.Conn;
const handshake = quic.handshake;

/// One stream each way, 1 KiB windows, room for 16 packets in flight.
const Storage = quic.Storage(.{ .streams = 1, .stream_ring = 1024, .sent_packets = 16, .crypto = 512 });

/// File scope: `Conn` and the storage it points into must not move.
var client_storage: Storage = undefined;
var server_storage: Storage = undefined;
var client: Conn = undefined;
var server: Conn = undefined;

var now: u64 = 0; // The machine has no clock: the caller's, in nanoseconds.

/// Hand one datagram to `conn`, with the storage `feed` reports into.
fn feed(conn: *Conn, storage: *Storage, datagram: []u8) !Conn.Opened {
    return conn.feed(datagram, &storage.plaintext, &storage.frames, &storage.stream_events, &storage.events, now);
}

/// One packet of stream 0. Which streams to offer, and how much, is the caller's.
fn sendStream(conn: *Conn, storage: *Storage) !Conn.Packet {
    return (try conn.writeStreams(.{
        .offers = &.{.{ .stream_id = 0, .length = 1024 }},
        .frames = &storage.scratch,
        .out = &storage.datagram,
        .written = &storage.written,
        .max_payload = 1200,
        .now = now,
    })) orelse error.NothingToSend;
}

pub fn main() !void {
    // Two stub drivers that agree on secrets. The client has neither the
    // server's parameters nor the 1-RTT secrets until the server's flight.
    const client_secret: [quic.protection.secret_length]u8 = @splat(0x11);
    const server_secret: [quic.protection.secret_length]u8 = @splat(0x22);
    const secrets: handshake.Secrets = .{ .client = &client_secret, .server = &server_secret };
    var client_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ClientHello, faked" }},
        .handshake_secrets = secrets,
    };
    // §7.2: the client invents the server's name, eight bytes that also seed
    // the Initial keys (RFC 9001 §5.2).
    const named_server: [8]u8 = @splat(0x5e);
    client = .init(try client_storage.config(.{
        .role = .{ .client = &named_server },
        .connection_id = &.{ 0xc1, 0xc2 },
        .tls = client_stub.driver(),
    }));
    const flight = (try client.writeHandshake(&client_storage.scratch, &client_storage.datagram, now)).?;
    const first = client_storage.datagram[0..flight];

    // The server is built from that datagram and names itself in four bytes,
    // which the client adopts (§7.2). It lets the client open one stream.
    var server_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ServerHello, faked" }},
        .handshake_secrets = secrets,
        .app_secrets = secrets,
        .peer_parameters = client.transport_parameters,
    };
    server = .init(try server_storage.config(.{
        .role = .{ .server = try server_storage.opening(first) },
        .connection_id = &.{ 0x71, 0x72, 0x73, 0x74 },
        .tls = server_stub.driver(),
        .parameters = .{ .initial_max_streams_bidi = 1 },
    }));
    _ = try feed(&server, &server_storage, first);
    server_stub.confirmed = true;
    try server.installSpaces();
    print("server: 1-RTT keys from the faked handshake: {}\n", .{server.app != null});

    const hello = (try server.writeHandshake(&server_storage.scratch, &server_storage.datagram, now)).?;
    _ = try feed(&client, &client_storage, server_storage.datagram[0..hello]);
    client_stub.peer_parameters = server.transport_parameters;
    client_stub.app_secrets = secrets;
    try client.installSpaces();
    print("client: the server allows {d} bytes and {d} stream, named in {d} bytes\n", .{
        client.peer.?.max_data, client.peer.?.max_streams.bidi, client.destination_connection_id.len,
    });
    // The limit is enforced: stream 4 is past the one the server allows.
    assert(client.openStream(4) == error.NoStreamCredit);

    // RFC 9001 §4.1.2: the client is confirmed by the server's HANDSHAKE_DONE.
    const done = (try server.writeConfirmation(&server_storage.datagram, now)).?;
    _ = try feed(&client, &client_storage, server_storage.datagram[0..done]);
    print("client: handshake confirmed by HANDSHAKE_DONE: {}\n", .{client.handshakeConfirmed()});

    // `write` takes all of it or returns `error.NoSpace`: no short writes.
    const stream = try client.openStream(0);
    try stream.send.write("hello from the client");
    try stream.send.finish();
    const sent = try sendStream(&client, &client_storage);

    // That datagram is lost. A PING that arrives and its ACK arm the loss timer.
    const later = try client.writeFrames(.app, &.{0x01}, &client_storage.datagram, .data(now));
    _ = try feed(&server, &server_storage, client_storage.datagram[0..later]);
    const ack = try server.writeAck(.app, &server_storage.datagram, now);
    _ = try feed(&client, &client_storage, server_storage.datagram[0..ack]);
    var timers = client_storage.recoveryDriver();
    const due = timers.deadline(client.recoveryOptions());
    assert(due.kind == .loss);
    now = due.at; // Instead of sleeping until the deadline, say it came.
    _ = (try timers.poll(now, client.recoveryOptions(), .client, &client_storage.events)).?;
    const lost = client_storage.events.lostPackets();
    assert(lost[0].packet_number == sent.number);
    print("client: packet {d} declared lost by the timer\n", .{sent.number});

    // A timer's losses are the caller's to hand over; the same offer resends.
    client.onPacketsLost(.app, lost);
    const resent = try sendStream(&client, &client_storage);
    print("client: resent the same bytes in packet {d}\n", .{resent.number});

    // `feed` reports which streams a packet made readable. A stream the peer
    // opened is joined, not opened, before this end can write to it.
    const at_server = try feed(&server, &server_storage, client_storage.datagram[0..resent.length]);
    var read: [1024]u8 = undefined;
    const count = try server.stream(at_server.streams[0].stream_id).?.recv.readInto(&read);
    const back = try server.joinStream(0);
    try back.send.write(read[0..count]);
    try back.send.finish();
    const reply = try sendStream(&server, &server_storage);
    print("server: echoed {d} bytes in packet {d}\n", .{ count, reply.number });

    const at_client = try feed(&client, &client_storage, server_storage.datagram[0..reply.length]);
    const echoed = try client.stream(at_client.streams[0].stream_id).?.recv.readInto(&read);
    print("client: read back \"{s}\"\n", .{read[0..echoed]});
}
