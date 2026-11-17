//! `Storage(limits)`: every buffer one `Conn` points into, sized at compile time
//! from five numbers. It is the machine layer's twin of `quic-io`'s `Sizing`,
//! for a caller that drives `Conn` itself: the loss state and the three sent
//! tables, the STREAM records, the CRYPTO buffers per level, the stream table
//! and each stream's two buffers, the connection-ID and transport-parameter
//! bytes, and the arrays `feed` and `writeStreams` fill.
//!
//! No allocator: a `Storage` is one value whose size is `@sizeOf` of it, and it
//! holds no `Conn`. `config` hands back a `Conn.Config` that points into it, so
//! from that call on it must not move, like the `Conn` built from it.
//!
//! Measured (Zig 0.17.1, aarch64): `Storage(.{})` is 78,776 bytes. The
//! smallest limits the tests run a stub handshake, one stream each way, and a
//! resend under, `.{ .streams = 1, .stream_ring = 64, .sent_packets = 4,
//! .crypto = 64, .datagram = 1232 }`, make 12,392, of which 5,632 is the 64
//! frames `feed` may hand back and 3,696 the three datagram buffers.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const Conn = @import("Conn.zig");
const Recovery = @import("Recovery.zig");
const RecoveryDriver = @import("RecoveryDriver.zig");
const StreamTable = @import("StreamTable.zig");
const TransportParameters = @import("TransportParameters.zig");
const Writer = @import("Writer.zig");
const frame = @import("frame.zig");
const handshake = @import("handshake.zig");

/// The numbers a caller chooses, as `quic-io`'s `SizingLimits` names them.
/// Every other length follows from them.
pub const Limits = struct {
    /// Streams live at once, both directions and both initiators: the stream
    /// table's length, and so the most the advertised stream counts may sum to.
    streams: u16 = 4,
    /// Each stream's receive ring and send buffer, and so the per-stream window
    /// advertised (§4.1). The send buffer does not wrap: a stream carries at
    /// most this many bytes out over its life.
    stream_ring: u32 = 4096,
    /// Sent packets tracked per packet number space for loss recovery.
    sent_packets: u16 = 32,
    /// CRYPTO reassembly and replay at each level, each way (§19.6, §13.3).
    crypto: u32 = 4096,
    /// One datagram: what `feed` opens into and what a write seals into, and
    /// the max_udp_payload_size advertised.
    datagram: u16 = 1500,
};

/// Who the endpoint is and what it decides; `Storage.config` derives the rest.
pub const Setup = struct {
    role: Role,
    /// This endpoint's own connection ID, copied in. The machine holds no
    /// entropy, and §5.1 wants it unpredictable, so the caller picks it.
    connection_id: []const u8,
    /// The TLS driver. Without one the peer's limits are `peer`'s.
    tls: ?handshake.Driver = null,
    /// What this endpoint advertises (§18.2). The windows,
    /// max_udp_payload_size, and the connection IDs §7.3 asks for are written
    /// over from the limits and `role`; the stream counts are the caller's, and
    /// together may not pass `streams`.
    parameters: TransportParameters = .{},
    /// The peer's limits for a machine with no driver (`Conn.Config.peer`).
    peer: ?Conn.PeerParameters = null,
};

pub const Role = union(Conn.Role) {
    /// The name a client invents for the server, copied in: the seed of the
    /// Initial keys, and at least eight bytes (§7.2).
    client: []const u8,
    /// What a server read from the client's first Initial (`Storage.opening`).
    server: Conn.Opening,
};

/// §17.2: a version 1 connection ID is at most 20 bytes.
const max_connection_id = 20;

/// Room for this endpoint's encoded transport parameters.
const parameter_capacity = 256;

/// The most frames one packet may carry that `feed` hands back rather than
/// acts on, as `quic-io` allows. More is `error.NoSpace` from `feed`.
const frames_per_packet = 64;

pub fn Storage(comptime limits_given: Limits) type {
    comptime {
        assert(limits_given.streams > 0);
        assert(limits_given.stream_ring > 0);
        assert(limits_given.sent_packets > 0);
        assert(limits_given.crypto > 0);
        // IPv6's minimum path, 1280 bytes less 48 of headers: it holds the
        // 1200-byte Initial datagram §14.1 asks for.
        assert(limits_given.datagram >= 1232);
    }
    const streams = limits_given.streams;
    const ring = limits_given.stream_ring;
    const sent = limits_given.sent_packets;
    const crypto = limits_given.crypto;
    const datagram_len = limits_given.datagram;

    return struct {
        const Self = @This();

        pub const limits = limits_given;
        /// §4.1: the connection window, every ring full.
        pub const receive_limit: u64 = @as(u64, streams) * ring;

        loss_state: Recovery,
        spaces: [3]Recovery.Space,
        space_pointers: [3]*Recovery.Space,
        sent: [3][sent]Recovery.SentPacket,
        /// The STREAM ranges each tracked 1-RTT packet carried, one per slot
        /// of the 1-RTT sent table.
        sent_streams: [sent]Conn.SentStreams,
        acked: [sent]Recovery.SentPacket,
        lost: [sent]Recovery.SentPacket,
        /// What `feed` and `RecoveryDriver.poll` report acknowledged and lost.
        events: Recovery.Events,
        crypto_in: [3][crypto]u8,
        crypto_sent: [3][crypto]u8,
        slots: [streams]StreamTable.Slot,
        streams: [streams]Conn.Stream,
        send_buffers: [streams][ring]u8,
        recv_buffers: [streams][ring]u8,
        /// Both of a client's first Initial's connection IDs, for `opening`.
        connection_ids: [2 * max_connection_id]u8,
        own_id: [max_connection_id]u8,
        /// The name a client invented for the server.
        original_id: [max_connection_id]u8,
        /// Where a client copies the name the server gives itself (§7.2).
        adopted_id: [max_connection_id]u8,
        parameter_bytes: [parameter_capacity]u8,
        /// `feed`'s: the datagram opened, its frames, and the streams it moved.
        plaintext: [datagram_len]u8,
        frames: [frames_per_packet]frame.Frame,
        stream_events: [streams]Conn.StreamEvent,
        /// A write's: the frames encoded, the sealed datagram, and the STREAM
        /// frames one packet carried.
        scratch: [datagram_len]u8,
        datagram: [datagram_len]u8,
        written: [Conn.stream_frames_per_packet]Conn.Written,

        /// Read a client's first Initial into a server's identity, with both
        /// connection IDs copied here (`Conn.Opening.fromDatagram`).
        pub fn opening(self: *Self, first: []const u8) Conn.Error!Conn.Opening {
            return Conn.Opening.fromDatagram(first, &self.connection_ids);
        }

        /// The configuration for `Conn.init`, over this storage, with every
        /// buffer, window, and stream count in place and the transport
        /// parameters encoded. Change a field of it before `init` to differ.
        pub fn config(self: *Self, setup: Setup) TransportParameters.Error!Conn.Config {
            assert(setup.connection_id.len <= max_connection_id);
            self.prepare();
            const own = copyId(&self.own_id, setup.connection_id);
            var parameters = advertised(setup.parameters);
            parameters.initial_source_connection_id = own;
            var base = switch (setup.role) {
                .client => |name| Conn.clientConfig(copyId(&self.original_id, name), own, self.loss()),
                .server => |first| first.serverConfig(own, self.loss()),
            };
            if (setup.role == .server) {
                parameters.original_destination_connection_id = base.original_destination_connection_id;
            }
            base.connection_id_storage = &self.adopted_id;
            base.tls = setup.tls;
            base.peer = setup.peer;
            base.transport_parameters = try self.encode(parameters, setup.role);
            base.ack_delay_exponent = @intCast(parameters.ackDelayExponent());
            base.crypto = levels(&self.crypto_in);
            base.crypto_sent = levels(&self.crypto_sent);
            base.stream_slots = &self.slots;
            base.streams = &self.streams;
            base.receive_limit = receive_limit;
            base.max_streams_bidi = parameters.initial_max_streams_bidi orelse 0;
            base.max_streams_uni = parameters.initial_max_streams_uni orelse 0;
            // §4.6: credit the table cannot back is refused at construction.
            assert(base.max_streams_bidi + base.max_streams_uni <= streams);
            return base;
        }

        /// One timer over this storage's three spaces, for the loss and probe
        /// deadlines the caller services (RFC 9002 §6).
        pub fn recoveryDriver(self: *Self) RecoveryDriver {
            return .init(&self.loss_state, &self.space_pointers);
        }

        /// Point what `config` hands out at its own storage.
        fn prepare(self: *Self) void {
            self.loss_state = .{};
            self.space_pointers = .{ &self.spaces[0], &self.spaces[1], &self.spaces[2] };
            self.events = .init(&self.acked, &self.lost);
            for (&self.streams, &self.send_buffers, &self.recv_buffers) |*entry, *send, *recv| {
                entry.* = .{ .send_buffer = send, .recv_buffer = recv, .recv_limit_bytes = ring };
            }
        }

        fn levels(buffers: *[3][crypto]u8) Conn.CryptoStorage {
            return .{ .initial = &buffers[0], .handshake = &buffers[1], .app = &buffers[2] };
        }

        fn loss(self: *Self) Conn.Loss {
            return .{
                .shared = &self.loss_state,
                .spaces = &self.spaces,
                .sent_initial = &self.sent[0],
                .sent_handshake = &self.sent[1],
                .sent_app = &self.sent[2],
                .sent_streams = &self.sent_streams,
            };
        }

        /// The caller's parameters with the numbers the limits decide written
        /// over: the windows and the datagram size.
        fn advertised(given: TransportParameters) TransportParameters {
            var parameters = given;
            parameters.initial_max_data = receive_limit;
            parameters.initial_max_stream_data_bidi_local = ring;
            parameters.initial_max_stream_data_bidi_remote = ring;
            parameters.initial_max_stream_data_uni = ring;
            parameters.max_udp_payload_size = datagram_len;
            return parameters;
        }

        fn encode(self: *Self, parameters: TransportParameters, role: Conn.Role) TransportParameters.Error![]const u8 {
            var writer: Writer = .init(&self.parameter_bytes);
            const sender: TransportParameters.Role = switch (role) {
                .client => .client,
                .server => .server,
            };
            try TransportParameters.encode(&writer, parameters, sender);
            return writer.written();
        }
    };
}

fn copyId(storage: *[max_connection_id]u8, id: []const u8) []const u8 {
    assert(id.len <= max_connection_id);
    @memcpy(storage[0..id.len], id);
    return storage[0..id.len];
}

// -- Tests -------------------------------------------------------------------

const protection = @import("protection.zig");

/// The smallest limits that still run what `examples/machine.zig` runs: a stub
/// handshake, one stream each way, and one lost packet resent.
const Small = Storage(.{ .streams = 1, .stream_ring = 64, .sent_packets = 4, .crypto = 64, .datagram = 1232 });

/// File scope: a `Storage` must not move once `config` has pointed into it.
var test_client: Small = undefined;
var test_server: Small = undefined;

fn testFeed(conn: *Conn, storage: *Small, datagram: []u8) Conn.Error!Conn.Opened {
    return conn.feed(datagram, &storage.plaintext, &storage.frames, &storage.stream_events, &storage.events, 0);
}

fn testSend(conn: *Conn, storage: *Small) Conn.Error!Conn.Packet {
    const packet = try conn.writeStreams(.{
        .offers = &.{.{ .stream_id = 0, .length = Small.limits.stream_ring }},
        .frames = &storage.scratch,
        .out = &storage.datagram,
        .written = &storage.written,
        .max_payload = 1200,
        .now = 0,
    });
    return packet orelse error.NoSpace;
}

// The exchange `examples/machine.zig` walks through, each end's buffers all a
// `Storage`: the handshake, the server named by its own ID (§7.2), confirmation
// by HANDSHAKE_DONE (RFC 9001 §4.1.2), a STREAM packet declared lost by the
// timer and sent again (§13.3), and the bytes echoed back.
test "RFC 9000 §13.3, a Conn over Storage handshakes, resends a lost packet, and echoes a stream" {
    const client_secret: [protection.secret_length]u8 = @splat(0x11);
    const server_secret: [protection.secret_length]u8 = @splat(0x22);
    const secrets: handshake.Secrets = .{ .client = &client_secret, .server = &server_secret };
    const named_server: [8]u8 = @splat(0x5e);
    const server_id = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var client_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ClientHello" }},
        .handshake_secrets = secrets,
    };
    var client: Conn = .init(try test_client.config(.{
        .role = .{ .client = &named_server },
        .connection_id = &.{ 0xc1, 0xc2 },
        .tls = client_stub.driver(),
    }));
    const flight = (try client.writeHandshake(&test_client.scratch, &test_client.datagram, 0)).?;
    const first = test_client.datagram[0..flight];

    var server_stub: handshake.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = "ServerHello" }},
        .handshake_secrets = secrets,
        .app_secrets = secrets,
        .peer_parameters = client.transport_parameters,
    };
    var server: Conn = .init(try test_server.config(.{
        .role = .{ .server = try test_server.opening(first) },
        .connection_id = &server_id,
        .tls = server_stub.driver(),
        .parameters = .{ .initial_max_streams_bidi = 1 },
    }));
    _ = try testFeed(&server, &test_server, first);
    server_stub.confirmed = true;
    try server.installSpaces();
    const hello = (try server.writeHandshake(&test_server.scratch, &test_server.datagram, 0)).?;
    _ = try testFeed(&client, &test_client, test_server.datagram[0..hello]);
    try testing.expectEqualSlices(u8, &server_id, client.destination_connection_id);

    client_stub.peer_parameters = server.transport_parameters;
    client_stub.app_secrets = secrets;
    try client.installSpaces();
    try testing.expectEqual(Small.receive_limit, client.peer.?.max_data);
    const done = (try server.writeConfirmation(&test_server.datagram, 0)).?;
    _ = try testFeed(&client, &test_client, test_server.datagram[0..done]);
    try testing.expect(client.handshakeConfirmed());

    const outgoing = try client.openStream(0);
    try outgoing.send.write("ping");
    try outgoing.send.finish();
    const lost = try testSend(&client, &test_client);
    // Never delivered. A PING that is, and its ACK, arm the loss timer.
    const later = try client.writeFrames(.app, &.{0x01}, &test_client.datagram, .data(0));
    _ = try testFeed(&server, &test_server, test_client.datagram[0..later]);
    const ack = try server.writeAck(.app, &test_server.datagram, 0);
    _ = try testFeed(&client, &test_client, test_server.datagram[0..ack]);
    var timers = test_client.recoveryDriver();
    const options = client.recoveryOptions();
    const due = timers.deadline(options);
    try testing.expectEqual(.loss, due.kind);
    _ = (try timers.poll(due.at, options, .client, &test_client.events)).?;
    try testing.expectEqual(lost.number, test_client.events.lostPackets()[0].packet_number);
    client.onPacketsLost(.app, test_client.events.lostPackets());

    const resent = try testSend(&client, &test_client);
    try testing.expect(resent.number != lost.number);
    const at_server = try testFeed(&server, &test_server, test_client.datagram[0..resent.length]);
    try testing.expectEqual(@as(usize, 1), at_server.streams.len);
    var read: [Small.limits.stream_ring]u8 = undefined;
    const count = try server.stream(0).?.recv.readInto(&read);
    try testing.expectEqualStrings("ping", read[0..count]);

    const back = try server.joinStream(0);
    try back.send.write(read[0..count]);
    try back.send.finish();
    const reply = try testSend(&server, &test_server);
    _ = try testFeed(&client, &test_client, test_server.datagram[0..reply.length]);
    const echoed = try client.stream(0).?.recv.readInto(&read);
    try testing.expectEqualStrings("ping", read[0..echoed]);
}

test "Storage, every dependent length follows from its numbers" {
    try testing.expectEqual(@as(u64, 64), Small.receive_limit);
    // A stream's two buffers, and nothing else, grow with the ring.
    const Wider = Storage(.{ .streams = 1, .stream_ring = 128, .sent_packets = 4, .crypto = 64, .datagram = 1232 });
    try testing.expectEqual(@sizeOf(Small) + 2 * 64, @sizeOf(Wider));
    // Six CRYPTO buffers, one per level each way.
    const Deeper = Storage(.{ .streams = 1, .stream_ring = 64, .sent_packets = 4, .crypto = 128, .datagram = 1232 });
    try testing.expectEqual(@sizeOf(Small) + 6 * 64, @sizeOf(Deeper));
}
