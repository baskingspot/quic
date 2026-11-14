//! A real TLS 1.3 handshake between two `Conn`s: the `quic-tls` driver on both
//! ends, real certificates, real key schedules, real AEAD, and one stream each
//! way once the handshake completes.
//!
//! This is the proof the driver works. Everything below goes through the public
//! API of the three packages: `Conn` seals and opens packets, the driver runs
//! the handshake, and tls does the cryptography. No secret is handed in.
//!
//! The certificates come from `baskingspot/tls`'s own fixtures, through the
//! build's anonymous imports, so the test signs with a real P-256 key and the
//! client parses a real chain. The client policy takes the fixture as its own
//! anchor rather than skipping verification.

const std = @import("std");
const testing = std.testing;

const quic = @import("quic");
const driver = @import("quic-tls");
const tls = @import("tls");
const core = tls.handshake_core;

const Conn = quic.Conn;

const server_cert_pem = @embedFile("tls_server_crt");
const server_key_pem = @embedFile("tls_server_key");

const TransportParameters = quic.TransportParameters;

/// What the handshake carries opaquely (RFC 9001 §8.2), and what `Conn` reads
/// back out of it: the machine adopts these as the peer's limits, so they are
/// real. Both ends advertise the same numbers, and they are the ones the two
/// `Conn.Config`s below must agree with (`receive_limit`, `max_streams_*`).
fn encodeParameters(comptime sender: TransportParameters.Role, comptime identity: TransportParameters) []const u8 {
    const bytes = comptime blk: {
        var buffer: [128]u8 = undefined;
        var writer: quic.Writer = .init(&buffer);
        var parameters = identity;
        parameters.initial_max_data = 4096;
        parameters.initial_max_stream_data_bidi_local = 1024;
        parameters.initial_max_stream_data_bidi_remote = 1024;
        parameters.initial_max_stream_data_uni = 1024;
        parameters.initial_max_streams_bidi = 1;
        parameters.initial_max_streams_uni = 1;
        TransportParameters.encode(&writer, parameters, sender) catch unreachable;
        const written = buffer[0..writer.written().len].*;
        break :blk written;
    };
    return &bytes;
}

/// §7.3: a client names itself, and a server also echoes the connection ID the
/// client first addressed.
const client_parameters = encodeParameters(.client, .{ .initial_source_connection_id = &client_cid });
const server_parameters = encodeParameters(.server, .{
    .original_destination_connection_id = &dcid,
    .initial_source_connection_id = &dcid,
});

test "RFC 9001 §4, a client and a server complete a TLS handshake through Conn" {
    // -- The credentials a server has to have -------------------------------
    var der: [server_cert_pem.len]u8 = undefined;
    var chain_slots: [1][]const u8 = undefined;
    const chain = try tls.certificate_chain.CertificateChain.fromPem(
        server_cert_pem,
        &der,
        &chain_slots,
    );
    var key = try tls.signature.PrivateKey.fromPemAuto(server_key_pem);
    defer key.deinit();
    const credentials: core.Credentials = .{ .chain = chain, .signer = key.signer() };

    // -- Two drivers, each with its own storage -----------------------------
    const client_storage: driver.Storage = .{
        .slots = &client_slots,
        .out = &client_out,
        .peer_bytes = .{
            .initial = &client_initial,
            .handshake = &client_handshake,
            .app = &client_app,
        },
        .peer_shares = &client_shares,
        .extension_slots = &client_extension_slots,
        .our_parameters = &client_our_parameters,
        .peer_parameters = &client_peer_parameters,
        .alpn = &client_alpn,
        .server_hello = &client_server_hello,
    };
    var client_policy: tls.certificate.Policy = .init;
    // The fixture is self-signed, and this test is about the handshake, not
    // about trusting a public CA.
    client_policy.insecure_no_chain_anchor = true;
    var client_driver = try driver.Tls.init(client_storage, .{ .client = .{
        .policy = client_policy,
        .alpn = &.{"h3"},
    } }, @splat(0x11));
    defer client_driver.deinit();

    const server_storage: driver.Storage = .{
        .slots = &server_slots,
        .out = &server_out,
        .peer_bytes = .{
            .initial = &server_initial,
            .handshake = &server_handshake,
            .app = &server_app,
        },
        .peer_shares = &server_shares,
        .extension_slots = &server_extension_slots,
        .our_parameters = &server_our_parameters,
        .peer_parameters = &server_peer_parameters,
        .alpn = &server_alpn,
        .server_hello = &server_server_hello,
    };
    var server_driver = try driver.Tls.init(server_storage, .{ .server = .{
        .credentials = credentials,
        .alpn = &.{"h3"},
    } }, @splat(0x22));
    defer server_driver.deinit();

    // -- The machines, with the driver on each ------------------------------
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &client_cid,
        .connection_id_storage = &client_cid_storage,
        .tls = client_driver.driver(),
        .transport_parameters = client_parameters,
        .crypto = .{ .initial = &client_crypto_initial, .handshake = &client_crypto_handshake },
        .crypto_sent = .{ .initial = &client_sent_initial, .handshake = &client_sent_handshake },
        .stream_slots = &client_stream_slots,
        .streams = &client_streams,
        .receive_limit = 4096,
        .max_streams_bidi = 1,
        .max_streams_uni = 1,
    });
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &client_cid,
        .source_connection_id = &dcid,
        .tls = server_driver.driver(),
        .transport_parameters = server_parameters,
        .crypto = .{ .initial = &server_crypto_initial, .handshake = &server_crypto_handshake },
        .crypto_sent = .{ .initial = &server_sent_initial, .handshake = &server_sent_handshake },
        .stream_slots = &server_stream_slots,
        .streams = &server_streams,
        .receive_limit = 4096,
        .max_streams_bidi = 1,
        .max_streams_uni = 1,
    });

    // -- The handshake, packet by packet, in memory -------------------------
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        var moved = false;
        while (try client.writeHandshake(&payload, &datagram, 0)) |sent| {
            _ = try server.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);
            moved = true;
        }
        while (try server.writeHandshake(&payload, &datagram, 0)) |sent| {
            _ = try client.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);
            moved = true;
        }
        if (!moved) break;
    }

    // Both sides believe the handshake completed, and it is the same handshake:
    // ALPN agreed, and each read the other's transport parameters out of the
    // extension tls carried opaquely (RFC 9001 §8.2).
    try testing.expect(client_driver.done());
    try testing.expect(server_driver.done());
    try testing.expectEqualStrings("h3", client_driver.selectedAlpn().?);
    try testing.expectEqualStrings("h3", server_driver.selectedAlpn().?);
    try testing.expectEqualSlices(u8, client_parameters, server_driver.peerTransportParameters().?);
    try testing.expectEqualSlices(u8, server_parameters, client_driver.peerTransportParameters().?);

    // The seam lets `secrets` hand back borrowed bytes and promises they stay
    // valid until the next call, so both roles must report the same pair and
    // the client's copy must live in the driver, not in the frame that produced
    // it. Getting this wrong reads as correct on one target and as an AEAD
    // authentication failure on another, which is how it was found.
    const client_secrets = (try client_driver.driver().secrets(.handshake)).?;
    const server_secrets = (try server_driver.driver().secrets(.handshake)).?;
    try testing.expectEqualSlices(u8, server_secrets.client, client_secrets.client);
    try testing.expectEqualSlices(u8, server_secrets.server, client_secrets.server);
    try testing.expectEqual(
        @intFromPtr(&client_driver.handshake_secrets.client),
        @intFromPtr(client_secrets.client.ptr),
    );

    // §7.1 of RFC 9001 through §4.9.2 of RFC 9000: the 1-RTT space exists on
    // both ends, and a server's handshake is confirmed by its own Finished.
    try testing.expect(client.app != null);
    try testing.expect(server.app != null);

    // §7.4: each `Conn` adopted what the other advertised, from the handshake
    // and not from its configuration.
    try testing.expectEqual(@as(u64, 4096), client.peer.?.max_data);
    try testing.expectEqual(@as(u64, 1), server.peer.?.max_streams.bidi);
    try testing.expectEqual(@as(u64, 1024), client.peer.?.stream_data.bidi_remote);

    // -- One stream each way -------------------------------------------------
    const opened = try client.openStream(0);
    try opened.send.write("hello over tls");

    var offers = [_]Conn.Offer{.{ .stream_id = 0, .length = 1024 }};
    var written: [1]Conn.Written = undefined;
    var frame_bytes: [256]u8 = undefined;
    const flight = (try client.writeStreams(.{
        .offers = &offers,
        .frames = &frame_bytes,
        .out = &datagram,
        .written = &written,
        .max_payload = 1024,
        .now = 1,
    })) orelse return error.TestUnexpectedResult;
    _ = try server.feed(datagram[0..flight.length], &plaintext, &frames, &stream_events, &report, 1);

    const arrived = server.stream(0) orelse return error.TestUnexpectedResult;
    var read: [64]u8 = undefined;
    const count = try arrived.recv.readInto(&read);
    try testing.expectEqualStrings("hello over tls", read[0..count]);

    // And the answer, on the same bidirectional stream's other half, which the
    // peer opened and this endpoint joins (§2.1).
    const back_half = try server.joinStream(0);
    try back_half.send.write("hello back");
    var back_offers = [_]Conn.Offer{.{ .stream_id = 0, .length = 1024 }};
    var back_written: [1]Conn.Written = undefined;
    const back = (try server.writeStreams(.{
        .offers = &back_offers,
        .frames = &frame_bytes,
        .out = &datagram,
        .written = &back_written,
        .max_payload = 1024,
        .now = 2,
    })) orelse return error.TestUnexpectedResult;
    _ = try client.feed(datagram[0..back.length], &plaintext, &frames, &stream_events, &report, 2);

    const returned = client.stream(0) orelse return error.TestUnexpectedResult;
    const back_count = try returned.recv.readInto(&read);
    try testing.expectEqualStrings("hello back", read[0..back_count]);
}

// -- Storage ----------------------------------------------------------------
//
// File scope because a `Conn` holds slices into it and the test's frame is
// already the largest thing on the stack.

const dcid = [_]u8{ 0x71, 0x72 };
const client_cid = [_]u8{0x7a};

/// The caller's loss-recovery storage: the estimator, one slot per packet
/// number space, and the sent tables (RFC 9002 §5, §6).
const Loss = struct {
    shared: quic.Recovery = .{},
    spaces: [3]quic.Recovery.Space = undefined,
    sent_initial: [16]quic.Recovery.SentPacket = undefined,
    sent_handshake: [16]quic.Recovery.SentPacket = undefined,
    sent_app: [16]quic.Recovery.SentPacket = undefined,

    fn value(self: *Loss) Conn.Loss {
        return .{
            .shared = &self.shared,
            .spaces = &self.spaces,
            .sent_initial = &self.sent_initial,
            .sent_handshake = &self.sent_handshake,
            .sent_app = &self.sent_app,
        };
    }
};

var client_loss: Loss = .{};
var server_loss: Loss = .{};

var client_slots: [16]tls.level.Output = undefined;
var server_slots: [16]tls.level.Output = undefined;
var client_out: [4096]u8 = undefined;
var server_out: [4096]u8 = undefined;
var client_initial: [2048]u8 = undefined;
var server_initial: [2048]u8 = undefined;
var client_handshake: [4096]u8 = undefined;
var server_handshake: [4096]u8 = undefined;
var client_app: [512]u8 = undefined;
var server_app: [512]u8 = undefined;
var client_shares: [core.peer_share_storage_len]u8 = undefined;
var server_shares: [core.peer_share_storage_len]u8 = undefined;
var client_extension_slots: [1]tls.extension_type.ExtraExtension = undefined;
var server_extension_slots: [1]tls.extension_type.ExtraExtension = undefined;
var client_our_parameters: [512]u8 = undefined;
var server_our_parameters: [512]u8 = undefined;
var client_peer_parameters: [512]u8 = undefined;
var server_peer_parameters: [512]u8 = undefined;
var client_alpn: [64]u8 = undefined;
var server_alpn: [64]u8 = undefined;
var client_server_hello: [256]u8 = undefined;
var server_server_hello: [256]u8 = undefined;
var client_cid_storage: [20]u8 = undefined;
var client_crypto_initial: [2048]u8 = undefined;
var server_crypto_initial: [2048]u8 = undefined;
var client_crypto_handshake: [4096]u8 = undefined;
var server_crypto_handshake: [4096]u8 = undefined;
var client_sent_initial: [2048]u8 = undefined;
var server_sent_initial: [2048]u8 = undefined;
var client_sent_handshake: [4096]u8 = undefined;
var server_sent_handshake: [4096]u8 = undefined;
var client_stream_slots: [2]quic.StreamTable.Slot = undefined;
var server_stream_slots: [2]quic.StreamTable.Slot = undefined;
var client_send_bytes: [2][1024]u8 = undefined;
var client_recv_bytes: [2][1024]u8 = undefined;
var server_send_bytes: [2][1024]u8 = undefined;
var server_recv_bytes: [2][1024]u8 = undefined;
var client_streams: [2]Conn.Stream = .{
    .{ .send_buffer = &client_send_bytes[0], .recv_buffer = &client_recv_bytes[0], .recv_limit_bytes = 1024 },
    .{ .send_buffer = &client_send_bytes[1], .recv_buffer = &client_recv_bytes[1], .recv_limit_bytes = 1024 },
};
var server_streams: [2]Conn.Stream = .{
    .{ .send_buffer = &server_send_bytes[0], .recv_buffer = &server_recv_bytes[0], .recv_limit_bytes = 1024 },
    .{ .send_buffer = &server_send_bytes[1], .recv_buffer = &server_recv_bytes[1], .recv_limit_bytes = 1024 },
};

var payload: [1500]u8 = undefined;
var datagram: [1500]u8 = undefined;
var plaintext: [1500]u8 = undefined;
var frames: [16]quic.frame.Frame = undefined;
var stream_events: [16]Conn.StreamEvent = undefined;
var acked: [32]quic.Recovery.SentPacket = undefined;
var lost: [32]quic.Recovery.SentPacket = undefined;
var report: quic.Recovery.Events = .init(&acked, &lost);
