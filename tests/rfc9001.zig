//! RFC 9001 Appendix A, pinned byte for byte.
//!
//! The vectors are the RFC's own worked example: the client Initial it prints
//! in A.2 and the server Initial in A.3, both with AES-128-GCM, and the
//! ChaCha20-Poly1305 short header packet from A.5. A protection implementation
//! that produces one of these packets byte for byte is not close to correct, it
//! is correct on the path those bytes take.
//!
//! This file lives outside `src/` so the vectors stay out of the package a
//! consumer fetches.

const std = @import("std");
const testing = std.testing;
const quic = @import("quic");
const data = @import("rfc9001_data.zig");

const protection = quic.protection;

test "RFC 9001 A.1, the Initial secrets come from the connection ID" {
    const secrets = protection.initialSecrets(&data.dcid);
    try testing.expectEqualSlices(u8, &data.client_initial_secret, &secrets.client);
    try testing.expectEqualSlices(u8, &data.server_initial_secret, &secrets.server);

    const client = protection.deriveKeys(secrets.client, .aes_128_gcm);
    try testing.expectEqualSlices(u8, &data.client_key, client.keyBytes());
    try testing.expectEqualSlices(u8, &data.client_iv, &client.iv);
    try testing.expectEqualSlices(u8, &data.client_hp, client.headerKeyBytes());

    const server = protection.deriveKeys(secrets.server, .aes_128_gcm);
    try testing.expectEqualSlices(u8, &data.server_key, server.keyBytes());
    try testing.expectEqualSlices(u8, &data.server_iv, &server.iv);
    try testing.expectEqualSlices(u8, &data.server_hp, server.headerKeyBytes());
}

test "RFC 9001 A.2, the client Initial seals to the printed packet" {
    const secrets = protection.initialSecrets(&data.dcid);
    const client = protection.deriveKeys(secrets.client, .aes_128_gcm);

    // A.2 prints a 22-byte header with a 4-byte packet number, so the number
    // starts at offset 18, and a 1162-byte payload.
    const pn_offset = data.client_header.len - 4;
    try testing.expectEqual(@as(usize, 18), pn_offset);

    var packet: [1200]u8 = undefined;
    @memcpy(packet[0..data.client_header.len], &data.client_header);
    const total = try protection.sealPacket(
        &client,
        2,
        pn_offset,
        4,
        &data.client_payload,
        &packet,
    );

    try testing.expectEqual(data.client_packet.len, total);
    try testing.expectEqualSlices(u8, &data.client_packet, packet[0..total]);

    // The sample and the mask A.2 prints, taken from the sealed bytes.
    const sample = packet[pn_offset + 4 ..][0..16];
    try testing.expectEqualSlices(u8, &data.client_sample, sample);
    try testing.expectEqualSlices(u8, &data.client_mask, &protection.mask(&client, sample.*));
}

test "RFC 9001 A.2, the client Initial the RFC printed opens back" {
    const secrets = protection.initialSecrets(&data.dcid);
    const client = protection.deriveKeys(secrets.client, .aes_128_gcm);

    var packet: [1200]u8 = undefined;
    @memcpy(&packet, &data.client_packet);

    var plaintext: [1162]u8 = undefined;
    const opened = try protection.openPacket(&client, &packet, 18, null, &plaintext);

    try testing.expectEqual(@as(u64, 2), opened.packet_number);
    try testing.expectEqual(@as(u32, 22), opened.header_len);
    try testing.expectEqualSlices(u8, &data.client_payload, opened.payload);
}

test "RFC 9001 A.3, the server Initial seals and opens" {
    const secrets = protection.initialSecrets(&data.dcid);
    const server = protection.deriveKeys(secrets.server, .aes_128_gcm);

    // A.3: a 20-byte header with a 2-byte packet number of 1, and 99 bytes of
    // frames.
    const pn_offset = data.server_header.len - 2;
    try testing.expectEqual(@as(usize, 18), pn_offset);

    var packet: [135]u8 = undefined;
    @memcpy(packet[0..data.server_header.len], &data.server_header);
    const total = try protection.sealPacket(
        &server,
        1,
        pn_offset,
        2,
        &data.server_payload,
        &packet,
    );

    try testing.expectEqual(data.server_packet.len, total);
    try testing.expectEqualSlices(u8, &data.server_packet, packet[0..total]);

    const sample = packet[pn_offset + 4 ..][0..16];
    try testing.expectEqualSlices(u8, &data.server_sample, sample);
    try testing.expectEqualSlices(u8, &data.server_mask, &protection.mask(&server, sample.*));

    var plaintext: [99]u8 = undefined;
    const opened = try protection.openPacket(&server, packet[0..total], pn_offset, null, &plaintext);
    try testing.expectEqual(@as(u64, 1), opened.packet_number);
    try testing.expectEqualSlices(u8, &data.server_payload, opened.payload);
}

test "RFC 9001 A.5, the ChaCha20 short header packet" {
    const keys = protection.deriveKeys(data.chacha_secret, .chacha20_poly1305);
    try testing.expectEqualSlices(u8, &data.chacha_key, keys.keyBytes());
    try testing.expectEqualSlices(u8, &data.chacha_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &data.chacha_hp, keys.headerKeyBytes());

    try testing.expectEqualSlices(u8, &data.chacha_nonce, &protection.nonce(&keys, 654360564));

    // A short header with an empty destination connection ID: one byte, then a
    // three-byte packet number at offset 1.
    var packet: [21]u8 = undefined;
    @memcpy(packet[0..data.chacha_header.len], &data.chacha_header);

    const total = try protection.sealPacket(
        &keys,
        654360564,
        1,
        3,
        &data.chacha_plaintext,
        &packet,
    );
    try testing.expectEqual(@as(u32, 21), total);
    try testing.expectEqualSlices(u8, &data.chacha_packet, packet[0..total]);

    // The protected header and ciphertext the RFC prints, separately.
    try testing.expectEqualSlices(u8, &data.chacha_protected_header, packet[0 .. data.chacha_header.len]);
    try testing.expectEqualSlices(u8, &data.chacha_ciphertext, packet[4..]);

    const sample = packet[1 + 4 ..][0..16];
    try testing.expectEqualSlices(u8, &data.chacha_sample, sample);
    try testing.expectEqualSlices(u8, &data.chacha_mask, &protection.mask(&keys, sample.*));

    // Opening needs the number's neighbourhood, because the wire carries only
    // its low three bytes: with the previous packet as context the full number
    // comes back.
    var opened_packet = packet;
    var plaintext: [1]u8 = undefined;
    const opened = try protection.openPacket(
        &keys,
        &opened_packet,
        1,
        654360563,
        &plaintext,
    );
    try testing.expectEqual(@as(u64, 654360564), opened.packet_number);
    try testing.expectEqualSlices(u8, &data.chacha_plaintext, opened.payload);
}

test "RFC 9001 A.2, one bit of the packet and the tag does not verify" {
    const secrets = protection.initialSecrets(&data.dcid);
    const client = protection.deriveKeys(secrets.client, .aes_128_gcm);

    // The payload is changed: the tag covers it.
    {
        var packet: [1200]u8 = undefined;
        @memcpy(&packet, &data.client_packet);
        packet[100] ^= 0x01;
        var plaintext: [1162]u8 = undefined;
        try testing.expectError(
            error.AuthenticationFailed,
            protection.openPacket(&client, &packet, 18, null, &plaintext),
        );
    }

    // The packet number is changed after header protection is removed: the
    // nonce changes with it, so the same tag fails.
    {
        var packet: [1200]u8 = undefined;
        @memcpy(&packet, &data.client_packet);
        var plaintext: [1162]u8 = undefined;
        const opened = try protection.openPacket(&client, &packet, 18, null, &plaintext);
        try testing.expectEqual(@as(u64, 2), opened.packet_number);

        var again: [1200]u8 = undefined;
        @memcpy(&again, &data.client_packet);
        // Flip a bit of the (still protected) packet number; header protection
        // spreads it, and the AEAD refuses the result.
        again[21] ^= 0x01;
        try testing.expectError(
            error.AuthenticationFailed,
            protection.openPacket(&client, &again, 18, null, &plaintext),
        );
    }

    // The wrong key is the wrong key. The buffer has to be generous: a wrong
    // header protection key also garbles the packet number length, so the
    // ciphertext may appear longer than the real payload.
    {
        const server = protection.deriveKeys(secrets.server, .aes_128_gcm);
        var packet: [1200]u8 = undefined;
        @memcpy(&packet, &data.client_packet);
        var plaintext: [1200]u8 = undefined;
        try testing.expectError(
            error.AuthenticationFailed,
            protection.openPacket(&server, &packet, 18, null, &plaintext),
        );
    }
}
