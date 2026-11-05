//! Initial packet protection, RFC 9001 §5.
//!
//! Initial keys come from the Destination Connection ID the client put in its
//! first Initial packet, not from TLS (§5.2), so a server can open the first
//! packet before any handshake exists. That is the whole reason this module can
//! be written and tested before the handshake work lands.
//!
//! The AEAD is AES-128-GCM for Initial packets (§5.3, and §5.5 says AES header
//! protection applies until TLS picks a suite). TLS_AES_256_GCM_SHA384 is a
//! later addition, not a missing primitive: std has the SHA-384 HMAC and
//! AES-256-GCM, so it is a suite enum arm and a key schedule, not a cipher to
//! write. The header protection key
//! arrives with the label `quic hp` and masks the low four bits of the first
//! byte of a long header and the packet number (§5.4.1), sampling the
//! ciphertext four bytes past the packet number.
//!
//! Order matters and this module keeps it: a sender seals the payload and then
//! applies header protection; a receiver removes header protection first,
//! because the packet number length is inside the masked bits, then decrypts.
//!
//! The ciphers are std's. Nothing here implements a primitive, and the constant
//! time comparison inside the AEAD tag check is std's, not ours.

const std = @import("std");
const testing = std.testing;
const hkdf = @import("hkdf.zig");
const packet_number = @import("packet_number.zig");

const protection = @This();

/// The AEADs this package protects packets with today. TLS_AES_256_GCM_SHA384
/// is not wired up; its parts are in std.
pub const Suite = enum {
    aes_128_gcm,
    chacha20_poly1305,

    /// The size of the traffic secret the suite's KDF produces. Both suites
    /// here are SHA-256, so 32 bytes. A 48-byte secret is
    /// TLS_AES_256_GCM_SHA384, which this package does not implement, and
    /// `deriveKeys` says so by returning an error rather than reading the first
    /// 32 bytes of a longer secret.
    pub fn secretLength(self: Suite) usize {
        _ = self;
        return secret_length;
    }

    /// The AEAD key and header protection key length for the suite (§5.1).
    pub fn keyLength(self: Suite) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .chacha20_poly1305 => 32,
        };
    }
};

pub const tag_length = 16;
pub const sample_length = 16;
pub const mask_length = 5;
pub const nonce_length = 12;
pub const secret_length = hkdf.secret_length;

/// RFC 9001 §5.2: the version 1 Initial salt.
pub const initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

pub const Error = error{
    /// §5.4.2: the packet is too short to hold a complete header protection
    /// sample, and must be discarded.
    TooShort,
    /// The tag did not verify. The packet is discarded, not a connection error.
    AuthenticationFailed,
    /// The caller's output buffer is too small.
    NoSpace,
    /// The packet ended inside its tag or its header.
    Truncated,
    /// A traffic secret whose length does not match the suite: 48 bytes means a
    /// SHA-384 suite, which this package does not implement.
    SecretLengthMismatch,
};

/// The three keys one direction uses (§5.1). `key` and `hp` are used up to
/// `suite.keyLength()` bytes; the rest is zero.
pub const Keys = struct {
    suite: Suite,
    key: [32]u8,
    iv: [nonce_length]u8,
    hp: [32]u8,

    pub fn keyBytes(self: *const Keys) []const u8 {
        return self.key[0..self.suite.keyLength()];
    }

    pub fn headerKeyBytes(self: *const Keys) []const u8 {
        return self.hp[0..self.suite.keyLength()];
    }
};

pub const InitialSecrets = struct {
    client: [secret_length]u8,
    server: [secret_length]u8,
};

/// §5.2: both Initial secrets from the client's Destination Connection ID.
///
/// The ID is the one in the client's first Initial packet, which after a Retry
/// is the one the server chose.
pub fn initialSecrets(destination_connection_id: []const u8) InitialSecrets {
    const initial = hkdf.HkdfSha256.extract(&initial_salt, destination_connection_id);
    return .{
        .client = hkdf.expandLabel(secret_length, initial, "client in", ""),
        .server = hkdf.expandLabel(secret_length, initial, "server in", ""),
    };
}

/// §5.1: the AEAD key, the IV, and the header protection key from a secret.
///
/// The secret is a slice because its length is the suite's, not ours: TLS 1.3
/// hands out 32-byte secrets for SHA-256 suites and 48-byte ones for SHA-384,
/// and a 48-byte secret is refused here instead of being truncated to 32.
pub fn deriveKeys(secret: []const u8, suite: Suite) Error!Keys {
    if (secret.len != suite.secretLength()) return error.SecretLengthMismatch;

    var keys: Keys = .{
        .suite = suite,
        .key = @splat(0),
        .iv = @splat(0),
        .hp = @splat(0),
    };
    const sha256_secret: [secret_length]u8 = secret[0..secret_length].*;
    keys.iv = hkdf.expandLabel(nonce_length, sha256_secret, "quic iv", "");
    switch (suite) {
        .aes_128_gcm => {
            const key = hkdf.expandLabel(16, sha256_secret, "quic key", "");
            const hp = hkdf.expandLabel(16, sha256_secret, "quic hp", "");
            @memcpy(keys.key[0..16], &key);
            @memcpy(keys.hp[0..16], &hp);
        },
        .chacha20_poly1305 => {
            keys.key = hkdf.expandLabel(32, sha256_secret, "quic key", "");
            keys.hp = hkdf.expandLabel(32, sha256_secret, "quic hp", "");
        },
    }
    return keys;
}

/// §5.3: the IV with the packet number exclusive-ored into its low bytes.
pub fn nonce(keys: *const Keys, pn: u64) [nonce_length]u8 {
    var npub = keys.iv;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast(i * 8);
        npub[nonce_length - 1 - i] ^= @truncate(pn >> shift);
    }
    return npub;
}

/// §5.4.1: the five-byte mask a 16-byte ciphertext sample produces.
pub fn mask(keys: *const Keys, sample: [sample_length]u8) [mask_length]u8 {
    var out: [mask_length]u8 = undefined;
    switch (keys.suite) {
        .aes_128_gcm => {
            // §5.4.3: AES-ECB over the sample.
            const ctx = std.crypto.core.aes.Aes128.initEnc(keys.hp[0..16].*);
            var block: [16]u8 = undefined;
            ctx.encrypt(&block, &sample);
            @memcpy(&out, block[0..mask_length]);
        },
        .chacha20_poly1305 => {
            // §5.4.4: raw ChaCha20, counter from the first four bytes of the
            // sample little-endian, nonce from the last twelve, over five
            // zero bytes.
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const npub: [nonce_length]u8 = sample[4..16].*;
            const zeros: [mask_length]u8 = @splat(0);
            std.crypto.stream.chacha.ChaCha20IETF.xor(
                &out,
                &zeros,
                counter,
                keys.hp[0..32].*,
                npub,
            );
        },
    }
    return out;
}

/// §5.4.1, sending side: mask the first byte and the packet number in place.
///
/// The caller has already sealed the payload, because the sample comes from the
/// ciphertext.
pub fn applyHeaderProtection(keys: *const Keys, packet: []u8, pn_offset: u32) Error!void {
    const pn_len: u3 = @truncate((packet[0] & 0x03) + 1);
    const bytes = try sampleMask(keys, packet, pn_offset);
    maskFirstByte(packet, bytes[0]);
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        packet[@as(usize, pn_offset) + i] ^= bytes[1 + i];
    }
}

/// §5.4.1, receiving side: unmask in place and report the packet number length.
///
/// The length comes out of the byte this removes protection from, which is why
/// this direction cannot read it first.
pub fn removeHeaderProtection(keys: *const Keys, packet: []u8, pn_offset: u32) Error!u3 {
    const bytes = try sampleMask(keys, packet, pn_offset);
    maskFirstByte(packet, bytes[0]);
    const pn_len: u3 = @truncate((packet[0] & 0x03) + 1);
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        packet[@as(usize, pn_offset) + i] ^= bytes[1 + i];
    }
    return pn_len;
}

fn maskFirstByte(packet: []u8, byte: u8) void {
    // Long headers protect four bits, short headers five.
    packet[0] ^= if (packet[0] & 0x80 != 0) byte & 0x0f else byte & 0x1f;
}

fn sampleMask(keys: *const Keys, packet: []const u8, pn_offset: u32) Error![mask_length]u8 {
    // §5.4.2: assume the packet number is four bytes and sample past it.
    const start = @as(usize, pn_offset) + 4;
    if (start + sample_length > packet.len) return error.TooShort;
    var sample: [sample_length]u8 = undefined;
    @memcpy(&sample, packet[start..][0..sample_length]);
    return mask(keys, sample);
}

/// §5.3, sending side: seal `plaintext` into `out`, which must hold it plus
/// the tag. `header` is the associated data, through the packet number.
pub fn seal(
    keys: *const Keys,
    pn: u64,
    header: []const u8,
    plaintext: []const u8,
    out: []u8,
) Error!void {
    if (out.len < plaintext.len + tag_length) return error.NoSpace;

    const npub = nonce(keys, pn);
    var tag: [tag_length]u8 = undefined;
    switch (keys.suite) {
        .aes_128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
            out[0..plaintext.len],
            &tag,
            plaintext,
            header,
            npub,
            keys.key[0..16].*,
        ),
        .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            out[0..plaintext.len],
            &tag,
            plaintext,
            header,
            npub,
            keys.key,
        ),
    }
    @memcpy(out[plaintext.len..][0..tag_length], &tag);
}

/// §5.3, receiving side: verify and decrypt. `out` holds the plaintext.
pub fn open(
    keys: *const Keys,
    pn: u64,
    header: []const u8,
    ciphertext: []const u8,
    tag: [tag_length]u8,
    out: []u8,
) Error!void {
    if (out.len < ciphertext.len) return error.NoSpace;
    if (ciphertext.len + tag_length > std.math.maxInt(u32)) return error.NoSpace;

    const npub = nonce(keys, pn);
    switch (keys.suite) {
        .aes_128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
            out[0..ciphertext.len],
            ciphertext,
            tag,
            header,
            npub,
            keys.key[0..16].*,
        ) catch return error.AuthenticationFailed,
        .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            out[0..ciphertext.len],
            ciphertext,
            tag,
            header,
            npub,
            keys.key,
        ) catch return error.AuthenticationFailed,
    }
}

/// A packet the caller has unprotected.
pub const Opened = struct {
    /// The full packet number, recovered from the truncated one (§17.1 of
    /// RFC 9000).
    packet_number: u64,
    /// The header, through the packet number: the AEAD's associated data.
    header_len: u32,
    /// The plaintext, written into the caller's buffer.
    payload: []u8,
};

/// Protect one packet in place: seal the payload and mask the header.
///
/// `packet` already holds the header through the packet number at `pn_offset`,
/// with the Length field counting `pn_len + payload.len + 16`, and has room for
/// all of it. Returns the packet's length.
pub fn sealPacket(
    keys: *const Keys,
    pn: u64,
    pn_offset: u32,
    pn_len: u3,
    payload: []const u8,
    packet: []u8,
) Error!u32 {
    std.debug.assert(pn_len >= 1);
    std.debug.assert(pn_len <= packet_number.max_len);

    const header_len = @as(usize, pn_offset) + pn_len;
    const total = header_len + payload.len + tag_length;
    if (packet.len < total) return error.NoSpace;

    try seal(keys, pn, packet[0..header_len], payload, packet[header_len..total]);
    try applyHeaderProtection(keys, packet[0..total], pn_offset);
    return @intCast(total);
}

/// Remove protection from one packet in place and recover its number.
///
/// `packet` is exactly one packet, not the datagram: the tag sits at its end.
/// `plaintext` receives the payload. `largest_received` is the largest packet
/// number already processed in this space, or null for the first.
pub fn openPacket(
    keys: *const Keys,
    packet: []u8,
    pn_offset: u32,
    largest_received: ?u64,
    plaintext: []u8,
) Error!Opened {
    const pn_len = try removeHeaderProtection(keys, packet, pn_offset);

    const header_len: u32 = pn_offset + pn_len;
    if (packet.len < @as(usize, header_len) + tag_length) return error.Truncated;

    const truncated = readTruncated(packet[pn_offset..][0..pn_len]);
    const pn = packet_number.decode(truncated, @as(u6, pn_len) * 8, largest_received);

    const ciphertext = packet[header_len .. packet.len - tag_length];
    if (plaintext.len < ciphertext.len) return error.NoSpace;
    var tag: [tag_length]u8 = undefined;
    @memcpy(&tag, packet[packet.len - tag_length ..]);

    try open(keys, pn, packet[0..header_len], ciphertext, tag, plaintext[0..ciphertext.len]);

    return .{
        .packet_number = pn,
        .header_len = header_len,
        .payload = plaintext[0..ciphertext.len],
    };
}

fn readTruncated(bytes: []const u8) u64 {
    var value: u64 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

test "RFC 9001 Appendix A.1, the client and server keys from the Initial secret" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = initialSecrets(&dcid);

    const client = try deriveKeys(&secrets.client, .aes_128_gcm);
    try testing.expectEqualSlices(u8, &.{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    }, client.keyBytes());
    try testing.expectEqualSlices(u8, &.{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    }, &client.iv);
    try testing.expectEqualSlices(u8, &.{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    }, client.headerKeyBytes());

    const server = try deriveKeys(&secrets.server, .aes_128_gcm);
    try testing.expectEqualSlices(u8, &.{
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
        0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    }, server.keyBytes());
    try testing.expectEqualSlices(u8, &.{
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
    }, &server.iv);
    try testing.expectEqualSlices(u8, &.{
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
    }, server.headerKeyBytes());
}

test "RFC 9001 Appendix A.2 and A.3, the header protection masks" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = initialSecrets(&dcid);

    const sample = [_]u8{
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
    };
    const client_keys = try deriveKeys(&secrets.client, .aes_128_gcm);
    const client_mask = mask(&client_keys, sample);
    try testing.expectEqualSlices(u8, &.{ 0x43, 0x7b, 0x9a, 0xec, 0x36 }, &client_mask);

    const server_sample = [_]u8{
        0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac,
        0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39, 0x41, 0x00,
    };
    const server_keys = try deriveKeys(&secrets.server, .aes_128_gcm);
    const server_mask = mask(&server_keys, server_sample);
    try testing.expectEqualSlices(u8, &.{ 0x2e, 0xc0, 0xd8, 0x35, 0x6a }, &server_mask);
}

test "RFC 9001 Appendix A.5, the ChaCha20 header protection mask and the nonce" {
    const secret = [_]u8{
        0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
        0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
        0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
        0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
    };
    const keys = try deriveKeys(&secret, .chacha20_poly1305);

    try testing.expectEqualSlices(u8, &.{
        0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1,
        0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c, 0xaa, 0x2e,
        0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a,
        0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8,
    }, keys.keyBytes());

    // A.5: the nonce for packet number 654360564.
    try testing.expectEqualSlices(u8, &.{
        0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x6d, 0x41, 0x7e, 0xb0,
    }, &nonce(&keys, 654360564));

    const sample = [_]u8{
        0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
        0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
    };
    try testing.expectEqualSlices(u8, &.{ 0xae, 0xfe, 0xfe, 0x7d, 0x03 }, &mask(&keys, sample));
}

test "RFC 9001 §5.1, a secret of the wrong length is refused, not truncated" {
    // A SHA-384 suite hands out a 48-byte secret. This package implements the
    // two SHA-256 suites, so the answer is an error that says so, not the first
    // 32 bytes of somebody else's secret.
    const sha384_secret: [48]u8 = @splat(0x5a);
    try testing.expectError(
        error.SecretLengthMismatch,
        deriveKeys(&sha384_secret, .aes_128_gcm),
    );
    try testing.expectError(
        error.SecretLengthMismatch,
        deriveKeys(&sha384_secret, .chacha20_poly1305),
    );

    // And one byte short is the same mistake.
    const short: [31]u8 = @splat(0);
    try testing.expectError(error.SecretLengthMismatch, deriveKeys(&short, .aes_128_gcm));
}

test "RFC 9001 §5.4.2, a packet too short for a sample is discarded" {
    const zero: [secret_length]u8 = @splat(0);
    const keys = try deriveKeys(&zero, .aes_128_gcm);
    // A sample is 16 bytes from four past the packet number, so a packet with
    // fewer than 20 bytes after `pn_offset` has no complete sample.
    var packet = [_]u8{0xc0} ++ @as([18]u8, @splat(0));
    try testing.expectError(error.TooShort, removeHeaderProtection(&keys, &packet, 0));
    try testing.expectError(error.TooShort, removeHeaderProtection(&keys, packet[0..19], 0));
}

test "RFC 9001 §5.3, a flipped tag fails to verify" {
    const seven: [secret_length]u8 = @splat(7);
    const keys = try deriveKeys(&seven, .aes_128_gcm);
    var plaintext = [_]u8{ 1, 2, 3, 4 };
    var sealed: [plaintext.len + tag_length]u8 = undefined;
    const header = [_]u8{ 0xc3, 0, 0, 0, 1 };
    try seal(&keys, 9, &header, &plaintext, &sealed);

    var opened: [plaintext.len]u8 = undefined;
    try open(&keys, 9, &header, sealed[0..plaintext.len], sealed[plaintext.len..][0..tag_length].*, &opened);
    try testing.expectEqualSlices(u8, &plaintext, &opened);

    var tag: [tag_length]u8 = sealed[plaintext.len..][0..tag_length].*;
    tag[0] ^= 0x01;
    try testing.expectError(
        error.AuthenticationFailed,
        open(&keys, 9, &header, sealed[0..plaintext.len], tag, &opened),
    );

    // The header is authenticated too: changing it breaks the same way.
    var wrong_header = header;
    wrong_header[0] = 0xc7;
    try testing.expectError(
        error.AuthenticationFailed,
        open(&keys, 9, &wrong_header, sealed[0..plaintext.len], sealed[plaintext.len..][0..tag_length].*, &opened),
    );
}

test "a sealed packet opens back to what it held" {
    inline for (.{ .aes_128_gcm, .chacha20_poly1305 }) |suite| {
        const secret: [secret_length]u8 = @splat(0x2a);
        const keys = try deriveKeys(&secret, suite);
        const payload = "a payload long enough for the sample";
        const pn: u64 = 42;

        // A long header, 8-byte destination connection ID, 2-byte packet number.
        var packet: [256]u8 = undefined;
        packet[0] = 0xc1;
        packet[1..5].* = .{ 0, 0, 0, 1 };
        packet[5] = 8;
        @memset(packet[6..14], 0xaa);
        packet[14] = 0;
        packet[15] = 0; // token length
        const body_len = 2 + payload.len + tag_length;
        packet[16] = 0x40;
        packet[17] = body_len; // the Length field, two-byte form
        const pn_offset: u32 = 18;
        packet[18] = 0; // packet number 42 in two bytes
        packet[19] = 42;

        const total = try sealPacket(&keys, pn, pn_offset, 2, payload, &packet);
        try testing.expectEqual(@as(u32, @intCast(20 + payload.len + tag_length)), total);

        var plaintext: [128]u8 = undefined;
        const opened = try openPacket(&keys, packet[0..total], pn_offset, null, &plaintext);
        try testing.expectEqual(pn, opened.packet_number);
        try testing.expectEqual(@as(u32, 20), opened.header_len);
        try testing.expectEqualStrings(payload, opened.payload);
    }
}

test "fuzz the unprotect path" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            const dcid_len: u32 = smith.valueRangeAtMost(u32, 0, 20);
            var dcid_buf: [20]u8 = undefined;
            smith.bytes(dcid_buf[0..dcid_len]);
            const secrets = initialSecrets(dcid_buf[0..dcid_len]);

            var keys = try deriveKeys(&secrets.client, .aes_128_gcm);
            // Half the time, use whatever key a peer would have.
            if (smith.value(bool)) keys = try deriveKeys(&secrets.server, .aes_128_gcm);

            var packet_buf: [512]u8 = undefined;
            const len = smith.slice(&packet_buf);
            const pn_offset = smith.valueRangeAtMost(u32, 0, @intCast(len / 2));

            // Arbitrary bytes under a real key either fail to authenticate or
            // open, and a packet that opens reports a number the wire can hold.
            var plaintext: [512]u8 = undefined;
            if (openPacket(&keys, packet_buf[0..len], pn_offset, null, &plaintext)) |opened| {
                try testing.expect(opened.packet_number <= packet_number.max);
                try testing.expect(opened.header_len <= len);
                try testing.expect(opened.payload.len <= len);
            } else |err| {
                try testing.expect(switch (err) {
                    error.TooShort, error.AuthenticationFailed, error.Truncated => true,
                    else => false,
                });
            }
        }
    }.run, .{ .corpus = &.{ "", "\xc0", "\xc0\x00\x00\x00\x01" } });
}
