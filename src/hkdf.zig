//! HKDF-Expand-Label, the TLS 1.3 derivation QUIC builds every key on.
//!
//! RFC 8446 §7.1 wraps HKDF-Expand with a structure that carries the output
//! length, a label, and a context, and prefixes every label with `tls13 `. QUIC
//! uses it with the labels `quic key`, `quic iv`, `quic hp`, and `quic ku`
//! (RFC 9001 §5.1 and §6), which is what keeps a packet protection key from
//! being the same bytes as anything TLS derived from the same secret.
//!
//! The hash is SHA-256. That covers TLS_AES_128_GCM_SHA256 and
//! TLS_CHACHA20_POLY1305_SHA256, which are the two suites this package
//! implements. TLS_AES_256_GCM_SHA384 would need a SHA-384 instantiation and is
//! not here.

const std = @import("std");
const testing = std.testing;

const hkdf = @This();

pub const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// A traffic secret for SHA-256 is 32 bytes.
pub const secret_length = 32;

/// The prefix TLS 1.3 puts in front of every label (RFC 8446 §7.1).
pub const label_prefix = "tls13 ";

/// The largest label the structure can carry: the length byte minus the prefix.
pub const max_label_length = 249;

/// The buffer `encodeLabel` needs for the largest label and context.
pub const max_encoded_length = 2 + 1 + label_prefix.len + max_label_length + 1 + 255;

/// HKDF-Expand-Label, with a zero-length context as every QUIC use requires.
///
/// `len` is the output length in bytes, which `HkdfLabel.length` carries.
pub fn expandLabel(
    comptime len: usize,
    secret: [secret_length]u8,
    label: []const u8,
    context: []const u8,
) [len]u8 {
    std.debug.assert(len <= std.math.maxInt(u16));

    var info: [max_encoded_length]u8 = undefined;
    const encoded = encodeLabel(&info, @intCast(len), label, context);

    var out: [len]u8 = undefined;
    HkdfSha256.expand(&out, encoded, secret);
    return out;
}

/// The `HkdfLabel` structure itself, which RFC 9001 Appendix A prints for each
/// of the QUIC labels. Exposed so the test can pin those bytes.
pub fn encodeLabel(out: []u8, length: u16, label: []const u8, context: []const u8) []const u8 {
    std.debug.assert(label.len <= max_label_length);
    std.debug.assert(context.len <= 255);

    var pos: usize = 0;
    std.mem.writeInt(u16, out[pos..][0..2], length, .big);
    pos += 2;

    const full_label_length = label_prefix.len + label.len;
    out[pos] = @intCast(full_label_length);
    pos += 1;
    @memcpy(out[pos..][0..label_prefix.len], label_prefix);
    pos += label_prefix.len;
    @memcpy(out[pos..][0..label.len], label);
    pos += label.len;

    out[pos] = @intCast(context.len);
    pos += 1;
    @memcpy(out[pos..][0..context.len], context);
    pos += context.len;

    return out[0..pos];
}

test "RFC 9001 Appendix A.1, the HkdfLabel bytes for every QUIC label" {
    // A.1 prints the structure for each label, so this pins the encoding and
    // not just its output.
    const cases = [_]struct { label: []const u8, length: u16, expected: []const u8 }{
        .{ .label = "client in", .length = 32, .expected = &.{
            0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x6c,
            0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00,
        } },
        .{ .label = "server in", .length = 32, .expected = &.{
            0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73, 0x65,
            0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x00,
        } },
        .{ .label = "quic key", .length = 16, .expected = &.{
            0x00, 0x10, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75,
            0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00,
        } },
        .{ .label = "quic iv", .length = 12, .expected = &.{
            0x00, 0x0c, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75,
            0x69, 0x63, 0x20, 0x69, 0x76, 0x00,
        } },
        .{ .label = "quic hp", .length = 16, .expected = &.{
            0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75,
            0x69, 0x63, 0x20, 0x68, 0x70, 0x00,
        } },
    };

    for (cases) |case| {
        var out: [hkdf.max_encoded_length]u8 = undefined;
        const got = encodeLabel(&out, case.length, case.label, "");
        try testing.expectEqualSlices(u8, case.expected, got);
    }
}

test "RFC 9001 Appendix A.1, the initial secret and the two Initial secrets" {
    // The salt, the connection ID, and the three secrets A.1 prints.
    const salt = [_]u8{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a,
    };
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    const initial = HkdfSha256.extract(&salt, &dcid);
    try testing.expectEqualSlices(u8, &.{
        0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
        0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
        0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
        0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
    }, &initial);

    const client = expandLabel(secret_length, initial, "client in", "");
    try testing.expectEqualSlices(u8, &.{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
        0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
        0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    }, &client);

    const server = expandLabel(secret_length, initial, "server in", "");
    try testing.expectEqualSlices(u8, &.{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
        0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
        0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    }, &server);
}

test "RFC 9001 Appendix A.5, the application key, IV, header key, and next secret" {
    const secret = [_]u8{
        0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
        0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
        0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
        0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
    };

    try testing.expectEqualSlices(u8, &.{
        0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1,
        0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c, 0xaa, 0x2e,
        0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a,
        0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8,
    }, &expandLabel(32, secret, "quic key", ""));

    try testing.expectEqualSlices(u8, &.{
        0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
    }, &expandLabel(12, secret, "quic iv", ""));

    try testing.expectEqualSlices(u8, &.{
        0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
        0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
        0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
        0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
    }, &expandLabel(32, secret, "quic hp", ""));

    // RFC 9001 §6: the next secret is derived with the "quic ku" label.
    try testing.expectEqualSlices(u8, &.{
        0x12, 0x23, 0x50, 0x47, 0x55, 0x03, 0x6d, 0x55,
        0x63, 0x42, 0xee, 0x93, 0x61, 0xd2, 0x53, 0x42,
        0x1a, 0x82, 0x6c, 0x9e, 0xcd, 0xf3, 0xc7, 0x14,
        0x86, 0x84, 0xb3, 0x6b, 0x71, 0x48, 0x81, 0xf9,
    }, &expandLabel(32, secret, "quic ku", ""));
}

test "fuzz the label encoding against its own length arithmetic" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var label_buf: [max_label_length]u8 = undefined;
            var context_buf: [255]u8 = undefined;

            const label_len: u32 = smith.valueRangeAtMost(u32, 0, label_buf.len);
            const context_len: u32 = smith.valueRangeAtMost(u32, 0, context_buf.len);
            const label = label_buf[0..label_len];
            const context = context_buf[0..context_len];

            var out: [max_encoded_length]u8 = undefined;
            const encoded = encodeLabel(&out, 32, label, context);

            // The structure is exactly the fields it claims, nothing more.
            try testing.expect(got(encoded, label_len, context_len));
        }

        fn got(encoded: []const u8, label_len: u32, context_len: u32) bool {
            const expected = 2 + 1 + label_prefix.len + label_len + 1 + context_len;
            if (encoded.len != expected) return false;
            if (encoded[2] != label_prefix.len + label_len) return false;
            if (encoded[3 + label_prefix.len + label_len] != context_len) return false;
            return true;
        }
    }.run, .{ .corpus = &.{ "", "a", "quic key" } });
}
