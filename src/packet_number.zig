//! Packet number truncation and recovery, RFC 9000 §17.1 and Appendix A.
//!
//! A packet number is 62 bits, but the header carries 1 to 4 bytes of it. The
//! sender picks a width wide enough for the peer to recover the number from the
//! largest one it has received, and the receiver reverses that with the same
//! information. Both directions live here: `encodeLength` and `write` on the
//! sending side, `decode` on the receiving side.
//!
//! This is arithmetic over the packet number, not the packet number space.
//! Which number comes next, and which one was acknowledged, is the caller's.

const std = @import("std");
const testing = std.testing;
const Writer = @import("Writer.zig");

const packet_number = @This();

/// The largest packet number, 2^62 - 1 (§12.3).
pub const max: u64 = (1 << 62) - 1;

/// The widest truncation the wire allows: four bytes.
pub const max_len: u3 = 4;

/// How many bytes of `pn` the header must carry so the peer recovers it.
///
/// `largest_acked` is `null` before any packet in this space is acknowledged,
/// where §17.1 requires the full number. `limit` caps the width, normally
/// `max_len`; a width past 8 bytes recovers nothing the wire can carry.
///
/// §17.1 asks for one bit more than the base-2 logarithm of the unacknowledged
/// range, which is the bit length of `pn - largest_acked`.
pub fn encodeLength(pn: u64, largest_acked: ?u64, limit: u3) u3 {
    std.debug.assert(pn <= max);
    std.debug.assert(limit >= 1);
    std.debug.assert(limit <= max_len);

    const unacked = if (largest_acked) |acked| blk: {
        std.debug.assert(pn > acked);
        break :blk pn - acked;
    } else pn + 1;

    // Bit length: log2(unacked) + 1, which is at least one bit for any number.
    const bits: u32 = 64 - @clz(unacked);
    const bytes: u32 = @min((bits + 7) / 8, limit);
    return @intCast(bytes);
}

/// Write the low `len` bytes of `pn`, big-endian.
pub fn write(writer: *Writer, pn: u64, len: u3) Writer.Error!void {
    std.debug.assert(pn <= max);
    std.debug.assert(len >= 1);
    std.debug.assert(len <= max_len);

    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, @truncate(pn), .big);
    try writer.put(buf[4 - len ..]);
}

/// Recover the full packet number from the truncated one.
///
/// `bits` is the width of the truncated field: 8, 16, 24, or 32. `largest` is
/// the largest packet number received in this space, which §17.1 calls the
/// basis for the search; `null` means none was received and the truncated
/// value is the number itself, because the sender must have sent it whole.
pub fn decode(truncated: u64, bits: u6, largest: ?u64) u64 {
    std.debug.assert(bits >= 8);
    std.debug.assert(bits <= 32);
    std.debug.assert(bits % 8 == 0);

    const largest_received = largest orelse return truncated;
    const window: u64 = @as(u64, 1) << @intCast(bits);
    std.debug.assert(truncated < window);

    const expected = largest_received + 1;
    const half = window / 2;
    const mask = window - 1;

    const candidate = (expected & ~mask) | truncated;
    // Appendix A.3, with the comparisons written so a hostile header cannot
    // underflow or overflow them: the truncated value comes off the wire and
    // the peer supplies the rest.
    if (candidate + half <= expected and candidate < (1 << 62) - window) {
        return candidate + window;
    }
    if (candidate > expected + half and candidate >= window) {
        return candidate - window;
    }
    return candidate;
}

test "RFC 9000 Appendix A.2, the sample encoding widths" {
    // The worked example: full_pn 0xac5c02 with largest_acked 0xabe8b3.
    try testing.expectEqual(@as(u3, 2), encodeLength(0xac5c02, 0xabe8b3, max_len));
    // Nothing acknowledged in the space: the number's own width, not four.
    try testing.expectEqual(@as(u3, 3), encodeLength(0xac5c02, null, max_len));
    try testing.expectEqual(@as(u3, 1), encodeLength(0, null, max_len));
    try testing.expectEqual(@as(u3, 4), encodeLength(max, null, max_len));
}

test "RFC 9000 §17.1, the width grows with the unacknowledged range" {
    try testing.expectEqual(@as(u3, 1), encodeLength(1, 0, max_len));
    try testing.expectEqual(@as(u3, 1), encodeLength(127, 0, max_len));
    try testing.expectEqual(@as(u3, 1), encodeLength(128, 0, max_len));
    try testing.expectEqual(@as(u3, 2), encodeLength(256, 0, max_len));
    try testing.expectEqual(@as(u3, 2), encodeLength(0x7fff, 0, max_len));
    try testing.expectEqual(@as(u3, 2), encodeLength(0x8000, 0, max_len));
    try testing.expectEqual(@as(u3, 3), encodeLength(0x800000, 0, max_len));
    try testing.expectEqual(@as(u3, 4), encodeLength(0x1000000, 0, max_len));
    try testing.expectEqual(@as(u3, 4), encodeLength(max, 0, max_len));
    // The limit wins when the range would ask for more.
    try testing.expectEqual(@as(u3, 1), encodeLength(0x8000, 0, 1));
    try testing.expectEqual(@as(u3, 2), encodeLength(max, 0, 2));
}

test "RFC 9000 Appendix A.3, the sample decoding table" {
    // largest_pn 0xa82f30ea, truncated 0x9b32 in 16 bits.
    try testing.expectEqual(@as(u64, 0xa82f9b32), decode(0x9b32, 16, 0xa82f30ea));
}

test "RFC 9000 §17.1, decode picks the number nearest the expected one" {
    // With nothing received, the truncated value is the number.
    try testing.expectEqual(@as(u64, 7), decode(7, 8, null));

    // expected = 256, window = 256, so the search spans 128..383.
    try testing.expectEqual(@as(u64, 260), decode(4, 8, 255));
    try testing.expectEqual(@as(u64, 300), decode(44, 8, 255));

    // expected = 1001: the candidate is 0x320 = 800, which trails by more than
    // half a window, so it is lifted to 1056.
    try testing.expectEqual(@as(u64, 1056), decode(32, 8, 1000));

    // One window late: 511 trails nothing, so it is dropped to 255.
    try testing.expectEqual(@as(u64, 255), decode(255, 8, 256));
}

test "RFC 9000 §17.1, decode never leaves the 62-bit range" {
    // Near the ceiling, a candidate is not lifted past 2^62 - 1.
    try testing.expect(decode(0xff, 8, max - 1) <= max);

    var bits: u6 = 8;
    while (bits <= 32) : (bits += 8) {
        const window: u64 = @as(u64, 1) << @intCast(bits);
        try testing.expect(decode(0, bits, max - 1) <= max);
        try testing.expect(decode(window - 1, bits, 0) <= max);
    }
}

test "write emits only the low bytes, big-endian" {
    var buf: [4]u8 = undefined;
    var writer: Writer = .init(&buf);
    try write(&writer, 0xac5c02, 2);
    try testing.expectEqualSlices(u8, &.{ 0x5c, 0x02 }, writer.written());

    var full: [4]u8 = undefined;
    var full_writer: Writer = .init(&full);
    try write(&full_writer, 0xac5c02, 4);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xac, 0x5c, 0x02 }, full_writer.written());

    var one: [1]u8 = undefined;
    var one_writer: Writer = .init(&one);
    try write(&one_writer, max, 1);
    try testing.expectEqualSlices(u8, &.{0xff}, one_writer.written());
}

test "fuzz the width and the recovery" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            const len: u3 = smith.valueRangeAtMost(u3, 1, max_len);
            const bits: u6 = @as(u6, len) * 8;
            const window: u64 = @as(u64, 1) << @intCast(bits);
            const pn: u64 = smith.valueRangeAtMost(u64, 0, max);
            const truncated = pn & (window - 1);

            // §17.1: a peer that has seen anything within half a window below
            // the number recovers it exactly.
            const delta: u64 = smith.valueRangeAtMost(u64, 0, @min(pn, window / 2 - 1));
            if (pn > delta) {
                const largest = pn - delta - 1;
                try testing.expectEqual(pn, decode(truncated, bits, largest));
            }

            // Whatever the peer has seen, the result is a packet number.
            const any_largest: u64 = smith.valueRangeAtMost(u64, 0, max);
            try testing.expect(decode(truncated, bits, any_largest) <= max);

            var buf: [4]u8 = undefined;
            var writer: Writer = .init(&buf);
            try write(&writer, pn, len);
            try testing.expectEqual(@as(u32, len), writer.pos);
            try testing.expectEqual(truncated, readLow(writer.written()));
        }

        fn readLow(bytes: []const u8) u64 {
            var value: u64 = 0;
            for (bytes) |byte| value = (value << 8) | byte;
            return value;
        }
    }.run, .{ .corpus = &.{ "", "a", "abcdef" } });
}
