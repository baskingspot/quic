//! QUIC variable-length integers, RFC 9000 §16.
//!
//! The two most significant bits of the first byte give the width: 1, 2, 4, or
//! 8 bytes, carrying 6, 14, 30, or 62 bits. The value is the remaining bits in
//! network byte order.
//!
//! Non-minimal encodings are legal everywhere except one field. §16: "Values do
//! not need to be encoded on the minimum number of bytes necessary, with the
//! sole exception of the Frame Type field". `decode` accepts every width, for
//! every field that can carry a wider encoding than it needs. `decodeMinimal`
//! rejects the wider encoding, and the frame codec calls it for the frame type.
//!
//! `write` always emits the shortest encoding, so a value written here round
//! trips through `decode` at the same width.

const std = @import("std");
const testing = std.testing;
const Cursor = @import("Cursor.zig");
const Writer = @import("Writer.zig");

const varint = @This();

/// The largest value the encoding can carry: 2^62 - 1.
pub const max: u64 = (1 << 62) - 1;

pub const DecodeError = error{
    /// The buffer ended inside the integer. Nothing moved.
    Truncated,
    /// The integer does not use the shortest encoding for its value (§16).
    NonMinimal,
};

pub const EncodeError = error{
    /// The writer has no room for the encoding.
    NoSpace,
    /// `value` is larger than `max`, so no valid encoding exists.
    Overflow,
};

/// The width of the encoding of `value`, in bytes: 1, 2, 4, or 8.
///
/// `value` must not exceed `max`, which `write` checks before it calls this.
pub fn size(value: u64) usize {
    std.debug.assert(value <= max);
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return 8;
}

/// Read one integer of any width. On `error.Truncated` the cursor does not move.
pub fn decode(cursor: *Cursor) DecodeError!u64 {
    const rest = cursor.rest();
    if (rest.len == 0) return error.Truncated;
    const width = widthOfPrefix(rest[0]);
    if (rest.len < width) return error.Truncated;
    _ = cursor.skip(@intCast(width));
    return assemble(rest[0..width]);
}

/// Read one integer and reject a width wider than its value needs.
///
/// RFC 9000 §12.4 requires the Frame Type field to use the shortest encoding,
/// and §16 names that field as the sole exception to the rule. On
/// `error.NonMinimal` the cursor does not move.
pub fn decodeMinimal(cursor: *Cursor) DecodeError!u64 {
    const rest = cursor.rest();
    if (rest.len == 0) return error.Truncated;
    const width = widthOfPrefix(rest[0]);
    if (rest.len < width) return error.Truncated;
    const value = assemble(rest[0..width]);
    if (width != size(value)) return error.NonMinimal;
    _ = cursor.skip(@intCast(width));
    return value;
}

/// Write `value` in the shortest encoding that carries it.
pub fn write(writer: *Writer, value: u64) EncodeError!void {
    if (value > max) return error.Overflow;
    const width = size(value);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    const start = buf.len - width;
    buf[start] |= switch (width) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        else => 0xc0,
    };
    try writer.put(buf[start..]);
}

/// The width in bytes that the first byte's two-bit prefix announces.
fn widthOfPrefix(first: u8) usize {
    return @as(usize, 1) << @intCast(first >> 6);
}

/// The integer carried by a slice whose width matches the prefix.
fn assemble(bytes: []const u8) u64 {
    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..]) |byte| value = (value << 8) | byte;
    return value;
}

fn expectDecode(bytes: []const u8, expected: u64) !void {
    var cursor: Cursor = .init(bytes);
    try testing.expectEqual(expected, try decode(&cursor));
    try testing.expectEqual(bytes.len, cursor.pos);
}

fn expectEncoded(value: u64, expected: []const u8) !void {
    var buf: [8]u8 = undefined;
    var writer: Writer = .init(&buf);
    try write(&writer, value);
    try testing.expectEqualSlices(u8, expected, writer.written());
    try expectDecode(expected, value);
}

test "RFC 9000 §16 Table 4, the four widths and their boundaries" {
    try expectEncoded(0, &.{0x00});
    try expectEncoded(37, &.{0x25});
    try expectEncoded(63, &.{0x3f});

    try expectEncoded(64, &.{ 0x40, 0x40 });
    try expectEncoded(15293, &.{ 0x7b, 0xbd });
    try expectEncoded(16383, &.{ 0x7f, 0xff });

    try expectEncoded(16384, &.{ 0x80, 0x00, 0x40, 0x00 });
    try expectEncoded(494878333, &.{ 0x9d, 0x7f, 0x3e, 0x7d });
    try expectEncoded(1073741823, &.{ 0xbf, 0xff, 0xff, 0xff });

    try expectEncoded(1073741824, &.{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 });
    try expectEncoded(151288809941952652, &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
    try expectEncoded(varint.max, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
}

test "RFC 9000 Appendix A.1, the sample encodings decode" {
    try expectDecode(&.{0x25}, 37);
    try expectDecode(&.{ 0x7b, 0xbd }, 15293);
    try expectDecode(&.{ 0x9d, 0x7f, 0x3e, 0x7d }, 494878333);
    try expectDecode(&.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, 151288809941952652);
}

test "RFC 9000 §16, a value may use a wider encoding than it needs" {
    try expectDecode(&.{ 0x40, 0x25 }, 37);
    try expectDecode(&.{ 0x80, 0x00, 0x00, 0x25 }, 37);
    try expectDecode(&.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25 }, 37);
    try expectDecode(&.{ 0x7f, 0xff }, 16383);
}

test "RFC 9000 §12.4, the frame type field must use the shortest encoding" {
    var cursor: Cursor = .init(&.{0x25});
    try testing.expectEqual(@as(u64, 0x25), try decodeMinimal(&cursor));

    const padded = [_][]const u8{
        &.{ 0x40, 0x25 },
        &.{ 0x80, 0x00, 0x00, 0x25 },
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25 },
    };
    for (padded) |bytes| {
        var padded_cursor: Cursor = .init(bytes);
        try testing.expectError(error.NonMinimal, decodeMinimal(&padded_cursor));
        try testing.expectEqual(@as(u32, 0), padded_cursor.pos);
    }
}

test "RFC 9000 §16, a truncated integer is an error and moves nothing" {
    const truncated = [_][]const u8{
        &.{},
        &.{0x40},
        &.{0x80},
        &.{ 0x80, 0x00 },
        &.{ 0x80, 0x00, 0x00 },
        &.{0xc0},
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    for (truncated) |bytes| {
        var cursor: Cursor = .init(bytes);
        try testing.expectError(error.Truncated, decode(&cursor));
        try testing.expectEqual(@as(u32, 0), cursor.pos);
    }
}

test "RFC 9000 §16, a value above the 62-bit range has no encoding" {
    var buf: [8]u8 = undefined;
    var writer: Writer = .init(&buf);
    try testing.expectError(error.Overflow, write(&writer, varint.max + 1));
    try testing.expectError(error.Overflow, write(&writer, std.math.maxInt(u64)));
    try testing.expectEqual(@as(u32, 0), writer.pos);
}

test "a value that does not fit leaves the writer untouched" {
    var buf: [1]u8 = undefined;
    var writer: Writer = .init(&buf);
    try testing.expectError(error.NoSpace, write(&writer, 16384));
    try testing.expectEqual(@as(u32, 0), writer.pos);
    try write(&writer, 63);
    try testing.expectEqualSlices(u8, &.{0x3f}, writer.written());
}

test "decode reads only the integer, leaving the rest for the caller" {
    var cursor: Cursor = .init(&.{ 0x7b, 0xbd, 0xaa, 0xbb });
    try testing.expectEqual(@as(u64, 15293), try decode(&cursor));
    try testing.expectEqual(@as(u32, 2), cursor.pos);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, cursor.rest());
}

test "fuzz decode against a bounded model" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [16]u8 = undefined;
            const input = buf[0..smith.slice(&buf)];

            var cursor: Cursor = .init(input);
            const value = decode(&cursor) catch |err| {
                try testing.expect(err == error.Truncated);
                try testing.expectEqual(@as(u32, 0), cursor.pos);
                return;
            };
            try testing.expect(value <= varint.max);

            // A successful decode consumed exactly the width the prefix
            // announced, which is at least the width the value needs.
            const announced: u32 = @intCast(widthOfPrefix(input[0]));
            try testing.expectEqual(announced, cursor.pos);
            const width: u32 = @intCast(size(value));
            try testing.expect(cursor.pos >= width);

            var out: [8]u8 = undefined;
            var writer: Writer = .init(&out);
            try write(&writer, value);
            var round: Cursor = .init(writer.written());
            try testing.expectEqual(value, try decode(&round));
            try testing.expectEqual(width, @as(u32, @intCast(writer.pos)));
        }
    }.run, .{
        .corpus = &.{ "", "\x25", "\x7b\xbd", "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", "\xff\xff\xff\xff\xff\xff\xff\xff" },
    });
}
