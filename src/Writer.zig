//! A bounded byte writer: one write position over caller-owned storage.
//!
//! The mirror of `Cursor`. A QUIC packet is built in the caller's datagram
//! buffer, so the writer hands back offsets rather than a stream: a header
//! writer returns where the Length field and the packet number sit, and the
//! caller patches them after the payload exists. Every method either writes all
//! of its bytes or none, so `pos` never lands inside a field.
//!
//! Offsets are `u32` for the reason given in `Cursor`.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const Writer = @This();

/// The caller's storage. Borrowed; the writer owns nothing.
buf: []u8,
/// The offset of the next byte to write.
pos: u32,

pub const Error = error{NoSpace};

/// A writer at the start of `buf`. `buf` must be shorter than 4 GiB.
pub fn init(buf: []u8) Writer {
    assert(buf.len <= std.math.maxInt(u32));
    return .{ .buf = buf, .pos = 0 };
}

/// The bytes written so far.
pub fn written(self: *const Writer) []u8 {
    return self.buf[0..@intCast(self.pos)];
}

/// Space still unused.
pub fn remaining(self: *const Writer) u32 {
    return @intCast(self.buf.len - self.pos);
}

/// Whether at least `count` bytes are left unwritten.
pub fn has(self: *const Writer, count: u32) bool {
    return count <= self.remaining();
}

/// Write all of `bytes`, or nothing when they do not fit.
pub fn put(self: *Writer, bytes: []const u8) Error!void {
    if (!self.has(@intCast(bytes.len))) return error.NoSpace;
    const start: usize = self.pos;
    self.pos += @intCast(bytes.len);
    @memcpy(self.buf[start..@intCast(self.pos)], bytes);
}

/// Write one byte, or nothing when the buffer is full.
pub fn putByte(self: *Writer, byte: u8) Error!void {
    const start: usize = self.pos;
    if (!self.has(1)) return error.NoSpace;
    self.pos += 1;
    self.buf[start] = byte;
}

/// Reserve `count` zeroed bytes and return them to fill. Nothing moves when
/// they do not fit.
pub fn reserve(self: *Writer, count: u32) Error![]u8 {
    if (!self.has(count)) return error.NoSpace;
    const start: usize = self.pos;
    self.pos += count;
    const slice = self.buf[start..@intCast(self.pos)];
    @memset(slice, 0);
    return slice;
}

/// Overwrite `bytes` at an absolute offset. The caller guarantees the range is
/// already reserved, as a packet header's Length field was.
pub fn patch(self: *Writer, offset: u32, bytes: []const u8) void {
    assert(@as(usize, offset) + bytes.len <= self.buf.len);
    @memcpy(self.buf[@intCast(offset)..][0..bytes.len], bytes);
}

test "put, putByte, and the boundary" {
    var buf: [4]u8 = undefined;
    var writer: Writer = .init(&buf);
    try testing.expectEqual(@as(u32, 4), writer.remaining());

    try writer.put("ab");
    try writer.putByte('c');
    try testing.expectEqualStrings("abc", writer.written());
    try testing.expectEqual(@as(u32, 1), writer.remaining());

    try testing.expectError(error.NoSpace, writer.put("de"));
    try testing.expectEqual(@as(u32, 3), writer.pos);

    try writer.put("d");
    try testing.expectEqualStrings("abcd", writer.written());
    try testing.expectEqual(@as(u32, 0), writer.remaining());

    // An empty write needs no room, and a full buffer rejects one more byte.
    try writer.put("");
    try testing.expectError(error.NoSpace, writer.putByte('e'));
    try testing.expectError(error.NoSpace, writer.put("e"));
}

test "reserve zeroes what it hands out, and patch reaches back" {
    var buf: [8]u8 = undefined;
    var writer: Writer = .init(&buf);
    try writer.put("hi");

    const gap = try writer.reserve(3);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, gap);
    writer.patch(2, &.{ 1, 2, 3 });
    try testing.expectEqualStrings("hi\x01\x02\x03", writer.written());

    try testing.expectError(error.NoSpace, writer.reserve(6));
    try testing.expectEqual(@as(u32, 5), writer.pos);
}

test "fuzz writes against a model" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [64]u8 = undefined;
            var writer: Writer = .init(&buf);

            var len: u32 = 0;
            while (smith.value(bool)) {
                const count: u32 = smith.valueRangeAtMost(u32, 0, 8);
                const before = writer.pos;
                if (@as(usize, before) + count <= buf.len) {
                    const slice = try writer.reserve(count);
                    try testing.expectEqual(@as(usize, count), slice.len);
                    try testing.expectEqual(before + count, writer.pos);
                    len += count;
                } else {
                    try testing.expectError(error.NoSpace, writer.reserve(count));
                    try testing.expectEqual(before, writer.pos);
                }
                try testing.expectEqual(@as(u32, @intCast(buf.len)) - len, writer.remaining());
            }
            try testing.expectEqual(@as(usize, len), writer.written().len);
        }
    }.run, .{ .corpus = &.{ "", "short", "a longer one" } });
}
