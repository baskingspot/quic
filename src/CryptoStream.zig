//! Reassembly of one encryption level's CRYPTO stream, RFC 9000 §19.6.
//!
//! A CRYPTO frame carries an offset and a run of bytes. The peer may send them
//! out of order and twice, and the driver underneath takes one contiguous stream
//! per level and never sees an offset. This is the piece in between: it keeps
//! bytes that arrived past a gap in a ring the caller owns, and hands back the
//! runs that are contiguous from the next expected offset.
//!
//! Delivery is two slices rather than one because a run can wrap the ring;
//! feeding them in order is feeding the same bytes, with no copy at the call
//! site. The slices stay valid until the next call to `onData`, which is also
//! when the ring may reuse those bytes.
//!
//! There is no flow control. §19.6 gives CRYPTO frames no window, so the ring is
//! the limit: a frame that would put the end of the stream further past the
//! delivered offset than the ring holds is `error.NoSpace`. The caller sizes the
//! ring for the largest handshake it expects, because a silent truncation here
//! is a handshake that stalls with nothing on the wire to show for it.

const std = @import("std");
const testing = std.testing;
const varint = @import("varint.zig");

const CryptoStream = @This();

pub const Error = error{
    /// The frame ends further past the delivered offset than the ring holds.
    NoSpace,
    /// More disjoint runs are outstanding than the table holds.
    TooManyGaps,
    /// §19.6: the end of the data is past 2^62 - 1, which nothing else in this
    /// protocol can name.
    OutOfRange,
};

/// How many disjoint runs beyond the contiguous end are tracked.
pub const pending_capacity = 8;

const Range = struct { start: u64, end: u64 };

/// Bytes that are contiguous from the delivered offset, in order. Both empty
/// means the stream is waiting on a gap.
pub const Delivery = struct {
    first: []const u8 = "",
    second: []const u8 = "",
};

/// The ring, borrowed from the caller.
ring: []u8 = "",
/// The offset of the next byte the driver has not been given.
delivered: u64 = 0,
/// Runs past `delivered`, sorted by offset and never overlapping. Every byte in
/// them is in the ring at its own offset's position.
pending: [pending_capacity]Range = undefined,
pending_len: u8 = 0,

pub fn init(ring: []u8) CryptoStream {
    return .{ .ring = ring };
}

/// The next offset the driver is owed: the length of the contiguous prefix.
pub fn received(self: *const CryptoStream) u64 {
    return self.delivered;
}

/// Take one CRYPTO frame's offset and bytes.
///
/// Everything that became contiguous goes back in the result and is marked
/// delivered; the caller hands it to the driver before calling this again. A
/// frame that adds nothing — a duplicate, or a range already delivered — returns
/// an empty delivery, which is ordinary: CRYPTO data is retransmitted.
pub fn onData(self: *CryptoStream, offset: u64, data: []const u8) Error!Delivery {
    if (data.len == 0) return .{};
    if (self.ring.len == 0) return error.NoSpace;

    const end = offset + data.len;
    if (end > varint.max) return error.OutOfRange;
    if (end <= self.delivered) return .{};
    if (end - self.delivered > self.ring.len) return error.NoSpace;

    // Everything below the delivered offset is already in the driver's hands.
    const start = @max(offset, self.delivered);
    self.store(start, data[@intCast(start - offset)..]);

    var extent = self.delivered;
    if (start == self.delivered) {
        extent = end;
    } else {
        try self.insert(start, end);
    }

    // A contiguous run can uncover a stored one behind it.
    while (self.pending_len > 0 and self.pending[0].start <= extent) {
        extent = @max(extent, self.pending[0].end);
        self.removeFirst();
    }

    if (extent == self.delivered) return .{};
    const delivery = self.slices(self.delivered, extent);
    self.delivered = extent;
    return delivery;
}

fn store(self: *CryptoStream, offset: u64, data: []const u8) void {
    const capacity: u64 = @intCast(self.ring.len);
    const start: usize = @intCast(offset % capacity);
    const first = @min(data.len, self.ring.len - start);
    @memcpy(self.ring[start..][0..first], data[0..first]);
    @memcpy(self.ring[0 .. data.len - first], data[first..]);
}

/// The bytes in `[start, end)` as one or two slices of the ring.
fn slices(self: *const CryptoStream, start: u64, end: u64) Delivery {
    std.debug.assert(start < end);
    const capacity: u64 = @intCast(self.ring.len);
    const begin: usize = @intCast(start % capacity);
    const length: usize = @intCast(end - start);
    const first = @min(length, self.ring.len - begin);
    return .{
        .first = self.ring[begin..][0..first],
        .second = self.ring[0 .. length - first],
    };
}

fn insert(self: *CryptoStream, start: u64, end: u64) Error!void {
    var merged_start = start;
    var merged_end = end;
    var out: [pending_capacity]Range = undefined;
    var kept: usize = 0;
    var placed = false;

    for (self.pending[0..self.pending_len]) |range| {
        if (range.end < merged_start) {
            out[kept] = range;
            kept += 1;
            continue;
        }
        if (range.start > merged_end) {
            if (!placed) {
                if (kept == out.len) return error.TooManyGaps;
                out[kept] = .{ .start = merged_start, .end = merged_end };
                kept += 1;
                placed = true;
            }
            out[kept] = range;
            kept += 1;
            continue;
        }
        // Overlapping or adjacent: one run.
        merged_start = @min(merged_start, range.start);
        merged_end = @max(merged_end, range.end);
    }

    if (!placed) {
        if (kept == out.len) return error.TooManyGaps;
        out[kept] = .{ .start = merged_start, .end = merged_end };
        kept += 1;
    }

    self.pending = out;
    self.pending_len = @intCast(kept);
}

fn removeFirst(self: *CryptoStream) void {
    std.debug.assert(self.pending_len > 0);
    const left = self.pending_len - 1;
    _ = @memmove(self.pending[0..left], self.pending[1..][0..left]);
    self.pending_len = left;
}

test "RFC 9000 §19.6, in-order frames are delivered as they arrive" {
    var ring: [64]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    const first = try stream.onData(0, "hello ");
    try testing.expectEqualStrings("hello ", first.first);
    try testing.expectEqual(@as(usize, 0), first.second.len);
    try testing.expectEqual(@as(u64, 6), stream.received());

    const second = try stream.onData(6, "world");
    try testing.expectEqualStrings("world", second.first);
    try testing.expectEqual(@as(u64, 11), stream.received());
}

test "RFC 9000 §19.6, a gap holds the bytes until the frame before it arrives" {
    var ring: [64]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    // Arrives second, processed first.
    const early = try stream.onData(5, "world");
    try testing.expectEqual(@as(usize, 0), early.first.len);
    try testing.expectEqual(@as(u64, 0), stream.received());

    const filling = try stream.onData(0, "hello");
    // The gap is closed, so the stored run comes back with it as one slice:
    // delivery is by contiguous extent, not by frame.
    try testing.expectEqualStrings("helloworld", filling.first);
    try testing.expectEqual(@as(usize, 0), filling.second.len);
    try testing.expectEqual(@as(u64, 10), stream.received());
}

test "RFC 9000 §19.6, a duplicate adds nothing and an overlap merges" {
    var ring: [64]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    _ = try stream.onData(0, "abcdef");
    // A retransmission of the same range.
    const again = try stream.onData(0, "abcdef");
    try testing.expectEqual(@as(usize, 0), again.first.len);
    try testing.expectEqual(@as(usize, 0), again.second.len);
    try testing.expectEqual(@as(u64, 6), stream.received());

    // Two overlapping out-of-order runs covering [6, 12) between them.
    _ = try stream.onData(9, "ghi");
    const merged = try stream.onData(6, "defghi");
    try testing.expectEqualStrings("defghi", merged.first);
    try testing.expectEqual(@as(usize, 0), merged.second.len);
    try testing.expectEqual(@as(u64, 12), stream.received());
}

test "RFC 9000 §19.6, a delivery that wraps the ring is two slices and no copy" {
    var ring: [8]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    _ = try stream.onData(0, "123456");
    try testing.expectEqual(@as(u64, 6), stream.received());

    // "7890" lands at offsets 6..10, so it wraps at 8.
    const wrapped = try stream.onData(6, "7890");
    try testing.expectEqualStrings("78", wrapped.first);
    try testing.expectEqualStrings("90", wrapped.second);
    try testing.expectEqual(@as(u64, 10), stream.received());
}

test "RFC 9000 §19.6, a span wider than the ring is refused rather than truncated" {
    var ring: [8]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    try testing.expectError(error.NoSpace, stream.onData(0, "123456789"));
    // A far-future offset is the same refusal, and the stream did not move.
    try testing.expectError(error.NoSpace, stream.onData(1_000_000, "x"));
    try testing.expectEqual(@as(u64, 0), stream.received());

    // No ring at all is the same: the caller has to give it storage.
    var none: CryptoStream = .init("");
    try testing.expectError(error.NoSpace, none.onData(0, "x"));
}

test "RFC 9000 §19.6, the end of the data must fit a 62-bit offset" {
    var ring: [64]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    // One byte short of the limit is inside the ring's span question, not the
    // protocol's: the ring is what refuses it.
    try testing.expectError(error.OutOfRange, stream.onData(varint.max - 1, "xx"));
    try testing.expectError(error.OutOfRange, stream.onData(varint.max, "x"));
    try testing.expectEqual(@as(u64, 0), stream.received());
}

test "RFC 9000 §19.6, more gaps than the table holds is an error, not a drop" {
    var ring: [256]u8 = undefined;
    var stream: CryptoStream = .init(&ring);

    var index: u64 = 0;
    while (index < pending_capacity) : (index += 1) {
        _ = try stream.onData(2 + index * 2, "x");
    }
    try testing.expectError(error.TooManyGaps, stream.onData(100, "x"));
    // Filling the first gap drains one and makes room again.
    const delivery = try stream.onData(0, "ab");
    try testing.expectEqualStrings("abx", delivery.first);
    try testing.expectEqual(@as(u64, 3), stream.received());
    _ = try stream.onData(100, "y");
}
