//! A fixed table of open streams, RFC 9000 §2.1.
//!
//! Stream IDs are sparse and monotonic: client bidirectional streams are 0, 4,
//! 8, server unidirectional are 3, 7, 11, and so on. Any caller holding more
//! than one stream needs the same id-to-slot lookup, so it lives here once.
//!
//! The table owns the slots and nothing else. The streams themselves, and every
//! buffer inside them, are the caller's, exactly as they would be without a
//! table. It never evicts: a full table is an error the caller sees, because
//! silently dropping a stream's state is the one failure that cannot be
//! recovered from. When the caller is done with a stream it says so and the
//! slot is free.

const std = @import("std");
const testing = std.testing;
const SendStream = @import("SendStream.zig");
const ReceiveStream = @import("ReceiveStream.zig");

const StreamTable = @This();

pub const Error = error{
    /// Every slot is taken. `capacity` is the limit; the table does not evict.
    TableFull,
    /// A stream with this ID is already open.
    AlreadyOpen,
    /// No stream with this ID is open.
    NotOpen,
};

/// One stream: a sending half, a receiving half, or both.
pub const Slot = struct {
    id: u64 = 0,
    send: ?*SendStream = null,
    recv: ?*ReceiveStream = null,
};

slots: []Slot,
len: usize = 0,

/// The table over the caller's storage. `storage.len` is the capacity and never
/// changes.
pub fn init(storage: []Slot) StreamTable {
    return .{ .slots = storage };
}

pub fn capacity(self: *const StreamTable) usize {
    return self.slots.len;
}

pub fn count(self: *const StreamTable) usize {
    return self.len;
}

/// The slot for `id`, or null. Slots are kept sorted by ID, so this is a binary
/// search: the IDs are sparse, but they arrive in order per kind and the table
/// is small by construction.
pub fn get(self: *StreamTable, id: u64) ?*Slot {
    var low: usize = 0;
    var high: usize = self.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (self.slots[mid].id < id) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (low < self.len and self.slots[low].id == id) return &self.slots[low];
    return null;
}

/// Open a slot for `id`, with either or both halves. The halves are the
/// caller's; the table only points at them.
pub fn open(
    self: *StreamTable,
    id: u64,
    send: ?*SendStream,
    recv: ?*ReceiveStream,
) Error!*Slot {
    if (self.get(id) != null) return error.AlreadyOpen;
    if (self.len == self.slots.len) return error.TableFull;

    var index: usize = 0;
    while (index < self.len and self.slots[index].id < id) : (index += 1) {}
    var move = self.len;
    while (move > index) : (move -= 1) self.slots[move] = self.slots[move - 1];
    self.slots[index] = .{ .id = id, .send = send, .recv = recv };
    self.len += 1;
    return &self.slots[index];
}

/// Free the slot for `id`. The caller does this when it is finished; the table
/// never decides that on its own.
pub fn close(self: *StreamTable, id: u64) Error!void {
    const slot = self.get(id) orelse return error.NotOpen;
    const index: usize = @intCast((@intFromPtr(slot) - @intFromPtr(self.slots.ptr)) / @sizeOf(Slot));
    var move = index;
    while (move + 1 < self.len) : (move += 1) self.slots[move] = self.slots[move + 1];
    self.len -= 1;
}

/// The slots in ID order, for a caller that wants to walk every stream.
pub fn iterator(self: *StreamTable) []Slot {
    return self.slots[0..self.len];
}

test "RFC 9000 §2.1, sparse IDs look up without a hash" {
    var storage: [4]Slot = undefined;
    var table: StreamTable = init(&storage);

    var sent: [8]u8 = undefined;
    var ring: [8]u8 = undefined;
    var send: SendStream = .init(0, &sent, 100);
    var recv: ReceiveStream = .init(0, &ring, 8);

    _ = try table.open(0, &send, &recv);
    _ = try table.open(8, &send, null);
    _ = try table.open(3, null, &recv);

    // Sorted, so the iterator is the connection's stream order.
    var ids: [3]u64 = undefined;
    for (table.iterator(), 0..) |slot, i| ids[i] = slot.id;
    try testing.expectEqualSlices(u64, &.{ 0, 3, 8 }, &ids);

    try testing.expect(table.get(0) != null);
    try testing.expect(table.get(3) != null);
    try testing.expect(table.get(8) != null);
    try testing.expect(table.get(4) == null);
    try testing.expect(table.get(0).?.recv != null);
    try testing.expect(table.get(8).?.recv == null);
}

test "a full table refuses rather than evicting" {
    var storage: [2]Slot = undefined;
    var table: StreamTable = init(&storage);

    _ = try table.open(0, null, null);
    _ = try table.open(4, null, null);
    try testing.expectEqual(@as(usize, 2), table.capacity());

    // The third is refused and the first two are untouched.
    try testing.expectError(error.TableFull, table.open(8, null, null));
    try testing.expectEqual(@as(usize, 2), table.count());
    try testing.expect(table.get(0) != null);
    try testing.expect(table.get(4) != null);

    // Closing one makes room, in ID order.
    try table.close(0);
    _ = try table.open(8, null, null);
    try testing.expect(table.get(0) == null);
    try testing.expect(table.get(8) != null);
    try testing.expectEqual(@as(u64, 8), table.iterator()[1].id);
}

test "opening the same ID twice is refused, and closing what is not open is too" {
    var storage: [2]Slot = undefined;
    var table: StreamTable = init(&storage);
    _ = try table.open(4, null, null);
    try testing.expectError(error.AlreadyOpen, table.open(4, null, null));
    try testing.expectError(error.NotOpen, table.close(0));
}
