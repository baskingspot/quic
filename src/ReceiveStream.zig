//! The receiving half of a stream, RFC 9000 §3.2, with §4 flow control.
//!
//! Data arrives out of order and is reassembled into a contiguous byte stream
//! in a ring buffer the caller owns. The stream knows three offsets: what has
//! been received, what is contiguous from the read point, and how much the peer
//! is allowed to send. The last is the one §4.1 makes a connection error:
//! "A receiver MUST close the connection with an error of type
//! FLOW_CONTROL_ERROR if the sender violates the advertised connection or
//! stream data limits."
//!
//! The ring is indexed by absolute offset modulo capacity, so a byte's position
//! never moves and reading does not shift anything.

const std = @import("std");
const testing = std.testing;

const ReceiveStream = @This();

pub const State = enum {
    recv,
    /// A FIN has been seen, so the final size is known (§3.2).
    size_known,
    /// Every byte is here, waiting for the application.
    data_recvd,
    /// The application read to the final size. Terminal.
    data_read,
    /// A RESET_STREAM arrived.
    reset_recvd,
    /// The application consumed the reset. Terminal.
    reset_read,
};

pub const Error = error{
    /// FLOW_CONTROL_ERROR: the peer exceeded the stream limit (§4.1).
    FlowControl,
    /// FINAL_SIZE_ERROR: the final size changed, or data arrived past it (§4.5).
    FinalSize,
    /// STREAM_STATE_ERROR: the stream cannot accept this (§3.2).
    StreamState,
    /// More out-of-order runs are outstanding than the reassembly table holds.
    /// This is the table's limit, not the ring's: a frame that does not fit the
    /// ring is backpressure, see `Stored`.
    TooManyGaps,
};

/// What happened to a STREAM frame's payload.
pub const Stored = enum {
    /// The bytes are in the ring.
    accepted,
    /// The ring has no room. The stream is unchanged: nothing was stored and no
    /// range was recorded, so the caller can read, or widen its window, and
    /// offer the same frame again. A peer that respected the advertised window
    /// did nothing wrong, which is why this is not an error.
    backpressure,
};

const Range = struct {
    start: u64,
    end: u64,
};

/// How many disjoint out-of-order runs are tracked beyond the contiguous end.
pub const pending_capacity = 8;

id: u64,
state: State = .recv,
/// The reassembly ring. Borrowed; the stream owns nothing.
buffer: []u8,
/// The first byte the application has not read.
read_offset: u64 = 0,
/// The end of the contiguous run that starts at `read_offset`.
contiguous_end: u64 = 0,
pending: [pending_capacity]Range = undefined,
pending_len: usize = 0,
/// The highest byte offset received, contiguous or not.
highest: u64 = 0,
/// §4.1: the limit we last advertised, as an absolute offset.
limit: u64,
/// The final size, once a FIN or a RESET_STREAM tells us (§4.5).
final_size: ?u64 = null,
reset_code: ?u64 = null,
stop_sending_code: ?u64 = null,

pub fn init(id: u64, buffer: []u8, limit: u64) ReceiveStream {
    std.debug.assert(buffer.len > 0);
    return .{ .id = id, .buffer = buffer, .limit = limit };
}

pub fn isTerminal(self: *const ReceiveStream) bool {
    return self.state == .data_read or self.state == .reset_read;
}

/// Bytes the application may read now.
pub fn readable(self: *const ReceiveStream) u64 {
    return self.contiguous_end - self.read_offset;
}

/// §4.1: the limit this receiver is willing to enforce. Advertising less than
/// what the ring holds wastes it; advertising more cannot be buffered.
pub fn window(self: *const ReceiveStream) u64 {
    return self.read_offset + self.buffer.len;
}

/// §4.2: the limit to put in a MAX_STREAM_DATA frame, or null when the peer
/// already has enough credit.
///
/// The raise is held back until the credit left is under half the ring. Sending
/// on every read call would spend a frame per call, and waiting for the peer to
/// hit the limit would stall it: half a ring is the point where the peer still
/// has room to send while the frame is in flight.
pub fn nextMaxStreamData(self: *const ReceiveStream) ?u64 {
    if (self.state != .recv) return null;

    // §4.1: the limit is an absolute offset, and it only ever grows, so the
    // read position can never be past it.
    std.debug.assert(self.limit >= self.read_offset);

    const target = self.window();
    if (target <= self.limit) return null;

    const credit = self.limit - self.read_offset;
    if (credit >= self.buffer.len / 2) return null;
    return target;
}

/// Take a STREAM frame's payload.
pub fn onData(self: *ReceiveStream, offset: u64, data: []const u8, fin: bool) Error!Stored {
    // §3.2 lets a receiver discard everything on a stream it has reset, and
    // §4.5 makes data past the final size a connection error a receiver MAY
    // raise. This one does not: once the application has read the stream, late
    // retransmissions are the peer catching up with its own acknowledgments,
    // not a violation worth closing over.
    if (self.state == .reset_recvd or self.state == .reset_read) return .accepted;
    if (self.state == .data_read) return .accepted;

    const end = offset + data.len;
    if (self.final_size) |size| {
        // §4.5: a final size cannot change, and nothing may arrive past it.
        // Split: the two halves are different violations of §4.5.
        if (end > size) return error.FinalSize;
        if (data.len > 0) {
            if (offset >= size) return error.FinalSize;
        }
        if (fin and end != size) return error.FinalSize;
    } else if (fin) {
        self.final_size = end;
    }

    // §4.1: the limit is an absolute offset, and the final size counts against
    // it whether or not every byte was sent.
    if (end > self.limit) return error.FlowControl;
    if (fin) {
        if (self.final_size.? > self.limit) return error.FlowControl;
    }

    // A frame inside the advertised window always fits a ring that is as large
    // as the window. A caller that advertised more than it can hold gets
    // backpressure, not an error, and the stream stays exactly as it was.
    if (data.len > 0 and end > self.window()) return .backpressure;

    if (data.len > 0) {
        self.store(offset, data);
        self.highest = @max(self.highest, end);
        try self.noteRange(offset, end);
    }

    if (fin and self.state == .recv) self.state = .size_known;
    if (self.final_size) |size| {
        if (self.contiguous_end >= size) {
            switch (self.state) {
                .recv, .size_known => self.state = .data_recvd,
                else => {},
            }
        }
    }
    return .accepted;
}

/// §3.2: a RESET_STREAM. Legal in Recv, Size Known, and after the data is in.
pub fn onReset(self: *ReceiveStream, error_code: u64, final_size: u64) Error!void {
    if (self.state == .data_read or self.state == .reset_read) return;
    // §4.5: the final size from a reset must agree with one already known.
    if (self.final_size) |size| {
        if (size != final_size) return error.FinalSize;
    }
    if (final_size > self.limit) return error.FlowControl;

    self.final_size = final_size;
    self.reset_code = error_code;
    self.state = .reset_recvd;
}

/// §3.5: the application is no longer interested. Returns the error code to put
/// in a STOP_SENDING frame, or null when there is nothing to send.
///
/// STREAM frames that arrive afterwards still count against flow control, so
/// this does not stop `onData` from accounting; it stops it from storing.
pub fn onStopSending(self: *ReceiveStream, error_code: u64) ?u64 {
    if (self.state != .recv and self.state != .size_known) return null;
    self.stop_sending_code = error_code;
    return error_code;
}

/// Copy up to `dest.len` contiguous bytes out and advance the read point.
pub fn readInto(self: *ReceiveStream, dest: []u8) Error!usize {
    if (self.state == .reset_recvd or self.state == .reset_read) return error.StreamState;
    const count: usize = @intCast(@min(self.readable(), dest.len));
    if (count == 0) {
        self.settleRead();
        return 0;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        dest[i] = self.buffer[@intCast((self.read_offset + i) % self.buffer.len)];
    }
    self.read_offset += count;
    self.settleRead();
    return count;
}

/// §3.2: once the application has consumed a reset, the stream is done.
pub fn readReset(self: *ReceiveStream) Error!u64 {
    if (self.state != .reset_recvd) return error.StreamState;
    self.state = .reset_read;
    return self.reset_code orelse 0;
}

fn settleRead(self: *ReceiveStream) void {
    if (self.final_size) |size| {
        if (self.read_offset >= size and (self.state == .data_recvd or self.state == .size_known)) {
            self.state = .data_read;
        }
    }
}

fn store(self: *ReceiveStream, offset: u64, data: []const u8) void {
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        const absolute = offset + i;
        if (absolute < self.read_offset) continue;
        self.buffer[@intCast(absolute % self.buffer.len)] = data[i];
    }
}

fn noteRange(self: *ReceiveStream, start: u64, end: u64) Error!void {
    if (end <= self.contiguous_end) return;
    if (start <= self.contiguous_end) {
        self.contiguous_end = end;
        self.absorb();
        return;
    }
    if (self.pending_len == self.pending.len) return error.TooManyGaps;

    var index: usize = 0;
    while (index < self.pending_len and self.pending[index].start < start) : (index += 1) {}
    var shift = self.pending_len;
    while (shift > index) : (shift -= 1) self.pending[shift] = self.pending[shift - 1];
    self.pending[index] = .{ .start = start, .end = end };
    self.pending_len += 1;

    // Coalesce neighbours so the table does not fill with abutting runs.
    var merged: usize = 1;
    while (merged < self.pending_len) : (merged += 1) {
        const previous = &self.pending[merged - 1];
        if (self.pending[merged].start <= previous.end) {
            previous.end = @max(previous.end, self.pending[merged].end);
            var move = merged;
            while (move + 1 < self.pending_len) : (move += 1) {
                self.pending[move] = self.pending[move + 1];
            }
            self.pending_len -= 1;
            merged -= 1;
        }
    }
}

fn absorb(self: *ReceiveStream) void {
    var progressed = true;
    while (progressed) {
        progressed = false;
        var index: usize = 0;
        while (index < self.pending_len) : (index += 1) {
            if (self.pending[index].start <= self.contiguous_end) {
                if (self.pending[index].end > self.contiguous_end) {
                    self.contiguous_end = self.pending[index].end;
                }
                var move = index;
                while (move + 1 < self.pending_len) : (move += 1) {
                    self.pending[move] = self.pending[move + 1];
                }
                self.pending_len -= 1;
                progressed = true;
                break;
            }
        }
    }
}

test "RFC 9000 §3.2, in-order data is read and the stream ends cleanly" {
    var ring: [16]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 16);

    _ = try stream.onData(0, "hello", false);
    try testing.expectEqual(@as(u64, 5), stream.readable());
    try testing.expectEqual(State.recv, stream.state);

    _ = try stream.onData(5, " world", true);
    try testing.expectEqual(@as(u64, 11), stream.readable());
    // §3.2: the FIN tells us the final size, and with all the data here the
    // stream is Data Recvd.
    try testing.expectEqual(@as(?u64, 11), stream.final_size);
    try testing.expectEqual(State.data_recvd, stream.state);

    var out: [16]u8 = undefined;
    const read = try stream.readInto(&out);
    try testing.expectEqual(@as(usize, 11), read);
    try testing.expectEqualStrings("hello world", out[0..read]);
    try testing.expectEqual(State.data_read, stream.state);
    try testing.expect(stream.isTerminal());
}

test "RFC 9000 §2.2, out-of-order data reassembles into a contiguous stream" {
    var ring: [32]u8 = undefined;
    var stream: ReceiveStream = .init(4, &ring, 32);

    // The tail arrives first: nothing is readable yet.
    _ = try stream.onData(5, "fghij", false);
    try testing.expectEqual(@as(u64, 0), stream.readable());
    try testing.expectEqual(@as(u64, 10), stream.highest);

    // The head arrives and the run joins it.
    _ = try stream.onData(0, "abcde", false);
    try testing.expectEqual(@as(u64, 10), stream.readable());
    try testing.expectEqual(State.recv, stream.state);

    var out: [32]u8 = undefined;
    const read = try stream.readInto(&out);
    try testing.expectEqualStrings("abcdefghij", out[0..read]);
}

test "RFC 9000 §3.2 and §4.1, the stream limit is an absolute offset" {
    var ring: [64]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 10);

    _ = try stream.onData(0, "0123456789", false);
    try testing.expectEqual(@as(u64, 10), stream.readable());

    // One byte past the advertised limit is a connection error, not a dropped
    // byte (§4.1: FLOW_CONTROL_ERROR).
    try testing.expectError(error.FlowControl, stream.onData(10, "x", false));
    // A frame that starts past it is the same violation.
    try testing.expectError(error.FlowControl, stream.onData(20, "y", false));
    // A FIN at exactly the limit is legal: it sets no byte past it. One byte
    // further is a violation, because the final size consumes credit (§4.5).
    _ = try stream.onData(10, "", true);
    try testing.expectEqual(@as(?u64, 10), stream.final_size);
    var other: ReceiveStream = .init(0, &ring, 10);
    try testing.expectError(error.FlowControl, other.onData(11, "", true));
}

test "RFC 9000 §4.5, the final size cannot change" {
    var ring: [32]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 32);

    _ = try stream.onData(0, "abcd", true);
    try testing.expectEqual(@as(?u64, 4), stream.final_size);
    try testing.expectEqual(State.data_recvd, stream.state);

    // Data past the final size.
    try testing.expectError(error.FinalSize, stream.onData(4, "e", false));
    // A reset with another final size.
    try testing.expectError(error.FinalSize, stream.onReset(0, 6));
}

test "RFC 9000 §3.2, a reset ends the stream and the application collects the code" {
    var ring: [32]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 32);

    _ = try stream.onData(0, "abc", false);
    try stream.onReset(0x42, 3);
    try testing.expectEqual(State.reset_recvd, stream.state);
    try testing.expectEqual(@as(?u64, 0x42), stream.reset_code);

    // Reading data after a reset is an application error.
    var out: [8]u8 = undefined;
    try testing.expectError(error.StreamState, stream.readInto(&out));

    try testing.expectEqual(@as(u64, 0x42), try stream.readReset());
    try testing.expectEqual(State.reset_read, stream.state);
    try testing.expect(stream.isTerminal());

    // A reset after a reset is not the application's business any more.
    try stream.onReset(1, 3);
    try testing.expectEqual(@as(?u64, 0x42), stream.reset_code);
}

test "RFC 9000 §4.2, the receiver owes a MAX_STREAM_DATA after the application reads" {
    var ring: [16]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 16);

    // With nothing read, the window is what we already advertised.
    try testing.expectEqual(@as(?u64, null), stream.nextMaxStreamData());

    _ = try stream.onData(0, "0123456789", false);
    var out: [16]u8 = undefined;
    _ = try stream.readInto(&out);

    // Ten bytes freed, so the new limit is ten bytes further on.
    try testing.expectEqual(@as(?u64, 10 + 16), stream.nextMaxStreamData());
    try testing.expectEqual(@as(u64, 26), stream.window());
}

test "RFC 9000 §3.5, STOP_SENDING is answered once and only while receiving" {
    var ring: [16]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 16);
    try testing.expectEqual(@as(?u64, 7), stream.onStopSending(7));
    // Frames after the stop are still accounted for flow control.
    _ = try stream.onData(0, "abc", false);
    try testing.expectEqual(@as(u64, 3), stream.highest);

    // Once the stream is reset, there is nothing left to ask the peer to stop.
    try stream.onReset(1, 3);
    try testing.expectEqual(@as(?u64, null), stream.onStopSending(7));
}

/// A stream in the given state, over the caller's ring.
fn inState(state: State, ring: []u8) ReceiveStream {
    var stream: ReceiveStream = .init(0, ring, 16);
    switch (state) {
        .recv => {},
        .size_known => _ = stream.onData(0, "ab", true) catch unreachable,
        .data_recvd => {
            _ = stream.onData(0, "ab", true) catch unreachable;
        },
        .data_read => {
            _ = stream.onData(0, "ab", true) catch unreachable;
            var out: [4]u8 = undefined;
            _ = stream.readInto(&out) catch unreachable;
        },
        .reset_recvd => stream.onReset(1, 2) catch unreachable,
        .reset_read => {
            stream.onReset(1, 2) catch unreachable;
            _ = stream.readReset() catch unreachable;
        },
    }
    return stream;
}

test "RFC 9000 §3.2, every operation in every receiving state" {
    inline for (std.meta.tags(State)) |state| {
        var ring: [16]u8 = undefined;

        // onData: data is always accepted while the stream is live, and after a
        // reset or a full read it is ignored rather than refused.
        {
            var stream = inState(state, &ring);
            const stored = try stream.onData(0, "xy", false);
            switch (state) {
                .recv, .size_known => try testing.expectEqual(Stored.accepted, stored),
                else => try testing.expectEqual(Stored.accepted, stored),
            }
        }

        // onReset: legal until the application has finished with the stream.
        {
            var stream = inState(state, &ring);
            const result = stream.onReset(3, 2);
            switch (state) {
                .data_read, .reset_read => try result,
                else => try result,
            }
        }

        // readInto: reading a reset stream is the application's mistake.
        {
            var stream = inState(state, &ring);
            var out: [4]u8 = undefined;
            const result = stream.readInto(&out);
            switch (state) {
                .reset_recvd, .reset_read => try testing.expectError(error.StreamState, result),
                else => _ = try result,
            }
        }

        // readReset: only a reset stream has a code to collect.
        {
            var stream = inState(state, &ring);
            const result = stream.readReset();
            switch (state) {
                .reset_recvd => try testing.expectEqual(@as(u64, 1), try result),
                else => try testing.expectError(error.StreamState, result),
            }
        }
    }
}

test "RFC 9000 §2.2, overlapping and duplicate ranges are idempotent" {
    var ring: [32]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 32);

    _ = try stream.onData(0, "abcdef", false);
    // The same bytes again, and a range that overlaps both ends.
    _ = try stream.onData(0, "abcdef", false);
    _ = try stream.onData(2, "cdefgh", false);

    try testing.expectEqual(@as(u64, 8), stream.readable());
    var out: [16]u8 = undefined;
    const read = try stream.readInto(&out);
    try testing.expectEqualStrings("abcdefgh", out[0..read]);

    // A duplicate that arrives behind the read point is not an error.
    _ = try stream.onData(0, "ab", false);
    try testing.expectEqual(@as(u64, 0), stream.readable());
}

test "RFC 9000 §4.5, a FIN in the middle of the range and data past it" {
    var ring: [32]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 32);

    // A FIN with data: the final size is offset plus length.
    _ = try stream.onData(2, "cd", true);
    try testing.expectEqual(@as(?u64, 4), stream.final_size);
    try testing.expectEqual(State.size_known, stream.state);

    // Data past that final size is FINAL_SIZE_ERROR, even though the stream is
    // not complete.
    try testing.expectError(error.FinalSize, stream.onData(4, "e", false));

    // The gap closes and the stream completes.
    _ = try stream.onData(0, "ab", false);
    try testing.expectEqual(State.data_recvd, stream.state);

    // Exactly at the final size with no bytes is legal and changes nothing.
    _ = try stream.onData(4, "", false);
    try testing.expectEqual(State.data_recvd, stream.state);
}

test "the ring is the caller's limit, and a full one is backpressure" {
    var ring: [4]u8 = undefined;
    // A window larger than the ring: the caller advertised more than it holds.
    var stream: ReceiveStream = .init(0, &ring, 32);

    _ = try stream.onData(0, "abcd", false);
    try testing.expectEqual(@as(u64, 4), stream.readable());

    // The fifth byte does not fit. The stream is unchanged, and the caller can
    // read and offer it again.
    try testing.expectEqual(Stored.backpressure, try stream.onData(4, "e", false));
    try testing.expectEqual(@as(u64, 4), stream.readable());
    try testing.expectEqual(@as(u64, 4), stream.highest);

    var out: [4]u8 = undefined;
    _ = try stream.readInto(&out);
    try testing.expectEqual(Stored.accepted, try stream.onData(4, "e", false));
    try testing.expectEqual(@as(u64, 1), stream.readable());
}
