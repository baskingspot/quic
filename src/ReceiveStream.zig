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
    /// The caller's ring is smaller than the window it advertised, so the byte
    /// cannot be stored. That is a caller defect, not a wire error.
    NoSpace,
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
pub fn nextMaxStreamData(self: *const ReceiveStream) ?u64 {
    if (self.state != .recv) return null;
    const target = self.window();
    if (target <= self.limit) return null;
    return target;
}

/// Take a STREAM frame's payload.
pub fn onData(self: *ReceiveStream, offset: u64, data: []const u8, fin: bool) Error!void {
    if (self.state == .reset_recvd or self.state == .reset_read) return;
    if (self.state == .data_read) return;

    const end = offset + data.len;
    if (self.final_size) |size| {
        // §4.5: a final size cannot change, and nothing may arrive past it.
        if (end > size or data.len > 0 and offset >= size) return error.FinalSize;
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

    // Everything inside the advertised window must fit the ring.
    if (data.len > 0 and end > self.window()) return error.NoSpace;

    if (data.len > 0) {
        self.store(offset, data);
        self.highest = @max(self.highest, end);
        self.noteRange(offset, end) catch return error.NoSpace;
    }

    if (fin and self.state == .recv) self.state = .size_known;
    if (self.final_size) |size| {
        if (self.contiguous_end >= size and (self.state == .recv or self.state == .size_known)) {
            self.state = .data_recvd;
        }
    }
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
    if (self.pending_len == self.pending.len) return error.NoSpace;

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

    try stream.onData(0, "hello", false);
    try testing.expectEqual(@as(u64, 5), stream.readable());
    try testing.expectEqual(State.recv, stream.state);

    try stream.onData(5, " world", true);
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
    try stream.onData(5, "fghij", false);
    try testing.expectEqual(@as(u64, 0), stream.readable());
    try testing.expectEqual(@as(u64, 10), stream.highest);

    // The head arrives and the run joins it.
    try stream.onData(0, "abcde", false);
    try testing.expectEqual(@as(u64, 10), stream.readable());
    try testing.expectEqual(State.recv, stream.state);

    var out: [32]u8 = undefined;
    const read = try stream.readInto(&out);
    try testing.expectEqualStrings("abcdefghij", out[0..read]);
}

test "RFC 9000 §3.2 and §4.1, the stream limit is an absolute offset" {
    var ring: [64]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 10);

    try stream.onData(0, "0123456789", false);
    try testing.expectEqual(@as(u64, 10), stream.readable());

    // One byte past the advertised limit is a connection error, not a dropped
    // byte (§4.1: FLOW_CONTROL_ERROR).
    try testing.expectError(error.FlowControl, stream.onData(10, "x", false));
    // A frame that starts past it is the same violation.
    try testing.expectError(error.FlowControl, stream.onData(20, "y", false));
    // A FIN at exactly the limit is legal: it sets no byte past it. One byte
    // further is a violation, because the final size consumes credit (§4.5).
    try stream.onData(10, "", true);
    try testing.expectEqual(@as(?u64, 10), stream.final_size);
    var other: ReceiveStream = .init(0, &ring, 10);
    try testing.expectError(error.FlowControl, other.onData(11, "", true));
}

test "RFC 9000 §4.5, the final size cannot change" {
    var ring: [32]u8 = undefined;
    var stream: ReceiveStream = .init(0, &ring, 32);

    try stream.onData(0, "abcd", true);
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

    try stream.onData(0, "abc", false);
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

    try stream.onData(0, "0123456789", false);
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
    try stream.onData(0, "abc", false);
    try testing.expectEqual(@as(u64, 3), stream.highest);

    // Once the stream is reset, there is nothing left to ask the peer to stop.
    try stream.onReset(1, 3);
    try testing.expectEqual(@as(?u64, null), stream.onStopSending(7));
}
