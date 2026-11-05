//! The sending half of a stream, RFC 9000 §3.1, with §4.1 flow control.
//!
//! The application writes into a buffer it owns, and asks for segments to
//! packetize. Each segment is the next run of unsent bytes that the peer's
//! limit allows, and the stream reports how far the peer has acknowledged so the
//! application can reuse the front of the buffer.
//!
//! The state machine is §3.1's: Ready, Send, Data Sent, Data Recvd, Reset Sent,
//! Reset Recvd. Transitions happen on what is actually sent and acknowledged,
//! not on what the application asked for, because the peer can only observe the
//! former.

const std = @import("std");
const testing = std.testing;

const SendStream = @This();

pub const State = enum {
    /// The application may write; nothing has been sent.
    ready,
    /// Data has been sent and more may follow.
    send,
    /// The FIN has been sent; only retransmission remains.
    data_sent,
    /// Every byte and the FIN are acknowledged. Terminal.
    data_recvd,
    /// RESET_STREAM has been sent.
    reset_sent,
    /// RESET_STREAM is acknowledged. Terminal.
    reset_recvd,
};

pub const Error = error{
    /// STREAM_STATE_ERROR (§3.1, §19.8): the stream cannot accept this.
    StreamState,
    /// The caller's buffer is full, or its out-of-order acknowledgment table is.
    NoSpace,
    /// The stream already ended or was reset; the application cannot write.
    Closed,
    /// More bytes than the stream holds were written at an offset.
    OutOfBounds,
};

/// One run of bytes to put in a STREAM frame.
pub const Segment = struct {
    offset: u64,
    data: []const u8,
    /// §19.8: the FIN bit belongs on the segment that reaches the final size.
    fin: bool,
};

const Range = struct {
    start: u64,
    end: u64,
};

/// How many out-of-order acknowledged runs are tracked. Beyond it, `onAck`
/// reports `error.NoSpace` rather than forgetting an acknowledgment.
pub const pending_capacity = 8;

id: u64,
state: State = .ready,
/// The application's bytes. Borrowed; the stream owns nothing.
buffer: []u8,
/// How many bytes the application has written, from offset 0.
written: u64 = 0,
/// The highest offset handed out by `nextSegment`.
sent: u64 = 0,
/// The highest contiguous acknowledged offset.
acked: u64 = 0,
pending: [pending_capacity]Range = undefined,
pending_len: usize = 0,
/// §4.1: the peer's limit for this stream, in absolute bytes.
limit: u64,
/// Set by `end`, which is what makes the last byte carry FIN.
final_size: ?u64 = null,
/// The application error code to put in RESET_STREAM, once the stream is reset.
reset_code: ?u64 = null,
/// §3.5: a STOP_SENDING the peer sent, waiting for the caller to send a reset.
stop_sending_code: ?u64 = null,

pub fn init(id: u64, buffer: []u8, limit: u64) SendStream {
    return .{ .id = id, .buffer = buffer, .limit = limit };
}

pub fn isTerminal(self: *const SendStream) bool {
    return self.state == .data_recvd or self.state == .reset_recvd;
}

/// Append the application's bytes. Returns how many were taken, which is short
/// when the buffer is full.
pub fn write(self: *SendStream, bytes: []const u8) Error!usize {
    if (self.final_size != null) return error.Closed;
    if (self.reset_code != null) return error.Closed;
    if (self.state == .data_recvd or self.state == .reset_recvd) return error.Closed;

    const space = self.buffer.len - @as(usize, @intCast(self.written));
    const take = @min(space, bytes.len);
    @memcpy(self.buffer[@intCast(self.written)..][0..take], bytes[0..take]);
    self.written += take;
    return take;
}

/// Record that the application has no more data.
///
/// This does not end the stream on its own: §3.1 waits for a STREAM frame with
/// the FIN bit, which `nextSegment` produces once the data is out, as a segment
/// of length zero at the final size.
pub fn end(self: *SendStream) Error!void {
    if (self.final_size != null) return error.Closed;
    if (self.isTerminal()) return error.Closed;
    self.final_size = self.written;
}

/// §3.1: abandon sending. Legal from Ready, Send, and Data Sent.
pub fn reset(self: *SendStream, error_code: u64) Error!void {
    switch (self.state) {
        .ready, .send, .data_sent => {},
        .reset_sent, .reset_recvd, .data_recvd => return error.StreamState,
    }
    self.reset_code = error_code;
    self.state = .reset_sent;
}

/// The next run to packetize, bounded by `max_len` and by the peer's limit.
///
/// Retransmission is the caller's: this only hands out bytes that were never
/// sent. A caller that needs a lost range again asks `data(offset, len)`.
pub fn nextSegment(self: *SendStream, max_len: u32) ?Segment {
    if (self.state != .ready and self.state != .send) return null;

    // §19.8: FIN sets the final size, and a frame of length zero at that offset
    // is how a stream whose data is already out ends. It consumes no flow
    // control credit, so the limit does not bound it.
    if (self.final_size) |size| {
        if (self.sent == size) {
            self.state = .data_sent;
            return .{ .offset = size, .data = &.{}, .fin = true };
        }
    }

    if (self.sent >= self.limit) return null;
    if (self.sent == self.written) return null;

    const available = @min(self.limit, self.written) - self.sent;
    const length: u64 = @min(available, max_len);
    const offset = self.sent;
    const fin = if (self.final_size) |size| offset + length == size else false;

    self.sent += length;
    // §3.1: sending the first STREAM frame is what opens the stream, and
    // sending the one with FIN ends it.
    self.state = if (fin) .data_sent else .send;

    return .{
        .offset = offset,
        .data = self.buffer[@intCast(offset)..][0..@intCast(length)],
        .fin = fin,
    };
}

/// The bytes to put in a retransmission of `[offset, offset + length)`.
pub fn data(self: *const SendStream, offset: u64, length: u32) Error![]const u8 {
    if (offset + length > self.written) return error.OutOfBounds;
    return self.buffer[@intCast(offset)..][0..length];
}

/// §4.1: a MAX_STREAM_DATA frame. A limit that does not increase is ignored.
pub fn onMaxStreamData(self: *SendStream, limit: u64) void {
    if (limit > self.limit) self.limit = limit;
}

/// §3.1: bytes the peer acknowledged, possibly out of order.
pub fn onAck(self: *SendStream, offset: u64, length: u32) Error!void {
    if (length == 0) return;
    const stop = offset + length;
    if (stop <= self.acked) return;

    if (offset <= self.acked) {
        self.acked = stop;
        self.absorb();
    } else {
        try self.insertPending(offset, stop);
    }

    // §3.1: Data Sent moves to Data Recvd once everything is acknowledged.
    if (self.state == .data_sent) {
        if (self.final_size) |size| {
            if (self.acked >= size) self.state = .data_recvd;
        }
    }
}

/// §3.1: the RESET_STREAM was acknowledged.
pub fn onResetAcked(self: *SendStream) Error!void {
    if (self.state != .reset_sent) return error.StreamState;
    self.state = .reset_recvd;
}

/// §3.5: the peer asked us to stop. Returns whether a RESET_STREAM must be sent
/// now: it must in Ready or Send, and may be deferred in Data Sent.
pub fn onStopSending(self: *SendStream, error_code: u64) Error!bool {
    if (self.isTerminal() or self.state == .reset_sent) return false;
    self.stop_sending_code = error_code;
    if (self.state == .data_sent) return false;
    try self.reset(error_code);
    return true;
}

/// Bytes the application wrote that the peer has not acknowledged.
pub fn unacknowledged(self: *const SendStream) u64 {
    return self.written - self.acked;
}

/// Whether there is data to send that the peer's limit forbids. A stream that
/// has ended but is waiting for credit is blocked too: §3.1 only excuses the
/// Data Sent state, where there is no data left to send.
pub fn isBlocked(self: *const SendStream) bool {
    return self.sent == self.limit and self.written > self.limit;
}

fn insertPending(self: *SendStream, start: u64, stop: u64) Error!void {
    if (self.pending_len == self.pending.len) return error.NoSpace;

    var index: usize = 0;
    while (index < self.pending_len and self.pending[index].start < start) : (index += 1) {}
    var shift = self.pending_len;
    while (shift > index) : (shift -= 1) self.pending[shift] = self.pending[shift - 1];
    self.pending[index] = .{ .start = start, .end = stop };
    self.pending_len += 1;

    // Merge neighbours so the table does not fill with abutting runs.
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

/// Extend the contiguous offset through whatever pending runs now touch it.
fn absorb(self: *SendStream) void {
    var absorbed = true;
    while (absorbed) {
        absorbed = false;
        var index: usize = 0;
        while (index < self.pending_len) : (index += 1) {
            if (self.pending[index].start <= self.acked) {
                if (self.pending[index].end > self.acked) self.acked = self.pending[index].end;
                var move = index;
                while (move + 1 < self.pending_len) : (move += 1) {
                    self.pending[move] = self.pending[move + 1];
                }
                self.pending_len -= 1;
                absorbed = true;
                break;
            }
        }
    }
}

test "RFC 9000 §3.1, the sending state machine" {
    var buffer: [64]u8 = undefined;
    var stream: SendStream = .init(4, &buffer, 1000);
    try testing.expectEqual(State.ready, stream.state);

    try testing.expectEqual(@as(usize, 5), try stream.write("hello"));
    try testing.expectEqual(@as(usize, 10), try stream.write("-world...."));

    // The first segment opens the stream: Ready to Send.
    const first = stream.nextSegment(8).?;
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expectEqualStrings("hello-wo", first.data);
    try testing.expect(!first.fin);
    try testing.expectEqual(State.send, stream.state);

    // The rest of the data goes without FIN, because the application has not
    // ended the stream yet.
    const rest = stream.nextSegment(100).?;
    try testing.expectEqual(@as(u64, 8), rest.offset);
    try testing.expectEqualStrings("rld....", rest.data);
    try testing.expect(!rest.fin);
    try testing.expectEqual(State.send, stream.state);

    // Nothing left to send, and not ended: no segment.
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(100));

    // Ending produces the zero-length FIN at the final size, which is the
    // frame that moves the stream to Data Sent.
    try stream.end();
    const fin = stream.nextSegment(100).?;
    try testing.expectEqual(@as(u64, 15), fin.offset);
    try testing.expectEqual(@as(usize, 0), fin.data.len);
    try testing.expect(fin.fin);
    try testing.expectEqual(State.data_sent, stream.state);

    // Acknowledging it all reaches the terminal state.
    try stream.onAck(0, 8);
    try testing.expectEqual(State.data_sent, stream.state);
    try stream.onAck(8, 7);
    try testing.expectEqual(State.data_recvd, stream.state);
    try testing.expect(stream.isTerminal());
}

test "RFC 9000 §3.1, Data Sent is reached by ending, not by writing" {
    var buffer: [16]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);

    _ = try stream.write("abcd");
    _ = stream.nextSegment(4).?;
    try testing.expectEqual(State.send, stream.state);

    // Ending with nothing left to send still needs a FIN segment, so the state
    // does not move until one is handed out.
    try stream.end();
    try testing.expectEqual(State.send, stream.state);
    const fin = stream.nextSegment(1).?;
    try testing.expect(fin.fin);
    try testing.expectEqual(@as(usize, 0), fin.data.len);
    try testing.expectEqual(State.data_sent, stream.state);

    // Writing after the end is the application's mistake, not a wire event.
    try testing.expectError(error.Closed, stream.write("e"));
    try testing.expectError(error.Closed, stream.end());
}

test "RFC 9000 §3.1, reset is legal before the end and refused after" {
    var buffer: [16]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);

    // From Ready.
    try stream.reset(0x100);
    try testing.expectEqual(State.reset_sent, stream.state);
    try stream.onResetAcked();
    try testing.expectEqual(State.reset_recvd, stream.state);
    try testing.expectError(error.StreamState, stream.reset(1));
    try testing.expectError(error.StreamState, stream.onResetAcked());

    // From Send.
    var second: SendStream = .init(0, &buffer, 1000);
    _ = try second.write("abc");
    _ = second.nextSegment(3).?;
    try second.reset(0x200);
    try testing.expectEqual(State.reset_sent, second.state);

    // A stream that reached Data Recvd cannot be reset either.
    var third: SendStream = .init(0, &buffer, 1000);
    _ = try third.write("ab");
    try third.end();
    _ = third.nextSegment(2).?;
    try third.onAck(0, 2);
    try testing.expectEqual(State.data_recvd, third.state);
    try testing.expectError(error.StreamState, third.reset(3));
}

test "RFC 9000 §4.1, segments stop at the peer's limit and resume when it moves" {
    var buffer: [32]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 4);
    _ = try stream.write("0123456789");
    try stream.end();

    const allowed = stream.nextSegment(16).?;
    try testing.expectEqualStrings("0123", allowed.data);
    try testing.expect(stream.isBlocked());

    // Nothing more until the limit moves.
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(16));

    // §4.1: a smaller limit has no effect.
    stream.onMaxStreamData(2);
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(16));

    stream.onMaxStreamData(10);
    const resumed = stream.nextSegment(16).?;
    try testing.expectEqual(@as(u64, 4), resumed.offset);
    try testing.expectEqualStrings("456789", resumed.data);
    try testing.expect(resumed.fin);
    try testing.expectEqual(State.data_sent, stream.state);
}

test "RFC 9000 §3.1, acknowledgments arrive out of order and the count is honest" {
    var buffer: [32]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    _ = try stream.write("0123456789");
    try stream.end();
    _ = stream.nextSegment(10).?;

    // The back half lands first: nothing is contiguous yet.
    try stream.onAck(5, 5);
    try testing.expectEqual(@as(u64, 0), stream.acked);
    try testing.expectEqual(@as(u64, 10), stream.unacknowledged());
    try testing.expectEqual(State.data_sent, stream.state);

    // The front arrives and the run joins it.
    try stream.onAck(0, 5);
    try testing.expectEqual(@as(u64, 10), stream.acked);
    try testing.expectEqual(@as(u64, 0), stream.unacknowledged());
    try testing.expectEqual(State.data_recvd, stream.state);

    // A duplicate acknowledgment changes nothing.
    try stream.onAck(0, 5);
    try testing.expectEqual(@as(u64, 10), stream.acked);
}

test "RFC 9000 §3.5, STOP_SENDING demands a reset while data is still sendable" {
    var buffer: [16]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    _ = try stream.write("abc");

    // In Send, the reset must go now and carries the peer's code.
    try testing.expect(try stream.onStopSending(0x99));
    try testing.expectEqual(State.reset_sent, stream.state);
    try testing.expectEqual(@as(?u64, 0x99), stream.reset_code);

    // In Data Sent it may be deferred: the answer is false and the state stands.
    var finished: SendStream = .init(0, &buffer, 1000);
    _ = try finished.write("ab");
    try finished.end();
    _ = finished.nextSegment(2).?;
    try testing.expectEqual(State.data_sent, finished.state);
    try testing.expect(!try finished.onStopSending(0x10));
    try testing.expectEqual(State.data_sent, finished.state);
}
