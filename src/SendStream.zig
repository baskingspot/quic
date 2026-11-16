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
//!
//! A loss is a range marked unsent again, not a copy (§13.3). The bytes never
//! leave the application's buffer, so `onLost` records which offsets have to go
//! out again and `nextSegment` hands them out first, at the offsets they had.

const std = @import("std");
const assert = std.debug.assert;
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
    /// These bytes were sent before and declared lost (§13.3). The peer's
    /// credit for them was spent the first time (§4.1), so a sender counts only
    /// segments that are not retransmissions against the connection's window.
    retransmit: bool = false,
};

const Range = struct {
    start: u64,
    end: u64,
};

/// How many out-of-order acknowledged runs are tracked. Beyond it, `onAck`
/// reports `error.NoSpace` rather than forgetting an acknowledgment.
pub const pending_capacity = 8;

/// How many separate lost runs are tracked. Beyond it the runs collapse into
/// one, from the lowest lost offset to the highest: bytes the peer may already
/// have go again, which §2.2 allows because they are the same bytes at the same
/// offsets, and nothing lost is ever forgotten.
pub const lost_capacity = 8;

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
/// Set by `finish`, which is what makes the last byte carry FIN.
final_size: ?u64 = null,
/// The application error code to put in RESET_STREAM, once the stream is reset.
reset_code: ?u64 = null,
/// §3.5: a STOP_SENDING the peer sent, waiting for the caller to send a reset.
stop_sending_code: ?u64 = null,
/// Runs below `sent` that went out in a packet declared lost, ascending and
/// disjoint, waiting to be sent again (§13.3).
lost: [lost_capacity]Range = undefined,
lost_len: usize = 0,
/// The FIN went out in a packet declared lost and has not gone out since.
fin_lost: bool = false,

pub fn init(id: u64, buffer: []u8, limit: u64) SendStream {
    return .{ .id = id, .buffer = buffer, .limit = limit };
}

pub fn isTerminal(self: *const SendStream) bool {
    return self.state == .data_recvd or self.state == .reset_recvd;
}

/// Append the application's bytes: all of them, or `error.NoSpace` and nothing
/// written.
///
/// There is no partial write, because a count that can be short is a caller's
/// check against a silent truncation: a 21-byte write into a buffer too small
/// for it used to become a zero-length FIN, and the peer saw a closed stream
/// with no data.
pub fn write(self: *SendStream, bytes: []const u8) Error!void {
    if (self.final_size != null) return error.Closed;
    if (self.reset_code != null) return error.Closed;
    if (self.state == .data_recvd or self.state == .reset_recvd) return error.Closed;

    // The only mutator of `written` is this function, and it never passes the
    // end of the buffer, so the subtraction below cannot wrap.
    assert(self.written <= self.buffer.len);
    const space = self.buffer.len - @as(usize, @intCast(self.written));
    if (bytes.len > space) return error.NoSpace;

    @memcpy(self.buffer[@intCast(self.written)..][0..bytes.len], bytes);
    self.written += bytes.len;
}

/// Record that the application has no more data.
///
/// This does not end the stream on its own: §3.1 waits for a STREAM frame with
/// the FIN bit, which `nextSegment` produces once the data is out, as a segment
/// of length zero at the final size. The final size is exactly what `write`
/// accepted, and `write` accepts all of it or none, so this cannot publish a
/// stream shorter than the application asked for.
pub fn finish(self: *SendStream) Error!void {
    if (self.final_size != null) return error.Closed;
    if (self.reset_code != null) return error.Closed;
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
    // §13.3: "Once an endpoint sends a RESET_STREAM for that stream, no further
    // STREAM frames are needed."
    self.lost_len = 0;
    self.fin_lost = false;
}

/// The next run to packetize, bounded by `max_len` and by the peer's limit.
///
/// Lost runs come first, lowest offset first, because §13.3 asks a sender to
/// prioritize retransmission over new data; then bytes that were never sent.
pub fn nextSegment(self: *SendStream, max_len: u32) ?Segment {
    const segment = self.peekSegment(max_len) orelse return null;
    if (segment.retransmit) {
        self.takeLost(segment);
        return segment;
    }

    // A packetizer has to know a frame's size before it decides to write it, so
    // the decision and the taking are separate: `peekSegment` says what would go
    // and this is what moves the cursor.
    if (segment.data.len != 0) self.sent += segment.data.len;
    // §3.1: sending the first STREAM frame is what opens the stream, and sending
    // the one with FIN ends it. The FIN-only segment is zero bytes at the final
    // size, where `sent` already is, so the state is the only thing that stops it
    // being offered again.
    self.state = if (segment.fin) .data_sent else .send;
    return segment;
}

/// What `nextSegment(max_len)` would return, without consuming it.
///
/// A caller that packs several streams into one packet has to size each frame
/// before it commits to it; taking a segment it then cannot write would lose the
/// bytes, because `nextSegment` moves the stream's cursor.
pub fn peekSegment(self: *const SendStream, max_len: u32) ?Segment {
    if (self.peekLost(max_len)) |segment| return segment;
    if (self.state != .ready and self.state != .send) return null;

    // §19.8: FIN sets the final size, and a frame of length zero at that offset
    // is how a stream whose data is already out ends. It consumes no flow
    // control credit, so the limit does not bound it.
    if (self.final_size) |size| {
        if (self.sent == size) return .{ .offset = size, .data = &.{}, .fin = true };
    }

    if (self.sent >= self.limit) return null;
    if (self.sent == self.written) return null;

    const available = @min(self.limit, self.written) - self.sent;
    const length: u64 = @min(available, max_len);
    const offset = self.sent;
    const fin = if (self.final_size) |size| offset + length == size else false;

    return .{
        .offset = offset,
        .data = self.buffer[@intCast(offset)..][0..@intCast(length)],
        .fin = fin,
    };
}

/// The front of the first lost run, or the lost FIN on its own.
fn peekLost(self: *const SendStream, max_len: u32) ?Segment {
    if (self.lost_len == 0) {
        if (!self.fin_lost) return null;
        // The data before the FIN arrived or is still in flight; only the
        // final size has to be said again (§19.8).
        const size = self.final_size.?;
        return .{ .offset = size, .data = &.{}, .fin = true, .retransmit = true };
    }
    const run = self.lost[0];
    assert(run.start < run.end);
    assert(run.end <= self.sent);
    const length = @min(run.end - run.start, max_len);
    const end = run.start + length;
    const fin = self.fin_lost and end == self.final_size.?;
    return .{
        .offset = run.start,
        .data = self.buffer[@intCast(run.start)..@intCast(end)],
        .fin = fin,
        .retransmit = true,
    };
}

/// Mark a retransmitted segment as sent: it was the front of the first run.
fn takeLost(self: *SendStream, segment: Segment) void {
    if (segment.fin) self.fin_lost = false;
    if (segment.data.len == 0) return;
    assert(self.lost_len > 0);
    assert(self.lost[0].start == segment.offset);
    self.lost[0].start += segment.data.len;
    assert(self.lost[0].start <= self.lost[0].end);
    if (self.lost[0].start == self.lost[0].end) removeRange(&self.lost, &self.lost_len, 0);
}

/// §13.3: the packet that carried `[offset, offset + length)`, and the FIN when
/// `fin` is set, was declared lost, so the range is unsent again.
///
/// Nothing is copied: the bytes are still in the application's buffer, and the
/// next `nextSegment` hands them out at the same offsets. A reset stream needs
/// no STREAM frames at all, a terminal one has nothing left to say, and bytes
/// the peer already acknowledged are not sent again.
pub fn onLost(self: *SendStream, offset: u64, length: u32, fin: bool) void {
    if (self.reset_code != null or self.isTerminal()) return;
    const end = offset + length;
    // Only what was handed out can have been in a packet.
    assert(end <= self.sent);
    if (fin) {
        // A FIN that left is the state's own record that it left.
        assert(self.state == .data_sent);
        assert(end == self.final_size.?);
        self.fin_lost = true;
    }
    const start = @max(offset, self.acked);
    if (start < end) self.insertLost(start, end);
}

/// Merge `[start, stop)` into the lost runs, collapsing them when full.
fn insertLost(self: *SendStream, start: u64, stop: u64) void {
    if (self.lost_len == self.lost.len) {
        // Full: one run from the lowest lost byte to the highest. Bounded, and
        // it can only send a byte twice, never forget one.
        const low = @min(start, self.lost[0].start);
        const high = @max(stop, self.lost[self.lost_len - 1].end);
        self.lost[0] = .{ .start = low, .end = high };
        self.lost_len = 1;
        return;
    }
    insertRange(&self.lost, &self.lost_len, start, stop);
}

/// Drop the parts of the lost runs the peer has now acknowledged.
fn trimLost(self: *SendStream) void {
    while (self.lost_len > 0 and self.lost[0].end <= self.acked) {
        removeRange(&self.lost, &self.lost_len, 0);
    }
    if (self.lost_len > 0 and self.lost[0].start < self.acked) self.lost[0].start = self.acked;
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
///
/// A zero-length acknowledgment is the FIN-only frame of §19.8 coming back: it
/// moves no offset, but it can be the last thing outstanding, so it still gets
/// the state check below.
pub fn onAck(self: *SendStream, offset: u64, length: u32) Error!void {
    const stop = offset + length;
    if (length > 0 and stop > self.acked) {
        if (offset <= self.acked) {
            self.acked = stop;
            self.absorb();
            self.trimLost();
        } else {
            try self.insertPending(offset, stop);
        }
    }

    // §3.1: Data Sent moves to Data Recvd once everything is acknowledged.
    if (self.state == .data_sent) {
        if (self.final_size) |size| {
            if (self.acked >= size) self.state = .data_recvd;
        }
    }
    // §13.3: "sending ceases when a packet containing that information is
    // acknowledged", and in Data Recvd all of it has been.
    if (self.state == .data_recvd) {
        self.lost_len = 0;
        self.fin_lost = false;
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
    insertRange(&self.pending, &self.pending_len, start, stop);
}

/// Insert `[start, stop)` into ascending runs with room for one more, merging
/// neighbours so the table does not fill with abutting runs.
fn insertRange(ranges: []Range, len: *usize, start: u64, stop: u64) void {
    assert(len.* < ranges.len);
    assert(start < stop);

    var index: usize = 0;
    while (index < len.* and ranges[index].start < start) : (index += 1) {}
    var shift = len.*;
    while (shift > index) : (shift -= 1) ranges[shift] = ranges[shift - 1];
    ranges[index] = .{ .start = start, .end = stop };
    len.* += 1;

    var merged: usize = 1;
    while (merged < len.*) : (merged += 1) {
        const previous = &ranges[merged - 1];
        if (ranges[merged].start <= previous.end) {
            previous.end = @max(previous.end, ranges[merged].end);
            removeRange(ranges, len, merged);
            merged -= 1;
        }
    }
}

/// Remove the run at `index`, moving the ones after it down.
fn removeRange(ranges: []Range, len: *usize, index: usize) void {
    assert(index < len.*);
    var move = index;
    while (move + 1 < len.*) : (move += 1) ranges[move] = ranges[move + 1];
    len.* -= 1;
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

    try stream.write("hello");
    try stream.write("-world....");

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

    // Finishing produces the zero-length FIN at the final size, which is the
    // frame that moves the stream to Data Sent.
    try stream.finish();
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

test "RFC 9000 §3.1, a write that does not fit is refused whole" {
    var buffer: [4]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("abc");

    // One byte of room and two offered: an error, not a count the caller has to
    // compare, and the stream is still exactly where it was.
    try testing.expectError(error.NoSpace, stream.write("de"));
    try testing.expectEqual(@as(u64, 3), stream.written);
    try testing.expectEqualStrings("abc", try stream.data(0, 3));

    // The empty buffer the example hit: before this contract a 21-byte write
    // took nothing, and the FIN that followed published a stream whose data the
    // peer never received. The refusal is the only way to say so.
    var empty: [0]u8 = .{};
    var starved: SendStream = .init(0, &empty, 1000);
    try testing.expectError(error.NoSpace, starved.write("hello from the client"));
    try testing.expectEqual(@as(u64, 0), starved.written);
    try testing.expectEqual(@as(?Segment, null), starved.nextSegment(16));

    // An empty write is always fine: it appends nothing and cannot be short.
    try stream.write("");
    try testing.expectEqual(@as(u64, 3), stream.written);
}

test "RFC 9000 §3.1, Data Sent is reached by finishing, not by writing" {
    var buffer: [16]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);

    try stream.write("abcd");
    _ = stream.nextSegment(4).?;
    try testing.expectEqual(State.send, stream.state);

    // Finishing with nothing left to send still needs a FIN segment, so the state
    // does not move until one is handed out.
    try stream.finish();
    try testing.expectEqual(State.send, stream.state);
    const fin = stream.nextSegment(1).?;
    try testing.expect(fin.fin);
    try testing.expectEqual(@as(usize, 0), fin.data.len);
    try testing.expectEqual(State.data_sent, stream.state);

    // Writing after the end is the application's mistake, not a wire event.
    try testing.expectError(error.Closed, stream.write("e"));
    try testing.expectError(error.Closed, stream.finish());
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
    try second.write("abc");
    _ = second.nextSegment(3).?;
    try second.reset(0x200);
    try testing.expectEqual(State.reset_sent, second.state);

    // A stream that reached Data Recvd cannot be reset either.
    var third: SendStream = .init(0, &buffer, 1000);
    try third.write("ab");
    try third.finish();
    _ = third.nextSegment(2).?;
    try third.onAck(0, 2);
    try testing.expectEqual(State.data_recvd, third.state);
    try testing.expectError(error.StreamState, third.reset(3));
}

test "RFC 9000 §4.1, segments stop at the peer's limit and resume when it moves" {
    var buffer: [32]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 4);
    try stream.write("0123456789");
    try stream.finish();

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
    try stream.write("0123456789");
    try stream.finish();
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
    try stream.write("abc");

    // In Send, the reset must go now and carries the peer's code.
    try testing.expect(try stream.onStopSending(0x99));
    try testing.expectEqual(State.reset_sent, stream.state);
    try testing.expectEqual(@as(?u64, 0x99), stream.reset_code);

    // In Data Sent it may be deferred: the answer is false and the state stands.
    var finished: SendStream = .init(0, &buffer, 1000);
    try finished.write("ab");
    try finished.finish();
    _ = finished.nextSegment(2).?;
    try testing.expectEqual(State.data_sent, finished.state);
    try testing.expect(!try finished.onStopSending(0x10));
    try testing.expectEqual(State.data_sent, finished.state);
}

/// A stream in the given state, over the caller's buffer.
fn inState(state: State, buffer: []u8) SendStream {
    var stream: SendStream = .init(0, buffer, 1000);
    switch (state) {
        .ready => {},
        .send => {
            stream.write("abcd") catch unreachable;
            _ = stream.nextSegment(2);
        },
        .data_sent, .data_recvd => {
            stream.write("abcd") catch unreachable;
            stream.finish() catch unreachable;
            _ = stream.nextSegment(4);
            if (state == .data_recvd) stream.onAck(0, 4) catch unreachable;
        },
        .reset_sent => stream.reset(1) catch unreachable,
        .reset_recvd => {
            stream.reset(1) catch unreachable;
            stream.onResetAcked() catch unreachable;
        },
    }
    return stream;
}

test "RFC 9000 §3.1, every operation in every sending state" {
    inline for (std.meta.tags(State)) |state| {
        var buffer: [16]u8 = undefined;

        // write: legal until the application ends or the stream dies.
        {
            var stream = inState(state, &buffer);
            const result = stream.write("x");
            switch (state) {
                .ready, .send => try result,
                else => try testing.expectError(error.Closed, result),
            }
        }

        // finish: the same rule, and idempotence is not allowed either.
        {
            var stream = inState(state, &buffer);
            const result = stream.finish();
            switch (state) {
                .ready, .send => try result,
                else => try testing.expectError(error.Closed, result),
            }
        }

        // reset: legal from the three live states only.
        {
            var stream = inState(state, &buffer);
            const result = stream.reset(9);
            switch (state) {
                .ready, .send, .data_sent => try result,
                else => try testing.expectError(error.StreamState, result),
            }
        }

        // nextSegment: data only while there is data to hand out.
        {
            var stream = inState(state, &buffer);
            const segment = stream.nextSegment(2);
            switch (state) {
                // Ready has nothing queued: this stream was created and never
                // written to. Send always has something left.
                .ready => try testing.expect(segment == null),
                .send => try testing.expect(segment != null),
                else => try testing.expect(segment == null),
            }
        }

        // onAck: a valid acknowledgment is never an error, in any state.
        {
            var stream = inState(state, &buffer);
            try stream.onAck(0, 1);
        }

        // onResetAcked: only a reset stream can have one acknowledged.
        {
            var stream = inState(state, &buffer);
            const result = stream.onResetAcked();
            switch (state) {
                .reset_sent => try result,
                else => try testing.expectError(error.StreamState, result),
            }
        }

        // onStopSending: a demand for a reset in the live states, a deferral in
        // Data Sent, and nothing at all once the stream is over.
        {
            var stream = inState(state, &buffer);
            const must_reset = try stream.onStopSending(5);
            switch (state) {
                .ready, .send => try testing.expect(must_reset),
                .data_sent, .reset_sent, .reset_recvd, .data_recvd => try testing.expect(!must_reset),
            }
        }
    }
}

test "RFC 9000 §3.1, an acknowledgment beyond the final size is still an acknowledgment" {
    // The stream does not police what the peer acknowledges; it only tracks the
    // contiguous prefix, which is capped by what it sent.
    var buffer: [8]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("ab");
    try stream.finish();
    _ = stream.nextSegment(2).?;
    try stream.onAck(0, 2);
    try testing.expectEqual(State.data_recvd, stream.state);
    try testing.expectEqual(@as(u64, 2), stream.acked);
}

test "RFC 9000 §3.1, a FIN sent on its own is acknowledged on its own" {
    // The data goes out and is acknowledged first; the application finishes
    // later, so the FIN rides a zero-length frame (§19.8). Its acknowledgment
    // carries no bytes and is still what ends the stream.
    var buffer: [8]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("ab");
    _ = stream.nextSegment(8).?;
    try stream.onAck(0, 2);
    try testing.expectEqual(State.send, stream.state);

    try stream.finish();
    const fin = stream.nextSegment(8).?;
    try testing.expect(fin.fin);
    try testing.expectEqual(@as(usize, 0), fin.data.len);
    try testing.expectEqual(State.data_sent, stream.state);

    try stream.onAck(fin.offset, 0);
    try testing.expectEqual(State.data_recvd, stream.state);
}

test "RFC 9000 §13.3, a lost range goes again at its own offset, before new data" {
    var buffer: [32]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("0123456789");
    _ = stream.nextSegment(4).?;
    _ = stream.nextSegment(4).?;
    try stream.write("abcd");

    // The packet with [4, 8) is lost: the bytes are still in the buffer, so the
    // range is unsent again and nothing is copied.
    stream.onLost(4, 4, false);
    const again = stream.nextSegment(16).?;
    try testing.expect(again.retransmit);
    try testing.expectEqual(@as(u64, 4), again.offset);
    try testing.expectEqualStrings("4567", again.data);
    try testing.expect(!again.fin);
    // §13.3 puts the retransmission ahead of the bytes never sent, which come
    // next and are not marked as a retransmission.
    const fresh = stream.nextSegment(16).?;
    try testing.expect(!fresh.retransmit);
    try testing.expectEqual(@as(u64, 8), fresh.offset);
    try testing.expectEqualStrings("89abcd", fresh.data);
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(16));
}

test "RFC 9000 §13.3, a lost range is cut to the packet and to what was acknowledged" {
    var buffer: [32]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("0123456789");
    _ = stream.nextSegment(10).?;

    // A later copy of [0, 3) was acknowledged, so only [3, 10) goes again.
    try stream.onAck(0, 3);
    stream.onLost(0, 10, false);
    const first = stream.nextSegment(4).?;
    try testing.expectEqual(@as(u64, 3), first.offset);
    try testing.expectEqualStrings("3456", first.data);
    // An acknowledgment that arrives while the rest waits trims it too.
    try stream.onAck(3, 5);
    const rest = stream.nextSegment(16).?;
    try testing.expectEqual(@as(u64, 8), rest.offset);
    try testing.expectEqualStrings("89", rest.data);
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(16));
}

test "RFC 9000 §13.3, a lost FIN goes again, alone or on the last bytes" {
    var buffer: [16]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("abcd");
    try stream.finish();
    const all = stream.nextSegment(16).?;
    try testing.expect(all.fin);
    try testing.expectEqual(State.data_sent, stream.state);

    // The whole frame is lost: the bytes and the FIN go together again.
    stream.onLost(0, 4, true);
    const again = stream.nextSegment(16).?;
    try testing.expectEqualStrings("abcd", again.data);
    try testing.expect(again.fin);
    try testing.expectEqual(State.data_sent, stream.state);

    try stream.onAck(0, 4);
    try testing.expectEqual(State.data_recvd, stream.state);

    // The data went and was acknowledged before the application finished, so
    // the FIN rode a frame of its own, and that frame is lost: §19.8's
    // zero-length frame at the final size says it again.
    var late: SendStream = .init(0, &buffer, 1000);
    try late.write("ab");
    _ = late.nextSegment(16).?;
    try late.onAck(0, 2);
    try late.finish();
    _ = late.nextSegment(16).?;
    late.onLost(2, 0, true);
    const fin = late.nextSegment(16).?;
    try testing.expect(fin.fin and fin.retransmit);
    try testing.expectEqual(@as(u64, 2), fin.offset);
    try testing.expectEqual(@as(usize, 0), fin.data.len);
    try testing.expectEqual(@as(?Segment, null), late.nextSegment(16));
    try late.onAck(2, 0);
    try testing.expectEqual(State.data_recvd, late.state);
}

test "RFC 9000 §13.3, a reset stream sends no lost STREAM data" {
    var buffer: [16]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write("abcd");
    _ = stream.nextSegment(16).?;
    stream.onLost(0, 4, false);
    try stream.reset(7);
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(16));
    // A loss reported after the reset is not owed either.
    stream.onLost(0, 4, false);
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(16));
}

test "RFC 9000 §13.3, more lost runs than the table holds collapse and lose nothing" {
    var buffer: [64]u8 = undefined;
    var stream: SendStream = .init(0, &buffer, 1000);
    try stream.write(&@as([40]u8, @splat('x')));
    _ = stream.nextSegment(40).?;

    // Every other two-byte run, one more than `lost_capacity`.
    var run: u64 = 0;
    while (run <= lost_capacity) : (run += 1) stream.onLost(run * 4, 2, false);
    try testing.expectEqual(@as(usize, 1), stream.lost_len);
    // One run from the first lost byte to the last: bounded, and nothing lost
    // is forgotten, which is the trade §2.2 allows.
    const again = stream.nextSegment(64).?;
    try testing.expectEqual(@as(u64, 0), again.offset);
    try testing.expectEqual(@as(usize, lost_capacity * 4 + 2), again.data.len);
    try testing.expectEqual(@as(?Segment, null), stream.nextSegment(64));
}
