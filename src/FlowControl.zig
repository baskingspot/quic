//! Connection-level flow control, RFC 9000 §4.1 and §4.2.
//!
//! Two counters and a limit. §4.1 makes flow control limit-based: a receiver
//! advertises a maximum, and a sender may not exceed it. The stream-level limit
//! lives with the stream; this is the connection-wide one, which counts the
//! highest offset reached on every stream rather than the bytes delivered.
//!
//! §4.2: a limit never decreases, and a frame that does not increase it has no
//! effect.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const FlowControl = @This();

/// The limit this endpoint has advertised to its peer.
limit: u64,
/// The sum of the highest offsets received across all streams, which is what
/// §4.1 says the limit is compared against.
used: u64 = 0,
/// §4.2: the window this receiver keeps open ahead of what the application has
/// consumed. It starts at the configured limit and stays there: a raise moves
/// the advertised limit, not the size of the window.
window: u64,

/// A receiver's controller, starting from the limit it sends in its transport
/// parameters.
pub fn init(limit: u64) FlowControl {
    // §16: a MAX_DATA value is a variable-length integer, so a window that does
    // not fit one could never be advertised.
    assert(limit <= (1 << 62) - 1);
    return .{ .limit = limit, .window = limit };
}

pub const Error = error{
    /// §4.1: "A receiver MUST close the connection with an error of type
    /// FLOW_CONTROL_ERROR if the sender violates the advertised connection or
    /// stream data limits."
    FlowControl,
};

/// Account for a stream's highest offset moving forward by `delta` bytes.
pub fn onStreamProgress(self: *FlowControl, delta: u64) Error!void {
    const next = self.used + delta;
    if (next > self.limit) return error.FlowControl;
    self.used = next;
}

/// §4.2: the limit to put in a MAX_DATA frame, or null when the peer already
/// has enough credit.
///
/// `consumed` is how many bytes the application has taken out of its receive
/// rings, which is the only thing that may open a window: advertising credit
/// the ring cannot back is how a receiver talks itself into `error.NoSpace`.
/// The target keeps `window` bytes ahead of consumption, and a raise is worth a
/// frame only once the credit left is under half a window. That half window is
/// the hysteresis: without it, every read call that consumed a byte would owe a
/// frame.
pub fn nextLimit(self: *const FlowControl, consumed: u64) ?u64 {
    // The application cannot have read what never arrived.
    assert(consumed <= self.used);

    const target = consumed + self.window;
    if (target <= self.limit) return null;
    if (self.limit - consumed >= self.window / 2) return null;
    return target;
}

/// §4.2: apply a limit the peer advertised. A smaller limit is ignored.
pub fn raise(self: *FlowControl, limit: u64) void {
    if (limit > self.limit) self.limit = limit;
}

/// The sender's view of the peer's connection-wide limit.
pub const Sender = struct {
    limit: u64,
    sent: u64 = 0,

    pub fn init(limit: u64) Sender {
        return .{ .limit = limit };
    }

    /// Whether `bytes` more may be sent on any stream.
    pub fn allows(self: *const Sender, bytes: u64) bool {
        return self.sent + bytes <= self.limit;
    }

    /// How many more bytes may be sent before the connection is blocked.
    pub fn available(self: *const Sender) u64 {
        return self.limit - self.sent;
    }

    pub fn onSent(self: *Sender, bytes: u64) Error!void {
        if (!self.allows(bytes)) return error.FlowControl;
        self.sent += bytes;
    }

    /// §4.1: "A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that
    /// do not increase flow control limits."
    pub fn onMaxData(self: *Sender, limit: u64) void {
        if (limit > self.limit) self.limit = limit;
    }
};

test "RFC 9000 §4.1, a receiver permits exactly the advertised total" {
    var flow: FlowControl = .init(1000);
    try flow.onStreamProgress(600);
    try flow.onStreamProgress(400);
    try testing.expectError(error.FlowControl, flow.onStreamProgress(1));
    try testing.expectEqual(@as(u64, 1000), flow.used);
}

test "RFC 9000 §4.2, a receiver raises the limit once half the window is consumed" {
    const window: u64 = 40_000;
    var flow: FlowControl = .init(window);
    try flow.onStreamProgress(window);

    // Nothing has been read, so nothing is due.
    try testing.expectEqual(@as(?u64, null), flow.nextLimit(0));

    // §4.2: exactly half a window consumed still leaves half the window of
    // credit ahead, which is enough for the peer to keep going.
    try testing.expectEqual(@as(?u64, null), flow.nextLimit(window / 2));

    // One byte past half is where the credit left drops under half a window, so
    // the raise is due, and it keeps a full window ahead of what was read.
    const consumed = window / 2 + 1;
    try testing.expectEqual(@as(?u64, consumed + window), flow.nextLimit(consumed));
    flow.raise(consumed + window);

    // The window slid, so the next raise is another half window of reading
    // later, not the next read call. The peer keeps sending, or the application
    // could not read what `next` names.
    try flow.onStreamProgress(20_000);
    try testing.expectEqual(@as(?u64, null), flow.nextLimit(consumed + 1));
    const next = consumed + window / 2 + 1;
    try testing.expectEqual(@as(?u64, next + window), flow.nextLimit(next));

    // A smaller limit is not a decrease (§4.2).
    flow.raise(10);
    try testing.expectEqual(consumed + window, flow.limit);
}

test "RFC 9000 §4.1, a sender stops at the connection limit and ignores a smaller one" {
    var sender: Sender = .init(2000);
    try sender.onSent(1200);
    try testing.expectEqual(@as(u64, 800), sender.available());

    try testing.expectError(error.FlowControl, sender.onSent(900));
    try testing.expectEqual(@as(u64, 1200), sender.sent);

    // §4.1: an increase applies, a decrease does not.
    sender.onMaxData(1000);
    try testing.expectEqual(@as(u64, 2000), sender.limit);
    sender.onMaxData(3000);
    try testing.expectEqual(@as(u64, 3000), sender.limit);
    try sender.onSent(800);
    try testing.expectEqual(@as(u64, 1000), sender.available());
}
