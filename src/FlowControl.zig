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
const testing = std.testing;

const FlowControl = @This();

/// The limit this endpoint has advertised to its peer.
limit: u64,
/// The sum of the highest offsets received across all streams, which is what
/// §4.1 says the limit is compared against.
used: u64 = 0,
/// The smallest limit worth advertising: a window that shrinks below this is
/// not worth a frame.
pub const minimum_increment: u64 = 1 << 14;

/// A receiver's controller, starting from the limit it sends in its transport
/// parameters.
pub fn init(limit: u64) FlowControl {
    return .{ .limit = limit };
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

/// §4.2: the receiver raises the limit once the peer has consumed most of the
/// window. This returns the new limit to put in a MAX_DATA frame, or null when
/// nothing needs sending.
pub fn nextLimit(self: *const FlowControl, consumed: u64) ?u64 {
    const target = consumed + minimum_increment;
    if (target <= self.limit) return null;
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

test "RFC 9000 §4.2, a receiver raises the limit only when it must" {
    var flow: FlowControl = .init(1000);
    // 500 consumed: a new window of 500 + 16384 is larger, so advertise it.
    try testing.expectEqual(@as(?u64, 500 + minimum_increment), flow.nextLimit(500));
    flow.raise(500 + minimum_increment);
    // Nothing more to say until the peer has consumed another increment: at
    // 100 bytes consumed the window still has more than `minimum_increment`
    // left in it.
    try testing.expectEqual(@as(?u64, null), flow.nextLimit(100));
    // At 600 it does not: 600 + 16384 is past the advertised limit.
    try testing.expectEqual(@as(?u64, 600 + minimum_increment), flow.nextLimit(600));

    // A smaller limit is not a decrease (§4.2).
    flow.raise(10);
    try testing.expectEqual(@as(u64, 500 + minimum_increment), flow.limit);
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
