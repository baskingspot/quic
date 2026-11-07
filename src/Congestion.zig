//! NewReno congestion control, RFC 9002 §7.
//!
//! This is the part of §7 that is about being correct rather than about being a
//! full transport. In: bytes in flight, the initial and minimum window, slow
//! start, congestion avoidance with a carried residue, one window reduction per
//! recovery period, and persistent congestion handed in by `Recovery`. Out:
//! pacing (§7.7), application-limited growth (§7.8), HyStart++, BBR, PRR, MTU
//! probe special cases, and ECN.
//!
//! Nothing here reads a clock. The caller passes the send time of the packet it
//! is reporting on and, for a loss, the time the loss was detected, which is what
//! §7.3.2 means by the start of a recovery period.
//!
//! The controller does not own the sent packets: `Recovery.Space` does. It owns
//! the byte count, because that is the number the window is compared against,
//! and the caller says which packets are in flight when it reports them.

const std = @import("std");
const testing = std.testing;
const Recovery = @import("Recovery.zig");

const Congestion = @This();

pub const Duration = Recovery.Duration;

/// RFC 9002 §7.2: the initial window is ten maximum datagram sizes.
pub const initial_window_packets: u64 = 10;

/// RFC 9002 §7.2: "limiting the window to the larger of 14,720 bytes or twice
/// the maximum datagram size".
pub const initial_window_bytes: u64 = 14_720;

/// RFC 9002 §7.2: "The RECOMMENDED value is 2 * max_datagram_size."
pub const minimum_window_packets: u64 = 2;

/// The largest datagram we will be told about. the wire limit is 65527 (§14.1 of
/// RFC 9000), and the field exists to catch a caller passing a bogus value.
pub const max_datagram_size_limit: u32 = 65527;

/// What a loss report changed.
pub const Loss = struct {
    /// Whether this report started a new recovery period and reduced the
    /// window. A loss inside the current period still leaves `false`, which is
    /// the property a test can assert without inferring it from the window.
    reduced: bool,
    /// The recovery period's start after this report: the detection time of the
    /// loss that began it. A packet whose send time is at or before it is inside
    /// the period. Null when no loss has been reported.
    recovery_start: ?Duration = null,
};

max_datagram_size: u32,
/// Bytes in flight, as reported by `onPacketSent`, `onPacketAcked` and
/// `onPacketsLost`.
bytes_in_flight: u64 = 0,
/// The congestion window in bytes (§7.1: "the controller's congestion window in
/// bytes").
window: u64,
/// Slow start while `window < ssthresh`; §7.3.1 starts it at infinity.
ssthresh: u64 = std.math.maxInt(u64),
/// §7.3.2: "The recovery period aims to limit congestion window reduction to
/// once per round trip."
recovery_start: ?Duration = null,
/// §7.3.3's increase carries its remainder so the window grows by exactly one
/// datagram per window, rather than drifting low.
residue: u64 = 0,

/// A controller for a path with this maximum datagram size.
pub fn init(max_datagram_size: u32) Congestion {
    std.debug.assert(max_datagram_size > 0);
    std.debug.assert(max_datagram_size <= max_datagram_size_limit);
    const mds: u64 = max_datagram_size;
    return .{
        .max_datagram_size = max_datagram_size,
        .window = @min(
            initial_window_packets * mds,
            @max(initial_window_bytes, minimum_window_packets * mds),
        ),
    };
}

/// §7.2: the floor the window may be reduced to.
pub fn minimumWindow(self: *const Congestion) u64 {
    return minimum_window_packets * self.max_datagram_size;
}

/// §7.3.1: a sender is in slow start while the window is below the threshold.
pub fn inSlowStart(self: *const Congestion) bool {
    return self.window < self.ssthresh;
}

pub fn inRecovery(self: *const Congestion) bool {
    return self.recovery_start != null;
}

/// §7.1: "An endpoint MUST NOT send a packet if it would cause bytes_in_flight
/// to be larger than the congestion window". The two exceptions in the same
/// paragraph, a PTO probe and the packet that enters recovery, are the caller's
/// to apply: this only answers the arithmetic question.
pub fn canSend(self: *const Congestion, bytes: u32) bool {
    return self.bytes_in_flight + bytes <= self.window;
}

/// Note a packet that was sent. `in_flight` is false for a packet that carries
/// only frames that are not congestion controlled (§7).
pub fn onPacketSent(self: *Congestion, bytes: u32, in_flight: bool) void {
    if (in_flight) self.bytes_in_flight += bytes;
}

/// §7.3.1 and §7.3.3. `sent_time` is when the acknowledged packet was sent: a
/// packet sent inside the recovery period does not grow the window (§7.3.2).
pub fn onPacketAcked(self: *Congestion, bytes: u32, in_flight: bool, sent_time: Duration) void {
    if (in_flight) self.bytes_in_flight -|= bytes;

    if (self.recovery_start) |start| {
        if (sent_time <= start) return;
        // §7.3.2: "A recovery period ends and the sender enters congestion
        // avoidance when a packet sent during the recovery period is
        // acknowledged."
        self.recovery_start = null;
    }

    if (self.inSlowStart()) {
        // §7.3.1: "the congestion window increases by the number of bytes
        // acknowledged".
        self.window += bytes;
        return;
    }

    // §7.3.3: at most one datagram per window acknowledged. The multiplication
    // and the remainder are the RFC 3465 form, which is exact over many
    // acknowledgments where adding a fraction per packet would drift.
    const mds: u64 = self.max_datagram_size;
    const increase = mds * bytes + self.residue;
    self.residue = increase % self.window;
    self.window += increase / self.window;
}

/// §7.3 and §7.6: report packets declared lost.
///
/// `largest_lost_sent_time` is the send time of the largest lost packet, which
/// decides whether this loss is inside the current recovery period. `now` is
/// when the loss was detected, and becomes the period's start. `persistent` is
/// §7.6.2's verdict, computed by `Recovery`.
pub fn onPacketsLost(
    self: *Congestion,
    lost_bytes: u32,
    largest_lost_sent_time: Duration,
    now: Duration,
    persistent: bool,
) Loss {
    self.bytes_in_flight -|= lost_bytes;

    if (self.recovery_start) |start| {
        if (largest_lost_sent_time <= start) {
            // §7.3.2: during a recovery period the window does not change in
            // response to new losses.
            return .{ .reduced = false, .recovery_start = start };
        }
    }

    // §7.3.2: "set the slow start threshold to half the value of the congestion
    // window when loss is detected" and reduce the window to it. The floor is
    // the minimum window from §7.2.
    self.ssthresh = @max(self.window / 2, self.minimumWindow());
    self.window = self.ssthresh;
    self.residue = 0;
    self.recovery_start = now;

    if (persistent) {
        // §7.6.2: "the congestion window MUST be reduced to the minimum
        // congestion window". The threshold keeps the halved value, so the
        // window is now below it and §7.3.1 puts the sender back in slow start.
        self.window = self.minimumWindow();
    }

    return .{ .reduced = true, .recovery_start = self.recovery_start };
}

test "RFC 9002 §7.2, the initial window and the floor" {
    // 10 * 1200 = 12000, under the 14720 byte limit.
    const small: Congestion = .init(1200);
    try testing.expectEqual(@as(u64, 12_000), small.window);
    try testing.expectEqual(@as(u64, 2400), small.minimumWindow());

    // 10 * 1500 = 15000 is above it, so the limit binds at 14720.
    const large: Congestion = .init(1500);
    try testing.expectEqual(@as(u64, 14_720), large.window);

    // A datagram size where twice the size beats 14720: 8000 * 10 = 80000 over
    // the limit, and 2 * 8000 = 16000 is the larger of the two, so it binds.
    const huge: Congestion = .init(8000);
    try testing.expectEqual(@as(u64, 16_000), huge.window);

    try testing.expect(small.inSlowStart());
    try testing.expect(!small.inRecovery());
}

test "RFC 9002 §7.3.1, slow start adds the bytes acknowledged" {
    var cc: Congestion = .init(1200);
    const start = cc.window;

    cc.onPacketSent(1200, true);
    cc.onPacketAcked(1200, true, 1);
    try testing.expectEqual(start + 1200, cc.window);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);

    // Four at once, as one ACK would deliver them.
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        cc.onPacketSent(1200, true);
        cc.onPacketAcked(1200, true, 2);
    }
    try testing.expectEqual(start + 5 * 1200, cc.window);
    try testing.expect(cc.inSlowStart());
}

test "RFC 9002 §7.3.3, congestion avoidance grows by one datagram per window, exactly" {
    var cc: Congestion = .init(1200);
    // Drive it into congestion avoidance with a loss: 12000 -> 6000.
    cc.onPacketSent(1200, true);
    const loss = cc.onPacketsLost(1200, 100, 110, false);
    try testing.expect(loss.reduced);
    try testing.expectEqual(@as(u64, 6000), cc.window);
    try testing.expectEqual(@as(u64, 6000), cc.ssthresh);
    try testing.expect(!cc.inSlowStart());

    // One acknowledgment of 1200 bytes: 1200 * 1200 = 1,440,000, and
    // 1,440,000 / 6000 is exactly 240, so the window becomes 6240 and nothing
    // is left over.
    cc.onPacketSent(1200, true);
    cc.onPacketAcked(1200, true, 200);
    try testing.expectEqual(@as(u64, 6240), cc.window);
    try testing.expectEqual(@as(u64, 0), cc.residue);

    // The next one divides by the new window: 1,440,000 % 6240 = 4800 is
    // carried, and 1,440,000 / 6240 = 230 is added, so the window is 6470 with
    // 4800 waiting. That is the residue the RFC's "one datagram per window"
    // leaves to the implementer.
    cc.onPacketSent(1200, true);
    cc.onPacketAcked(1200, true, 210);
    try testing.expectEqual(@as(u64, 6470), cc.window);
    try testing.expectEqual(@as(u64, 4800), cc.residue);
}

test "RFC 9002 §7.3.2, one loss episode halves the window once" {
    var cc: Congestion = .init(1200);
    cc.window = 20_000;

    // The first loss is detected at t=110 and was sent at t=100.
    const first = cc.onPacketsLost(1200, 100, 110, false);
    try testing.expect(first.reduced);
    try testing.expectEqual(@as(?Duration, 110), first.recovery_start);
    try testing.expectEqual(@as(u64, 10_000), cc.window);

    // A second loss in the same episode does not halve again.
    const second = cc.onPacketsLost(1200, 105, 115, false);
    try testing.expect(!second.reduced);
    try testing.expectEqual(@as(?Duration, 110), second.recovery_start);
    try testing.expectEqual(@as(u64, 10_000), cc.window);

    // A packet sent after the period started, acked, ends the period, and its
    // acknowledgment grows the window because the window is now at the
    // threshold: 1200 * 1200 = 1,440,000, and 1,440,000 / 10,000 = 144 exactly.
    cc.onPacketSent(1200, true);
    cc.onPacketAcked(1200, true, 120);
    try testing.expect(cc.recovery_start == null);
    try testing.expectEqual(@as(u64, 10_144), cc.window);

    // Now a later loss is a new episode and halves that window again.
    const third = cc.onPacketsLost(1200, 130, 140, false);
    try testing.expect(third.reduced);
    try testing.expectEqual(@as(?Duration, 140), third.recovery_start);
    try testing.expectEqual(@as(u64, 5072), cc.window);
}

test "RFC 9002 §7.2, the window never goes below twice the datagram size" {
    var cc: Congestion = .init(1200);
    cc.window = 3000;
    const loss = cc.onPacketsLost(1200, 0, 10, false);
    try testing.expect(loss.reduced);
    // Half of 3000 is 1500, under the 2400 floor.
    try testing.expectEqual(@as(u64, 2400), cc.window);
    try testing.expectEqual(@as(u64, 2400), cc.ssthresh);
}

test "RFC 9002 §7.6.2, persistent congestion drops the window to the floor" {
    var cc: Congestion = .init(1200);
    cc.window = 12_000;

    const loss = cc.onPacketsLost(1200, 100, 110, true);
    try testing.expect(loss.reduced);
    try testing.expectEqual(@as(u64, 2400), cc.window);
    try testing.expectEqual(@as(u64, 6000), cc.ssthresh);
    // §7.3.1: the window is now below the threshold, so slow start resumes.
    try testing.expect(cc.inSlowStart());
}

test "RFC 9002 §7, bytes in flight follow what the caller says is in flight" {
    var cc: Congestion = .init(1200);
    cc.onPacketSent(1000, true);
    cc.onPacketSent(200, false); // an ACK-only packet is not congestion controlled
    try testing.expectEqual(@as(u64, 1000), cc.bytes_in_flight);

    cc.onPacketAcked(200, false, 1);
    try testing.expectEqual(@as(u64, 1000), cc.bytes_in_flight);

    _ = cc.onPacketsLost(1000, 1, 2, false);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
    try testing.expect(!cc.canSend(13_000));
    try testing.expect(cc.canSend(1200));
}

test "RFC 9002 §7.3.2, Recovery's loss event halves the window exactly once" {
    const frame = @import("frame.zig");
    const ms = Recovery.ms;

    var estimate: Recovery = .{};
    var sent: [16]Recovery.SentPacket = undefined;
    var space = estimate.space(&sent);
    var cc: Congestion = .init(1200);

    var pn: u64 = 0;
    while (pn < 6) : (pn += 1) {
        try space.onPacketSent(pn, ms(10), true, true, 1200);
        cc.onPacketSent(1200, true);
    }

    // Acknowledge only packet 5. The packet threshold makes 0, 1 and 2 lost.
    const ack: frame.Ack = .{
        .largest = 5,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]Recovery.SentPacket = undefined;
    var events_lost: [64]Recovery.SentPacket = undefined;
    var events: Recovery.Events = .init(&events_acked, &events_lost);
    try space.onAckReceived(&ack, ms(30), .{}, &events);
    try testing.expectEqual(@as(usize, 3), events.lostPackets().len);
    try testing.expectEqual(@as(u32, 3600), events.lost_bytes);

    // The acknowledgment grows the window in slow start, then the loss halves
    // it: 12000 + 1200 = 13200, and 13200 / 2 = 6600.
    cc.onPacketAcked(events.acked_bytes, true, ms(10));
    const loss = cc.onPacketsLost(
        events.lost_bytes,
        events.largest_lost_sent_time,
        ms(30),
        events.persistent_congestion,
    );
    try testing.expect(loss.reduced);
    try testing.expectEqual(@as(?Duration, ms(30)), loss.recovery_start);
    try testing.expectEqual(@as(u64, 6600), cc.window);

    // A second loss of a packet sent inside that period does not halve again.
    const second = cc.onPacketsLost(1200, ms(10), ms(40), false);
    try testing.expect(!second.reduced);
    try testing.expectEqual(@as(?Duration, ms(30)), second.recovery_start);
    try testing.expectEqual(@as(u64, 6600), cc.window);

    // A packet sent after the period began, acknowledged, ends it: the window
    // is at the threshold, so this is congestion avoidance, and 1440000 / 6600
    // is 218 with 1200 carried.
    cc.onPacketSent(1200, true);
    cc.onPacketAcked(1200, true, ms(50));
    try testing.expect(cc.recovery_start == null);
    try testing.expectEqual(@as(u64, 6818), cc.window);
    try testing.expectEqual(@as(u64, 1200), cc.residue);
}
