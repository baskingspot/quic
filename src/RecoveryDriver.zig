//! The timer side of recovery: when to wake up, and what to do when you do.
//!
//! `Recovery.Space` knows its own deadline and how to react to it firing. A
//! connection has several spaces and one timer, so something has to arbitrate:
//! this is that thing, and it is deliberately the smallest piece in the package.
//!
//! There is no clock. The caller passes the current time in nanoseconds, the
//! driver answers with a deadline and, when that deadline has passed, the event
//! that the caller must service. Two calls at the same time cannot both fire:
//! firing changes the state the deadline is computed from, so the second call
//! sees a deadline in the future. That property is the whole reason the driver
//! recomputes instead of caching an armed flag.

const std = @import("std");
const testing = std.testing;
const Recovery = @import("Recovery.zig");
const frame = @import("frame.zig");

const RecoveryDriver = @This();

pub const Duration = Recovery.Duration;
pub const Options = Recovery.Options;

/// One timer for every space: the earliest loss time, or failing that the
/// earliest probe timeout (§6.2.1: with ack-eliciting packets in several
/// spaces, the earliest value wins).
pub const Deadline = struct {
    kind: Recovery.TimerKind,
    at: Duration = 0,
    /// Which space the deadline belongs to.
    space: usize = 0,
};

/// What the caller must do when the deadline passes.
pub const Fired = struct {
    kind: Recovery.TimeoutKind,
    space: usize,
    /// Probe packets to send, for a probe timeout.
    probes: u8 = 0,
};

shared: *Recovery,
/// The spaces this connection has, in whatever order the caller keeps them.
/// A discarded space stays in the slice and reports no timer.
spaces: []const *Recovery.Space,

pub fn init(shared: *Recovery, spaces: []const *Recovery.Space) RecoveryDriver {
    return .{ .shared = shared, .spaces = spaces };
}

/// The next deadline, or null when nothing is armed.
///
/// A.8 checks the loss timers first: a time-threshold loss that is due beats a
/// probe timeout that would fire sooner, because the loss is information and
/// the probe is a guess.
pub fn deadline(self: *const RecoveryDriver, options: Options) Deadline {
    var best: Deadline = .{ .kind = .none };

    for (self.spaces, 0..) |space, index| {
        if (space.loss_time == 0) continue;
        if (best.kind != .loss or space.loss_time < best.at) {
            best = .{ .kind = .loss, .at = space.loss_time, .space = index };
        }
    }
    if (best.kind == .loss) return best;

    for (self.spaces, 0..) |space, index| {
        const timer = space.nextTimer(options);
        if (timer.kind != .probe) continue;
        if (best.kind == .none or timer.at < best.at) {
            best = .{ .kind = .probe, .at = timer.at, .space = index };
        }
    }
    return best;
}

/// Fire the deadline if `now` has reached it.
///
/// `events` receives the loss set for a loss timeout, over storage the caller
/// sized with `Recovery.Events.init`. Returns null when there is nothing to
/// do: no deadline, a deadline still in the future, or a deadline
/// that passed while the state moved on (everything acknowledged, keys
/// discarded), in which case the driver simply forgets it.
pub fn poll(
    self: *RecoveryDriver,
    now: Duration,
    options: Options,
    side: Recovery.Side,
    events: *Recovery.Events,
) Recovery.Error!?Fired {
    var due = self.deadline(options);
    if (due.kind == .none) return null;
    if (now < due.at) return null;

    // The deadline may have been computed before the state changed; ask again
    // with the current state rather than trusting a stale time.
    due = self.deadline(options);
    if (due.kind == .none) return null;
    if (now < due.at) return null;

    const space = self.spaces[due.space];
    const fired = try space.onTimeout(side, now, options, events);
    return .{ .kind = fired.kind, .space = due.space, .probes = fired.probes };
}

/// §6.4: a space's keys were discarded. The caller says which space; the driver
/// forgets it and the next deadline is computed without it.
pub fn onKeysDiscarded(self: *RecoveryDriver, space: *Recovery.Space) void {
    _ = self;
    space.discard();
}

const Harness = struct {
    shared: Recovery = .{},
    sent_a: [16]Recovery.SentPacket = undefined,
    sent_b: [16]Recovery.SentPacket = undefined,
    space_a: Recovery.Space = undefined,
    space_b: Recovery.Space = undefined,
    pointers: [2]*Recovery.Space = undefined,
    driver: RecoveryDriver = undefined,

    fn init(self: *Harness) void {
        self.space_a = self.shared.space(&self.sent_a);
        self.space_b = self.shared.space(&self.sent_b);
        self.pointers = .{ &self.space_a, &self.space_b };
        self.driver = .init(&self.shared, &self.pointers);
    }
};

test "RFC 9002 §6.2.1, a probe timeout fires once per arm and backs off" {
    var h: Harness = .{};
    h.init();
    const ms = Recovery.ms;
    h.shared.rtt.onSample(0, ms(80), 0, .{}); // smoothed 80, variance 40
    try h.space_a.onPacketSent(0, ms(10), true, true, 1200);

    // 80 + 4*40 = 240ms after the packet was sent.
    const first = h.driver.deadline(.{});
    try testing.expectEqual(Recovery.TimerKind.probe, first.kind);
    try testing.expectEqual(ms(10) + ms(240), first.at);

    // Before the deadline: nothing.
    var events_acked: [64]Recovery.SentPacket = undefined;
    var events_lost: [64]Recovery.SentPacket = undefined;
    var events: Recovery.Events = .init(&events_acked, &events_lost);
    try testing.expect((try h.driver.poll(ms(10) + ms(239), .{}, .client, &events)) == null);

    // At the deadline: one probe, and the backoff doubled the next arm.
    const fired = (try h.driver.poll(ms(10) + ms(240), .{}, .client, &events)).?;
    try testing.expectEqual(Recovery.TimeoutKind.probe, fired.kind);
    try testing.expectEqual(@as(usize, 0), fired.space);
    try testing.expectEqual(@as(u8, 2), fired.probes);

    const second = h.driver.deadline(.{});
    try testing.expectEqual(ms(10) + ms(480), second.at);

    // The same instant again: already fired, nothing to do.
    try testing.expect((try h.driver.poll(ms(10) + ms(240), .{}, .client, &events)) == null);

    // The next deadline fires once more, and doubles again.
    const again = (try h.driver.poll(ms(10) + ms(480), .{}, .client, &events)).?;
    try testing.expectEqual(Recovery.TimeoutKind.probe, again.kind);
    try testing.expectEqual(ms(10) + ms(960), h.driver.deadline(.{}).at);
}

test "RFC 9002 §6.1.2, a loss deadline fires once" {
    var h: Harness = .{};
    h.init();
    const ms = Recovery.ms;
    try h.space_a.onPacketSent(0, 0, true, true, 1200);
    try h.space_a.onPacketSent(1, 0, true, true, 1200);

    const ack: frame.Ack = .{
        .largest = 1,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]Recovery.SentPacket = undefined;
    var events_lost: [64]Recovery.SentPacket = undefined;
    var events: Recovery.Events = .init(&events_acked, &events_lost);
    try h.space_a.onAckReceived(&ack, ms(100), .{}, &events);

    const due = h.driver.deadline(.{});
    try testing.expectEqual(Recovery.TimerKind.loss, due.kind);
    try testing.expectEqual(ms(112) + 500_000, due.at);

    const fired = (try h.driver.poll(due.at, .{}, .client, &events)).?;
    try testing.expectEqual(Recovery.TimeoutKind.loss, fired.kind);
    try testing.expectEqual(@as(usize, 1), events.lostPackets().len);

    // Idempotent at the same instant, and nothing left to arm.
    try testing.expect((try h.driver.poll(due.at, .{}, .client, &events)) == null);
    try testing.expectEqual(Recovery.TimerKind.none, h.driver.deadline(.{}).kind);
}

test "RFC 9002 Appendix A.8, a deadline that passes with nothing in flight does nothing" {
    var h: Harness = .{};
    h.init();
    const ms = Recovery.ms;
    try h.space_a.onPacketSent(0, ms(10), true, true, 1200);

    const armed = h.driver.deadline(.{});
    try testing.expectEqual(Recovery.TimerKind.probe, armed.kind);

    // Everything is acknowledged before the timer fires.
    const ack: frame.Ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]Recovery.SentPacket = undefined;
    var events_lost: [64]Recovery.SentPacket = undefined;
    var events: Recovery.Events = .init(&events_acked, &events_lost);
    try h.space_a.onAckReceived(&ack, ms(20), .{}, &events);
    try testing.expectEqual(Recovery.TimerKind.none, h.driver.deadline(.{}).kind);

    // The old deadline passes with nothing in flight: no event.
    try testing.expect((try h.driver.poll(armed.at, .{}, .client, &events)) == null);
}

test "RFC 9002 Appendix A.8, a due loss timer beats a probe that would fire sooner" {
    var h: Harness = .{};
    h.init();
    const ms = Recovery.ms;
    h.shared.rtt.onSample(0, ms(100), 0, .{});

    // Space B has a PTO soon after its packet.
    try h.space_b.onPacketSent(0, ms(10), true, true, 1200);
    const probe = h.driver.deadline(.{});
    try testing.expectEqual(Recovery.TimerKind.probe, probe.kind);
    try testing.expectEqual(@as(usize, 1), probe.space);
    try testing.expectEqual(ms(10) + ms(300), probe.at);

    // Space A acquires a loss time further out. A.8 makes the loss timer win
    // even though the probe would fire first.
    h.space_a.loss_time = ms(10) + ms(400);
    const chosen = h.driver.deadline(.{});
    try testing.expectEqual(Recovery.TimerKind.loss, chosen.kind);
    try testing.expectEqual(@as(usize, 0), chosen.space);
}

test "RFC 9002 §6.4, discarding a space removes its timer and keeps the RTT" {
    var h: Harness = .{};
    h.init();
    const ms = Recovery.ms;
    h.shared.rtt.onSample(0, ms(80), 0, .{});
    try h.space_a.onPacketSent(0, ms(10), true, true, 1200);
    try testing.expectEqual(@as(usize, 0), h.driver.deadline(.{}).space);

    h.driver.onKeysDiscarded(&h.space_a);
    try testing.expectEqual(Recovery.TimerKind.none, h.driver.deadline(.{}).kind);
    try testing.expectEqual(@as(usize, 0), h.space_a.sent_len);

    // §6.4 removes the packets and the timers, not the path's estimate (A.2).
    try testing.expectEqual(ms(80), h.shared.rtt.smoothed);

    // A poll after the discard still does nothing.
    var events_acked: [64]Recovery.SentPacket = undefined;
    var events_lost: [64]Recovery.SentPacket = undefined;
    var events: Recovery.Events = .init(&events_acked, &events_lost);
    try testing.expect((try h.driver.poll(ms(1000), .{}, .client, &events)) == null);
}
