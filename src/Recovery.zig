//! Loss detection and round-trip estimation, RFC 9002 §5 and §6.
//!
//! Two levels of state, because the RFC has two: `Recovery` holds what belongs
//! to the connection, and `Space` holds what belongs to one packet number sp.
//!
//! - The RTT estimator is a property of the path, not of a space: Appendix A.2
//!   lists `latest_rtt`, `smoothed_rtt` and `rttvar` as connection variables.
//!   It lives in `Recovery`.
//! - `pto_count` is also connection-wide. A.8 doubles the timeout on every
//!   expiry and says the exponential increase "occurs across all spaces", so two
//!   spaces sharing a connection share one backoff, not two.
//! - Sent packets, `largest_acked`, the time threshold and the time of the last
//!   ack-eliciting packet are per space (A.1, A.8).
//!
//! The sent-packet storage is the caller's. `Space` keeps a slice the caller
//! supplies at `Recovery.space`, so the capacity is the connection's decision
//! and a full table is an error the caller sees, not a packet silently forgotten.
//!
//! The order of operations follows the pseudocode in Appendix A, which is the
//! normative form: A.7 for an acknowledgment, A.8 for the timer, A.9 for a
//! timeout, A.10 for the loss set. Where §5.3 lists the smoothed-RTT update
//! before the variance update and A.7 lists it after, this follows A.7, so the
//! variance is computed from the previous smoothed RTT. That is also what
//! RFC 6298 does.
//!
//! Durations are nanoseconds in a `u64`. The RTT smoothing divides by 8 and the
//! variance by 4, so a measurement that is not a multiple of those loses
//! sub-nanosecond precision, once. The time threshold divides by 8 too, and
//! rounds up: §6.1.2 says the threshold must not be too small, and rounding a
//! loss timer down is how a sender retransmits a packet that was merely late.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const frame = @import("frame.zig");
const varint = @import("varint.zig");
const Writer = @import("Writer.zig");

const Recovery = @This();

pub const Duration = u64;

/// Convert milliseconds to the internal unit.
pub fn ms(milliseconds: u64) Duration {
    return milliseconds * std.time.ns_per_ms;
}

/// RFC 9002 §6.1.1: "The RECOMMENDED initial value for the packet reordering
/// threshold (kPacketThreshold) is 3".
pub const packet_threshold: u64 = 3;

/// RFC 9002 §6.1.2: "The RECOMMENDED time threshold (kTimeThreshold) ...
/// is 9/8", as a numerator and denominator so the multiplication stays integer.
pub const time_threshold_numerator: u64 = 9;
pub const time_threshold_denominator: u64 = 8;

/// RFC 9002 §6.1.2: "The RECOMMENDED value of the timer granularity
/// (kGranularity) is 1 millisecond."
pub const granularity: Duration = ms(1);

/// RFC 9002 §6.2.2: "When no previous RTT is available, the initial RTT SHOULD
/// be set to 333 milliseconds."
pub const initial_rtt: Duration = ms(333);

/// Which endpoint is asking, for the two places §6.2 treats them differently.
pub const Side = enum { client, server };

pub const Options = struct {
    /// The peer's `max_ack_delay`. §6.2.1 sets it to zero for the Initial and
    /// Handshake spaces, so a space's PTO ignores it; the RTT estimator uses it
    /// after handshake confirmation.
    max_ack_delay: Duration = 0,
    /// §5.3: the peer's `max_ack_delay` limits a reported delay only after the
    /// handshake is confirmed.
    handshake_confirmed: bool = false,
    /// §6.2.1: a client that is not yet certain the server validated its
    /// address does not reset the PTO backoff on an acknowledgment.
    peer_address_validated: bool = true,
};

pub const Error = error{
    /// The caller's storage has no room: either the sent table cannot take
    /// another packet, or the event report cannot describe every packet the call
    /// would report. The caller owns both and sizes them for the connection.
    NoSpace,
    /// §19.3.1 of RFC 9000: the ACK's ranges do not describe packet numbers.
    InvalidAckRange,
};

pub const TimerKind = enum { none, loss, probe };
pub const TimeoutKind = enum { loss, probe };

/// A timer the caller should set, or the absence of one.
pub const Timer = struct {
    kind: TimerKind,
    /// When it should fire. Meaningless when `kind` is `.none`.
    at: Duration = 0,
};

/// What a timeout asked for.
pub const Timeout = struct {
    kind: TimeoutKind,
    /// How many ack-eliciting packets to send for a probe (§6.2.4). Zero for a
    /// loss timeout, whose packets are in `Events.lost`.
    probes: u8 = 0,
};

/// The sent packets a call reported. The records carry what a congestion
/// controller needs, because the packets are gone from the space by the time the
/// caller sees them.
///
/// The storage is the caller's, like the sent table itself: one record per
/// packet in flight, `acked` for what an acknowledgment cleared and `lost` for
/// what a timer did. A call that cannot describe every packet in the table
/// refuses to start rather than reporting part of an event, so the two arrays
/// must be at least as long as that table.
pub const Events = struct {
    acked: []SentPacket,
    acked_len: usize = 0,
    acked_bytes: u32 = 0,
    lost: []SentPacket,
    lost_len: usize = 0,
    lost_bytes: u32 = 0,
    /// The send time of the largest lost packet, which is what a controller
    /// compares against its recovery period (§7.3.2).
    largest_lost_sent_time: Duration = 0,
    /// §7.6.2: this acknowledgment established persistent congestion. The
    /// controller sets its window to the floor when it sees this.
    persistent_congestion: bool = false,

    /// A report over the caller's storage.
    pub fn init(acked: []SentPacket, lost: []SentPacket) Events {
        assert(acked.len > 0);
        assert(lost.len > 0);
        return .{ .acked = acked, .lost = lost };
    }

    /// Whether this report has a place for every record a table of `capacity`
    /// packets could produce. A call checks this before it looks at anything, so
    /// a report that is too small leaves the space untouched.
    pub fn fits(self: *const Events, capacity: usize) bool {
        return self.acked.len >= capacity and self.lost.len >= capacity;
    }

    pub fn ackedPackets(self: *const Events) []const SentPacket {
        return self.acked[0..self.acked_len];
    }

    pub fn lostPackets(self: *const Events) []const SentPacket {
        return self.lost[0..self.lost_len];
    }

    /// Start a new report. The machine calls this once per packet it parses, so
    /// a report describes the call the caller just made and never the one
    /// before it.
    pub fn clear(self: *Events) void {
        self.acked_len = 0;
        self.acked_bytes = 0;
        self.lost_len = 0;
        self.lost_bytes = 0;
        self.largest_lost_sent_time = 0;
        self.persistent_congestion = false;
    }

    fn pushAcked(self: *Events, packet: SentPacket) void {
        assert(self.acked_len < self.acked.len);
        self.acked[self.acked_len] = packet;
        self.acked_len += 1;
        self.acked_bytes += packet.sent_bytes;
    }

    fn pushLost(self: *Events, packet: SentPacket) void {
        assert(self.lost_len < self.lost.len);
        self.lost[self.lost_len] = packet;
        self.lost_len += 1;
        self.lost_bytes += packet.sent_bytes;
        self.largest_lost_sent_time = packet.time_sent;
    }
};

/// One packet that was sent and is not accounted for yet.
pub const SentPacket = struct {
    packet_number: u64,
    time_sent: Duration,
    ack_eliciting: bool,
    in_flight: bool,
    /// §7.1 counts bytes in flight, and a congestion controller needs the size
    /// of the packet it is being told about.
    sent_bytes: u32,
};

/// The RTT estimator of §5.
pub const Rtt = struct {
    /// §5.1: the time from sending the largest acknowledged packet to acking it.
    latest: Duration = 0,
    /// §5.3: initialized to kInitialRtt before the first sample.
    smoothed: Duration = initial_rtt,
    /// §5.3: initialized to kInitialRtt / 2.
    variance: Duration = initial_rtt / 2,
    /// §5.2: the smallest sample seen. `first` says whether one exists.
    min_rtt: Duration = 0,
    first: bool = false,
    /// When the first sample was taken. §7.6.2 requires a prior RTT sample to
    /// have existed when the packets that established persistent congestion
    /// were sent, so the time is needed, not only the fact.
    first_sample_time: Duration = 0,

    /// §5.3 read through A.7's pseudocode. `ack_delay` is already scaled by the
    /// peer's `ack_delay_exponent`; the caller decodes it from the ACK frame.
    pub fn onSample(
        self: *Rtt,
        now: Duration,
        latest: Duration,
        ack_delay: Duration,
        options: Options,
    ) void {
        if (!self.first) {
            // §5.3: "On the first RTT sample after initialization, the
            // estimator is reset using that sample", and the acknowledgment
            // delay plays no part in it.
            self.latest = latest;
            self.min_rtt = latest;
            self.smoothed = latest;
            self.variance = latest / 2;
            self.first = true;
            self.first_sample_time = now;
            return;
        }

        self.latest = latest;
        // §5.2: min_rtt ignores the acknowledgment delay.
        self.min_rtt = @min(self.min_rtt, latest);

        // A.7: limit the delay by max_ack_delay only once the handshake is
        // confirmed.
        const delay = if (options.handshake_confirmed)
            @min(ack_delay, options.max_ack_delay)
        else
            ack_delay;

        // §5.3: never subtract if that would take the sample below min_rtt.
        const adjusted = if (latest >= self.min_rtt + delay) latest - delay else latest;

        // A.7 computes the variance from the smoothed RTT it is about to
        // replace; §5.3's prose lists the two lines the other way round.
        const difference = if (self.smoothed > adjusted)
            self.smoothed - adjusted
        else
            adjusted - self.smoothed;
        self.variance = (3 * self.variance + difference) / 4;
        self.smoothed = (7 * self.smoothed + adjusted) / 8;
    }

    /// §6.1.2: `max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
    /// kGranularity)`. The 9/8 multiplies up and rounds up, so a threshold
    /// never fires a fraction early.
    pub fn lossDelay(self: *const Rtt) Duration {
        const base = @max(self.smoothed, self.latest);
        const scaled = (base * time_threshold_numerator + time_threshold_denominator - 1) /
            time_threshold_denominator;
        return @max(scaled, granularity);
    }

    /// §6.2.1: `smoothed_rtt + max(4*rttvar, kGranularity)`, which the Initial
    /// space uses as is because its `max_ack_delay` is zero.
    pub fn ptoBase(self: *const Rtt) Duration {
        return self.smoothed + @max(4 * self.variance, granularity);
    }
};

/// §7.6.1: `(smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) *
/// kPersistentCongestionThreshold`, with the threshold fixed at 3 by the
/// recommendation in the same section.
///
/// Unlike the PTO period, this always includes `max_ack_delay`, whatever space
/// the loss was established in, which is why it is computed here rather than
/// from the PTO.
pub fn persistentPeriod(rtt: *const Rtt, max_ack_delay: Duration) Duration {
    const threshold: u64 = 3;
    return (rtt.smoothed + @max(4 * rtt.variance, granularity) + max_ack_delay) * threshold;
}

/// The connection-wide half of loss recovery: everything the RFC measures per
/// path rather than per packet number space (A.2, A.8).
rtt: Rtt = .{},
/// §6.2.1: doubles the PTO period on each timeout, across every space, and
/// resets on an acknowledgment that validates the peer's address.
pto_count: u5 = 0,

/// A per-space loss detector over caller-owned sent-packet storage.
///
/// `sent` must outlive the space. Size it for the connection: a packet that
/// cannot be recorded is a packet whose frames are never retransmitted, so
/// `onPacketSent` returns `error.NoSpace` rather than dropping one. The report
/// the caller passes to `onAckReceived` or `onTimeout` must hold as many
/// records as this table, or the call refuses with `error.NoSpace`.
pub fn space(self: *Recovery, sent: []SentPacket) Space {
    assert(sent.len > 0);
    return .{ .shared = self, .sent = sent };
}

/// The per-space half of loss recovery: the sent packets, the largest number
/// acknowledged, and the timers that depend on them.
pub const Space = struct {
    shared: *Recovery,
    sent: []SentPacket,
    sent_len: usize = 0,
    largest_acked: ?u64 = null,
    /// §6.1.2: the earliest time an unacknowledged packet becomes lost, once a
    /// later packet is acknowledged. Zero means none.
    loss_time: Duration = 0,
    /// When the last ack-eliciting packet in flight in this space was sent
    /// (§6.2.1).
    last_ack_eliciting: Duration = 0,
    /// The run of consecutive lost ack-eliciting packets, for §7.6.2.
    run_start: Duration = 0,
    run_last: u64 = 0,
    run_eliciting: u32 = 0,
    /// §6.4: the keys this space was using are gone, and the loss state goes
    /// with them. A discarded space cannot send, so it must contribute no
    /// timer: the anti-deadlock probe of §6.2.2.1 is what would otherwise arm
    /// itself forever for a client that still doubts the peer's address.
    discarded: bool = false,

    pub fn rtt(self: *const Space) *const Rtt {
        return &self.shared.rtt;
    }

    /// The packet numbers this space is still accounting for.
    pub fn inFlight(self: *const Space) []const SentPacket {
        assert(self.sentValid());
        return self.sent[0..self.sent_len];
    }

    /// The sent table's own invariant: the count never runs past the caller's
    /// storage. Both places that move the count assert it, so an index that
    /// goes one too far, or a decrement that never happened, fails where it
    /// happened instead of at the next read.
    pub fn sentValid(self: *const Space) bool {
        return self.sent_len <= self.sent.len;
    }

    /// Note a packet that was sent. `in_flight` is false for a packet that
    /// carries only frames congestion control does not count; this driver still
    /// tracks it for loss detection, because §6.1 only exempts it from the loss
    /// set when it is not in flight.
    pub fn onPacketSent(
        self: *Space,
        packet_number: u64,
        now: Duration,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: u32,
    ) Error!void {
        assert(self.sentValid());
        if (!self.hasRoom()) return error.NoSpace;
        self.sent[self.sent_len] = .{
            .packet_number = packet_number,
            .time_sent = now,
            .ack_eliciting = ack_eliciting,
            .in_flight = in_flight,
            .sent_bytes = sent_bytes,
        };
        self.sent_len += 1;
        assert(self.sentValid());
        if (ack_eliciting and in_flight) self.last_ack_eliciting = now;
    }

    /// Handle an acknowledgment: the RTT sample, the newly acknowledged
    /// packets, and the packets the acknowledgment declares lost (§6.1, A.7).
    ///
    /// The caller has already refused an ACK that names a packet never sent, and
    /// has scaled the ACK's delay field by its own `ack_delay_exponent`.
    pub fn onAckReceived(
        self: *Space,
        ack: *const frame.Ack,
        now: Duration,
        options: Options,
        events: *Events,
    ) Error!void {
        // One record per packet in the table, so an acknowledgment covering all
        // of them fits. Refusing here, before anything moves, is what keeps a
        // small report from truncating an event halfway through.
        if (!events.fits(self.sent_len)) return error.NoSpace;

        events.clear();

        self.largest_acked = if (self.largest_acked) |largest|
            @max(largest, ack.largest)
        else
            ack.largest;

        var index: usize = 0;
        var acked_largest_eliciting = false;
        var largest_was_new = false;
        var largest_send_time: Duration = 0;
        while (index < self.sent_len) {
            const packet = self.sent[index];
            if (!ackedBy(ack, packet.packet_number)) {
                index += 1;
                continue;
            }
            if (packet.ack_eliciting) acked_largest_eliciting = true;
            if (packet.packet_number == ack.largest) {
                largest_was_new = true;
                largest_send_time = packet.time_sent;
            }
            events.pushAcked(packet);
            // The tail moved down, so `index` now names the packet that
            // replaced this one, and the next iteration must not advance it.
            self.remove(index);
        }

        if (events.acked_len == 0) return;

        // §5.1: a sample only from a newly acknowledged largest packet, and only
        // when at least one newly acknowledged packet was ack-eliciting.
        if (largest_was_new and acked_largest_eliciting) {
            const latest = if (now >= largest_send_time) now - largest_send_time else 0;
            self.shared.rtt.onSample(now, latest, ack.delay, options);
        }

        self.detectLost(now, events, options);

        // §6.2.1: an acknowledgment resets the PTO backoff, unless this is a
        // client that does not know the server has validated its address.
        if (options.peer_address_validated) self.shared.pto_count = 0;
    }

    /// §6.1 and A.10: the packets this space now calls lost, and the time the
    /// rest become lost if nothing else is acknowledged.
    fn detectLost(self: *Space, now: Duration, events: *Events, options: Options) void {
        self.loss_time = 0;
        const largest = self.largest_acked orelse return;

        const delay = self.shared.rtt.lossDelay();
        // A.10: "Packets sent before this time are deemed lost."
        const lost_send_time = if (now > delay) now - delay else 0;

        var index: usize = 0;
        while (index < self.sent_len) {
            const packet = self.sent[index];
            if (packet.packet_number > largest) {
                index += 1;
                continue;
            }
            // A.10: the time threshold, or three packets newer already acked.
            const lost_by_time = packet.time_sent <= lost_send_time and now >= delay;
            const lost_by_packet = largest >= packet.packet_number + packet_threshold;
            if (lost_by_time or lost_by_packet) {
                self.noteLost(packet, events, options);
                events.pushLost(packet);
                self.remove(index);
                continue;
            }
            const candidate = packet.time_sent + delay;
            if (self.loss_time == 0 or candidate < self.loss_time) self.loss_time = candidate;
            index += 1;
        }
    }

    /// §7.6.2: persistent congestion needs two ack-eliciting packets declared
    /// lost, no acknowledged packet between them, a duration between their send
    /// times above the §7.6.1 threshold, and a prior RTT sample when they were
    /// sent.
    ///
    /// The run is tracked over packets lost in this one event, in packet number
    /// order, and it breaks when the packet numbers are not consecutive. That is
    /// stricter than the RFC: a packet that is still in flight between two lost
    /// ones is not an acknowledged packet, but treating it as a break can only
    /// miss a declaration, never invent one.
    fn noteLost(self: *Space, packet: SentPacket, events: *Events, options: Options) void {
        if (!packet.ack_eliciting) {
            self.run_start = 0;
            self.run_last = 0;
            self.run_eliciting = 0;
            return;
        }
        const continues = self.run_last != 0 and packet.packet_number == self.run_last + 1;
        if (!continues) {
            self.run_start = packet.time_sent;
            self.run_eliciting = 0;
        }
        self.run_last = packet.packet_number;
        self.run_eliciting += 1;
        if (self.run_eliciting < 2) return;

        // §7.6.2: a prior RTT sample must have existed when the run was sent.
        const estimate = &self.shared.rtt;
        if (!estimate.first or self.run_start < estimate.first_sample_time) return;

        const period = persistentPeriod(estimate, options.max_ack_delay);
        if (packet.time_sent - self.run_start > period) events.persistent_congestion = true;
    }

    /// §6.4: when the keys for this space are discarded, its sent packets, its
    /// loss timer, and its claim on the next PTO go with them. The connection's
    /// RTT estimate does not: it belongs to the path (A.2).
    pub fn discard(self: *Space) void {
        self.sent_len = 0;
        self.largest_acked = null;
        self.loss_time = 0;
        self.last_ack_eliciting = 0;
        self.run_start = 0;
        self.run_last = 0;
        self.run_eliciting = 0;
        self.discarded = true;
    }

    /// The timer the caller should set after any event (§6.1.2 and §6.2.1, A.8).
    pub fn nextTimer(self: *Space, options: Options) Timer {
        // §6.4: the timers of a discarded space are reset, and nothing below
        // may re-arm one. Without this the anti-deadlock branch at the end
        // returns a probe at every call, forever.
        if (self.discarded) return .{ .kind = .none };
        if (self.loss_time != 0) return .{ .kind = .loss, .at = self.loss_time };

        // A.8: with nothing ack-eliciting in flight, and a peer whose address is
        // validated, there is nothing to time out.
        if (!self.ackElicitingInFlight() and options.peer_address_validated) {
            return .{ .kind = .none };
        }

        // §6.2.1: the period doubles with each timeout. The count is the
        // connection's, so a timeout in one space lengthens the next in every
        // other one.
        const backoff: u64 = @as(u64, 1) << @intCast(self.shared.pto_count);
        const duration = self.shared.rtt.ptoBase() * backoff;
        return .{ .kind = .probe, .at = self.last_ack_eliciting + duration };
    }

    /// Handle the timer firing (§6.2, A.9). Either the time threshold declared
    /// packets lost, or this is a probe timeout.
    pub fn onTimeout(
        self: *Space,
        side: Side,
        now: Duration,
        options: Options,
        events: *Events,
    ) Error!Timeout {
        // A loss timeout can declare every packet in the table lost at once.
        if (!events.fits(self.sent_len)) return error.NoSpace;

        events.clear();

        if (self.loss_time != 0) {
            self.detectLost(now, events, options);
            return .{ .kind = .loss };
        }

        // A.9: a client with nothing in flight arms a probe anyway, to unblock a
        // server that may be waiting on its address validation.
        const anti_deadlock = !self.ackElicitingInFlight() and !options.peer_address_validated;

        // §6.2.4: two ack-eliciting packets are allowed, and a client that has
        // not confirmed the handshake sends two to survive one more loss.
        const probes: u8 = if (anti_deadlock)
            1
        else if (side == .client and !options.handshake_confirmed)
            2
        else
            1;

        self.shared.pto_count +|= 1;
        return .{ .kind = .probe, .probes = probes };
    }

    fn ackElicitingInFlight(self: *const Space) bool {
        for (self.sent[0..self.sent_len]) |packet| {
            if (packet.ack_eliciting and packet.in_flight) return true;
        }
        return false;
    }

    /// Whether one more packet fits. Asking first is what lets a writer refuse
    /// a full table before it seals anything, so the caller's output buffer and
    /// the packet number counter are untouched on the way out.
    pub fn hasRoom(self: *const Space) bool {
        assert(self.sentValid());
        return self.sent_len < self.sent.len;
    }

    /// Drop the record at `index`, moving the tail down over it. The index and
    /// the count are the two numbers that can disagree here, so the caller's
    /// match is asserted into a precondition.
    fn remove(self: *Space, index: usize) void {
        assert(self.sentValid());
        assert(index < self.sent_len);

        @memmove(self.sent[index .. self.sent_len - 1], self.sent[index + 1 .. self.sent_len]);
        self.sent_len -= 1;
        assert(self.sentValid());
    }
};

/// Whether an ACK frame acknowledges `packet_number`, walking its ranges.
fn ackedBy(ack: *const frame.Ack, packet_number: u64) bool {
    if (packet_number > ack.largest) return false;
    if (packet_number >= ack.largest - ack.first_range) return true;

    var largest = ack.largest;
    var smallest = ack.largest - ack.first_range;
    var ranges = ack.ranges();
    while (ranges.next() catch null) |range| {
        if (largest < range.gap + 2) return false;
        const range_largest = smallest - range.gap - 2;
        const range_smallest = range_largest - range.length;
        if (packet_number >= range_smallest and packet_number <= range_largest) return true;
        largest = range_largest;
        smallest = range_smallest;
    }
    return false;
}

fn expectNumbers(records: []const SentPacket, expected: []const u64) !void {
    try testing.expectEqual(expected.len, records.len);
    for (records, expected) |record, number| try testing.expectEqual(number, record.packet_number);
}

const Harness = struct {
    conn: Recovery = .{},
    sent: [64]SentPacket = undefined,

    fn space(self: *Harness) Space {
        return self.conn.space(&self.sent);
    }
};

test "RFC 9002 §5.3, one sample initializes the estimator and ignores the delay" {
    var rtt: Rtt = .{};
    try testing.expectEqual(initial_rtt, rtt.smoothed);
    try testing.expectEqual(initial_rtt / 2, rtt.variance);

    // A first sample of 80ms with a reported delay of 20ms: the delay plays no
    // part in the reset.
    rtt.onSample(0, ms(80), ms(20), .{ .max_ack_delay = ms(25), .handshake_confirmed = true });
    try testing.expectEqual(ms(80), rtt.smoothed);
    try testing.expectEqual(ms(40), rtt.variance);
    try testing.expectEqual(ms(80), rtt.min_rtt);
    try testing.expectEqual(ms(80), rtt.latest);
}

test "RFC 9002 Appendix A.7, three samples move the average and the variance" {
    var rtt: Rtt = .{};

    // First sample 80ms: smoothed 80, variance 40, min 80.
    rtt.onSample(0, ms(80), 0, .{});
    // Second sample 96ms, no delay: variance = (3*40 + |80-96|)/4 = 34,
    // smoothed = (7*80 + 96)/8 = 82.
    rtt.onSample(0, ms(96), 0, .{});
    try testing.expectEqual(ms(34), rtt.variance);
    try testing.expectEqual(ms(82), rtt.smoothed);
    try testing.expectEqual(ms(80), rtt.min_rtt);
    // Third sample 64ms: variance = (3*34 + |82-64|)/4 = 30,
    // smoothed = (7*82 + 64)/8 = 79.75.
    rtt.onSample(0, ms(64), 0, .{});
    try testing.expectEqual(ms(30), rtt.variance);
    try testing.expectEqual(ms(79) + 750_000, rtt.smoothed);
    try testing.expectEqual(ms(64), rtt.min_rtt);
}

test "RFC 9002 §5.3, a delay is subtracted only when it is plausible" {
    var rtt: Rtt = .{};
    rtt.onSample(0, ms(80), 0, .{});

    // 100ms with a 10ms delay, handshake confirmed and max_ack_delay 25ms: the
    // delay is subtracted from an adjusted sample of 90ms. Variance becomes
    // (3*40 + |80-90|)/4 = 32.5ms, smoothed (7*80 + 90)/8 = 81.25ms.
    rtt.onSample(0, ms(100), ms(10), .{ .max_ack_delay = ms(25), .handshake_confirmed = true });
    try testing.expectEqual(ms(32) + 500_000, rtt.variance);
    try testing.expectEqual(ms(81) + 250_000, rtt.smoothed);

    // A delay that would take the sample below min_rtt is not subtracted:
    // 60ms with a 50ms delay stays 60ms.
    var second: Rtt = .{};
    second.onSample(0, ms(80), 0, .{});
    second.onSample(0, ms(60), ms(50), .{ .max_ack_delay = ms(25), .handshake_confirmed = true });
    try testing.expectEqual(ms(60), second.min_rtt);
    try testing.expectEqual((7 * ms(80) + ms(60)) / 8, second.smoothed);

    // Before the handshake is confirmed, max_ack_delay does not clamp the
    // delay, so a 200ms delay on a 300ms sample is subtracted in full.
    var unconfirmed: Rtt = .{};
    unconfirmed.onSample(0, ms(80), 0, .{});
    unconfirmed.onSample(0, ms(300), ms(200), .{ .max_ack_delay = ms(25) });
    try testing.expectEqual((7 * ms(80) + ms(100)) / 8, unconfirmed.smoothed);
}

test "RFC 9002 §6.1.2, the loss delay is 9/8 of the larger RTT and never rounds down" {
    var rtt: Rtt = .{};
    rtt.onSample(0, ms(80), 0, .{});
    // smoothed 80, latest 80, so 9/8 of 80 is 90.
    try testing.expectEqual(ms(90), rtt.lossDelay());

    rtt.onSample(0, ms(96), 0, .{});
    // max(82, 96) = 96, 9/8 of it is 108.
    try testing.expectEqual(ms(108), rtt.lossDelay());

    // A 1ns RTT scales to 1.125ns, which rounds up to 2, but the threshold
    // never goes below the 1ms timer granularity (§6.1.2).
    var tiny: Rtt = .{};
    tiny.onSample(0, 1, 0, .{});
    try testing.expectEqual(granularity, tiny.lossDelay());

    // 1_000_003ns scales to 1_125_003.375ns. Truncating gives 1_125_003, which
    // would let a loss timer fire early; rounding up gives 1_125_004.
    var awkward: Rtt = .{};
    awkward.onSample(0, 1_000_003, 0, .{});
    try testing.expectEqual(@as(Duration, 1_125_004), awkward.lossDelay());
}

test "RFC 9002 §6.1.1, the packet threshold declares three older packets lost" {
    var h: Harness = .{};
    var sp = h.space();

    var i: u64 = 0;
    while (i < 6) : (i += 1) try sp.onPacketSent(i, ms(10), true, true, 1200);

    // Acknowledge nothing but packet 5, one RTT later.
    const ack: frame.Ack = .{
        .largest = 5,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&ack, ms(20), .{}, &events);

    try expectNumbers(events.ackedPackets(), &.{5});
    // 5 >= 0+3, 5 >= 1+3, 5 >= 2+3; but 5 < 3+3 and 5 < 4+3.
    try expectNumbers(events.lostPackets(), &.{ 0, 1, 2 });
    // §7.1: the lost bytes are what a congestion controller reacts to.
    try testing.expectEqual(@as(u32, 3 * 1200), events.lost_bytes);
    try testing.expectEqual(@as(u32, 1200), events.acked_bytes);
    try testing.expectEqual(@as(usize, 2), sp.sent_len);
    // §6.1.2: the rest become lost a loss delay after they were sent, and the
    // timer carries the earliest of them.
    try testing.expectEqual(ms(10) + h.conn.rtt.lossDelay(), sp.loss_time);
}

test "RFC 9002 §6.1, an acknowledgment covering a full table reports every packet" {
    // The report is the caller's resend queue input: a packet that is acked but
    // left out of it stays in the queue forever. So a report as large as the
    // table must fill exactly, and a smaller one must be refused rather than
    // truncate.
    var h: Harness = .{};
    var sp = h.space();
    try testing.expect(sp.sentValid());

    var number: u64 = 0;
    while (number < h.sent.len) : (number += 1) {
        try sp.onPacketSent(number, ms(10), true, true, 1200);
    }
    try testing.expectEqual(h.sent.len, sp.inFlight().len);

    const last: u64 = @intCast(h.sent.len - 1);
    const all: frame.Ack = .{
        .largest = last,
        .delay = 0,
        .first_range = last,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };

    // One record short of the table: refused before anything moves.
    var short_acked: [63]SentPacket = undefined;
    var short_lost: [64]SentPacket = undefined;
    var short: Events = .init(&short_acked, &short_lost);
    try testing.expectError(error.NoSpace, sp.onAckReceived(&all, ms(20), .{}, &short));
    try testing.expectEqual(h.sent.len, sp.inFlight().len);

    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&all, ms(20), .{}, &events);

    try testing.expectEqual(h.sent.len, events.ackedPackets().len);
    try testing.expectEqual(@as(usize, 0), events.lostPackets().len);
    try testing.expectEqual(@as(usize, 0), sp.inFlight().len);
    try testing.expect(sp.sentValid());
}

test "RFC 9002 §6.1.2, a gap is lost only by time" {
    var h: Harness = .{};
    var sp = h.space();
    try sp.onPacketSent(0, 0, true, true, 1200);
    try sp.onPacketSent(1, 0, true, true, 1200);

    const only_one: frame.Ack = .{
        .largest = 1,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };

    // Acknowledged 100ms after it was sent: the first sample sets smoothed to
    // 100ms and the variance to 50ms, so the loss delay is 9/8 of 100ms.
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&only_one, ms(100), .{}, &events);
    try expectNumbers(events.ackedPackets(), &.{1});
    // One packet newer is acked, but the packet threshold needs three, and too
    // little time has passed for the time threshold.
    try testing.expectEqual(@as(usize, 0), events.lost_len);
    try testing.expectEqual(ms(112) + 500_000, sp.loss_time);

    // The timer carries that time, and firing it declares the gap lost.
    const timer = sp.nextTimer(.{});
    try testing.expectEqual(TimerKind.loss, timer.kind);
    try testing.expectEqual(sp.loss_time, timer.at);

    var timeout_events_acked: [64]SentPacket = undefined;
    var timeout_events_lost: [64]SentPacket = undefined;
    var timeout_events: Events = .init(&timeout_events_acked, &timeout_events_lost);
    const fired = try sp.onTimeout(.client, timer.at, .{}, &timeout_events);
    try testing.expectEqual(TimeoutKind.loss, fired.kind);
    try expectNumbers(timeout_events.lostPackets(), &.{0});
    try testing.expectEqual(@as(usize, 0), sp.sent_len);
    try testing.expectEqual(TimerKind.none, sp.nextTimer(.{}).kind);
}

test "RFC 9002 §6.1, a reordered ACK supersedes nothing and samples nothing" {
    var h: Harness = .{};
    var sp = h.space();
    try sp.onPacketSent(0, ms(10), true, true, 1200);
    try sp.onPacketSent(1, ms(10), true, true, 1200);
    try sp.onPacketSent(2, ms(10), true, true, 1200);

    const ack2: frame.Ack = .{
        .largest = 2,
        .delay = 0,
        .first_range = 2,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&ack2, ms(200), .{}, &events);
    try expectNumbers(events.ackedPackets(), &.{ 0, 1, 2 });
    try testing.expectEqual(@as(u64, 2), sp.largest_acked.?);
    try testing.expectEqual(ms(190), h.conn.rtt.latest);

    // An ACK that arrives later and acknowledges less is not new information:
    // it must not move largest_acked and must not produce an RTT sample.
    const late: frame.Ack = .{
        .largest = 1,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var late_events_acked: [64]SentPacket = undefined;
    var late_events_lost: [64]SentPacket = undefined;
    var late_events: Events = .init(&late_events_acked, &late_events_lost);
    try sp.onAckReceived(&late, ms(500), .{}, &late_events);
    try testing.expectEqual(@as(usize, 0), late_events.acked_len);
    try testing.expectEqual(@as(u64, 2), sp.largest_acked.?);
    try testing.expectEqual(ms(190), h.conn.rtt.latest);
}

test "RFC 9002 §6.2.1, the PTO period, its backoff, and its reset" {
    var h: Harness = .{};
    var sp = h.space();
    h.conn.rtt.onSample(0, ms(80), 0, .{}); // smoothed 80, variance 40
    try sp.onPacketSent(0, ms(10), true, true, 1200);

    // 80 + max(4*40, 1) = 240ms after the packet was sent.
    var timer = sp.nextTimer(.{});
    try testing.expectEqual(TimerKind.probe, timer.kind);
    try testing.expectEqual(ms(10) + ms(240), timer.at);

    // A timeout doubles it.
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    const probe = try sp.onTimeout(.client, timer.at, .{}, &events);
    try testing.expectEqual(TimeoutKind.probe, probe.kind);
    try testing.expectEqual(@as(u8, 2), probe.probes);
    timer = sp.nextTimer(.{});
    try testing.expectEqual(ms(10) + ms(480), timer.at);

    // An acknowledgment resets the backoff, and with everything acknowledged
    // there is no timer at all.
    const ack: frame.Ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    try sp.onAckReceived(&ack, ms(300), .{}, &events);
    try testing.expectEqual(@as(u5, 0), h.conn.pto_count);
    try testing.expectEqual(TimerKind.none, sp.nextTimer(.{}).kind);
}

test "RFC 9002 Appendix A.2 and A.8, two spaces share one estimator and one backoff" {
    var h: Harness = .{};
    var sent_initial: [8]SentPacket = undefined;
    var sent_handshake: [8]SentPacket = undefined;
    var initial = h.conn.space(&sent_initial);
    var handshake = h.conn.space(&sent_handshake);

    try initial.onPacketSent(0, ms(10), true, true, 1200);
    try handshake.onPacketSent(0, ms(20), true, true, 1200);

    // A sample from one space is the connection's sample.
    const ack: frame.Ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try initial.onAckReceived(&ack, ms(110), .{}, &events);
    try testing.expectEqual(ms(100), h.conn.rtt.latest);
    try testing.expectEqual(ms(100), handshake.rtt().latest);

    // A PTO in the handshake space doubles the period in the initial space too,
    // because the backoff is the connection's.
    try handshake.onPacketSent(1, ms(120), true, true, 1200);
    _ = try handshake.onTimeout(.server, ms(400), .{}, &events);
    try testing.expectEqual(@as(u5, 1), h.conn.pto_count);

    try initial.onPacketSent(1, ms(500), true, true, 1200);
    const timer = initial.nextTimer(.{});
    try testing.expectEqual(ms(500) + 2 * h.conn.rtt.ptoBase(), timer.at);
}

test "RFC 9002 §6.2.1, a client keeps its backoff while it doubts the address" {
    var h: Harness = .{};
    var sp = h.space();
    try sp.onPacketSent(0, 0, true, true, 1200);

    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    _ = try sp.onTimeout(.client, ms(1000), .{}, &events);
    try testing.expectEqual(@as(u5, 1), h.conn.pto_count);

    // An ACK that cannot be honoured does not reset the backoff for a client
    // that has not seen the server validate its address.
    const ack: frame.Ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    try sp.onAckReceived(&ack, ms(2000), .{ .peer_address_validated = false }, &events);
    try testing.expectEqual(@as(u5, 1), h.conn.pto_count);
}

test "RFC 9002 §6.4, a discarded space arms no timer even for a client that doubts the address" {
    var h: Harness = .{};
    var sp = h.space();

    // §6.2.2.1: with nothing in flight and an address it has not seen
    // validated, a client arms a probe it will never otherwise cancel.
    const unvalidated: Options = .{ .peer_address_validated = false };
    try testing.expectEqual(TimerKind.probe, sp.nextTimer(unvalidated).kind);

    // §6.4: the keys went, and the probe with them.
    sp.discard();
    try testing.expectEqual(TimerKind.none, sp.nextTimer(unvalidated).kind);
    // The path's estimate is not the space's to lose (A.2).
    try testing.expectEqual(initial_rtt, h.conn.rtt.smoothed);
}

test "RFC 9002 §6.2.2.1, a client with nothing in flight still arms a probe" {
    var h: Harness = .{};
    var sp = h.space();

    const timer = sp.nextTimer(.{ .peer_address_validated = false });
    try testing.expectEqual(TimerKind.probe, timer.kind);
    // §6.2.1 with no sample yet: smoothed 333ms and variance 166.5ms, so the
    // period is 333 + 4*166.5 = 999ms, and nothing was sent, so it starts now.
    try testing.expectEqual(h.conn.rtt.ptoBase(), timer.at);
    try testing.expectEqual(ms(999), timer.at);

    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    const probe = try sp.onTimeout(.client, timer.at, .{ .peer_address_validated = false }, &events);
    try testing.expectEqual(TimeoutKind.probe, probe.kind);
    // One anti-deadlock packet, not the two of a real PTO.
    try testing.expectEqual(@as(u8, 1), probe.probes);

    // A server never arms it: it has nothing to unblock.
    var server_harness: Harness = .{};
    var server_space = server_harness.space();
    try testing.expectEqual(
        TimerKind.none,
        server_space.nextTimer(.{ .peer_address_validated = true }).kind,
    );
}

test "a fixed event sequence produces exactly one loss set" {
    // The sequence: six packets, then an ACK for 5 alone one RTT later, then an
    // ACK for 3 and 4 (a reordered pair), then silence.
    var h: Harness = .{};
    var sp = h.space();
    var i: u64 = 0;
    while (i < 6) : (i += 1) try sp.onPacketSent(i, ms(10), true, true, 1000 + @as(u32, @intCast(i)));

    const ack5: frame.Ack = .{
        .largest = 5,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&ack5, ms(110), .{}, &events);
    try expectNumbers(events.ackedPackets(), &.{5});
    try expectNumbers(events.lostPackets(), &.{ 0, 1, 2 });
    try testing.expectEqual(@as(u32, 1000 + 1001 + 1002), events.lost_bytes);

    // A reordered ACK for 3 and 4 arrives: one range covering both.
    const ack34: frame.Ack = .{
        .largest = 4,
        .delay = 0,
        .first_range = 1,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var second_acked: [64]SentPacket = undefined;
    var second_lost: [64]SentPacket = undefined;
    var second: Events = .init(&second_acked, &second_lost);
    try sp.onAckReceived(&ack34, ms(150), .{}, &second);
    try expectNumbers(second.ackedPackets(), &.{ 3, 4 });
    try testing.expectEqual(@as(usize, 0), second.lost_len);
    try testing.expectEqual(@as(usize, 0), sp.sent_len);

    // Nothing is left to lose.
    try testing.expectEqual(TimerKind.none, sp.nextTimer(.{}).kind);
}

test "the sent table is the caller's, and a full one is an error" {
    var h: Harness = .{};
    var small: [2]SentPacket = undefined;
    var sp = h.conn.space(&small);

    try sp.onPacketSent(0, 0, true, true, 1200);
    try sp.onPacketSent(1, 0, true, true, 1200);
    // The third is refused. A silently forgotten packet would be a packet whose
    // frames are never retransmitted, with no signal to the caller.
    try testing.expectError(error.NoSpace, sp.onPacketSent(2, 0, true, true, 1200));
    try testing.expectEqual(@as(usize, 2), sp.sent_len);
}

test "RFC 9000 §19.3.1, an ACK is read through its ranges" {
    // Two ranges: 10, and 5 through 6.
    var scratch: [8]u8 = undefined;
    var writer: Writer = .init(&scratch);
    // gap 2 (7..9 unacknowledged, three numbers encoded as two) and length 1.
    try varint.write(&writer, 2);
    try varint.write(&writer, 1);

    const ack: frame.Ack = .{
        .largest = 10,
        .delay = 0,
        .first_range = 0,
        .range_count = 1,
        .bytes = writer.written(),
        .ecn = null,
    };

    try testing.expect(ackedBy(&ack, 10));
    try testing.expect(!ackedBy(&ack, 9));
    try testing.expect(!ackedBy(&ack, 8));
    try testing.expect(!ackedBy(&ack, 7));
    try testing.expect(ackedBy(&ack, 6));
    try testing.expect(ackedBy(&ack, 5));
    try testing.expect(!ackedBy(&ack, 4));
    try testing.expect(!ackedBy(&ack, 11));
}

test "RFC 9002 §7.6.1, the persistent congestion duration always includes max_ack_delay" {
    var rtt: Rtt = .{};
    rtt.smoothed = ms(1);
    rtt.variance = 0;
    // 1ms + max(0, 1ms granularity) + 1ms, times the threshold of 3.
    try testing.expectEqual(ms(9), persistentPeriod(&rtt, ms(1)));
    // With no delay it is the PTO base without the space's own max_ack_delay
    // exemption: 2ms * 3.
    try testing.expectEqual(ms(6), persistentPeriod(&rtt, 0));
}

test "RFC 9002 §7.6.3, the worked example declares persistent congestion" {
    var h: Harness = .{};
    var sp = h.space();

    // The example assumes smoothed_rtt + max(4*rttvar, kGranularity) +
    // max_ack_delay = 2ms. Pin that: smoothed 1ms, no variance, and the 1ms
    // granularity fills the rest.
    h.conn.rtt.smoothed = ms(1);
    h.conn.rtt.variance = 0;
    h.conn.rtt.latest = ms(1);
    h.conn.rtt.first = true;
    h.conn.rtt.first_sample_time = 0;

    // Packets #1 through #9 at the table's send times.
    const times = [_]u64{ 0, 1, 2, 3, 4, 5, 6, 8, 12 };
    for (times, 0..) |time, i| try sp.onPacketSent(i, ms(time), true, true, 1200);

    // t=1.2: #1 is acknowledged.
    const ack1: frame.Ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&ack1, ms(1) + 200_000, .{}, &events);
    try testing.expect(!events.persistent_congestion);

    // t=12.2: #9 is acknowledged, and #2 through #8 are declared lost.
    const ack9: frame.Ack = .{
        .largest = 8,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    try sp.onAckReceived(&ack9, ms(12) + 200_000, .{}, &events);
    try expectNumbers(events.ackedPackets(), &.{8});
    try expectNumbers(events.lostPackets(), &.{ 1, 2, 3, 4, 5, 6, 7 });
    // The period is 8 - 1 = 7ms, and the §7.6.1 duration is 6ms at most.
    try testing.expect(events.persistent_congestion);
}

test "RFC 9002 §7.6.2, a run that is too quick is not persistent congestion" {
    var h: Harness = .{};
    var sp = h.space();
    h.conn.rtt.smoothed = ms(1);
    h.conn.rtt.variance = 0;
    h.conn.rtt.latest = ms(1);
    h.conn.rtt.first = true;
    h.conn.rtt.first_sample_time = 0;

    // Four packets a millisecond apart. The acknowledgment arrives one
    // millisecond after the newest was sent, so the estimator is a fixed point
    // at 1ms, the loss delay is 1.125ms, and the ack at 4ms declares the first
    // three lost by time. Their span is 2ms; the duration is
    // (1 + 1 + 0) * 3 = 6ms.
    var i: u64 = 0;
    while (i < 4) : (i += 1) try sp.onPacketSent(i, ms(i), true, true, 1200);

    const ack: frame.Ack = .{
        .largest = 3,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    var events_acked: [64]SentPacket = undefined;
    var events_lost: [64]SentPacket = undefined;
    var events: Events = .init(&events_acked, &events_lost);
    try sp.onAckReceived(&ack, ms(4), .{}, &events);
    try expectNumbers(events.lostPackets(), &.{ 0, 1, 2 });
    try testing.expect(!events.persistent_congestion);
}
