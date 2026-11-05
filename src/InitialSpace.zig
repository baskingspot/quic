//! One endpoint's Initial packet space: keys, packet numbers, and the ranges it
//! has received.
//!
//! This is a driver, not a connection. It holds exactly the state the Initial
//! level needs to exchange packets: the two Initial keys (RFC 9001 §5.2), the
//! next packet number to send, the largest one received, and a small set of
//! received ranges it can turn into an ACK frame (§19.3). It sends no
//! retransmissions, keeps no timers, recovers from no loss, negotiates no
//! version, answers no Retry, and knows nothing about streams or the handshake.
//! Its job is to be small enough to read and honest about all of that.
//!
//! What it deliberately leaves to the caller: padding a datagram to 1200 bytes
//! (§14.1 is a datagram rule and this driver never sees a datagram), choosing
//! which frames to send, and parsing the frames a packet's payload holds. It
//! writes and reads the packet, and returns bytes.
//!
//! The connection IDs are borrowed. They must outlive the space, because every
//! packet it builds names them.

const std = @import("std");
const testing = std.testing;
const Writer = @import("Writer.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const packet_number = @import("packet_number.zig");
const protection = @import("protection.zig");
const varint = @import("varint.zig");

const InitialSpace = @This();

pub const Side = enum {
    client,
    server,
};

pub const Error = protection.Error || packet.Error || error{
    /// The packet is not an Initial packet.
    NotInitial,
    /// A packet this driver has no answers for: anything carrying a Retry
    /// token, or any version but 1.
    UnexpectedToken,
    UnsupportedVersion,
    /// An ACK named a packet number this side never sent.
    AckForUnsentPacket,
};

/// How many separate received ranges the driver tracks. Eight covers the
/// reordering the Initial level sees in practice; beyond it, the oldest range
/// is forgotten, which §13.2.4 allows.
pub const range_capacity = 8;

/// A contiguous run of received packet numbers, inclusive.
pub const Range = struct {
    smallest: u64,
    largest: u64,
};

/// The AEAD is AES-128-GCM, which §5.5 says is what applies before TLS picks a
/// suite, so an Initial-level driver never needs another.
pub const suite = protection.Suite.aes_128_gcm;

/// The keys in both directions. `send` protects what this side writes, `receive`
/// opens what the peer wrote.
send_keys: protection.Keys,
receive_keys: protection.Keys,

/// The packet number the next `seal` uses. It only ever counts up.
next_packet_number: u64 = 0,
/// The largest packet number the peer has acknowledged. §17.1 sizes the
/// truncated packet number against it.
largest_acked: ?u64 = null,
/// The largest packet number this side has opened, for recovering the next one.
largest_received: ?u64 = null,

destination_connection_id: []const u8,
source_connection_id: []const u8,

/// Received ranges, descending by `largest` and never touching.
ranges: [range_capacity]Range = undefined,
range_count: u4 = 0,

pub const Config = struct {
    side: Side,
    /// The client's Destination Connection ID, which is what the Initial
    /// secrets are derived from (§5.2). Both endpoints use the same value.
    original_destination_connection_id: []const u8,
    /// The two IDs this endpoint writes into the packets it sends.
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
};

/// The two Initial secrets, from the connection ID (§5.2).
pub fn secrets(original_destination_connection_id: []const u8) protection.InitialSecrets {
    return protection.initialSecrets(original_destination_connection_id);
}

/// Build one endpoint's space. The peer builds the other with the same
/// `original_destination_connection_id` and mirrored IDs.
pub fn init(config: Config) InitialSpace {
    const initial = secrets(config.original_destination_connection_id);
    const client_keys = protection.deriveKeys(initial.client, suite);
    const server_keys = protection.deriveKeys(initial.server, suite);

    return .{
        .send_keys = if (config.side == .client) client_keys else server_keys,
        .receive_keys = if (config.side == .client) server_keys else client_keys,
        .destination_connection_id = config.destination_connection_id,
        .source_connection_id = config.source_connection_id,
    };
}

/// The packet number the next packet will carry.
pub fn packetNumber(self: *const InitialSpace) u64 {
    return self.next_packet_number;
}

/// A packet this side opened.
pub const Opened = struct {
    packet_number: u64,
    /// The header through the packet number: the bytes the AEAD authenticated.
    header_len: u32,
    /// Where this packet ends. A datagram may hold another packet after it
    /// (§12.2), and this is where that one starts.
    packet_len: u32,
    /// The frames, written into the caller's buffer.
    payload: []u8,
};

/// Seal one Initial packet holding `payload` into `out`.
///
/// `payload` is a sequence of frames the caller already wrote. The packet has
/// no token, because this driver has no Retry. Returns the packet length.
pub fn seal(self: *InitialSpace, payload: []const u8, out: []u8) Error!u32 {
    const pn = self.next_packet_number;
    const pn_len = packet_number.encodeLength(pn, self.largest_acked, packet_number.max_len);

    if (payload.len > std.math.maxInt(u32) - 64) return error.NoSpace;

    var writer: Writer = .init(out);
    const offsets = try packet.writeLong(&writer, .{
        .kind = .initial,
        .destination_connection_id = self.destination_connection_id,
        .source_connection_id = self.source_connection_id,
        .packet_number_len = pn_len,
        .body_len = @as(u32, pn_len) + @as(u32, @intCast(payload.len)) + protection.tag_length,
    });
    try packet_number.write(&writer, pn, pn_len);

    const total = try protection.sealPacket(
        &self.send_keys,
        pn,
        offsets.packet_number,
        pn_len,
        payload,
        out,
    );

    self.next_packet_number += 1;
    return total;
}

/// Open one Initial packet in place and return what it carried.
///
/// `bytes` is exactly one packet, and is modified: header protection is
/// removed in place, which is what a receiver does anyway. `plaintext` receives
/// the frames. The packet number is recorded for the next ACK.
pub fn open(self: *InitialSpace, bytes: []u8, plaintext: []u8) Error!Opened {
    const long = try packet.parseLong(bytes);
    if (long.kind != .initial) return error.NotInitial;
    if (long.token.len != 0) return error.UnexpectedToken;
    if (long.version != .v1) return error.UnsupportedVersion;

    // The Length field says where this packet ends, so a coalesced datagram
    // works: everything past it belongs to the next packet.
    const packet_end = @as(usize, long.body_offset) + long.length;
    if (packet_end > bytes.len) return error.Truncated;

    const opened = try protection.openPacket(
        &self.receive_keys,
        bytes[0..packet_end],
        long.body_offset,
        self.largest_received,
        plaintext,
    );

    self.largest_received = if (self.largest_received) |largest|
        @max(largest, opened.packet_number)
    else
        opened.packet_number;
    self.record(opened.packet_number);

    return .{
        .packet_number = opened.packet_number,
        .header_len = opened.header_len,
        .packet_len = @intCast(packet_end),
        .payload = opened.payload,
    };
}

/// Note the largest packet number the peer acknowledged (§17.1).
///
/// The range arithmetic of the ACK is the codec's business; this driver keeps
/// one number from it, because that is all a sender needs to size the next
/// truncated packet number. It does not police the ranges themselves: that is
/// loss recovery's job (RFC 9002), and there is none here.
pub fn recordAck(self: *InitialSpace, ack: *const frame.Ack) Error!void {
    if (ack.largest >= self.next_packet_number) return error.AckForUnsentPacket;
    self.largest_acked = if (self.largest_acked) |largest|
        @max(largest, ack.largest)
    else
        ack.largest;
}

/// Note a packet number as received, merging it into the ranges.
pub fn record(self: *InitialSpace, pn: u64) void {
    var buf: [range_capacity + 1]Range = undefined;
    var count: usize = 0;

    // Existing ranges, descending, with the new one inserted in place.
    var inserted = false;
    for (self.ranges[0..self.range_count]) |range| {
        if (!inserted and range.largest < pn) {
            buf[count] = .{ .smallest = pn, .largest = pn };
            count += 1;
            inserted = true;
        }
        buf[count] = range;
        count += 1;
    }
    if (!inserted) {
        buf[count] = .{ .smallest = pn, .largest = pn };
        count += 1;
    }

    // Merge neighbours that touch or overlap. Descending order makes one pass
    // enough: a range can only join the one above it.
    var merged: usize = 0;
    for (buf[0..count]) |range| {
        if (merged > 0) {
            const previous = &buf[merged - 1];
            if (range.largest +% 1 >= previous.smallest) {
                previous.smallest = @min(previous.smallest, range.smallest);
                continue;
            }
        }
        buf[merged] = range;
        merged += 1;
    }

    // Past the cap, the smallest range goes. Forgetting an acknowledged packet
    // is allowed: an ACK never withdraws an acknowledgment (§13.2.4).
    const kept = @min(merged, range_capacity);
    @memcpy(self.ranges[0..kept], buf[0..kept]);
    self.range_count = @intCast(kept);
}

/// Build an ACK frame for everything received, or null when nothing has been.
///
/// `scratch` holds the encoded Gap and ACK Range Length pairs, which the frame
/// borrows; the caller then writes the frame into a payload. `delay` is zero
/// because this driver has no clock.
pub fn ackFrame(self: *const InitialSpace, scratch: []u8) Error!?frame.Frame {
    if (self.range_count == 0) return null;

    const first = self.ranges[0];
    var writer: Writer = .init(scratch);
    var previous_smallest = first.smallest;
    var index: usize = 1;
    while (index < self.range_count) : (index += 1) {
        const range = self.ranges[index];
        // Ranges are merged when they touch, so at least one unacknowledged
        // number always sits between two of them.
        std.debug.assert(previous_smallest >= range.largest + 2);
        try writeVarint(&writer, previous_smallest - range.largest - 2);
        try writeVarint(&writer, range.largest - range.smallest);
        previous_smallest = range.smallest;
    }

    return .{ .ack = .{
        .largest = first.largest,
        .delay = 0,
        .first_range = first.largest - first.smallest,
        .range_count = self.range_count - 1,
        .bytes = writer.written(),
        .ecn = null,
    } };
}

/// A gap or a range length is a packet number difference, which is inside the
/// varint's 62 bits by construction.
fn writeVarint(writer: *Writer, value: u64) Writer.Error!void {
    varint.write(writer, value) catch |err| switch (err) {
        error.NoSpace => return error.NoSpace,
        error.Overflow => unreachable,
    };
}

test "RFC 9000 §19.3.1, received numbers become the ACK ranges the wire wants" {
    var space: InitialSpace = .init(.{
        .side = .client,
        .original_destination_connection_id = &.{ 1, 2, 3 },
        .destination_connection_id = &.{ 1, 2, 3 },
        .source_connection_id = &.{4},
    });

    // 10, 11, 12 arrive together: one range, no pairs.
    space.record(10);
    space.record(11);
    space.record(12);
    try testing.expectEqual(@as(u4, 1), space.range_count);
    try testing.expectEqual(@as(u64, 12), space.ranges[0].largest);
    try testing.expectEqual(@as(u64, 10), space.ranges[0].smallest);

    var scratch: [16]u8 = undefined;
    var ack = (try space.ackFrame(&scratch)).?.ack;
    try testing.expectEqual(@as(u64, 12), ack.largest);
    try testing.expectEqual(@as(u64, 2), ack.first_range);
    try testing.expectEqual(@as(u64, 0), ack.range_count);

    // A gap at 13 and a later range at 20..21.
    space.record(20);
    space.record(21);
    try testing.expectEqual(@as(u4, 2), space.range_count);
    try testing.expectEqual(@as(u64, 21), space.ranges[0].largest);
    try testing.expectEqual(@as(u64, 12), space.ranges[1].largest);

    var second_scratch: [16]u8 = undefined;
    ack = (try space.ackFrame(&second_scratch)).?.ack;
    try testing.expectEqual(@as(u64, 21), ack.largest);
    try testing.expectEqual(@as(u64, 1), ack.first_range);
    try testing.expectEqual(@as(u64, 1), ack.range_count);

    // Between range [10..12] and range [20..21] sit 13 through 19: seven
    // unacknowledged numbers, which the gap field encodes as six (§19.3.1).
    var ranges = ack.ranges();
    const range = (try ranges.next()).?;
    try testing.expectEqual(@as(u64, 6), range.gap);
    try testing.expectEqual(@as(u64, 2), range.length);
}

test "RFC 9000 §19.3.1, a number that bridges two ranges merges them" {
    var space: InitialSpace = .init(.{
        .side = .server,
        .original_destination_connection_id = &.{},
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
    });

    space.record(10);
    space.record(8);
    try testing.expectEqual(@as(u4, 2), space.range_count);

    // 9 closes the gap: one range, 8 through 10.
    space.record(9);
    try testing.expectEqual(@as(u4, 1), space.range_count);
    try testing.expectEqual(@as(u64, 10), space.ranges[0].largest);
    try testing.expectEqual(@as(u64, 8), space.ranges[0].smallest);

    // A duplicate changes nothing.
    space.record(9);
    try testing.expectEqual(@as(u4, 1), space.range_count);
}

test "the driver forgets its smallest range past the cap, and only that" {
    var space: InitialSpace = .init(.{
        .side = .client,
        .original_destination_connection_id = &.{},
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
    });

    // Ten isolated ranges, one per ten numbers.
    var i: u64 = 0;
    while (i < range_capacity + 2) : (i += 1) space.record(i * 10);

    try testing.expectEqual(@as(u4, range_capacity), space.range_count);
    // The newest is kept, the oldest two are gone.
    try testing.expectEqual(@as(u64, (range_capacity + 1) * 10), space.ranges[0].largest);
    try testing.expectEqual(@as(u64, 20), space.ranges[range_capacity - 1].largest);

    var scratch: [64]u8 = undefined;
    const ack = (try space.ackFrame(&scratch)).?.ack;
    try testing.expectEqual(@as(u64, range_capacity - 1), ack.range_count);
}

test "RFC 9000 §17.1, the packet number width follows what was acknowledged" {
    var client: InitialSpace = .init(.{
        .side = .client,
        .original_destination_connection_id = &.{ 9, 9 },
        .destination_connection_id = &.{ 9, 9 },
        .source_connection_id = &.{ 7, 7 },
    });
    var server: InitialSpace = .init(.{
        .side = .server,
        .original_destination_connection_id = &.{ 9, 9 },
        .destination_connection_id = &.{ 7, 7 },
        .source_connection_id = &.{ 9, 9 },
    });

    const payload = "a payload with enough bytes for the header protection sample";
    var datagram: [256]u8 = undefined;
    var opened_payload: [256]u8 = undefined;

    // With nothing acknowledged, §17.1 wants the whole number, so the width is
    // the number's own: one byte needs eight bits, which reaches packet number
    // 254, and packet number 255 is the first that needs two bytes.
    var lengths: [258]u32 = undefined;
    for (0..lengths.len) |i| {
        lengths[i] = try client.seal(payload, &datagram);
        const opened = try server.open(datagram[0..lengths[i]], &opened_payload);
        try testing.expectEqual(@as(u64, @intCast(i)), opened.packet_number);
    }
    try testing.expectEqual(lengths[254], lengths[253]);
    try testing.expectEqual(lengths[254] + 1, lengths[255]);

    // One ACK covering everything lets the next number shrink back to a byte.
    var scratch: [64]u8 = undefined;
    const ack = (try server.ackFrame(&scratch)).?.ack;
    try client.recordAck(&ack);
    try testing.expectEqual(@as(?u64, 257), client.largest_acked);

    const narrowed = try client.seal(payload, &datagram);
    try testing.expectEqual(lengths[254], narrowed);
    const opened = try server.open(datagram[0..narrowed], &opened_payload);
    try testing.expectEqual(@as(u64, 258), opened.packet_number);
}

test "RFC 9000 §13, an ACK for a packet never sent is refused" {
    var space: InitialSpace = .init(.{
        .side = .server,
        .original_destination_connection_id = &.{},
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
    });

    const ack: frame.Ack = .{
        .largest = 5,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    };
    try testing.expectError(error.AckForUnsentPacket, space.recordAck(&ack));
}

test "a packet sealed by one side opens on the other" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var client: InitialSpace = .init(.{
        .side = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xaa, 0xbb },
    });
    var server: InitialSpace = .init(.{
        .side = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0xaa, 0xbb },
        .source_connection_id = &.{ 0xcc, 0xdd },
    });

    const payload = "0123456789abcdef0123456789abcdef";
    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;

    const len = try client.seal(payload, &datagram);
    const opened = try server.open(datagram[0..len], &plaintext);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);
    try testing.expectEqualStrings(payload, opened.payload);
}

test "fuzz the driver's receive path" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            const dcid_len: u32 = smith.valueRangeAtMost(u32, 0, 20);
            var dcid: [20]u8 = undefined;
            smith.bytes(dcid[0..dcid_len]);

            var space: InitialSpace = .init(.{
                .side = .server,
                .original_destination_connection_id = dcid[0..dcid_len],
                .destination_connection_id = &.{},
                .source_connection_id = &.{},
            });

            var packet_buf: [512]u8 = undefined;
            const len = smith.slice(&packet_buf);
            var plaintext: [512]u8 = undefined;

            // Arbitrary bytes either fail to open or produce a payload that
            // fits, and a recorded number only ever widens the ranges.
            if (space.open(packet_buf[0..len], &plaintext)) |opened| {
                try testing.expect(opened.payload.len <= len);
                try testing.expect(space.range_count >= 1);
            } else |_| {
                // Any failure is fine, as long as it recorded nothing: a
                // packet that did not open must not move the ACK state.
                try testing.expectEqual(@as(u4, 0), space.range_count);
                try testing.expect(space.largest_received == null);
            }
        }
    }.run, .{ .corpus = &.{ "", "\xc0", "\xc0\x00\x00\x00\x01\x00\x00\x00\x00\x00" } });
}
