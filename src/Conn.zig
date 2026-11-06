//! The connection machine, slice one: parse, protect, acknowledge.
//!
//! A caller feeds one datagram and a time, and gets the frames that came out of
//! it. The machine holds the Initial keys, the packet numbers in both
//! directions, and the ranges it has received, which is exactly what producing
//! an acknowledgment requires. Nothing else is here yet: no handshake, no
//! streams, no congestion, no coalescing, no timers.
//!
//! Every buffer is the caller's, the clock is a value the caller passes, and
//! nothing allocates. The only frame this slice emits is an ACK, and it is
//! described as such, because a packet that does not say what it carries cannot
//! be retransmitted by a caller that later learns it was lost.

const std = @import("std");
const testing = std.testing;
const Cursor = @import("Cursor.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const packet_number = @import("packet_number.zig");
const protection = @import("protection.zig");
const Writer = @import("Writer.zig");
const varint = @import("varint.zig");

const Conn = @This();

const Range = struct { smallest: u64, largest: u64 };

pub const Role = enum { client, server };

pub const Error = protection.Error || packet.Error || frame.Error || error{
    NotInitial,
    UnsupportedVersion,
    /// The caller's output buffer cannot hold the packet.
    NoSpace,
};

pub const Config = struct {
    role: Role,
    /// The client's Destination Connection ID: the Initial keys come from it,
    /// and both endpoints derive the same ones (§5.2 of RFC 9001).
    original_destination_connection_id: []const u8,
    /// What this endpoint writes into the packets it sends.
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// The truncation width to use. §17.1 makes this a function of what the
    /// peer has acknowledged; until that lands, the caller picks, and four
    /// bytes is always legal.
    packet_number_len: u3 = 4,
};

pub const Opened = struct {
    packet_number: u64,
    /// The frames the packet carried, written into the caller's buffer.
    frames: []u8,
    header_len: u32,
    packet_len: u32,
};

/// One packet number space: its identity as far as the peer sees it, its keys,
/// its counters, and the ranges it has received.
///
/// Slice one populates `initial` and nothing else. `handshake` and `app` are
/// the fields the wiring fills in: a space stays null until the handshake
/// driver hands over its secrets.
pub const Space = struct {
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    send_keys: protection.Keys,
    receive_keys: protection.Keys,
    next_packet_number: u64 = 0,
    largest_received: ?u64 = null,
    /// The largest packet number an ACK has been sent for, so a machine does
    /// not acknowledge the same thing twice.
    acked_through: ?u64 = null,
    /// Received packet numbers, descending and merged, for the ACK frame.
    ranges: [8]Range = undefined,
    range_count: u4 = 0,
};

role: Role,
packet_number_len: u3,
/// The only space this slice knows how to build: Initial.
initial: Space,
/// Handshake keys come from the TLS driver, which is not wired yet.
handshake: ?Space = null,
/// 1-RTT keys, same.
app: ?Space = null,

pub fn init(config: Config) Conn {
    std.debug.assert(config.packet_number_len >= 1);
    std.debug.assert(config.packet_number_len <= 4);

    const secrets = protection.initialSecrets(config.original_destination_connection_id);
    const suite = protection.Suite.aes_128_gcm;
    const client = protection.deriveKeys(&secrets.client, suite) catch unreachable;
    const server = protection.deriveKeys(&secrets.server, suite) catch unreachable;

    return .{
        .role = config.role,
        .packet_number_len = config.packet_number_len,
        .initial = .{
            .destination_connection_id = config.destination_connection_id,
            .source_connection_id = config.source_connection_id,
            .send_keys = if (config.role == .client) client else server,
            .receive_keys = if (config.role == .client) server else client,
        },
    };
}

/// Take one datagram's first packet and return its frames.
///
/// `plaintext` receives the payload. A packet that will not unprotect is an
/// error and leaves the machine untouched, which is what §5.5 requires of a
/// caller that then drops it.
pub fn feed(self: *Conn, datagram: []u8, plaintext: []u8) Error!Opened {
    const long = try packet.parseLong(datagram);
    if (long.kind != .initial) return error.NotInitial;
    if (long.version != .v1) return error.UnsupportedVersion;

    const packet_end = @as(usize, long.body_offset) + long.length;
    if (packet_end > datagram.len) return error.Truncated;

    const opened = try protection.openPacket(
        &self.initial.receive_keys,
        datagram[0..packet_end],
        long.body_offset,
        self.initial.largest_received,
        plaintext,
    );

    self.initial.largest_received = if (self.initial.largest_received) |largest|
        @max(largest, opened.packet_number)
    else
        opened.packet_number;
    self.record(opened.packet_number);

    return .{
        .packet_number = opened.packet_number,
        .frames = opened.payload,
        .header_len = opened.header_len,
        .packet_len = @intCast(packet_end),
    };
}

/// Seal a packet carrying `frames`, which the caller already encoded.
///
/// This is the seam the later slices widen: the machine builds the header, the
/// packet number, and the protection, and the caller says what is inside.
pub fn writeFrames(self: *Conn, frames: []const u8, out: []u8) Error!u32 {
    const pn = self.initial.next_packet_number;
    const pn_len = self.packet_number_len;

    var writer: Writer = .init(out);
    const offsets = try packet.writeLong(&writer, .{
        .kind = .initial,
        .destination_connection_id = self.initial.destination_connection_id,
        .source_connection_id = self.initial.source_connection_id,
        .packet_number_len = pn_len,
        .body_len = @as(u32, pn_len) + @as(u32, @intCast(frames.len)) + protection.tag_length,
    });
    try packet_number.write(&writer, pn, pn_len);

    const total = try protection.sealPacket(&self.initial.send_keys, pn, offsets.packet_number, pn_len, frames, out);
    self.initial.next_packet_number += 1;
    return total;
}

/// Whether an acknowledgment is owed: something has been received since the
/// last one was sent.
pub fn ackOwed(self: *const Conn) bool {
    return self.initial.range_count != 0 and self.initial.acked_through != self.initial.largest_received;
}

/// Seal an Initial packet carrying one ACK frame for everything received.
pub fn writeAck(self: *Conn, out: []u8) Error!u32 {
    if (self.initial.range_count == 0) return error.WrongPacketType;

    var scratch: [64]u8 = undefined;
    var scratch_writer: Writer = .init(&scratch);
    const first = self.initial.ranges[0];
    var previous_smallest = first.smallest;
    var index: usize = 1;
    while (index < self.initial.range_count) : (index += 1) {
        const range = self.initial.ranges[index];
        std.debug.assert(previous_smallest >= range.largest + 2);
        varint.write(&scratch_writer, previous_smallest - range.largest - 2) catch unreachable;
        varint.write(&scratch_writer, range.largest - range.smallest) catch unreachable;
        previous_smallest = range.smallest;
    }

    const ack: frame.Ack = .{
        .largest = first.largest,
        .delay = 0,
        .first_range = first.largest - first.smallest,
        .range_count = self.initial.range_count - 1,
        .bytes = scratch_writer.written(),
        .ecn = null,
    };

    var payload: [128]u8 = undefined;
    var payload_writer: Writer = .init(&payload);
    try frame.write(&payload_writer, .{ .ack = ack });

    const total = try self.writeFrames(payload_writer.written(), out);
    self.initial.acked_through = self.initial.largest_received;
    return total;
}

fn record(self: *Conn, pn: u64) void {
    var buf: [9]Range = undefined;
    var count: usize = 0;
    var inserted = false;
    for (self.initial.ranges[0..self.initial.range_count]) |range| {
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

    const kept = @min(merged, self.initial.ranges.len);
    @memcpy(self.initial.ranges[0..kept], buf[0..kept]);
    self.initial.range_count = @intCast(kept);
}

test "RFC 9001 §5.2, two machines exchange an Initial and one acknowledges" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xc1, 0xc2 },
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0xc1, 0xc2 },
        .source_connection_id = &.{ 0x5e, 0x5e },
    });

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;

    const sent = try client.writeFrames("a payload with enough bytes to sample", &datagram);
    const at_server = try server.feed(datagram[0..sent], &plaintext);
    try testing.expectEqual(@as(u64, 0), at_server.packet_number);
    try testing.expectEqualStrings("a payload with enough bytes to sample", at_server.frames);
    try testing.expect(server.ackOwed());

    // The server answers with an ACK for packet 0.
    const ack_len = try server.writeAck(&datagram);
    try testing.expect(!server.ackOwed());

    const at_client = try client.feed(datagram[0..ack_len], &plaintext);
    var cursor = Cursor.init(at_client.frames);
    const ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, 0), ack.largest);
    try testing.expectEqual(@as(u64, 0), ack.first_range);
    try testing.expectEqual(@as(u64, 0), ack.range_count);
}

test "RFC 9000 §12.2, coalesced packets: only the first is taken, the length says where it ends" {
    const dcid = [_]u8{ 1, 2, 3 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 9, 9 },
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 9, 9 },
        .source_connection_id = &.{ 7, 7 },
    });

    var plaintext: [512]u8 = undefined;
    var combined: [1024]u8 = undefined;
    const first = try client.writeFrames("first packet bytes to sample", &combined);
    const second = try client.writeFrames("second packet bytes to sample", combined[first..]);

    const opened = try server.feed(&combined, &plaintext);
    try testing.expectEqual(@as(u32, @intCast(first)), opened.packet_len);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);

    // The caller continues where the machine said the packet ended.
    const next = try server.feed(combined[opened.packet_len..][0 .. first + second - opened.packet_len], &plaintext);
    try testing.expectEqual(@as(u64, 1), next.packet_number);
}

test "RFC 9001 §5.5, a packet that will not unprotect changes nothing" {
    const dcid = [_]u8{ 4, 5, 6 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 1, 1 },
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 1, 1 },
        .source_connection_id = &.{ 2, 2 },
    });

    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    const sent = try client.writeFrames("payload long enough to sample", &datagram);

    // One bit in the ciphertext, far from the header sample.
    datagram[sent - 20] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, server.feed(datagram[0..sent], &plaintext));
    try testing.expect(!server.ackOwed());
    try testing.expectEqual(@as(?u64, null), server.initial.largest_received);
}
