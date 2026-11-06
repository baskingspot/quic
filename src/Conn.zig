//! The connection machine, slice three: the three packet number spaces and the
//! datagram they arrive in.
//!
//! A caller hands over one datagram, and `Datagram` walks it: one datagram may
//! carry several packets end to end (RFC 9000 §12.2), and each packet belongs to
//! the space its form and type name (§12.3). A packet that will not open is
//! dropped and the walk continues (RFC 9001 §5.5).
//!
//! Initial keys come from the connection ID (§5.2 of RFC 9001), so they exist
//! from `init`; the Handshake and application spaces stay empty until a TLS
//! driver hands their traffic secrets over, and a packet for an empty space is
//! `error.NoKeys` for the caller to drop. There is no second notion of "not
//! ready": a space either has keys or it does not exist.
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

/// How many separate received ranges a space tracks. Eight covers the
/// reordering a handshake sees in practice; beyond it, the oldest range is
/// forgotten, which §13.2.4 allows.
pub const range_capacity = 8;

/// The widest encoding of one integer, from the codec that writes it.
const max_varint_len = varint.size(varint.max);

/// The most a gap and its range length can take: two eight-byte varints. A full
/// table holds `range_capacity` ranges, so at most one fewer pair (§19.3.1).
const ack_range_scratch_len = range_capacity * 2 * max_varint_len;

pub const Role = enum { client, server };

/// The packet number spaces of §12.3. There are three, not four: 0-RTT and
/// 1-RTT packets share the application data space.
pub const SpaceId = enum { initial, handshake, app };

pub const Error = protection.Error || packet.Error || frame.Error || error{
    /// No traffic keys are installed for the space. Handshake and application
    /// keys arrive from the TLS driver, and the space is absent until then.
    NoKeys,
    UnsupportedVersion,
    /// An acknowledgment was asked of a space that has received nothing.
    NothingToAcknowledge,
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
/// `initial` exists from `init`. `handshake` and `app` are the fields a TLS
/// driver fills in when it produces the space's traffic secrets: the keys, and
/// the connection IDs a packet in that space names. Nothing else here is
/// conditional on the space being present.
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
    ranges: [range_capacity]Range = undefined,
    range_count: u4 = 0,

    pub fn ackOwed(self: *const Space) bool {
        return self.range_count != 0 and self.acked_through != self.largest_received;
    }

    /// Note a packet number that arrived, merging it into the ranges an ACK
    /// frame is built from (§19.3.1).
    fn record(self: *Space, pn: u64) void {
        var buf: [range_capacity + 1]Range = undefined;
        var count: usize = 0;
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

        const kept = @min(merged, range_capacity);
        @memcpy(self.ranges[0..kept], buf[0..kept]);
        self.range_count = @intCast(kept);
    }
};

role: Role,
packet_number_len: u3,
/// Initial keys are derivable from the connection ID alone, so this space
/// cannot be absent.
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

/// The space for `id` with traffic keys installed, or `error.NoKeys` when there
/// is none to act on. A handshake or application space appears when its driver
/// does, and disappears when its keys are discarded; there is no third state.
pub fn spaceFor(self: *Conn, id: SpaceId) Error!*Space {
    switch (id) {
        .initial => return &self.initial,
        .handshake => return if (self.handshake) |*space| space else error.NoKeys,
        .app => return if (self.app) |*space| space else error.NoKeys,
    }
}

/// Take the first packet of a datagram and return its frames.
///
/// `plaintext` receives the payload. A packet that will not unprotect is an
/// error and leaves the machine untouched, which is what §5.5 requires of a
/// caller that then drops it.
pub fn feed(self: *Conn, datagram: []u8, plaintext: []u8) Error!Opened {
    return self.open(try self.locate(datagram), plaintext);
}

/// One packet of a datagram, located and assigned to a space, before it is
/// unprotected.
const Located = struct {
    /// The space the packet belongs to, from its form and type (§12.3).
    id: SpaceId,
    /// Exactly this packet's bytes. A short header has no Length field, so it
    /// runs to the end of the datagram (§12.2).
    bytes: []u8,
    /// Where the packet number starts, counted from `bytes[0]`.
    pn_offset: u32,
};

fn locate(self: *const Conn, bytes: []u8) Error!Located {
    if (bytes.len == 0) return error.Truncated;

    if (bytes[0] & 0x80 == 0) {
        // §17.3.1: a short header omits the destination connection ID length,
        // so reading one needs the connection and not only its bytes.
        const short = try packet.parseShort(bytes, self.localConnectionIdLen());
        return .{
            .id = .app,
            .bytes = bytes,
            .pn_offset = @intCast(1 + short.destination_connection_id.len),
        };
    }

    const long = try packet.parseLong(bytes);
    if (long.version != .v1) return error.UnsupportedVersion;
    const id: SpaceId = switch (long.kind) {
        .initial => .initial,
        .handshake => .handshake,
        // §12.3 puts 0-RTT in the application space. This build has no 0-RTT
        // keys, so a 0-RTT packet is opened, at best, under 1-RTT keys and
        // fails to authenticate: that is the drop §12.2 asks for.
        .zero_rtt => .app,
        // `parseLong` refuses a Retry, which has no Length field.
        .retry => unreachable,
    };

    return .{
        .id = id,
        .bytes = bytes[0 .. @as(usize, long.body_offset) + long.length],
        .pn_offset = long.body_offset,
    };
}

fn open(self: *Conn, at: Located, plaintext: []u8) Error!Opened {
    const space = try self.spaceFor(at.id);

    const opened = try protection.openPacket(
        &space.receive_keys,
        at.bytes,
        at.pn_offset,
        space.largest_received,
        plaintext,
    );

    space.largest_received = if (space.largest_received) |largest|
        @max(largest, opened.packet_number)
    else
        opened.packet_number;
    space.record(opened.packet_number);

    return .{
        .packet_number = opened.packet_number,
        .frames = opened.payload,
        .header_len = opened.header_len,
        .packet_len = @intCast(at.bytes.len),
    };
}

/// A datagram, walked one packet at a time.
///
/// §12.2 shapes this in three ways. Long header packets delimit themselves with
/// their Length field, so the next one starts where this one ended; a short
/// header has no Length field, so it runs to the end of the datagram and must
/// be the last packet in it. And a packet that cannot be processed is dropped
/// rather than fatal, which RFC 9001 §5.5 repeats for one that will not
/// unprotect: an attacker corrupting a datagram cannot kill the connection, so
/// the walk goes on to the next packet.
///
/// Every `next` hands out the frames of one packet in the caller's `plaintext`
/// buffer, which is why the caller pulls rather than receives a list: the frames
/// of two packets cannot share one buffer.
pub const Datagram = struct {
    /// The caller's receive buffer, as it arrived. `next` unprotects in place,
    /// because that is what removing header protection is: an XOR over these
    /// bytes.
    bytes: []u8,
    /// The read position, through the one read walker in this package.
    cursor: Cursor,
    /// Packets that the datagram delimited and that did not open: a bad tag, a
    /// space with no keys yet, or bytes with no readable end.
    dropped: u16 = 0,

    pub fn init(bytes: []u8) Datagram {
        return .{ .bytes = bytes, .cursor = .init(bytes) };
    }

    /// The next packet that opened, or null when there is nothing left to
    /// process. The frames are valid until the next call.
    pub fn next(self: *Datagram, conn: *Conn, plaintext: []u8) Error!?Opened {
        while (self.cursor.remaining() > 0) {
            const rest = self.bytes[self.cursor.pos..];
            const at = conn.locate(rest) catch {
                // The packet has no readable end, so there is no boundary to
                // find the next one at. The rest of the datagram goes with it.
                self.dropped += 1;
                self.cursor.pos = @intCast(self.bytes.len);
                return null;
            };
            _ = self.cursor.skip(@intCast(at.bytes.len));

            return conn.open(at, plaintext) catch |err| switch (err) {
                // The plaintext buffer is the caller's to size, and running out
                // of it is not the peer's doing: report it, do not drop it.
                error.NoSpace => err,
                else => {
                    self.dropped += 1;
                    continue;
                },
            };
        }
        return null;
    }
};

/// The length of this endpoint's own connection ID: what the peer echoes as the
/// destination of the packets it sends, and what a short header leaves off the
/// wire (§17.3.1). Connection IDs do not change in this build, so the one the
/// Initial space writes is the one every packet from the peer names.
fn localConnectionIdLen(self: *const Conn) u32 {
    return @intCast(self.initial.source_connection_id.len);
}

/// Seal a packet in `id`'s space carrying `frames`, which the caller already
/// encoded.
///
/// Initial and Handshake packets get a long header; an application packet gets
/// a short one, because §17.3 allows no other form for 1-RTT. This is the seam
/// the later slices widen: the machine builds the header, the packet number, and
/// the protection, and the caller says what is inside.
pub fn writeFrames(self: *Conn, id: SpaceId, frames: []const u8, out: []u8) Error!u32 {
    const space = try self.spaceFor(id);
    const pn = space.next_packet_number;
    const pn_len = self.packet_number_len;

    var writer: Writer = .init(out);
    const pn_offset = switch (id) {
        .initial, .handshake => (try packet.writeLong(&writer, .{
            .kind = if (id == .initial) .initial else .handshake,
            .destination_connection_id = space.destination_connection_id,
            .source_connection_id = space.source_connection_id,
            .packet_number_len = pn_len,
            .body_len = @as(u32, pn_len) + @as(u32, @intCast(frames.len)) + protection.tag_length,
        })).packet_number,
        .app => (try packet.writeShort(&writer, .{
            .destination_connection_id = space.destination_connection_id,
            .packet_number_len = pn_len,
        })).packet_number,
    };
    try packet_number.write(&writer, pn, pn_len);

    const total = try protection.sealPacket(&space.send_keys, pn, pn_offset, pn_len, frames, out);
    space.next_packet_number += 1;
    return total;
}

/// Whether an acknowledgment is owed in `id`'s space: something has been
/// received there since the last one was sent. A space with no keys owes
/// nothing, because nothing in it can have arrived.
pub fn ackOwed(self: *const Conn, id: SpaceId) bool {
    const space: *const Space = switch (id) {
        .initial => &self.initial,
        .handshake => if (self.handshake) |*space| space else return false,
        .app => if (self.app) |*space| space else return false,
    };
    return space.ackOwed();
}

/// Seal a packet carrying one ACK frame for everything received in `id`'s
/// space. An ACK is sent in the space it acknowledges (§13.2.1).
pub fn writeAck(self: *Conn, id: SpaceId, out: []u8) Error!u32 {
    const space = try self.spaceFor(id);
    if (space.range_count == 0) return error.NothingToAcknowledge;

    var scratch: [ack_range_scratch_len]u8 = undefined;
    var scratch_writer: Writer = .init(&scratch);
    const first = space.ranges[0];
    var previous_smallest = first.smallest;
    var index: usize = 1;
    while (index < space.range_count) : (index += 1) {
        const range = space.ranges[index];
        std.debug.assert(previous_smallest >= range.largest + 2);
        // Each value is below 2^62, so eight bytes hold it and the scratch,
        // sized for every pair at eight bytes, cannot run out.
        varint.write(&scratch_writer, previous_smallest - range.largest - 2) catch unreachable;
        varint.write(&scratch_writer, range.largest - range.smallest) catch unreachable;
        previous_smallest = range.smallest;
    }

    const ack: frame.Ack = .{
        .largest = first.largest,
        .delay = 0,
        .first_range = first.largest - first.smallest,
        .range_count = space.range_count - 1,
        .bytes = scratch_writer.written(),
        .ecn = null,
    };

    var payload: [ack_range_scratch_len + 32]u8 = undefined;
    var payload_writer: Writer = .init(&payload);
    try frame.write(&payload_writer, .{ .ack = ack });

    const total = try self.writeFrames(id, payload_writer.written(), out);
    space.acked_through = space.largest_received;
    return total;
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

    // Nothing has arrived yet, so there is nothing to acknowledge.
    try testing.expectError(error.NothingToAcknowledge, server.writeAck(.initial, &datagram));

    const sent = try client.writeFrames(.initial, "a payload with enough bytes to sample", &datagram);
    const at_server = try server.feed(datagram[0..sent], &plaintext);
    try testing.expectEqual(@as(u64, 0), at_server.packet_number);
    try testing.expectEqualStrings("a payload with enough bytes to sample", at_server.frames);
    try testing.expect(server.ackOwed(.initial));

    // The server answers with an ACK for packet 0.
    const ack_len = try server.writeAck(.initial, &datagram);
    try testing.expect(!server.ackOwed(.initial));

    const at_client = try client.feed(datagram[0..ack_len], &plaintext);
    var cursor = Cursor.init(at_client.frames);
    const ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, 0), ack.largest);
    try testing.expectEqual(@as(u64, 0), ack.first_range);
    try testing.expectEqual(@as(u64, 0), ack.range_count);
}

test "RFC 9000 §12.3, a Handshake packet opens in the handshake space" {
    const dcid = [_]u8{ 3, 1, 4, 1, 5 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xa1, 0xa2 },
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0xa1, 0xa2 },
        .source_connection_id = &.{ 0xb1, 0xb2 },
    });

    // What the TLS driver will do: both sides get the Handshake keys from the
    // handshake secrets, client and server halves crossed.
    const client_secret: [protection.secret_length]u8 = @splat(0x11);
    const server_secret: [protection.secret_length]u8 = @splat(0x22);
    installHandshake(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;

    const sent = try client.writeFrames(.handshake, "handshake bytes to sample", &datagram);
    const opened = try server.feed(datagram[0..sent], &plaintext);

    try testing.expectEqualStrings("handshake bytes to sample", opened.frames);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);
    try testing.expectEqual(@as(?u64, 0), server.handshake.?.largest_received);
    // Not the Initial space, which received nothing.
    try testing.expectEqual(@as(?u64, null), server.initial.largest_received);
    try testing.expect(server.ackOwed(.handshake));
    try testing.expect(!server.ackOwed(.initial));

    // And the acknowledgment is a Handshake packet, which is the only space the
    // client can read it in (§13.2.1).
    const ack_len = try server.writeAck(.handshake, &datagram);
    const at_client = try client.feed(datagram[0..ack_len], &plaintext);
    var cursor = Cursor.init(at_client.frames);
    try testing.expectEqual(@as(u64, 0), (try frame.read(&cursor)).ack.largest);
    try testing.expectEqual(@as(?u64, null), client.initial.largest_received);
}

test "RFC 9000 §12.3, a space with no keys is an error and not a second kind of empty" {
    const dcid = [_]u8{ 2, 7, 1, 8 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x01},
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x01},
        .source_connection_id = &.{0x02},
    });

    // The client learns the Handshake secrets and the server does not, which is
    // the window between the driver reporting them and nothing.
    const client_secret: [protection.secret_length]u8 = @splat(0x33);
    const server_secret: [protection.secret_length]u8 = @splat(0x44);
    installHandshake(&client, &client, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    const sent = try client.writeFrames(.handshake, "handshake bytes to sample", &datagram);

    try testing.expectError(error.NoKeys, server.feed(datagram[0..sent], &plaintext));
    try testing.expectError(error.NoKeys, server.writeFrames(.handshake, "x", &datagram));
    try testing.expectError(error.NoKeys, server.writeAck(.app, &datagram));
    // Nothing was recorded, so nothing is owed.
    try testing.expect(!server.ackOwed(.handshake));
    try testing.expect(!server.ackOwed(.app));
}

test "RFC 9000 §17.3.1, the application space writes a short header and opens one" {
    // A short header omits the connection ID length, so the two ends have to
    // agree on it: the client names the server's ID and the server names the
    // client's.
    const server_id = [_]u8{ 0x51, 0x52, 0x53 };
    const client_id = [_]u8{ 0x61, 0x62 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &server_id,
        .source_connection_id = &client_id,
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &client_id,
        .source_connection_id = &server_id,
    });

    const client_secret: [protection.secret_length]u8 = @splat(0x55);
    const server_secret: [protection.secret_length]u8 = @splat(0x66);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;

    const sent = try client.writeFrames(.app, "a one-rtt payload to sample", &datagram);
    // §17.3.1: the form bit is clear, and the destination connection ID has no
    // length on the wire.
    try testing.expectEqual(@as(u8, 0x00), datagram[0] & 0x80);
    try testing.expectEqualSlices(u8, &server_id, datagram[1..][0..server_id.len]);

    const opened = try server.feed(datagram[0..sent], &plaintext);
    try testing.expectEqualStrings("a one-rtt payload to sample", opened.frames);
    try testing.expectEqual(@as(?u64, 0), server.app.?.largest_received);
    try testing.expectEqual(@as(?u64, null), server.initial.largest_received);
    // The whole rest of the datagram is the packet: a short header has no
    // Length field (§12.2).
    try testing.expectEqual(@as(u32, @intCast(sent)), opened.packet_len);
}

test "RFC 9000 §19.3, eight received ranges do not overflow the ACK path" {
    const dcid = [_]u8{ 0xaa, 0xbb };
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xcc},
    });

    // Ranges wide enough that both the gap to the next one and the run length
    // need eight-byte varints: the widest ACK a full range table can produce.
    const run: u64 = 1 << 56;
    const spacing: u64 = 2 * run + 8;
    var index: usize = 0;
    while (index < range_capacity) : (index += 1) {
        const smallest: u64 = 4 + (range_capacity - 1 - index) * spacing;
        server.initial.ranges[index] = .{ .smallest = smallest, .largest = smallest + run };
        server.initial.range_count += 1;
    }
    server.initial.largest_received = server.initial.ranges[0].largest;

    var out: [512]u8 = undefined;
    const ack_len = try server.writeAck(.initial, &out);
    try testing.expect(ack_len > 0);

    // The frame round trips, which says the scratch held every pair.
    var plaintext: [512]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0xcc},
        .source_connection_id = &dcid,
    });
    const at_client = try client.feed(out[0..ack_len], &plaintext);
    var cursor = Cursor.init(at_client.frames);
    const ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, 7), ack.range_count);
    try testing.expectEqual(server.initial.ranges[0].largest, ack.largest);
}

test "RFC 9000 §12.2, a server flight of Initial and Handshake in one datagram" {
    const dcid = [_]u8{ 0x0d, 0x0e };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x0a},
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x0a},
        .source_connection_id = &.{0x0b},
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x77);
    const server_secret: [protection.secret_length]u8 = @splat(0x88);
    installHandshake(&client, &server, client_secret, server_secret);

    // The flight the server cannot know the client can read: both levels in
    // one datagram, because it is one datagram's worth of network.
    var flight: [1024]u8 = undefined;
    const initial_len = try server.writeFrames(.initial, "initial payload bytes", &flight);
    const handshake_len = try server.writeFrames(.handshake, "handshake payload bytes", flight[initial_len..]);
    var datagram: Datagram = .init(flight[0 .. initial_len + handshake_len]);

    var plaintext: [512]u8 = undefined;

    const first = (try datagram.next(&client, &plaintext)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("initial payload bytes", first.frames);
    try testing.expectEqual(@as(?u64, 0), client.initial.largest_received);
    try testing.expectEqual(@as(?u64, null), client.handshake.?.largest_received);

    const second = (try datagram.next(&client, &plaintext)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("handshake payload bytes", second.frames);
    try testing.expectEqual(@as(?u64, 0), client.handshake.?.largest_received);

    try testing.expect((try datagram.next(&client, &plaintext)) == null);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
    // Both spaces are accounted for separately, which is what the client needs
    // to answer each level with an ACK of its own (§13.2.1).
    try testing.expect(client.ackOwed(.initial));
    try testing.expect(client.ackOwed(.handshake));
}

test "RFC 9001 §5.5, a packet that will not unprotect is dropped and the next is processed" {
    const dcid = [_]u8{ 0x1d, 0x1e };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x1a},
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x1a},
        .source_connection_id = &.{0x1b},
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x99);
    const server_secret: [protection.secret_length]u8 = @splat(0xaa);
    installHandshake(&client, &server, client_secret, server_secret);

    var flight: [1024]u8 = undefined;
    const initial_len = try server.writeFrames(.initial, "initial payload bytes", &flight);
    const handshake_len = try server.writeFrames(.handshake, "handshake payload bytes", flight[initial_len..]);
    var datagram: Datagram = .init(flight[0 .. initial_len + handshake_len]);

    // A bit in the Initial's authentication tag. An attacker on the path can do
    // this to any datagram, so it must cost exactly one packet.
    datagram.bytes[initial_len - 8] ^= 0x01;

    var plaintext: [512]u8 = undefined;
    const opened = (try datagram.next(&client, &plaintext)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("handshake payload bytes", opened.frames);
    try testing.expectEqual(@as(?u64, null), client.initial.largest_received);
    try testing.expectEqual(@as(?u64, 0), client.handshake.?.largest_received);
    try testing.expectEqual(@as(u16, 1), datagram.dropped);
    try testing.expect(!client.ackOwed(.initial));
    try testing.expect(client.ackOwed(.handshake));
}

test "RFC 9000 §12.2, a short header ends the datagram and nothing is read past it" {
    const server_id = [_]u8{ 0x31, 0x32 };
    const client_id = [_]u8{ 0x41, 0x42 };
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &server_id,
        .source_connection_id = &client_id,
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &client_id,
        .source_connection_id = &server_id,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0xbb);
    const server_secret: [protection.secret_length]u8 = @splat(0xcc);
    installApp(&client, &server, client_secret, server_secret);

    // A long header, then a short one: legal, and the short one is last
    // because its length is the rest of the datagram.
    var flight: [1024]u8 = undefined;
    const initial_len = try client.writeFrames(.initial, "initial payload bytes", &flight);
    const app_len = try client.writeFrames(.app, "one-rtt payload bytes", flight[initial_len..]);
    var datagram: Datagram = .init(flight[0 .. initial_len + app_len]);

    var plaintext: [512]u8 = undefined;
    const initial = (try datagram.next(&server, &plaintext)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("initial payload bytes", initial.frames);
    const app = (try datagram.next(&server, &plaintext)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("one-rtt payload bytes", app.frames);
    // The whole tail of the datagram belonged to that packet.
    try testing.expectEqual(@as(u32, @intCast(app_len)), app.packet_len);
    try testing.expect((try datagram.next(&server, &plaintext)) == null);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
}

test "RFC 9000 §12.2, bytes with no readable end stop the walk without an error" {
    const dcid = [_]u8{0x5d};
    var client: Conn = .init(.{
        .role = .client,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x5a},
    });
    var server: Conn = .init(.{
        .role = .server,
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x5a},
        .source_connection_id = &.{0x5b},
    });

    var flight: [512]u8 = undefined;
    const initial_len = try client.writeFrames(.initial, "initial payload bytes", &flight);
    // A long header cut off inside its connection ID: no Length field, so
    // nothing says where the packet would have ended.
    const junk = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02 };
    @memcpy(flight[initial_len..][0..junk.len], &junk);
    var datagram: Datagram = .init(flight[0 .. initial_len + junk.len]);

    var plaintext: [512]u8 = undefined;
    const opened = (try datagram.next(&server, &plaintext)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("initial payload bytes", opened.frames);
    try testing.expect((try datagram.next(&server, &plaintext)) == null);
    try testing.expectEqual(@as(u16, 1), datagram.dropped);
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
    const first = try client.writeFrames(.initial, "first packet bytes to sample", &combined);
    const second = try client.writeFrames(.initial, "second packet bytes to sample", combined[first..]);

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
    const sent = try client.writeFrames(.initial, "payload long enough to sample", &datagram);

    // One bit in the ciphertext, far from the header sample.
    datagram[sent - 20] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, server.feed(datagram[0..sent], &plaintext));
    try testing.expect(!server.ackOwed(.initial));
    try testing.expectEqual(@as(?u64, null), server.initial.largest_received);
}

/// Stand in for the TLS driver: hand both endpoints a space, with the keys
/// crossed the way the two roles need them.
fn installSpace(conn: *Conn, id: SpaceId, send: protection.Keys, receive: protection.Keys) void {
    std.debug.assert(id != .initial);
    // The identity a driver copies from the Initial space plus its own keys.
    var installed: Space = conn.initial;
    installed.send_keys = send;
    installed.receive_keys = receive;
    installed.next_packet_number = 0;
    installed.largest_received = null;
    installed.acked_through = null;
    installed.range_count = 0;
    switch (id) {
        .initial => unreachable,
        .handshake => conn.handshake = installed,
        .app => conn.app = installed,
    }
}

fn installHandshake(
    client: *Conn,
    server: *Conn,
    client_secret: [protection.secret_length]u8,
    server_secret: [protection.secret_length]u8,
) void {
    installPaired(client, server, .handshake, client_secret, server_secret);
}

fn installApp(
    client: *Conn,
    server: *Conn,
    client_secret: [protection.secret_length]u8,
    server_secret: [protection.secret_length]u8,
) void {
    installPaired(client, server, .app, client_secret, server_secret);
}

fn installPaired(
    client: *Conn,
    server: *Conn,
    id: SpaceId,
    client_secret: [protection.secret_length]u8,
    server_secret: [protection.secret_length]u8,
) void {
    const client_keys = protection.deriveKeys(&client_secret, .aes_128_gcm) catch unreachable;
    const server_keys = protection.deriveKeys(&server_secret, .aes_128_gcm) catch unreachable;
    installSpace(client, id, client_keys, server_keys);
    installSpace(server, id, server_keys, client_keys);
}
