//! QUIC packet headers, RFC 9000 §17.
//!
//! A packet is a first byte, then fields whose meaning depends on two bits of
//! that byte and on the version. The long header carries a version, so an
//! observer that does not speak it can still read the connection IDs and answer
//! with version negotiation; the short header carries no version and no
//! connection ID length, so reading one needs the length from the connection.
//!
//! Packet protection and header protection are RFC 9001 and are not here. The
//! reserved bits and the packet number length in byte 0 stay masked until
//! header protection is removed, so the accessors for them are only meaningful
//! on a packet the caller has already unprotected. Everything the parser returns
//! is borrowed from the caller's buffer.

const std = @import("std");
const testing = std.testing;
const Cursor = @import("Cursor.zig");
const Writer = @import("Writer.zig");
const varint = @import("varint.zig");

const packet = @This();

/// The longest connection ID version 1 allows (§17.2). Another version may
/// allow more, and version negotiation has to be able to echo it.
pub const connection_id_max: u32 = 20;

/// The version this package speaks.
pub const version_1: u32 = 0x00000001;

/// The Retry Integrity Tag is 16 bytes, from RFC 9001 §5.8.
pub const retry_integrity_tag_len: u32 = 16;

/// A QUIC version. The registry is open (RFC 9000 §22.3), so this is a
/// non-exhaustive enum: a version this build has never heard of is still a
/// value, and version negotiation exists to deal with exactly that.
pub const Version = enum(u32) {
    negotiation = 0x00000000,
    v1 = 0x00000001,
    _,
};

/// The two bits at 0x30 of byte 0, for a long header (§17.2, Table 5).
pub const Kind = enum(u2) {
    initial = 0x00,
    zero_rtt = 0x01,
    handshake = 0x02,
    retry = 0x03,
};

pub const Error = error{
    /// The buffer ended inside a field.
    Truncated,
    /// The first byte of a long header has 0x80 clear.
    NotLongHeader,
    /// The first byte of a short header has 0x80 set.
    NotShortHeader,
    /// §17.2 and §17.3.1: a packet with the fixed bit clear is not valid in
    /// version 1 and must be discarded.
    FixedBitZero,
    /// A version 1 long header names a connection ID longer than 20 bytes.
    ConnectionIdTooLong,
    /// The Length field runs past the end of the datagram.
    LengthPastEnd,
    /// A version negotiation packet whose version list is not four bytes each.
    InvalidVersionList,
    /// A Retry packet too short to hold its 16-byte integrity tag.
    RetryTooShort,
    /// §17.2.5.2: a client must discard a Retry packet with no token.
    EmptyRetryToken,
    /// The packet number length is outside 1 to 4 bytes.
    InvalidPacketNumberLength,
    /// The body is shorter than the packet number it must contain.
    InvalidLength,
    /// This entry point takes one packet type and got another.
    WrongPacketType,
    /// The caller's buffer has no room for the header.
    NoSpace,
};

/// The part of a long header that no version changes: the form and fixed bits,
/// the version, and the two connection IDs (§17.2, and RFC 8999 for the
/// version-independent view).
pub const Invariant = struct {
    /// Byte 0, unchanged.
    first: u8,
    version: Version,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// Everything after the source connection ID.
    rest: []const u8,
    /// Where `rest` starts, counted from byte 0 of the datagram.
    rest_offset: u32,
};

/// A long header packet that carries a Length field: Initial, 0-RTT, or
/// Handshake.
pub const Long = struct {
    kind: Kind,
    version: Version,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// Empty unless `kind` is `.initial`.
    token: []const u8,
    /// Byte 0, unchanged. Header protection masks its low four bits.
    first: u8,
    /// The Length field: how many bytes follow it, the packet number and the
    /// protected payload.
    length: u32,
    /// Those bytes, borrowed.
    body: []const u8,
    /// Where `body` starts, counted from byte 0 of the datagram.
    body_offset: u32,
    /// The rest of the datagram after this packet, for coalesced packets
    /// (§12.2). Empty when this packet runs to the end.
    rest: []const u8,

    /// §17.4: only a short header carries the spin bit.
    pub fn packetNumberLen(self: *const Long) u3 {
        return @truncate((self.first & 0x03) + 1);
    }

    /// The two reserved bits, which must be zero after header protection is
    /// removed (§17.2).
    pub fn reserved(self: *const Long) u2 {
        return @truncate((self.first >> 2) & 0x03);
    }
};

/// A Version Negotiation packet (§17.2.1). It carries no Length field, so it
/// occupies the whole datagram.
pub const VersionNegotiation = struct {
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// The offered versions, four bytes each, network byte order. Use `count`
    /// and `at`, or `list` for a decoded copy.
    versions: []const u8,

    pub fn count(self: *const VersionNegotiation) u32 {
        return @intCast(self.versions.len / 4);
    }

    pub fn at(self: *const VersionNegotiation, index: u32) Version {
        std.debug.assert(index < self.count());
        const start = @as(usize, index) * 4;
        return @fromBackingInt(@intCast(std.mem.readInt(u32, self.versions[start..][0..4], .big)));
    }
};

/// A Retry packet (§17.2.5). It carries a token and an integrity tag, and no
/// packet number, so it cannot be acknowledged.
pub const Retry = struct {
    version: Version,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8,
    /// The Retry Integrity Tag. Validating it is RFC 9001 §5.8.
    integrity_tag: [retry_integrity_tag_len]u8,
};

/// A 1-RTT packet (§17.3.1).
pub const Short = struct {
    /// Byte 0, unchanged. Header protection masks its low five bits.
    first: u8,
    destination_connection_id: []const u8,
    /// The packet number and the protected payload: the rest of the datagram.
    body: []const u8,

    pub fn spin(self: *const Short) bool {
        return self.first & 0x20 != 0;
    }

    pub fn keyPhase(self: *const Short) bool {
        return self.first & 0x04 != 0;
    }

    /// The two reserved bits, which must be zero after header protection is
    /// removed (§17.3.1).
    pub fn reserved(self: *const Short) u2 {
        return @truncate((self.first >> 3) & 0x03);
    }

    pub fn packetNumberLen(self: *const Short) u3 {
        return @truncate((self.first & 0x03) + 1);
    }
};

pub const Packet = union(enum) {
    version_negotiation: VersionNegotiation,
    retry: Retry,
    long: Long,
    short: Short,
};

/// Read the first packet of a datagram.
///
/// `short_dcid_len` is the destination connection ID length of the connection,
/// used only when byte 0 says short header: a short header omits that length,
/// so a reader with no connection to ask cannot parse one.
pub fn parse(bytes: []const u8, short_dcid_len: u32) Error!Packet {
    if (bytes.len == 0) return error.Truncated;
    if (bytes[0] & 0x80 == 0) {
        return .{ .short = try parseShort(bytes, short_dcid_len) };
    }

    const invariant = try parseInvariant(bytes);
    if (invariant.version == .negotiation) {
        return .{ .version_negotiation = try parseVersionNegotiation(invariant) };
    }

    const kind: Kind = @fromBackingInt(@intCast((bytes[0] >> 4) & 0x03));
    if (kind == .retry) return .{ .retry = try parseRetry(invariant) };
    return .{ .long = try parseLong(bytes) };
}

/// Read the version-independent part of a long header.
pub fn parseInvariant(bytes: []const u8) Error!Invariant {
    var cursor: Cursor = .init(bytes);

    const first = cursor.take(1) orelse return error.Truncated;
    if (first[0] & 0x80 == 0) return error.NotLongHeader;

    const version_bytes = cursor.take(4) orelse return error.Truncated;
    const version: Version = @fromBackingInt(@intCast(std.mem.readInt(u32, version_bytes[0..4], .big)));

    // §17.2: the fixed bit is set unless this is a Version Negotiation packet,
    // whose unused bits are arbitrary. A packet with the bit clear is not valid
    // in this version and must be discarded.
    if (version != .negotiation and first[0] & 0x40 == 0) return error.FixedBitZero;

    const destination_connection_id = try takeConnectionId(&cursor, version);
    const source_connection_id = try takeConnectionId(&cursor, version);

    return .{
        .first = first[0],
        .version = version,
        .destination_connection_id = destination_connection_id,
        .source_connection_id = source_connection_id,
        .rest = cursor.rest(),
        .rest_offset = cursor.pos,
    };
}

/// Read an Initial, 0-RTT, or Handshake packet.
pub fn parseLong(bytes: []const u8) Error!Long {
    const invariant = try parseInvariant(bytes);
    if (invariant.version == .negotiation) return error.WrongPacketType;

    const kind: Kind = @fromBackingInt(@intCast((invariant.first >> 4) & 0x03));
    if (kind == .retry) return error.WrongPacketType;

    var cursor: Cursor = .init(bytes);
    cursor.pos = invariant.rest_offset;

    var token: []const u8 = "";
    if (kind == .initial) {
        const token_len = try readVarint(&cursor);
        if (token_len > cursor.remaining()) return error.Truncated;
        token = cursor.take(@intCast(token_len)).?;
    }

    const length = try readVarint(&cursor);
    if (length > cursor.remaining()) return error.LengthPastEnd;
    const body_offset = cursor.pos;
    const body = cursor.take(@intCast(length)).?;

    return .{
        .kind = kind,
        .version = invariant.version,
        .destination_connection_id = invariant.destination_connection_id,
        .source_connection_id = invariant.source_connection_id,
        .token = token,
        .first = invariant.first,
        .length = @intCast(length),
        .body = body,
        .body_offset = body_offset,
        .rest = cursor.rest(),
    };
}

/// Read a Version Negotiation packet from bytes whose invariant part is
/// already decoded.
pub fn parseVersionNegotiation(invariant: Invariant) Error!VersionNegotiation {
    if (invariant.version != .negotiation) return error.WrongPacketType;
    // §17.2.1: the remainder is a list of 32-bit versions.
    if (invariant.rest.len % 4 != 0) return error.InvalidVersionList;
    return .{
        .destination_connection_id = invariant.destination_connection_id,
        .source_connection_id = invariant.source_connection_id,
        .versions = invariant.rest,
    };
}

/// Read a Retry packet from bytes whose invariant part is already decoded.
pub fn parseRetry(invariant: Invariant) Error!Retry {
    const kind: Kind = @fromBackingInt(@intCast((invariant.first >> 4) & 0x03));
    if (kind != .retry or invariant.version == .negotiation) return error.WrongPacketType;

    const rest = invariant.rest;
    if (rest.len < retry_integrity_tag_len) return error.RetryTooShort;

    const token = rest[0 .. rest.len - retry_integrity_tag_len];
    // §17.2.5.2: a client must discard a Retry packet with no token.
    if (token.len == 0) return error.EmptyRetryToken;

    var tag: [retry_integrity_tag_len]u8 = undefined;
    @memcpy(&tag, rest[rest.len - retry_integrity_tag_len ..]);

    return .{
        .version = invariant.version,
        .destination_connection_id = invariant.destination_connection_id,
        .source_connection_id = invariant.source_connection_id,
        .token = token,
        .integrity_tag = tag,
    };
}

/// Read a 1-RTT packet. `destination_connection_id_len` comes from the
/// connection state, because the wire does not carry it.
pub fn parseShort(bytes: []const u8, destination_connection_id_len: u32) Error!Short {
    if (bytes.len == 0) return error.Truncated;
    if (bytes[0] & 0x80 != 0) return error.NotShortHeader;
    if (bytes[0] & 0x40 == 0) return error.FixedBitZero;
    if (destination_connection_id_len > connection_id_max) return error.ConnectionIdTooLong;

    const header_len = 1 + destination_connection_id_len;
    if (bytes.len < header_len) return error.Truncated;

    return .{
        .first = bytes[0],
        .destination_connection_id = bytes[1..header_len],
        .body = bytes[header_len..],
    };
}

pub const LongToWrite = struct {
    kind: Kind,
    version: Version = .v1,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// Must be empty unless `kind` is `.initial`.
    token: []const u8 = "",
    /// 1 to 4 bytes. `packet_number.encodeLength` picks it.
    packet_number_len: u3 = 4,
    /// The bytes after the Length field: the packet number and the payload.
    body_len: u32,
};

/// Where the caller writes next, after `writeLong`.
pub const LongOffsets = struct {
    /// The Packet Number field. The caller writes `packet_number_len` bytes
    /// here, then the payload, which fills the rest of `body_len`.
    packet_number: u32,
};

/// Write an Initial, 0-RTT, or Handshake header.
///
/// The Length field counts `body_len`, so the caller sizes the payload before
/// it writes the header. Nothing is patched afterwards.
pub fn writeLong(writer: *Writer, header: LongToWrite) Error!LongOffsets {
    if (header.kind == .retry) return error.WrongPacketType;
    if (header.packet_number_len < 1 or header.packet_number_len > 4) {
        return error.InvalidPacketNumberLength;
    }
    if (header.body_len < header.packet_number_len) return error.InvalidLength;
    if (header.kind != .initial and header.token.len != 0) return error.WrongPacketType;
    try checkConnectionId(header.destination_connection_id, header.version);
    try checkConnectionId(header.source_connection_id, header.version);

    // Form, fixed bit, and the packet type.
    const first: u8 = 0x80 | 0x40 | (@as(u8, @backingInt(header.kind)) << 4);
    // §17.2: the reserved bits are zero before header protection, and the low
    // two bits are one less than the packet number length.
    try writer.putByte(first | @as(u8, header.packet_number_len - 1));
    try writeVersion(writer, header.version);
    try writeConnectionId(writer, header.destination_connection_id);
    try writeConnectionId(writer, header.source_connection_id);

    if (header.kind == .initial) {
        try writeVarint(writer, header.token.len);
        try writer.put(header.token);
    }

    try writeVarint(writer, header.body_len);
    return .{ .packet_number = writer.pos };
}

pub const RetryToWrite = struct {
    version: Version = .v1,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8,
    /// §17.2.5: the four unused bits are arbitrary. Zero by default; the value
    /// is inside the scope of the retry integrity tag, so a sender that changes
    /// it changes the tag.
    unused: u4 = 0,
};

pub const RetryOffsets = struct {
    /// The 16-byte Retry Integrity Tag, left zeroed. The caller fills it with
    /// the tag that RFC 9001 §5.8 computes over the whole packet.
    integrity_tag: u32,
};

/// Write a Retry packet, leaving the integrity tag for the caller.
pub fn writeRetry(writer: *Writer, retry: RetryToWrite) Error!RetryOffsets {
    if (retry.token.len == 0) return error.EmptyRetryToken;
    try checkConnectionId(retry.destination_connection_id, retry.version);
    try checkConnectionId(retry.source_connection_id, retry.version);

    // §17.2.5: the unused bits are arbitrary; zero keeps them out of the way of
    // the tag the caller computes over these bytes.
    try writer.putByte(0x80 | 0x40 | (@as(u8, @backingInt(Kind.retry)) << 4) | @as(u8, retry.unused));
    try writeVersion(writer, retry.version);
    try writeConnectionId(writer, retry.destination_connection_id);
    try writeConnectionId(writer, retry.source_connection_id);
    try writer.put(retry.token);

    const offsets: RetryOffsets = .{ .integrity_tag = writer.pos };
    _ = try writer.reserve(retry_integrity_tag_len);
    return offsets;
}

pub const VersionNegotiationToWrite = struct {
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    versions: []const Version,
};

/// Write a Version Negotiation packet.
///
/// The connection ID limit is version 1's and does not apply here: these IDs
/// are copied from a packet of some other version, which may allow longer ones
/// (§17.2.1).
pub fn writeVersionNegotiation(writer: *Writer, negotiation: VersionNegotiationToWrite) Error!void {
    // §17.2.1: the version is zero, and the unused bits are arbitrary. Setting
    // the fixed bit keeps the packet looking like the rest to middleboxes.
    try writer.putByte(0xc0);
    try writer.put(&.{ 0, 0, 0, 0 });
    try writeConnectionId(writer, negotiation.destination_connection_id);
    try writeConnectionId(writer, negotiation.source_connection_id);
    for (negotiation.versions) |version| try writeVersion(writer, version);
}

pub const ShortToWrite = struct {
    destination_connection_id: []const u8,
    /// §17.4. Off by default: an endpoint that does not implement the spin bit
    /// must disable it.
    spin: bool = false,
    key_phase: bool = false,
    packet_number_len: u3 = 4,
};

pub const ShortOffsets = struct {
    /// The Packet Number field. The caller writes `packet_number_len` bytes
    /// here, then the payload.
    packet_number: u32,
};

/// Write a 1-RTT header.
pub fn writeShort(writer: *Writer, header: ShortToWrite) Error!ShortOffsets {
    if (header.packet_number_len < 1 or header.packet_number_len > 4) {
        return error.InvalidPacketNumberLength;
    }
    try checkConnectionId(header.destination_connection_id, .v1);

    // Form clear, fixed bit set, then the spin bit, zeroed reserved bits, the
    // key phase, and the packet number length.
    var first: u8 = 0x40;
    if (header.spin) first |= 0x20;
    if (header.key_phase) first |= 0x04;
    try writer.putByte(first | @as(u8, header.packet_number_len - 1));
    try writer.put(header.destination_connection_id);
    return .{ .packet_number = writer.pos };
}

fn takeConnectionId(cursor: *Cursor, version: Version) Error![]const u8 {
    const len = cursor.next() orelse return error.Truncated;
    // §17.2: in version 1 a long header carries at most 20 bytes. Other
    // versions may carry more, and a server answering with version negotiation
    // has to be able to read what it echoes.
    if (version == .v1 and len > connection_id_max) return error.ConnectionIdTooLong;
    return cursor.take(len) orelse error.Truncated;
}

fn checkConnectionId(bytes: []const u8, version: Version) Error!void {
    if (version == .v1 and bytes.len > connection_id_max) return error.ConnectionIdTooLong;
    if (bytes.len > std.math.maxInt(u8)) return error.ConnectionIdTooLong;
}

fn writeConnectionId(writer: *Writer, bytes: []const u8) Error!void {
    try writer.putByte(@intCast(bytes.len));
    try writer.put(bytes);
}

fn writeVersion(writer: *Writer, version: Version) Error!void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, @backingInt(version), .big);
    try writer.put(&buf);
}

/// `varint.decode` cannot return `NonMinimal`, but its error set says it can.
fn readVarint(cursor: *Cursor) Error!u64 {
    return varint.decode(cursor) catch |err| switch (err) {
        error.Truncated => return error.Truncated,
        error.NonMinimal => unreachable,
    };
}

/// `varint.write` cannot overflow on the values written here, which are all
/// shorter than a datagram.
fn writeVarint(writer: *Writer, value: u64) Error!void {
    varint.write(writer, value) catch |err| switch (err) {
        error.NoSpace => return error.NoSpace,
        error.Overflow => unreachable,
    };
}

const expect = testing.expect;
const expectEqual = testing.expectEqual;

test "RFC 9000 §17.2.2, a client Initial parses field by field" {
    const bytes = [_]u8{
        0xc3, // long, fixed, initial, reserved 00, packet number length 4
        0x00, 0x00, 0x00, 0x01, // version 1
        0x08, 1, 2, 3, 4, 5, 6, 7, 8, // destination connection ID
        0x00, // source connection ID length
        0x00, // token length
        0x14, // length: 20 bytes of packet number and payload
        0x00, 0x00, 0x00, 0x2a, // packet number 42
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // payload
    };

    const long = try parseLong(&bytes);
    try expectEqual(Kind.initial, long.kind);
    try expectEqual(Version.v1, long.version);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, long.destination_connection_id);
    try expectEqual(@as(usize, 0), long.source_connection_id.len);
    try expectEqual(@as(usize, 0), long.token.len);
    try expectEqual(@as(u32, 20), long.length);
    try expectEqual(@as(usize, 20), long.body.len);
    try expectEqual(@as(u3, 4), long.packetNumberLen());
    try expectEqual(@as(u2, 0), long.reserved());
    try expectEqual(@as(usize, 0), long.rest.len);
    try expectEqual(@as(u32, 17), long.body_offset);
}

test "RFC 9000 §17.2.1, version negotiation ignores the fixed bit and long connection IDs" {
    // 1 + 4 + 1 + 30 + 1 + 20 + 8 bytes.
    var bytes: [65]u8 = undefined;
    bytes[0] = 0x80; // form bit set, fixed bit clear: allowed in a negotiation
    bytes[1..5].* = .{ 0x00, 0x00, 0x00, 0x00 }; // version 0 identifies it
    bytes[5] = 30; // more than version 1 allows, and still readable
    @memset(bytes[6..36], 0xaa);
    bytes[36] = 20;
    @memset(bytes[37..57], 0xbb);
    bytes[57..65].* = .{ 0, 0, 0, 1, 0x0a, 0x0a, 0x0a, 0x0a };

    const negotiation = switch (try parse(&bytes, 0)) {
        .version_negotiation => |vn| vn,
        else => return error.WrongPacketType,
    };
    try expectEqual(@as(usize, 30), negotiation.destination_connection_id.len);
    try expectEqual(@as(usize, 20), negotiation.source_connection_id.len);
    try expectEqual(@as(u32, 2), negotiation.count());
    try expectEqual(Version.v1, negotiation.at(0));
    try expectEqual(@as(Version, @fromBackingInt(@intCast(0x0a0a0a0a))), negotiation.at(1));
}

test "RFC 9000 §17.2, the fixed bit and the version 1 connection ID limit" {
    const no_fixed = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    try testing.expectError(error.FixedBitZero, parseInvariant(&no_fixed));

    // 21 bytes in version 1 is over the limit, and the packet is dropped.
    var too_long: [1 + 4 + 1 + 21 + 1]u8 = undefined;
    too_long[0] = 0xc0;
    too_long[1..5].* = .{ 0x00, 0x00, 0x00, 0x01 };
    too_long[5] = 21;
    @memset(too_long[6..27], 0xaa);
    too_long[27] = 0;
    try testing.expectError(error.ConnectionIdTooLong, parseInvariant(&too_long));

    // The same shape in an unknown version is readable: a stateless observer
    // must be able to echo it.
    too_long[1..5].* = .{ 0xfa, 0xce, 0xb0, 0x0c };
    const invariant = try parseInvariant(&too_long);
    try expectEqual(@as(usize, 21), invariant.destination_connection_id.len);
}

test "RFC 9000 §17.2, the invariant fields are readable without keys" {
    var buf: [512]u8 = undefined;
    var writer: Writer = .init(&buf);
    const offsets = try writeLong(&writer, .{
        .kind = .initial,
        .destination_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .source_connection_id = &.{ 9, 10 },
        .body_len = 8,
        .packet_number_len = 1,
    });
    // First byte, version, both connection IDs, the token length, and the
    // Length field: 1 + 4 + 1 + 8 + 1 + 2 + 1 + 1.
    try expectEqual(@as(u32, 19), offsets.packet_number);

    const invariant = try parseInvariant(writer.written());
    try expectEqual(Version.v1, invariant.version);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, invariant.destination_connection_id);
    try testing.expectEqualSlices(u8, &.{ 9, 10 }, invariant.source_connection_id);
    // `rest` starts at the Token Length, before the fields this writer added.
    try expectEqual(@as(u32, 17), invariant.rest_offset);
}

test "the header round trips through the writer" {
    inline for (.{ Kind.initial, Kind.zero_rtt, Kind.handshake }) |kind| {
        var buf: [512]u8 = undefined;
        var writer: Writer = .init(&buf);

        const token = if (kind == .initial) "a token" else "";
        const offsets = try writeLong(&writer, .{
            .kind = kind,
            .destination_connection_id = &.{ 1, 2, 3 },
            .source_connection_id = &.{ 4, 5, 6, 7 },
            .token = token,
            .packet_number_len = 2,
            .body_len = 40,
        });
        // The caller fills the packet number and the payload.
        try writer.put(&.{ 0xde, 0xad });
        const payload = try writer.reserve(38);
        @memset(payload, 0x5a);

        const long = try parseLong(writer.written());
        try expectEqual(kind, long.kind);
        try expectEqual(Version.v1, long.version);
        try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, long.destination_connection_id);
        try testing.expectEqualSlices(u8, &.{ 4, 5, 6, 7 }, long.source_connection_id);
        try testing.expectEqualStrings(token, long.token);
        try expectEqual(@as(u32, 40), long.length);
        try expectEqual(offsets.packet_number, long.body_offset);
        try expectEqual(@as(u3, 2), long.packetNumberLen());
        try expectEqual(@as(usize, 40), long.body.len);
        try expectEqual(@as(usize, 0), long.rest.len);
    }
}

test "RFC 9000 §12.2, a coalesced datagram leaves the next packet in rest" {
    var buf: [512]u8 = undefined;
    var writer: Writer = .init(&buf);
    _ = try writeLong(&writer, .{
        .kind = .handshake,
        .destination_connection_id = &.{1},
        .source_connection_id = &.{ 2, 3 },
        .body_len = 7,
        .packet_number_len = 1,
    });
    try writer.put(&.{ 0x00, 1, 2, 3, 4, 5, 6 });
    const second_offset = writer.pos;
    _ = try writeLong(&writer, .{
        .kind = .handshake,
        .destination_connection_id = &.{1},
        .source_connection_id = &.{ 2, 3 },
        .body_len = 4,
        .packet_number_len = 1,
    });
    try writer.put(&.{ 0x00, 7, 8, 9 });

    const first = try parseLong(writer.written());
    try expectEqual(@as(usize, 7), first.body.len);
    try expectEqual(second_offset, first.body_offset + first.length);

    const second = try parseLong(first.rest);
    try expectEqual(@as(usize, 4), second.body.len);
    try expectEqual(@as(usize, 0), second.rest.len);
}

test "RFC 9000 §17.2.5, a Retry round trips and leaves the tag to the caller" {
    var buf: [256]u8 = undefined;
    var writer: Writer = .init(&buf);
    const offsets = try writeRetry(&writer, .{
        .destination_connection_id = &.{ 1, 2 },
        .source_connection_id = &.{ 3, 4, 5 },
        .token = "retry-token",
    });
    const tag = [_]u8{ 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } ++
        [_]u8{ 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 };
    writer.patch(offsets.integrity_tag, &tag);

    const retry = switch (try parse(writer.written(), 0)) {
        .retry => |r| r,
        else => return error.WrongPacketType,
    };
    try expectEqual(Version.v1, retry.version);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, retry.destination_connection_id);
    try testing.expectEqualSlices(u8, &.{ 3, 4, 5 }, retry.source_connection_id);
    try testing.expectEqualStrings("retry-token", retry.token);
    try testing.expectEqualSlices(u8, &tag, &retry.integrity_tag);
}

test "RFC 9000 §17.2.5.2, a Retry with no token is discarded" {
    var buf: [128]u8 = undefined;
    var writer: Writer = .init(&buf);
    try testing.expectError(error.EmptyRetryToken, writeRetry(&writer, .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
        .token = "",
    }));

    // A packet with the tag and nothing before it has a zero-length token.
    const bytes = [_]u8{ 0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 } ++ @as([16]u8, @splat(0));
    try testing.expectError(error.EmptyRetryToken, parse(&bytes, 0));
}

test "RFC 9000 §17.3.1 and §17.4, a short header round trips" {
    var buf: [128]u8 = undefined;
    var writer: Writer = .init(&buf);
    const offsets = try writeShort(&writer, .{
        .destination_connection_id = &.{ 7, 7, 7, 7 },
        .spin = true,
        .key_phase = true,
        .packet_number_len = 3,
    });
    try expectEqual(@as(u32, 5), offsets.packet_number);
    try writer.put(&.{ 1, 2, 3 });

    const short = try parseShort(writer.written(), 4);
    try testing.expectEqualSlices(u8, &.{ 7, 7, 7, 7 }, short.destination_connection_id);
    try expect(short.spin());
    try expect(short.keyPhase());
    try expectEqual(@as(u3, 3), short.packetNumberLen());
    try expectEqual(@as(u2, 0), short.reserved());
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, short.body);

    // The same bytes read with the wrong connection ID length land elsewhere.
    const wrong = try parseShort(writer.written(), 2);
    try testing.expectEqualSlices(u8, &.{ 7, 7 }, wrong.destination_connection_id);
    try expectEqual(@as(usize, 5), wrong.body.len);
}

test "§17, a short header needs the connection's length and a long one carries it" {
    const short_bytes = [_]u8{ 0x40, 1, 2, 3 };
    try testing.expectError(error.Truncated, parseShort(&short_bytes, 4));

    // An Initial with no Length field at all.
    const long_bytes = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0, 0 };
    try testing.expectError(error.Truncated, parseLong(&long_bytes));
}

test "every prefix of a packet is truncated, not a crash" {
    var buf: [512]u8 = undefined;
    var writer: Writer = .init(&buf);
    _ = try writeLong(&writer, .{
        .kind = .initial,
        .destination_connection_id = &.{ 1, 2, 3 },
        .source_connection_id = &.{ 4, 5 },
        .token = "tok",
        .body_len = 6,
        .packet_number_len = 2,
    });
    try writer.put(&.{ 0, 0, 0, 0, 0, 0 });

    const bytes = writer.written();
    var len: usize = 0;
    while (len < bytes.len) : (len += 1) {
        if (parse(bytes[0..len], 0)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    try expectEqual(@as(usize, 0), (try parseLong(bytes)).rest.len);
}

test "fuzz the header parser" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const input = buf[0..smith.slice(&buf)];
            const dcid_len: u32 = smith.valueRangeAtMost(u32, 0, 32);

            // Arbitrary bytes either parse or say why not, and a parsed packet
            // is bounds-checked against the buffer it came from.
            if (parse(input, dcid_len)) |result| {
                switch (result) {
                    .long => |long| try expect(long.body_offset + long.length <= input.len),
                    .retry => |retry| try expect(retry.integrity_tag.len == 16),
                    .version_negotiation => |vn| try expect(vn.versions.len % 4 == 0),
                    .short => |short| try expect(short.body.len <= input.len),
                }
            } else |_| {}
        }
    }.run, .{ .corpus = &.{ "", "a", "\xc0\x00\x00\x00\x01\x00\x00\x00\x00" } });
}
