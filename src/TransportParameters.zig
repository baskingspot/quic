//! QUIC transport parameters, RFC 9000 §18.
//!
//! These are the contents of the `quic_transport_parameters` TLS extension
//! (0x0039, §18). The extension carries a sequence of id, length, and value
//! triples; every id this version defines is listed in §18.2, and an id it does
//! not define must be ignored rather than refused.
//!
//! Reading fills a caller-owned struct and borrows the byte strings it finds.
//! Writing takes that struct. Both directions take the role of the endpoint
//! doing the work, because four parameters are server-only and a client that
//! sends one has a bug, while a server that receives one has a connection error.
//!
//! A parameter that is absent means its default, not zero. `maxUdpPayloadSize`
//! and the three others with defaults answer with the default when the field is
//! null; the field itself stays null so a decode and re-encode stays faithful.

const std = @import("std");
const testing = std.testing;
const Cursor = @import("Cursor.zig");
const Writer = @import("Writer.zig");
const varint = @import("varint.zig");

const TransportParameters = @This();

pub const Error = error{
    /// The extension ended inside a parameter.
    Truncated,
    /// The caller's buffer has no room for the parameters.
    NoSpace,
    /// §18.2: a parameter appeared more than once.
    DuplicateParameter,
    /// §18.2: a parameter carried a value outside its allowed range.
    InvalidValue,
    /// §18.2: a client sent a server-only parameter.
    NotAllowed,
    /// More parameters than this decoder tracks for duplicates. Every version 1
    /// parameter is known, so this is a peer sending dozens of extensions.
    TooManyParameters,
};

/// §18.2: the smallest UDP payload an endpoint may advertise.
pub const min_max_udp_payload_size: u64 = 1200;
/// §18.2: the default when max_udp_payload_size is absent.
pub const default_max_udp_payload_size: u64 = 65527;
/// §18.2: ack_delay_exponent above this is invalid.
pub const max_ack_delay_exponent: u64 = 20;
/// §18.2: the default when ack_delay_exponent is absent.
pub const default_ack_delay_exponent: u64 = 3;
/// §18.2: max_ack_delay of this or above is invalid.
pub const max_ack_delay_limit: u64 = 1 << 14;
/// §18.2: the default when max_ack_delay is absent.
pub const default_max_ack_delay: u64 = 25;
/// §18.2: active_connection_id_limit below this is invalid.
pub const min_active_connection_id_limit: u64 = 2;
/// §18.2: the default when active_connection_id_limit is absent.
pub const default_active_connection_id_limit: u64 = 2;

/// The identities of the two endpoints. A parameter is server-only or it is
/// not, and the check runs on the side that reads or writes it.
pub const Role = enum {
    client,
    server,
};

/// §18.2, the preferred_address value: both address families, then the
/// alternative connection ID and its stateless reset token.
pub const PreferredAddress = struct {
    ipv4: [4]u8,
    ipv4_port: u16,
    ipv6: [16]u8,
    ipv6_port: u16,
    /// Borrowed from the extension bytes when read. 1 to 20 bytes.
    connection_id: []const u8,
    reset_token: [16]u8,
};

/// The parameter identifiers of §18.2, in registry order.
pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,

    /// §18.2: a client must not send these, and a server that receives one
    /// closes the connection with TRANSPORT_PARAMETER_ERROR.
    pub fn isServerOnly(self: Id) bool {
        return switch (self) {
            .original_destination_connection_id,
            .stateless_reset_token,
            .preferred_address,
            .retry_source_connection_id,
            => true,
            else => false,
        };
    }
};

/// A null field means the parameter was absent, and its default applies.
/// `disableActiveMigration` has no default: its presence is the signal.
original_destination_connection_id: ?[]const u8 = null,
max_idle_timeout: ?u64 = null,
stateless_reset_token: ?[16]u8 = null,
max_udp_payload_size: ?u64 = null,
initial_max_data: ?u64 = null,
initial_max_stream_data_bidi_local: ?u64 = null,
initial_max_stream_data_bidi_remote: ?u64 = null,
initial_max_stream_data_uni: ?u64 = null,
initial_max_streams_bidi: ?u64 = null,
initial_max_streams_uni: ?u64 = null,
ack_delay_exponent: ?u64 = null,
max_ack_delay: ?u64 = null,
disable_active_migration: bool = false,
preferred_address: ?PreferredAddress = null,
active_connection_id_limit: ?u64 = null,
initial_source_connection_id: ?[]const u8 = null,
retry_source_connection_id: ?[]const u8 = null,

pub fn maxUdpPayloadSize(self: *const TransportParameters) u64 {
    return self.max_udp_payload_size orelse default_max_udp_payload_size;
}

pub fn ackDelayExponent(self: *const TransportParameters) u64 {
    return self.ack_delay_exponent orelse default_ack_delay_exponent;
}

pub fn maxAckDelay(self: *const TransportParameters) u64 {
    return self.max_ack_delay orelse default_max_ack_delay;
}

pub fn activeConnectionIdLimit(self: *const TransportParameters) u64 {
    return self.active_connection_id_limit orelse default_active_connection_id_limit;
}

/// Read the value of the `quic_transport_parameters` extension into `out`.
///
/// `role` is the endpoint doing the decoding, so a server reading a client's
/// parameters refuses the four that only a server may send. Unknown parameters
/// are skipped as §18.2 requires. On error `out` is left part-written.
pub fn decode(bytes: []const u8, role: Role, out: *TransportParameters) Error!void {
    // Duplicate detection needs every id seen so far. The cap is far past any
    // version 1 extension: this version defines 17 parameters, and the RFCs
    // since add a handful. A peer past it is sending extensions in bulk, and
    // one connection error is cheaper than an unbounded scan per parameter.
    var seen: [64]u64 = undefined;
    var seen_len: usize = 0;

    var cursor: Cursor = .init(bytes);
    while (!cursor.atEnd()) {
        const id_value = try readVarint(&cursor);
        const length = try readVarint(&cursor);
        if (length > cursor.remaining()) return error.Truncated;
        const value = cursor.take(@intCast(length)).?;

        for (seen[0..seen_len]) |previous| {
            if (previous == id_value) return error.DuplicateParameter;
        }
        if (seen_len == seen.len) return error.TooManyParameters;
        seen[seen_len] = id_value;
        seen_len += 1;

        try apply(@fromBackingInt(@intCast(id_value)), value, role, out);
    }
}

fn apply(id: Id, value: []const u8, role: Role, out: *TransportParameters) Error!void {
    if (role == .server and id.isServerOnly()) return error.NotAllowed;

    switch (id) {
        .original_destination_connection_id => {
            out.original_destination_connection_id = try readOpaque(value);
        },
        .max_idle_timeout => out.max_idle_timeout = try readInt(value),
        .stateless_reset_token => out.stateless_reset_token = try readToken(value),
        .max_udp_payload_size => {
            const size = try readInt(value);
            if (size < min_max_udp_payload_size) return error.InvalidValue;
            out.max_udp_payload_size = size;
        },
        .initial_max_data => out.initial_max_data = try readInt(value),
        .initial_max_stream_data_bidi_local => {
            out.initial_max_stream_data_bidi_local = try readInt(value);
        },
        .initial_max_stream_data_bidi_remote => {
            out.initial_max_stream_data_bidi_remote = try readInt(value);
        },
        .initial_max_stream_data_uni => out.initial_max_stream_data_uni = try readInt(value),
        .initial_max_streams_bidi => out.initial_max_streams_bidi = try readInt(value),
        .initial_max_streams_uni => out.initial_max_streams_uni = try readInt(value),
        .ack_delay_exponent => {
            const exponent = try readInt(value);
            if (exponent > max_ack_delay_exponent) return error.InvalidValue;
            out.ack_delay_exponent = exponent;
        },
        .max_ack_delay => {
            const delay = try readInt(value);
            if (delay >= max_ack_delay_limit) return error.InvalidValue;
            out.max_ack_delay = delay;
        },
        .disable_active_migration => {
            if (value.len != 0) return error.InvalidValue;
            out.disable_active_migration = true;
        },
        .preferred_address => out.preferred_address = try readPreferredAddress(value),
        .active_connection_id_limit => {
            const limit = try readInt(value);
            if (limit < min_active_connection_id_limit) return error.InvalidValue;
            out.active_connection_id_limit = limit;
        },
        .initial_source_connection_id => {
            out.initial_source_connection_id = try readOpaque(value);
        },
        .retry_source_connection_id => {
            out.retry_source_connection_id = try readOpaque(value);
        },
        // §18.2: a parameter this version does not define is ignored.
        else => {},
    }
}

/// Write the parameters as the extension's value bytes, in registry order.
pub fn encode(writer: *Writer, parameters: TransportParameters, role: Role) Error!void {
    if (parameters.original_destination_connection_id) |id| {
        try requireServer(role);
        try writeConnectionId(writer, .original_destination_connection_id, id);
    }
    if (parameters.max_idle_timeout) |value| {
        try writeInt(writer, .max_idle_timeout, value);
    }
    if (parameters.stateless_reset_token) |token| {
        try requireServer(role);
        try writeParam(writer, .stateless_reset_token, &token);
    }
    if (parameters.max_udp_payload_size) |value| {
        if (value < min_max_udp_payload_size) return error.InvalidValue;
        try writeInt(writer, .max_udp_payload_size, value);
    }
    if (parameters.initial_max_data) |value| {
        try writeInt(writer, .initial_max_data, value);
    }
    if (parameters.initial_max_stream_data_bidi_local) |value| {
        try writeInt(writer, .initial_max_stream_data_bidi_local, value);
    }
    if (parameters.initial_max_stream_data_bidi_remote) |value| {
        try writeInt(writer, .initial_max_stream_data_bidi_remote, value);
    }
    if (parameters.initial_max_stream_data_uni) |value| {
        try writeInt(writer, .initial_max_stream_data_uni, value);
    }
    if (parameters.initial_max_streams_bidi) |value| {
        try writeInt(writer, .initial_max_streams_bidi, value);
    }
    if (parameters.initial_max_streams_uni) |value| {
        try writeInt(writer, .initial_max_streams_uni, value);
    }
    if (parameters.ack_delay_exponent) |value| {
        if (value > max_ack_delay_exponent) return error.InvalidValue;
        try writeInt(writer, .ack_delay_exponent, value);
    }
    if (parameters.max_ack_delay) |value| {
        if (value >= max_ack_delay_limit) return error.InvalidValue;
        try writeInt(writer, .max_ack_delay, value);
    }
    if (parameters.disable_active_migration) {
        try writeParam(writer, .disable_active_migration, &.{});
    }
    if (parameters.preferred_address) |address| {
        try requireServer(role);
        try writePreferredAddress(writer, address);
    }
    if (parameters.active_connection_id_limit) |value| {
        if (value < min_active_connection_id_limit) return error.InvalidValue;
        try writeInt(writer, .active_connection_id_limit, value);
    }
    if (parameters.initial_source_connection_id) |id| {
        try writeConnectionId(writer, .initial_source_connection_id, id);
    }
    if (parameters.retry_source_connection_id) |id| {
        try requireServer(role);
        try writeConnectionId(writer, .retry_source_connection_id, id);
    }
}

fn requireServer(role: Role) Error!void {
    // §18.2: a client must not include a server-only parameter.
    if (role == .client) return error.NotAllowed;
}

fn readVarint(cursor: *Cursor) Error!u64 {
    return varint.decode(cursor) catch |err| switch (err) {
        error.Truncated => return error.Truncated,
    };
}

fn readInt(value: []const u8) Error!u64 {
    var cursor: Cursor = .init(value);
    const number = try readVarint(&cursor);
    // A parameter carries exactly one integer, so trailing bytes are malformed.
    if (!cursor.atEnd()) return error.InvalidValue;
    return number;
}

/// A connection ID parameter holds the bytes of a connection ID, so at most 20
/// of them in version 1 (§17.2).
fn readOpaque(value: []const u8) Error![]const u8 {
    if (value.len > 20) return error.InvalidValue;
    return value;
}

fn readToken(value: []const u8) Error![16]u8 {
    if (value.len != 16) return error.InvalidValue;
    var token: [16]u8 = undefined;
    @memcpy(&token, value);
    return token;
}

/// §18.2, Figure 22: 4 + 2 + 16 + 2 bytes of address, a length byte, the
/// connection ID, and its stateless reset token.
fn readPreferredAddress(value: []const u8) Error!PreferredAddress {
    var cursor: Cursor = .init(value);
    const ipv4 = cursor.take(4) orelse return error.Truncated;
    const ipv4_port = cursor.take(2) orelse return error.Truncated;
    const ipv6 = cursor.take(16) orelse return error.Truncated;
    const ipv6_port = cursor.take(2) orelse return error.Truncated;

    const id_len = cursor.next() orelse return error.Truncated;
    // §18.2: a zero-length connection ID here is a TRANSPORT_PARAMETER_ERROR,
    // and so is one over the version 1 limit.
    if (id_len < 1 or id_len > 20) return error.InvalidValue;
    const connection_id = cursor.take(id_len) orelse return error.Truncated;
    const token = cursor.take(16) orelse return error.Truncated;
    if (!cursor.atEnd()) return error.InvalidValue;

    var address: PreferredAddress = undefined;
    @memcpy(&address.ipv4, ipv4);
    @memcpy(&address.ipv6, ipv6);
    @memcpy(&address.reset_token, token);
    address.ipv4_port = std.mem.readInt(u16, ipv4_port[0..2], .big);
    address.ipv6_port = std.mem.readInt(u16, ipv6_port[0..2], .big);
    address.connection_id = connection_id;
    return address;
}

fn writePreferredAddress(writer: *Writer, address: PreferredAddress) Error!void {
    if (address.connection_id.len < 1 or address.connection_id.len > 20) {
        return error.InvalidValue;
    }
    // The fixed fields, the length byte, the connection ID, and the token.
    const length = 4 + 2 + 16 + 2 + 1 + address.connection_id.len + 16;
    try writeVarint(writer, @backingInt(Id.preferred_address));
    try writeVarint(writer, length);

    try writer.put(&address.ipv4);
    try writeU16(writer, address.ipv4_port);
    try writer.put(&address.ipv6);
    try writeU16(writer, address.ipv6_port);
    try writer.putByte(@intCast(address.connection_id.len));
    try writer.put(address.connection_id);
    try writer.put(&address.reset_token);
}

/// §17.2: a connection ID is at most 20 bytes, and this decoder refuses a
/// longer one, so a longer one here would be bytes that cannot come back.
fn writeConnectionId(writer: *Writer, id: Id, connection_id: []const u8) Error!void {
    if (connection_id.len > 20) return error.InvalidValue;
    try writeParam(writer, id, connection_id);
}

fn writeParam(writer: *Writer, id: Id, value: []const u8) Error!void {
    try writeVarint(writer, @backingInt(id));
    try writeVarint(writer, value.len);
    try writer.put(value);
}

fn writeInt(writer: *Writer, id: Id, value: u64) Error!void {
    // §16: a transport parameter value is a variable-length integer, so a value
    // above 2^62 - 1 has no encoding on the wire.
    if (value > varint.max) return error.InvalidValue;

    var buf: [8]u8 = undefined;
    var scratch: Writer = .init(&buf);
    try writeVarint(&scratch, value);
    try writeParam(writer, id, scratch.written());
}

fn writeU16(writer: *Writer, value: u16) Error!void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try writer.put(&buf);
}

fn writeVarint(writer: *Writer, value: u64) Error!void {
    varint.write(writer, value) catch |err| switch (err) {
        error.NoSpace => return error.NoSpace,
        // Every value written here is a parameter id, a length of a checked
        // parameter, or a value `writeInt` already bounded.
        error.Overflow => unreachable,
    };
}

const expect = testing.expect;
const expectEqual = testing.expectEqual;

/// Append one parameter to `writer`.
fn putParam(writer: *Writer, id: u64, value: []const u8) !void {
    try varint.write(writer, id);
    try varint.write(writer, value.len);
    try writer.put(value);
}

/// Append one integer parameter to `writer`.
fn putIntParam(writer: *Writer, id: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    var scratch: Writer = .init(&buf);
    try varint.write(&scratch, value);
    try putParam(writer, id, scratch.written());
}

test "RFC 9000 §18.2, an empty extension means every default" {
    var params: TransportParameters = .{};
    try decode(&.{}, .client, &params);
    try expectEqual(@as(?u64, null), params.max_ack_delay);
    try expectEqual(default_max_udp_payload_size, params.maxUdpPayloadSize());
    try expectEqual(default_ack_delay_exponent, params.ackDelayExponent());
    try expectEqual(default_max_ack_delay, params.maxAckDelay());
    try expectEqual(default_active_connection_id_limit, params.activeConnectionIdLimit());
    try expect(params.disable_active_migration == false);
}

test "RFC 9000 §18.2, the whole list round trips" {
    const source: TransportParameters = .{
        .original_destination_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .max_idle_timeout = 30_000,
        .stateless_reset_token = @splat(0x33),
        .max_udp_payload_size = 1400,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1000,
        .initial_max_stream_data_bidi_remote = 2000,
        .initial_max_stream_data_uni = 3000,
        .initial_max_streams_bidi = 10,
        .initial_max_streams_uni = 11,
        .ack_delay_exponent = 4,
        .max_ack_delay = 26,
        .disable_active_migration = true,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = &.{ 9, 10 },
        .retry_source_connection_id = &.{ 11, 12, 13 },
    };

    var buf: [512]u8 = undefined;
    var writer: Writer = .init(&buf);
    try encode(&writer, source, .server);

    var decoded: TransportParameters = .{};
    try decode(writer.written(), .client, &decoded);

    try testing.expectEqualSlices(
        u8,
        source.original_destination_connection_id.?,
        decoded.original_destination_connection_id.?,
    );
    try expectEqual(@as(?u64, 30_000), decoded.max_idle_timeout);
    try testing.expectEqualSlices(u8, &source.stateless_reset_token.?, &decoded.stateless_reset_token.?);
    try expectEqual(@as(?u64, 1400), decoded.max_udp_payload_size);
    try expectEqual(@as(?u64, 1 << 20), decoded.initial_max_data);
    try expectEqual(@as(?u64, 1000), decoded.initial_max_stream_data_bidi_local);
    try expectEqual(@as(?u64, 2000), decoded.initial_max_stream_data_bidi_remote);
    try expectEqual(@as(?u64, 3000), decoded.initial_max_stream_data_uni);
    try expectEqual(@as(?u64, 10), decoded.initial_max_streams_bidi);
    try expectEqual(@as(?u64, 11), decoded.initial_max_streams_uni);
    try expectEqual(@as(?u64, 4), decoded.ack_delay_exponent);
    try expectEqual(@as(?u64, 26), decoded.max_ack_delay);
    try expect(decoded.disable_active_migration);
    try expectEqual(@as(?u64, 4), decoded.active_connection_id_limit);
    try testing.expectEqualSlices(u8, &.{ 9, 10 }, decoded.initial_source_connection_id.?);
    try testing.expectEqualSlices(u8, &.{ 11, 12, 13 }, decoded.retry_source_connection_id.?);
}

test "RFC 9000 §18.2, preferred_address round trips" {
    const source: TransportParameters = .{
        .preferred_address = .{
            .ipv4 = .{ 127, 0, 0, 1 },
            .ipv4_port = 4433,
            .ipv6 = @splat(0xfe),
            .ipv6_port = 4434,
            .connection_id = &.{ 1, 2, 3 },
            .reset_token = @splat(0x44),
        },
    };

    var buf: [128]u8 = undefined;
    var writer: Writer = .init(&buf);
    try encode(&writer, source, .server);

    var decoded: TransportParameters = .{};
    try decode(writer.written(), .client, &decoded);

    const address = decoded.preferred_address.?;
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &address.ipv4);
    try expectEqual(@as(u16, 4433), address.ipv4_port);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, address.connection_id);
    try expectEqual(@as(u16, 4434), address.ipv6_port);
    try testing.expectEqualSlices(u8, &source.preferred_address.?.reset_token, &address.reset_token);

    // §18.2: a zero-length connection ID in a preferred address is an error.
    var bad_buf: [64]u8 = undefined;
    var bad: Writer = .init(&bad_buf);
    const empty_id: TransportParameters = .{
        .preferred_address = .{
            .ipv4 = @splat(0),
            .ipv4_port = 0,
            .ipv6 = @splat(0),
            .ipv6_port = 0,
            .connection_id = &.{},
            .reset_token = @splat(0),
        },
    };
    try testing.expectError(error.InvalidValue, encode(&bad, empty_id, .server));
}

test "RFC 9000 §18.2, a duplicated parameter is refused" {
    var buf: [32]u8 = undefined;
    var writer: Writer = .init(&buf);
    try putIntParam(&writer, 0x01, 1000);
    try putIntParam(&writer, 0x01, 2000);

    var params: TransportParameters = .{};
    try testing.expectError(error.DuplicateParameter, decode(writer.written(), .client, &params));
}

test "RFC 9000 §18.2, a server refuses the server-only parameters" {
    const server_only = [_]u64{ 0x00, 0x02, 0x0d, 0x10 };
    for (server_only) |id| {
        var buf: [64]u8 = undefined;
        var writer: Writer = .init(&buf);
        const token: [16]u8 = @splat(0);
        switch (id) {
            0x02 => try putParam(&writer, id, &token),
            else => try putParam(&writer, id, &.{1}),
        }
        var params: TransportParameters = .{};
        try testing.expectError(error.NotAllowed, decode(writer.written(), .server, &params));
    }

    // The same bytes are ordinary when a client is the receiver.
    var buf: [64]u8 = undefined;
    var writer: Writer = .init(&buf);
    try putIntParam(&writer, 0x01, 5);
    var params: TransportParameters = .{};
    try decode(writer.written(), .client, &params);
    try expectEqual(@as(?u64, 5), params.max_idle_timeout);
}

test "RFC 9000 §18.2, a client cannot write a server-only parameter" {
    var buf: [64]u8 = undefined;
    const params: TransportParameters = .{
        .initial_source_connection_id = &.{1},
        .retry_source_connection_id = &.{2},
    };
    var writer: Writer = .init(&buf);
    try testing.expectError(error.NotAllowed, encode(&writer, params, .client));
}

test "RFC 9000 §18.2, out-of-range values are refused" {
    const cases = [_]struct { id: u64, value: u64 }{
        .{ .id = 0x03, .value = 1199 }, // max_udp_payload_size below 1200
        .{ .id = 0x0a, .value = 21 }, // ack_delay_exponent above 20
        .{ .id = 0x0b, .value = 1 << 14 }, // max_ack_delay at 2^14
        .{ .id = 0x0e, .value = 1 }, // active_connection_id_limit below 2
    };
    for (cases) |case| {
        var buf: [64]u8 = undefined;
        var writer: Writer = .init(&buf);
        try putIntParam(&writer, case.id, case.value);
        var params: TransportParameters = .{};
        try testing.expectError(error.InvalidValue, decode(writer.written(), .client, &params));
    }

    // A stateless reset token is exactly 16 bytes.
    var short_buf: [64]u8 = undefined;
    var short_writer: Writer = .init(&short_buf);
    try putParam(&short_writer, 0x02, &.{ 0, 0, 0 });
    var params: TransportParameters = .{};
    try testing.expectError(error.InvalidValue, decode(short_writer.written(), .client, &params));

    // disable_active_migration is a zero-length value.
    var long_buf: [64]u8 = undefined;
    var long_writer: Writer = .init(&long_buf);
    try putParam(&long_writer, 0x0c, &.{1});
    try testing.expectError(error.InvalidValue, decode(long_writer.written(), .client, &params));

    // A connection ID parameter holds at most 20 bytes.
    var cid_buf: [64]u8 = undefined;
    var cid_writer: Writer = .init(&cid_buf);
    try putParam(&cid_writer, 0x0f, &@as([21]u8, @splat(0xaa)));
    try testing.expectError(error.InvalidValue, decode(cid_writer.written(), .client, &params));

    // An integer parameter with trailing bytes is not one integer.
    var trailing_buf: [64]u8 = undefined;
    var trailing_writer: Writer = .init(&trailing_buf);
    try putParam(&trailing_writer, 0x01, &.{ 0x01, 0x02 });
    try testing.expectError(error.InvalidValue, decode(trailing_writer.written(), .client, &params));
}

test "RFC 9000 §18.2, a parameter this version does not define is ignored" {
    var buf: [64]u8 = undefined;
    var writer: Writer = .init(&buf);
    try putParam(&writer, 0x20, &.{ 1, 2, 3 }); // RFC 9221 max_datagram_frame_size
    try putIntParam(&writer, 0x01, 7);

    var params: TransportParameters = .{};
    try decode(writer.written(), .client, &params);
    try expectEqual(@as(?u64, 7), params.max_idle_timeout);

    // A duplicated unknown parameter is still a duplicate.
    var dup_buf: [64]u8 = undefined;
    var dup_writer: Writer = .init(&dup_buf);
    try putParam(&dup_writer, 0x20, &.{1});
    try putParam(&dup_writer, 0x20, &.{2});
    try testing.expectError(error.DuplicateParameter, decode(dup_writer.written(), .client, &params));
}

// §18 gives each parameter an (identifier, length, value) tuple, and §7.4
// makes a malformed one a TRANSPORT_PARAMETER_ERROR. The length is a varint,
// so it can declare more bytes than any buffer holds; the declaration is
// refused before the value is taken.
test "RFC 9000 §18, a parameter that declares more bytes than are left is refused" {
    // Id 0x01 with a length of 4 and no bytes.
    var params: TransportParameters = .{};
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x04 }, .client, &params));
    try testing.expectError(error.Truncated, decode(&.{0x01}, .client, &params));

    // §16 allows a length in the eight-byte form, so the check cannot assume
    // the declared length fits the cursor's u32 position. This is 2^40 with a
    // single byte behind it: the length is refused before the byte is read.
    const huge = [_]u8{ 0x01, 0xcd, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xaa };
    try testing.expectError(error.Truncated, decode(&huge, .client, &params));

    // The largest length the form carries, with nothing behind it.
    const longest = [_]u8{ 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.Truncated, decode(&longest, .client, &params));
    try expectEqual(@as(?u64, null), params.max_idle_timeout);
}

test "RFC 9000 §18.2, encode refuses a value the wire has no encoding for" {
    // A parameter value is a variable-length integer (§18.2) and §16 caps the
    // encoding at 2^62 - 1, so a bigger field has no bytes to write. It is a
    // caller bug that returns, not one that panics.
    var buf: [64]u8 = undefined;
    var writer: Writer = .init(&buf);
    const too_big: TransportParameters = .{ .max_idle_timeout = 1 << 62 };
    try testing.expectError(error.InvalidValue, encode(&writer, too_big, .client));
    try expectEqual(@as(u32, 0), writer.pos);

    const largest: TransportParameters = .{ .initial_max_data = varint.max };
    try encode(&writer, largest, .client);
    var params: TransportParameters = .{};
    try decode(writer.written(), .client, &params);
    try expectEqual(@as(?u64, varint.max), params.initial_max_data);
}

test "RFC 9000 §17.2, encode refuses a connection ID longer than 20 bytes" {
    // The decoder refuses these bytes, so the encoder must not produce them:
    // an encode the peer reads as a TRANSPORT_PARAMETER_ERROR is never the
    // answer the caller wanted.
    const long = @as([21]u8, @splat(0xaa));
    var buf: [128]u8 = undefined;
    var writer: Writer = .init(&buf);

    const cases = [_]TransportParameters{
        .{ .original_destination_connection_id = &long },
        .{ .initial_source_connection_id = &long },
        .{ .retry_source_connection_id = &long },
    };
    for (cases) |params| {
        try testing.expectError(error.InvalidValue, encode(&writer, params, .server));
        try expectEqual(@as(u32, 0), writer.pos);
    }

    // Twenty bytes is the limit and still writes.
    const limit = @as([20]u8, @splat(0xbb));
    try encode(&writer, .{ .initial_source_connection_id = &limit }, .client);
    var params: TransportParameters = .{};
    try decode(writer.written(), .client, &params);
    try testing.expectEqualSlices(u8, &limit, params.initial_source_connection_id.?);
}

test "more distinct parameters than the decoder tracks is refused" {
    var buf: [1024]u8 = undefined;
    var writer: Writer = .init(&buf);
    var i: u64 = 0;
    while (i < 65) : (i += 1) try putParam(&writer, 0x4000 + i, &.{});

    var params: TransportParameters = .{};
    try testing.expectError(error.TooManyParameters, decode(writer.written(), .client, &params));
}

test "fuzz the transport parameter decoder" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const input = buf[0..smith.slice(&buf)];
            const role: Role = if (smith.value(bool)) .client else .server;

            var params: TransportParameters = .{};
            decode(input, role, &params) catch |err| {
                try expect(switch (err) {
                    error.Truncated,
                    error.DuplicateParameter,
                    error.InvalidValue,
                    error.NotAllowed,
                    error.TooManyParameters,
                    => true,
                    else => false,
                });
                return;
            };

            // Whatever parsed re-encodes and parses back to the same values.
            // The encode is as a server: a client reading a server's
            // parameters would answer with its own, not echo them back.
            var out: [512]u8 = undefined;
            var writer: Writer = .init(&out);
            try encode(&writer, params, .server);
            var again: TransportParameters = .{};
            try decode(writer.written(), role, &again);
            try expectEqual(params.max_idle_timeout, again.max_idle_timeout);
            try expectEqual(params.disable_active_migration, again.disable_active_migration);
        }
    }.run, .{ .corpus = &.{ "", "\x01\x01\x05", "\x00\x01\x00" } });
}
