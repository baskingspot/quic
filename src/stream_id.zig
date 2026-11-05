//! Stream identifiers, RFC 9000 §2.1.
//!
//! The two low bits of a stream ID say who opened it and whether it carries
//! data one way or both. Everything else is a count, so the ID space is four
//! interleaved sequences and an implementation that needs "the third
//! client-initiated bidirectional stream" can compute it without a table.

const std = @import("std");
const testing = std.testing;

const stream_id = @This();

/// The largest stream ID, 2^62 - 1 (§2.1).
pub const max: u64 = (1 << 62) - 1;

pub const Initiator = enum { client, server };
pub const Direction = enum { bidi, uni };

pub const Kind = struct {
    initiator: Initiator,
    direction: Direction,

    /// The two-bit type of §2.1, Table 1.
    pub fn bits(self: Kind) u2 {
        const who: u2 = if (self.initiator == .client) 0 else 1;
        const way: u2 = if (self.direction == .bidi) 0 else 2;
        return who | way;
    }

    /// The `ordinal`th stream of this kind, counting from zero.
    pub fn at(self: Kind, ordinal: u64) !u64 {
        if (ordinal > (max - 3) / 4) return error.StreamIdOverflow;
        return 4 * ordinal + self.bits();
    }
};

pub fn initiator(id: u64) Initiator {
    return if (id & 0x01 == 0) .client else .server;
}

pub fn direction(id: u64) Direction {
    return if (id & 0x02 == 0) .bidi else .uni;
}

pub fn kind(id: u64) Kind {
    return .{ .initiator = initiator(id), .direction = direction(id) };
}

/// The ordinal of `id` within its kind, counting from zero (§2.1: each kind's
/// space begins at 0x00 through 0x03 and increases by four).
pub fn index(id: u64) u64 {
    return id >> 2;
}

/// Whether a stream is the one this endpoint sends on. A unidirectional stream
/// is sent on only by the side that opened it.
pub fn isLocal(id: u64, local: Initiator) bool {
    return initiator(id) == local;
}

test "RFC 9000 §2.1, the two low bits name the kind" {
    try testing.expectEqual(Kind{ .initiator = .client, .direction = .bidi }, kind(0));
    try testing.expectEqual(Kind{ .initiator = .server, .direction = .bidi }, kind(1));
    try testing.expectEqual(Kind{ .initiator = .client, .direction = .uni }, kind(2));
    try testing.expectEqual(Kind{ .initiator = .server, .direction = .uni }, kind(3));
    try testing.expectEqual(Kind{ .initiator = .client, .direction = .bidi }, kind(4));
}

test "RFC 9000 §2.1, each kind is its own arithmetic sequence" {
    const client_bidi: Kind = .{ .initiator = .client, .direction = .bidi };
    try testing.expectEqual(@as(u64, 0), try client_bidi.at(0));
    try testing.expectEqual(@as(u64, 4), try client_bidi.at(1));
    try testing.expectEqual(@as(u64, 8), try client_bidi.at(2));

    const server_uni: Kind = .{ .initiator = .server, .direction = .uni };
    try testing.expectEqual(@as(u64, 3), try server_uni.at(0));
    try testing.expectEqual(@as(u64, 7), try server_uni.at(1));

    // The ordinal divides back out.
    try testing.expectEqual(@as(u64, 2), index(try client_bidi.at(2)));
    try testing.expectEqual(client_bidi, kind(try client_bidi.at(2)));
}

test "RFC 9000 §2.1, the last ordinal fits in 62 bits" {
    const kind_max: Kind = .{ .initiator = .server, .direction = .uni };
    try testing.expect(try kind_max.at((max - 3) / 4) <= max);
    try testing.expectError(error.StreamIdOverflow, kind_max.at((max - 3) / 4 + 1));
}
