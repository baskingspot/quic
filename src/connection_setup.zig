//! Version negotiation and Retry, RFC 9000 §6 and RFC 9001 §5.8.
//!
//! Both are stateless: a server answers a packet it cannot or will not accept
//! without keeping anything, and a client has one small piece of memory about
//! what it has already seen. That memory is the whole of `Client` below, and it
//! exists because the rules that matter are about what happened before.
//!
//! Retry does not keep state either, but it does keep a secret in the open: the
//! integrity tag is AES-128-GCM with a key published in RFC 9001 §5.8, over a
//! pseudo-packet that prepends the client's original Destination Connection ID
//! to the Retry as sent. The tag is what stops an attacker who never saw the
//! Initial from injecting a Retry, and it is why the client must check it before
//! it spends a token.

const std = @import("std");
const testing = std.testing;
const packet = @import("packet.zig");
const Writer = @import("Writer.zig");

const setup = @This();

pub const VersionNegotiation = struct {
    /// §6.1: a server answers a long header it does not support. It must not
    /// answer a Version Negotiation packet with another one, and the destination
    /// and source IDs are echoed by swapping the ones it received (§17.2.1).
    pub fn write(
        writer: *Writer,
        received: *const packet.Invariant,
        supported: []const packet.Version,
    ) packet.Error!void {
        if (received.version == .negotiation) return error.WrongPacketType;
        try packet.writeVersionNegotiation(writer, .{
            .destination_connection_id = received.source_connection_id,
            .source_connection_id = received.destination_connection_id,
            .versions = supported,
        });
    }

    pub const Action = enum {
        /// §6.2: the packet arrived after another one was processed, or it
        /// lists the version the client is trying. It is discarded.
        ignore,
        /// §6.2: a client that supports only one version abandons the attempt.
        /// Selecting a different version is future Standards Track work, so this
        /// package has no way to express it: see the note on `handle`.
        abandon,
    };

    /// What a client does with a Version Negotiation packet.
    ///
    /// The return type is the rule. §6.2 says a client that supports only the
    /// version it tried must abandon the attempt, and that how to negotiate is
    /// left to future specifications. There is no branch that returns another
    /// version, so the interoperability bug of switching versions in response
    /// to a Version Negotiation packet cannot be written here.
    pub fn handle(
        response: *const packet.VersionNegotiation,
        attempted: packet.Version,
        responded: bool,
    ) Action {
        // §6.2: discard if any other packet was processed, and discard a packet
        // that lists the version the client selected.
        if (responded) return .ignore;
        var index: u32 = 0;
        while (index < response.count()) : (index += 1) {
            if (response.at(index) == attempted) return .ignore;
        }
        return .abandon;
    }
};

pub const Retry = struct {
    /// RFC 9001 §5.8: the key.
    pub const key = [_]u8{
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    };
    /// RFC 9001 §5.8: the nonce.
    pub const nonce = [_]u8{
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    };

    pub const Error = packet.Error || error{
        /// RFC 9001 §5.8: the tag did not match the pseudo-packet. §17.2.5.2:
        /// a client must discard the packet.
        IntegrityCheckFailed,
        /// §17.2.5.2: a client must discard a Retry with a zero-length token.
        EmptyToken,
    };

    /// The largest pseudo-packet this builds: one length byte, a 20-byte
    /// original destination ID, and a Retry that fits a datagram.
    pub const max_pseudo_packet = 1 + 20 + 1500;

    /// RFC 9001 §5.8: the tag over the pseudo-packet, which is the original
    /// Destination Connection ID and the Retry as sent without its tag.
    pub fn integrityTag(original_destination_connection_id: []const u8, retry_without_tag: []const u8) [16]u8 {
        var pseudo: [max_pseudo_packet]u8 = undefined;
        const length = 1 + original_destination_connection_id.len + retry_without_tag.len;
        std.debug.assert(length <= pseudo.len);

        pseudo[0] = @intCast(original_destination_connection_id.len);
        @memcpy(pseudo[1..][0..original_destination_connection_id.len], original_destination_connection_id);
        @memcpy(
            pseudo[1 + original_destination_connection_id.len ..][0..retry_without_tag.len],
            retry_without_tag,
        );

        var tag: [16]u8 = undefined;
        std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
            &.{},
            &tag,
            &.{},
            pseudo[0..length],
            nonce,
            key,
        );
        return tag;
    }

    /// Build a Retry, tag included, into `out`. Returns its length.
    pub fn write(
        out: []u8,
        original_destination_connection_id: []const u8,
        retry: packet.RetryToWrite,
    ) Error!u32 {
        var writer: Writer = .init(out);
        const offsets = try packet.writeRetry(&writer, retry);
        const tag = integrityTag(original_destination_connection_id, out[0..offsets.integrity_tag]);
        writer.patch(offsets.integrity_tag, &tag);
        return writer.pos;
    }

    /// §17.2.5.2: a client discards a Retry whose tag does not validate.
    ///
    /// The tag is computed from public bytes with a published key, so an
    /// ordinary comparison leaks nothing: there is no secret to be timed.
    pub fn validate(raw: []const u8, original_destination_connection_id: []const u8) Error!void {
        if (raw.len < packet.retry_integrity_tag_len) return error.Truncated;
        const body = raw[0 .. raw.len - packet.retry_integrity_tag_len];
        const sent = raw[raw.len - packet.retry_integrity_tag_len ..];
        const expected = integrityTag(original_destination_connection_id, body);
        if (!std.mem.eql(u8, &expected, sent)) return error.IntegrityCheckFailed;
    }
};

/// The small amount of client state the rules in §6.2 and §17.2.5.2 depend on.
pub const Client = struct {
    /// The Destination Connection ID the client put in its first Initial, which
    /// the Retry tag covers.
    original_destination_connection_id: []const u8,
    /// §17.2.5.2: "A client MUST accept and process at most one Retry packet for
    /// each connection attempt."
    retried: bool = false,
    /// Set when any packet from the server has been processed. §6.2 discards a
    /// Version Negotiation packet after that, and §17.2.5.2 discards a Retry.
    responded: bool = false,
    /// Set when a 1-RTT packet has been sent. §17.2.5.2: a Retry after that is
    /// discarded.
    one_rtt_sent: bool = false,

    pub const Outcome = enum { accepted, ignored };

    pub fn init(original_destination_connection_id: []const u8) Client {
        return .{ .original_destination_connection_id = original_destination_connection_id };
    }

    /// Note that the server answered: any later Retry is discarded.
    pub fn onServerResponse(self: *Client) void {
        self.responded = true;
    }

    /// Note that a 1-RTT packet has been sent.
    pub fn onOneRttSent(self: *Client) void {
        self.one_rtt_sent = true;
    }

    /// §17.2.5.2 and §6.2 for a Version Negotiation packet.
    pub fn onVersionNegotiation(
        self: *Client,
        response: *const packet.VersionNegotiation,
        attempted: packet.Version,
    ) VersionNegotiation.Action {
        const action = VersionNegotiation.handle(response, attempted, self.responded);
        self.responded = true;
        return action;
    }

    /// §17.2.5.2: validate a Retry and decide whether to use its token.
    ///
    /// `retry` is the parsed packet and `raw` is the bytes it came from, because
    /// the tag covers the bytes and not the parsed fields. The order is
    /// deliberate: a Retry after the first response, or a second Retry, is
    /// ignored without spending an integrity check, because it is already
    /// disqualified. A first Retry with a bad tag is an error, because that is
    /// either corruption or an injection, and neither may be retried.
    pub fn onRetry(
        self: *Client,
        retry: *const packet.Retry,
        raw: []const u8,
    ) Retry.Error!Outcome {
        if (self.responded or self.one_rtt_sent or self.retried) return .ignored;
        // §17.2.5.2: a zero-length token is a discard. The parser refuses one
        // too; this is the client's own guard for a caller that built the
        // struct itself.
        if (retry.token.len == 0) return error.EmptyToken;
        try Retry.validate(raw, self.original_destination_connection_id);
        self.retried = true;
        return .accepted;
    }
};

test "RFC 9001 Appendix A.4, the worked Retry example validates" {
    // The packet as printed, tag included. The unused bits are 0x0f there.
    const raw = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    try Retry.validate(&raw, &odcid);

    // A different original connection ID changes the pseudo-packet.
    const other = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    try testing.expectError(error.IntegrityCheckFailed, Retry.validate(&raw, &other));
}

test "RFC 9001 §5.8, a server building the same Retry produces the printed bytes" {
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const expected = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    var out: [128]u8 = undefined;
    const length = try Retry.write(&out, &odcid, .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 },
        .token = "token",
        .unused = 0x0f,
    });
    try testing.expectEqual(expected.len, length);
    try testing.expectEqualSlices(u8, &expected, out[0..length]);
}

test "RFC 9000 §17.2.5.2, a Retry with a broken tag is refused, not retried" {
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var raw: [128]u8 = undefined;

    var out: [128]u8 = undefined;
    const length = try Retry.write(&out, &odcid, .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{ 0xaa, 0xbb },
        .token = "tok",
    });
    @memcpy(raw[0..length], out[0..length]);

    var client: Client = .init(&odcid);
    const parsed = (try packet.parse(raw[0..length], 0)).retry;
    try testing.expectEqual(Client.Outcome.accepted, try client.onRetry(&parsed, raw[0..length]));

    // One bit in the tag is corruption or an injection.
    var broken: [128]u8 = undefined;
    @memcpy(broken[0..length], raw[0..length]);
    broken[length - 1] ^= 0x01;

    var second: Client = .init(&odcid);
    const broken_parsed = (try packet.parse(broken[0..length], 0)).retry;
    try testing.expectError(
        error.IntegrityCheckFailed,
        second.onRetry(&broken_parsed, broken[0..length]),
    );
    try testing.expect(!second.retried);
}

test "RFC 9000 §17.2.5.2, a second Retry is ignored" {
    const odcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var out: [128]u8 = undefined;
    const length = try Retry.write(&out, &odcid, .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{ 0xaa, 0xbb },
        .token = "first",
    });

    var client: Client = .init(&odcid);
    const parsed = (try packet.parse(out[0..length], 0)).retry;
    try testing.expectEqual(Client.Outcome.accepted, try client.onRetry(&parsed, out[0..length]));

    // The same Retry again, byte for byte, is still a second Retry.
    try testing.expectEqual(Client.Outcome.ignored, try client.onRetry(&parsed, out[0..length]));

    // A different one with a valid tag is also ignored.
    var other: [128]u8 = undefined;
    const other_length = try Retry.write(&other, &odcid, .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{ 0xcc, 0xdd },
        .token = "second",
    });
    const other_parsed = (try packet.parse(other[0..other_length], 0)).retry;
    try testing.expectEqual(
        Client.Outcome.ignored,
        try client.onRetry(&other_parsed, other[0..other_length]),
    );
}

test "RFC 9000 §17.2.5.2, a Retry after a 1-RTT packet is ignored" {
    const odcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var out: [128]u8 = undefined;
    const length = try Retry.write(&out, &odcid, .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{ 0xaa, 0xbb },
        .token = "late",
    });

    const parsed = (try packet.parse(out[0..length], 0)).retry;
    var client: Client = .init(&odcid);
    client.onOneRttSent();
    try testing.expectEqual(Client.Outcome.ignored, try client.onRetry(&parsed, out[0..length]));

    // A Retry after any other server packet is the same case.
    var second: Client = .init(&odcid);
    second.onServerResponse();
    try testing.expectEqual(Client.Outcome.ignored, try second.onRetry(&parsed, out[0..length]));
}

test "RFC 9000 §6.2, a version negotiation never changes the client's version" {
    // The client tried version 1; the server offers 1 and a reserved version.
    var bytes: [64]u8 = undefined;
    bytes[0] = 0xc0;
    bytes[1..5].* = .{ 0, 0, 0, 0 };
    bytes[5] = 2;
    bytes[6] = 0xaa;
    bytes[7] = 0xbb;
    bytes[8] = 1;
    bytes[9] = 0xcc;
    bytes[10..14].* = .{ 0, 0, 0, 1 };
    bytes[14..18].* = .{ 0xfa, 0xfa, 0xfa, 0xfa };

    const response = (try packet.parse(bytes[0..18], 0)).version_negotiation;
    // The list contains the version the client tried, so the packet is a
    // protocol violation by the server and is discarded (§6.2).
    try testing.expectEqual(
        VersionNegotiation.Action.ignore,
        VersionNegotiation.handle(&response, .v1, false),
    );

    // Without our version in the list, the attempt is abandoned. There is no
    // return value that names another version, and that is the point.
    var other_bytes: [32]u8 = undefined;
    other_bytes[0] = 0xc0;
    other_bytes[1..5].* = .{ 0, 0, 0, 0 };
    other_bytes[5] = 2;
    other_bytes[6] = 0xaa;
    other_bytes[7] = 0xbb;
    other_bytes[8] = 0; // source connection ID length: the header is 9 bytes
    other_bytes[9..13].* = .{ 0xfa, 0xfa, 0xfa, 0xfa };
    const other = (try packet.parse(other_bytes[0..13], 0)).version_negotiation;
    try testing.expectEqual(
        VersionNegotiation.Action.abandon,
        VersionNegotiation.handle(&other, .v1, false),
    );

    // After any other packet was processed, even a valid one is discarded.
    try testing.expectEqual(
        VersionNegotiation.Action.ignore,
        VersionNegotiation.handle(&other, .v1, true),
    );
}

test "RFC 9000 §6.1 and §17.2.1, the server echoes the connection IDs it saw" {
    // A client Initial: DCID 4 bytes, SCID 2 bytes, version 2.
    var bytes: [64]u8 = undefined;
    var writer: Writer = .init(&bytes);
    const offsets = try packet.writeLong(&writer, .{
        .kind = .initial,
        .destination_connection_id = &.{ 1, 2, 3, 4 },
        .source_connection_id = &.{ 9, 9 },
        .body_len = 4,
        .packet_number_len = 1,
    });
    _ = offsets;

    const invariant = try packet.parseInvariant(writer.written());
    const supported = [_]packet.Version{ .v1, @fromBackingInt(@intCast(0x0a0a0a0a)) };

    var out: [64]u8 = undefined;
    var out_writer: Writer = .init(&out);
    try VersionNegotiation.write(&out_writer, &invariant, &supported);

    const response = (try packet.parse(out_writer.written(), 0)).version_negotiation;
    // The client's SCID becomes the destination, and its DCID the source.
    try testing.expectEqualSlices(u8, &.{ 9, 9 }, response.destination_connection_id);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, response.source_connection_id);
    try testing.expectEqual(@as(u32, 2), response.count());

    // §6.1: a server must not answer a Version Negotiation packet with one.
    var vn_bytes: [16]u8 = undefined;
    vn_bytes[0] = 0xc0;
    vn_bytes[1..5].* = .{ 0, 0, 0, 0 };
    vn_bytes[5] = 0;
    vn_bytes[6] = 0;
    vn_bytes[7..11].* = .{ 0, 0, 0, 1 };
    const vn = try packet.parseInvariant(&vn_bytes);
    try testing.expectError(
        error.WrongPacketType,
        VersionNegotiation.write(&out_writer, &vn, &supported),
    );
}

test "RFC 9000 §17.2.5.2, a Retry with an empty token is discarded" {
    const odcid = [_]u8{0x01};
    var out: [128]u8 = undefined;
    // The packet writer refuses an empty token, so build the frame by hand and
    // tag it: a peer that sends one has done the same.
    out[0] = 0xf0;
    out[1..5].* = .{ 0, 0, 0, 1 };
    out[5] = 0;
    out[6] = 0;
    const body_length = 7;
    const tag = Retry.integrityTag(&odcid, out[0..body_length]);
    @memcpy(out[body_length..][0..16], &tag);

    const empty: packet.Retry = .{
        .version = .v1,
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
        .token = &.{},
        .integrity_tag = @splat(0),
    };
    var client: Client = .init(&odcid);
    try testing.expectError(error.EmptyToken, client.onRetry(&empty, out[0 .. body_length + 16]));
    try testing.expect(!client.retried);
}
