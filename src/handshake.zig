//! The TLS handshake seam: what a driver does, and what this package asks of it.
//!
//! TLS 1.3 is not in this package, and this file is the whole of the contract
//! between the two. The driver is a sans-I/O message machine: it takes CRYPTO
//! frame payloads, hands back the bytes to put in CRYPTO frames at a level, and
//! reports the traffic secrets, confirmation, ALPN, and transport parameters at
//! the moments the RFCs give them. It opens no socket, keeps no clock, and
//! allocates nothing the machine can see, because neither side may.
//!
//! The seam is a vtable and a context pointer rather than a generic type
//! parameter: the machine holds one driver without knowing its type, and the
//! driver lives in another repository. `baskingspot/tls` will implement this
//! table; so does `Stub` below, which is what the tests in this package use in
//! its place.
//!
//! What the driver does not do, because the machine does:
//!
//! - Reassembly of CRYPTO data. §19.6 of RFC 9000 gives a CRYPTO frame an
//!   offset, frames arrive out of order and twice, and the receiver puts them in
//!   order. The driver sees one contiguous stream per level and never an offset.
//! - Packet number spaces. The driver names an encryption level; the machine
//!   maps that to a packet number space and to keys (§12.3 of RFC 9000).
//! - Transport parameters. QUIC encodes and parses them (§18); TLS carries them
//!   opaquely in extension 0x0039 (§8.2), in both directions.
//!
//! Alerts surface as transport error codes, never as a table: while the driver
//! is failed, `errorCode` is `0x100 + alert`, which is the CRYPTO_ERROR range of
//! §20.1 of RFC 9000. The machine closes with that number and maps nothing.
//!
//! Ownership: a slice handed to `feed` is borrowed for that call only, and a
//! slice returned by any other call is borrowed from the driver and stays valid
//! until the next call into it. The machine copies what it keeps.

const std = @import("std");
const testing = std.testing;
const protection = @import("protection.zig");

const handshake = @This();

/// The encryption levels of RFC 9001 §4, as far as handshake bytes go.
///
/// This is the driver's vocabulary, not the machine's: which packet number
/// space a level's packets use (§12.3 of RFC 9000) is the machine's business,
/// and a driver that never hears about spaces stays usable on its own.
///
/// 0-RTT is absent on purpose: this package has no 0-RTT keys and asks for
/// none, and RFC 9001 §4.6.1 makes requesting them a driver decision.
pub const Level = enum { initial, handshake, app };

pub const Error = error{
    /// The driver has failed. The transport error code to close with comes from
    /// `Driver.errorCode`; for a TLS alert it is `0x100 + alert` (§20.1).
    HandshakeFailed,
    /// A caller-owned buffer is too small. The driver never grows one.
    NoSpace,
    /// A call this driver's state does not allow, such as transport parameters
    /// set after the first message left.
    UnexpectedCall,
    /// The negotiated cipher suite is one this package does not implement. It is
    /// a refusal, never a substitution.
    UnsupportedCipherSuite,
};

/// The TLS 1.3 cipher suites of RFC 8446 §B.4, as the driver names them.
///
/// The names are the registry's, so a driver says what it negotiated and the
/// machine says whether it can protect packets with it. Keeping this separate
/// from `protection.Suite` is the point: that type is what this package can do,
/// and this one is what TLS may pick, which is two different sets. Reporting a
/// suite this package cannot do is a named error, not a quiet fall back to
/// AES-128-GCM.
pub const Suite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,
    aes_128_ccm_sha256,
    aes_128_ccm_8_sha256,

    /// The AEAD this package protects packets with for the suite, if it has one.
    pub fn protectionSuite(self: Suite) Error!protection.Suite {
        return switch (self) {
            .aes_128_gcm_sha256 => .aes_128_gcm,
            .chacha20_poly1305_sha256 => .chacha20_poly1305,
            // Named so a driver can report them and be refused. AES-256-GCM
            // needs SHA-384 for the key schedule, and the CCM suites are not
            // implemented at all; neither is a default this package may quietly
            // replace.
            .aes_256_gcm_sha384, .aes_128_ccm_sha256, .aes_128_ccm_8_sha256 => error.UnsupportedCipherSuite,
        };
    }
};

/// One level's traffic secrets. The pair is the same for both roles and the
/// machine picks by its own role, exactly as it does for the Initial keys.
pub const Secrets = struct {
    /// 32 bytes for a SHA-256 suite, 48 for SHA-384.
    /// `protection.deriveKeys` refuses a length it cannot use rather than
    /// truncating it, so a driver that reports a suite this package cannot do
    /// gets a named error instead of a broken handshake.
    client: []const u8,
    server: []const u8,
};

pub const Message = struct {
    level: Level,
    /// Handshake bytes for one CRYPTO frame at that level.
    bytes: []const u8,
};

pub const VTable = struct {
    /// Handshake bytes that arrived at a level, in order, with gaps and
    /// duplicates already resolved by the machine.
    feed: *const fn (ctx: *anyopaque, level: Level, bytes: []const u8) Error!void,
    /// The cipher suite the handshake settled on. Required, and asked before any
    /// key is derived: a default here is how a machine ends up using AES-128-GCM
    /// against a peer that negotiated something else, which fails in a way no
    /// test of ours would catch.
    suite: *const fn (ctx: *anyopaque) Suite,
    /// The next handshake bytes to send, or null when there are none. A caller
    /// drains until null.
    next: *const fn (ctx: *anyopaque) Error!?Message,
    /// The traffic secrets for a level once they exist, and null before that.
    /// Reporting them again after the machine has them is not an error: the
    /// machine installs a level once.
    secrets: *const fn (ctx: *anyopaque, level: Level) Error!?Secrets,
    /// This endpoint's `quic_transport_parameters`, before the first message
    /// leaves (§8.2). The bytes are opaque to the driver and it copies them.
    setTransportParameters: *const fn (ctx: *anyopaque, bytes: []const u8) Error!void,
    /// The peer's transport parameters, or null until they arrive.
    peerTransportParameters: *const fn (ctx: *anyopaque) Error!?[]const u8,
    /// Whether this endpoint's TLS handshake has completed. §4.1.2 of RFC 9001
    /// makes that the server's confirmation, not the client's: a client is
    /// confirmed by a HANDSHAKE_DONE frame, which no TLS driver can see. The
    /// machine asks this of a server and nowhere else.
    confirmed: *const fn (ctx: *anyopaque) bool,
    /// The ALPN protocol the handshake settled on, or null.
    alpn: *const fn (ctx: *anyopaque) ?[]const u8,
    /// The transport error code for the failure that just happened: `0x100 +
    /// alert` for a TLS alert (§20.1).
    errorCode: *const fn (ctx: *anyopaque) u64,
};

/// A driver with its context bound, which is what the machine holds.
pub const Driver = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub fn feed(self: Driver, level: Level, bytes: []const u8) Error!void {
        return self.vtable.feed(self.ctx, level, bytes);
    }

    pub fn suite(self: Driver) Suite {
        return self.vtable.suite(self.ctx);
    }

    pub fn next(self: Driver) Error!?Message {
        return self.vtable.next(self.ctx);
    }

    pub fn secrets(self: Driver, level: Level) Error!?Secrets {
        return self.vtable.secrets(self.ctx, level);
    }

    pub fn setTransportParameters(self: Driver, bytes: []const u8) Error!void {
        return self.vtable.setTransportParameters(self.ctx, bytes);
    }

    pub fn peerTransportParameters(self: Driver) Error!?[]const u8 {
        return self.vtable.peerTransportParameters(self.ctx);
    }

    pub fn confirmed(self: Driver) bool {
        return self.vtable.confirmed(self.ctx);
    }

    pub fn alpn(self: Driver) ?[]const u8 {
        return self.vtable.alpn(self.ctx);
    }

    pub fn errorCode(self: Driver) u64 {
        return self.vtable.errorCode(self.ctx);
    }
};

/// A scripted driver: it hands out what a test put in it and records what the
/// machine gave it.
///
/// It is part of the package rather than the test block because the machine
/// cannot be run without a driver, and a caller testing its own socket and send
/// loop against this package needs a handshake that does nothing.
pub const Stub = struct {
    /// Messages `next` hands out, in order.
    outbox: []const Message = &.{},
    outbox_at: usize = 0,
    handshake_secrets: ?Secrets = null,
    app_secrets: ?Secrets = null,
    peer_parameters: ?[]const u8 = null,
    alpn_protocol: ?[]const u8 = null,
    /// What `suite` reports.
    cipher_suite: Suite = .aes_128_gcm_sha256,
    confirmed: bool = false,
    /// Whether the application secrets appear only after the first `feed`.
    /// A real driver derives them from the peer's Finished, which arrives as
    /// CRYPTO bytes, so this is what makes a test's timing match a handshake's:
    /// a machine that installs the 1-RTT space too late drops a coalesced
    /// packet that a driver like this one would have unlocked.
    app_secrets_after_feed: bool = false,
    /// What `errorCode` reports after a failed call.
    failure: u64 = 0,
    fail_next: bool = false,
    fail_feed: bool = false,

    /// What `feed` was given.
    fed_level: ?Level = null,
    fed_calls: u32 = 0,
    fed: [256]u8 = undefined,
    fed_len: u32 = 0,

    /// What `setTransportParameters` was given.
    parameters_set: bool = false,
    parameters: [128]u8 = undefined,
    parameters_len: u32 = 0,

    pub const vtable: VTable = .{
        .feed = feed,
        .suite = suite,
        .next = next,
        .secrets = secrets,
        .setTransportParameters = setTransportParameters,
        .peerTransportParameters = peerTransportParameters,
        .confirmed = isConfirmed,
        .alpn = alpn,
        .errorCode = errorCode,
    };

    pub fn driver(self: *Stub) Driver {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn feed(ctx: *anyopaque, level: Level, bytes: []const u8) Error!void {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        if (self.fail_feed) return error.HandshakeFailed;
        if (@as(usize, self.fed_len) + bytes.len > self.fed.len) return error.NoSpace;
        @memcpy(self.fed[self.fed_len..][0..bytes.len], bytes);
        self.fed_len += @intCast(bytes.len);
        self.fed_level = level;
        self.fed_calls += 1;
    }

    fn suite(ctx: *anyopaque) Suite {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        return self.cipher_suite;
    }

    fn next(ctx: *anyopaque) Error!?Message {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        if (self.fail_next) return error.HandshakeFailed;
        if (self.outbox_at == self.outbox.len) return null;
        const message = self.outbox[self.outbox_at];
        self.outbox_at += 1;
        return message;
    }

    fn secrets(ctx: *anyopaque, level: Level) Error!?Secrets {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        return switch (level) {
            // Initial keys come from the connection ID (§5.2 of RFC 9001), not
            // from TLS, so a driver never has them.
            .initial => null,
            .handshake => self.handshake_secrets,
            .app => if (self.app_secrets_after_feed and self.fed_calls == 0)
                null
            else
                self.app_secrets,
        };
    }

    fn setTransportParameters(ctx: *anyopaque, bytes: []const u8) Error!void {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        // The contract: once the first message has left, they are in it.
        if (self.outbox_at != 0) return error.UnexpectedCall;
        if (bytes.len > self.parameters.len) return error.NoSpace;
        @memcpy(self.parameters[0..bytes.len], bytes);
        self.parameters_len = @intCast(bytes.len);
        self.parameters_set = true;
    }

    fn peerTransportParameters(ctx: *anyopaque) Error!?[]const u8 {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        return self.peer_parameters;
    }

    fn isConfirmed(ctx: *anyopaque) bool {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        return self.confirmed;
    }

    fn alpn(ctx: *anyopaque) ?[]const u8 {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        return self.alpn_protocol;
    }

    fn errorCode(ctx: *anyopaque) u64 {
        const self: *Stub = @ptrCast(@alignCast(ctx));
        return self.failure;
    }
};

test "the seam binds a driver's context and passes levels through" {
    const client_secret: [32]u8 = @splat(0x11);
    const server_secret: [32]u8 = @splat(0x22);

    var stub: Stub = .{
        .outbox = &.{.{ .level = .handshake, .bytes = "ServerHello bytes" }},
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
        .alpn_protocol = "h3",
    };
    const driver = stub.driver();

    // Transport parameters first: the driver must have them before its first
    // message leaves.
    try driver.setTransportParameters("later, and opaque");
    try testing.expect(stub.parameters_set);
    try testing.expectEqualStrings("later, and opaque", stub.parameters[0..stub.parameters_len]);
    try testing.expectEqual(@as(?[]const u8, null), try driver.peerTransportParameters());

    // Inbound bytes come with their level.
    try driver.feed(.handshake, "ClientHello bytes");
    try testing.expectEqual(Level.handshake, stub.fed_level.?);
    try testing.expectEqualStrings("ClientHello bytes", stub.fed[0..stub.fed_len]);

    // Outbound: drained one message at a time, with the level the driver chose.
    const message = (try driver.next()).?;
    try testing.expectEqual(Level.handshake, message.level);
    try testing.expectEqualStrings("ServerHello bytes", message.bytes);
    try testing.expect((try driver.next()) == null);

    // Secrets per level; Initial keys are not a driver's to give, because they
    // come from the connection ID.
    const secrets = (try driver.secrets(.handshake)).?;
    try testing.expectEqualStrings(&client_secret, secrets.client);
    try testing.expectEqualStrings(&server_secret, secrets.server);
    try testing.expect((try driver.secrets(.initial)) == null);
    try testing.expect((try driver.secrets(.app)) == null);

    try testing.expectEqualStrings("h3", driver.alpn().?);
    try testing.expectEqual(Suite.aes_128_gcm_sha256, driver.suite());
    try testing.expect(!driver.confirmed());
    // Nothing is set up for them after the first message.
    try testing.expectError(error.UnexpectedCall, driver.setTransportParameters("too late"));

    // A failure is one error, and the code to close with is a CRYPTO_ERROR.
    stub.fail_next = true;
    stub.failure = 0x100 + 40;
    try testing.expectError(error.HandshakeFailed, driver.next());
    try testing.expectEqual(@as(u64, 0x128), driver.errorCode());
}

test "RFC 8446 §B.4, a suite this package cannot do is refused by name" {
    try testing.expectEqual(protection.Suite.aes_128_gcm, try Suite.aes_128_gcm_sha256.protectionSuite());
    try testing.expectEqual(protection.Suite.chacha20_poly1305, try Suite.chacha20_poly1305_sha256.protectionSuite());

    // The rest exist in the registry and not in this package. Each is a refusal,
    // never a substitution.
    inline for (.{ Suite.aes_256_gcm_sha384, Suite.aes_128_ccm_sha256, Suite.aes_128_ccm_8_sha256 }) |suite| {
        try testing.expectError(error.UnsupportedCipherSuite, suite.protectionSuite());
    }
}

test "the seam reports a buffer that has no room instead of growing one" {
    var stub: Stub = .{};
    const driver = stub.driver();

    const big: [300]u8 = @splat(0x5a);
    try testing.expectError(error.NoSpace, driver.feed(.handshake, &big));
    // Nothing was recorded, so the caller can retry into a larger buffer.
    try testing.expectEqual(@as(u32, 0), stub.fed_calls);
    try testing.expectEqual(@as(?Level, null), stub.fed_level);
}
