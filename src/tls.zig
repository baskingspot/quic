//! A TLS 1.3 driver for the handshake seam, over `baskingspot/tls`.
//!
//! The seam (`handshake.zig`) asks for a message machine: bytes in at a level,
//! bytes out at a level, secrets when the key schedule reaches them, and a
//! transport error code when it fails. `baskingspot/tls`'s step core
//! (`tls.handshake_core`) is the same split from the other side: it owns the
//! transcript, the key schedule, and the state machine, and queues its output
//! because it frames and encrypts nothing.
//!
//! This file is the join. Four things the core does not do:
//!
//! - Framing. §4 of RFC 8446 puts a type and a three-byte length in front of
//!   every handshake message, and RFC 9000 §19.6 delivers them as one byte
//!   stream with gaps already filled. A CRYPTO chunk can end inside a message,
//!   so each level's bytes go through a reassembly buffer here and only whole
//!   messages reach the core.
//! - The two messages the core takes from its caller rather than building:
//!   ClientHello (it is a policy decision: SNI, ALPN, extensions) and
//!   ServerHello (the suite, the group, and the legacy session id echo). Both
//!   are composed here, on the first `next()`, because §8.2 of RFC 9001 makes
//!   this endpoint's transport parameters part of them and the machine hands
//!   those over immediately before it asks for the first message.
//! - Levels. The seam names `initial`/`handshake`/`app`; TLS names
//!   `plaintext`/`handshake`/`application`. The mapping is one function.
//! - Alerts. A TLS alert arrives as CRYPTO bytes and the seam turns it into
//!   `0x100 + description` (§20.1 of RFC 9000).
//!
//! What it does not do, and why: 0-RTT (no keys, and §4.6.1 makes asking a
//! driver decision), HelloRetryRequest, post-handshake KeyUpdate and tickets,
//! and client authentication. Each fails with a named error rather than a
//! fallback. The server picks from the suites and groups it can actually
//! protect with, so a peer that offers none of them gets a failed handshake.
//!
//! Sans-I/O like the rest of the package: the caller owns every buffer, there
//! is no allocator, and the only entropy is the platform CSPRNG for the two
//! messages' random fields and the ephemeral keypairs.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const quic = @import("quic");
const tls = @import("tls");

const seam = quic.handshake;
const core = tls.handshake_core;

/// The transport parameters extension (RFC 9001 §8.2).
const transport_parameters_type: u16 = 0x0039;

/// RFC 8446 §6.2: internal_error, the alert a caller that has nothing better
/// to say sends. Reported as `0x100 + 80`.
const internal_error: u8 = 80;

/// RFC 9000 §20.1: the CRYPTO_ERROR range, one code per TLS alert.
const crypto_error: u64 = 0x100;

/// Which half of the handshake this driver runs.
pub const Role = enum { client, server };

/// What each role has to be told. A client must have a verification policy —
/// there is no default, so no caller can compile a handshake that verifies
/// nothing by omission — and a server must have credentials, because a
/// ServerHello with no Certificate is not a TLS 1.3 handshake.
pub const Config = union(Role) {
    client: struct {
        policy: tls.certificate.Policy,
        /// The name sent in server_name_indication, when there is one.
        server_name: ?[]const u8 = null,
        /// Offered in order; the server picks.
        alpn: []const []const u8 = &.{},
        /// Answers a CertificateRequest. Null means this client never
        /// authenticates, and a server that asks ends the handshake.
        credentials: ?core.Credentials = null,
    },
    server: struct {
        credentials: core.Credentials,
        alpn: []const []const u8 = &.{},
        /// Asks the client for a certificate under this policy. Null means the
        /// server never asks.
        client_policy: ?tls.certificate.Policy = null,
    },
};

/// Every buffer the driver writes into, owned by the caller. Sizes are the
/// caller's to pick; a buffer too small for the job is `error.NoSpace` at the
/// moment of use, never a truncation.
pub const Storage = struct {
    /// The core's queue of handshake outputs: one per message and per level
    /// transition, so it needs room for the largest flight plus the
    /// transitions (four messages and three transitions at a time).
    slots: []tls.level.Output,
    /// Where the core composes the messages it builds: the ClientHello, or the
    /// server's whole flight. A server checks it holds `flightBufferLen` at
    /// init, because `sendFlight` writes its messages as one unit.
    out: []u8,
    /// Reassembly for the peer's CRYPTO stream, one per seam level (§19.6 of
    /// RFC 9000). Sized for the largest handshake message expected; a
    /// certificate chain is the one that grows.
    peer_bytes: Inbound,
    /// Storage the server retains the client's key shares in. Must be
    /// `handshake_core.Server.peer_share_storage_len` bytes.
    peer_shares: []u8,
    /// Slots for the peer's extension payloads. One is enough: QUIC reads one
    /// extension, 0x0039.
    extension_slots: []tls.extension_type.ExtraExtension,
    /// This endpoint's transport parameters, copied from `setTransportParameters`.
    our_parameters: []u8,
    /// The peer's transport parameters, copied out of the message that carried
    /// them because that message is reused.
    peer_parameters: []u8,
    /// The selected ALPN protocol, copied for the same reason.
    alpn: []u8,
    /// The server's encoded ServerHello. Unused by a client.
    server_hello: []u8,
};

pub const Inbound = struct {
    initial: []u8,
    handshake: []u8,
    app: []u8,
};

pub const Error = seam.Error || core.Error;

pub const Tls = struct {
    role: Role,
    engine: Engine,
    keypairs: tls.KeyPairs,
    /// The server's certificates and signer. Null for a client.
    credentials: ?core.Credentials,
    in: [3]Stream,
    out: []u8,
    our_parameters: []u8,
    our_parameters_len: u32 = 0,
    peer_parameters: []u8,
    peer_parameters_len: u32 = 0,
    alpn: []u8,
    alpn_len: u8 = 0,
    /// Our one extension, pointing at `our_parameters`. The core borrows this
    /// slice until it composes the message that carries it.
    our_extra: [1]tls.extension_type.ExtraExtension = undefined,
    /// What the ClientHello offers. Borrowed from `Config`, which the caller
    /// keeps alive for the driver's lifetime, as the core's ALPN slices are.
    server_name: ?[]const u8 = null,
    offer_alpn: []const []const u8 = &.{},
    /// The 32 fresh bytes this handshake's ClientHello or ServerHello carries
    /// (RFC 8446 §4.1.2). The caller owns entropy the way it owns the clock:
    /// the platform CSPRNG is I/O, so it is read outside this package. The same
    /// bytes in two handshakes is a repeated Hello random, which RFC 8446
    /// §4.1.2 forbids.
    random: [32]u8,
    server_hello: []u8,
    extension_slots: []tls.extension_type.ExtraExtension,
    /// The first message is composed on the first `next()`, after the machine
    /// has handed over this endpoint's transport parameters (§8.2 of RFC 9001).
    first_composed: bool = false,
    /// The client's Finished, composed once the server's arrives.
    finished_composed: bool = false,
    failed: bool = false,
    /// The transport error code for `failed`: `0x100 + alert`, or
    /// `0x100 + internal_error`.
    failure: u64 = crypto_error + internal_error,
    /// The alert description the peer sent, when one arrived.
    alert: ?u8 = null,

    const Engine = union(Role) {
        client: core.Client,
        server: core.Server,
    };

    const Stream = struct {
        buf: []u8,
        len: u32 = 0,
    };

    pub const allowed_extensions = [_]tls.extension_type.ExtraExtension{
        .{ .extension_type = transport_parameters_type, .data = &.{} },
    };

    pub fn init(storage: Storage, config: Config, random: [32]u8) Error!Tls {
        var self: Tls = .{
            .role = undefined,
            .engine = undefined,
            .keypairs = try tls.KeyPairs.init(tls.x25519.KeyPair.generate()),
            .credentials = null,
            .in = .{
                .{ .buf = storage.peer_bytes.initial },
                .{ .buf = storage.peer_bytes.handshake },
                .{ .buf = storage.peer_bytes.app },
            },
            .out = storage.out,
            .our_parameters = storage.our_parameters,
            .peer_parameters = storage.peer_parameters,
            .alpn = storage.alpn,
            .server_hello = storage.server_hello,
            .extension_slots = storage.extension_slots,
            .random = random,
        };

        switch (config) {
            .client => |client_config| {
                self.role = .client;
                var client = core.Client.init(storage.slots, client_config.policy);
                client.useKeypairs(self.keypairs);
                client.receiveExtensions(&allowed_extensions, storage.extension_slots);
                client.offerAlpn(client_config.alpn);
                // A client that was given credentials answers a
                // CertificateRequest; the core reads them at that moment.
                client.credentials = client_config.credentials;
                self.server_name = client_config.server_name;
                self.offer_alpn = client_config.alpn;
                // The encoder is the core's, so the ClientHello exists once:
                // it needs the transport parameters, which arrive before the
                // first `next`.
                self.engine = .{ .client = client };
            },
            .server => |server_config| {
                self.role = .server;
                var server = core.Server.init(storage.slots);
                server.useKeypairs(self.keypairs);
                server.usePeerShareStorage(storage.peer_shares);
                server.receiveExtensions(&allowed_extensions, storage.extension_slots);
                server.supportAlpn(server_config.alpn);
                if (server_config.client_policy) |policy| server.requireClientCertificate(policy);
                self.credentials = server_config.credentials;
                // A flight that does not fit is a caller bug with no partial
                // retry, so it is refused before the handshake starts rather
                // than discovered after half of it is queued.
                if (storage.out.len < server.flightBufferLen(server_config.credentials, longest(server_config.alpn))) {
                    return error.NoSpace;
                }
                self.engine = .{ .server = server };
            },
        }
        return self;
    }

    pub fn deinit(self: *Tls) void {
        switch (self.engine) {
            .client => |*client| client.deinit(),
            .server => |*server| server.deinit(),
        }
        self.keypairs.secureZero();
        self.* = undefined;
    }

    /// The seam's view of this driver, which the machine holds in `Conn.tls`.
    pub fn driver(self: *Tls) seam.Driver {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// The peer's transport parameters, or null until they arrive. Copied out
    /// of the message that carried them, so it outlives the handshake.
    pub fn peerTransportParameters(self: *const Tls) ?[]const u8 {
        if (self.peer_parameters_len == 0) return null;
        return self.peer_parameters[0..self.peer_parameters_len];
    }

    /// The ALPN protocol the handshake settled on, or null.
    pub fn selectedAlpn(self: *const Tls) ?[]const u8 {
        if (self.alpn_len == 0) return null;
        return self.alpn[0..self.alpn_len];
    }

    /// The transport error code for the failure, once `failed`.
    pub fn failureCode(self: *const Tls) u64 {
        return self.failure;
    }

    /// Whether the handshake completed. For a server that is its confirmation
    /// (§4.1.2 of RFC 9001); a client is confirmed by HANDSHAKE_DONE, which
    /// this driver cannot see.
    pub fn done(self: *const Tls) bool {
        return switch (self.engine) {
            .client => |*client| client.state == .connected,
            .server => |*server| server.state == .connected,
        };
    }

    const vtable: seam.VTable = .{
        .feed = feedBytes,
        .suite = suiteReported,
        .next = nextMessage,
        .secrets = secretsReported,
        .setTransportParameters = setParameters,
        .peerTransportParameters = peerParameters,
        .confirmed = isConfirmed,
        .alpn = alpnReported,
        .errorCode = errorReported,
    };

    fn feedBytes(ctx: *anyopaque, level: seam.Level, bytes: []const u8) seam.Error!void {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        if (self.failed) return error.HandshakeFailed;
        return self.absorb(level, bytes) catch |err| self.fail(err);
    }

    fn suiteReported(ctx: *anyopaque) seam.Suite {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        assert(self.role == .server or self.engine.client.selected != null);
        const suite = switch (self.engine) {
            // §4.1.3 of RFC 8446: the suite is the ServerHello's to choose, so
            // before it a client has none. The machine asks only where a secret
            // exists, and no secret exists before then.
            .client => |*client| client.selected orelse .aes_128_gcm_sha256,
            .server => |*server| switch (server.suite) {
                .buffering => unreachable,
                .sha256 => |arm| arm.aead,
                .sha384 => |arm| arm.aead,
            },
        };
        return switch (suite) {
            .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
            .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
            .aes_256_gcm_sha384 => .aes_256_gcm_sha384,
        };
    }

    fn nextMessage(ctx: *anyopaque) seam.Error!?seam.Message {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        if (self.failed) return error.HandshakeFailed;
        self.compose() catch |err| return self.fail(err);
        while (true) {
            const output = switch (self.engine) {
                .client => |*client| client.next(),
                .server => |*server| server.next(),
            } orelse return null;
            switch (output) {
                .message => |message| return .{
                    .level = seamLevel(message.level),
                    .bytes = message.bytes,
                },
                // Level transitions and key events are the record layer's
                // vocabulary. QUIC installs a space when the driver reports
                // secrets, which is the same moment, asked directly.
                .read_level, .write_level, .key_available, .alert, .done => continue,
            }
        }
    }

    fn secretsReported(ctx: *anyopaque, level: seam.Level) seam.Error!?seam.Secrets {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        if (self.failed) return null;
        const pair: ?core.HandshakeSecrets = switch (level) {
            // Initial keys come from the connection ID (§5.2 of RFC 9001).
            .initial => return null,
            .handshake => switch (self.engine) {
                .client => |*client| client.handshakeSecrets(),
                .server => |*server| server.handshakeSecrets(),
            },
            .app => switch (self.engine) {
                .client => |*client| client.applicationSecrets(),
                .server => |*server| server.applicationSecrets(),
            },
        };
        const secrets = pair orelse return null;
        return .{ .client = secrets.client[0..secrets.len], .server = secrets.server[0..secrets.len] };
    }

    fn setParameters(ctx: *anyopaque, bytes: []const u8) seam.Error!void {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        // The contract: they must be here before the first message leaves,
        // because they are inside it.
        if (self.first_composed) return error.UnexpectedCall;
        if (bytes.len > self.our_parameters.len) return error.NoSpace;
        @memcpy(self.our_parameters[0..bytes.len], bytes);
        self.our_parameters_len = @intCast(bytes.len);
        self.our_extra[0] = .{
            .extension_type = transport_parameters_type,
            .data = self.our_parameters[0..bytes.len],
        };
        if (self.engine == .server) self.engine.server.sendExtensions(&self.our_extra);
    }

    fn peerParameters(ctx: *anyopaque) seam.Error!?[]const u8 {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        return self.peerTransportParameters();
    }

    fn isConfirmed(ctx: *anyopaque) bool {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        // §4.1.2 of RFC 9001: a client's confirmation is a HANDSHAKE_DONE
        // frame, not anything TLS can see.
        return switch (self.engine) {
            .client => false,
            .server => |*server| server.state == .connected,
        };
    }

    fn alpnReported(ctx: *anyopaque) ?[]const u8 {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        return self.selectedAlpn();
    }

    fn errorReported(ctx: *anyopaque) u64 {
        const self: *Tls = @ptrCast(@alignCast(ctx));
        return self.failure;
    }

    /// Append the peer's bytes at a level and hand every complete message to
    /// the core.
    fn absorb(self: *Tls, level: seam.Level, bytes: []const u8) Error!void {
        const stream = &self.in[@backingInt(level)];
        if (@as(usize, stream.len) + bytes.len > stream.buf.len) return error.NoSpace;
        @memcpy(stream.buf[stream.len..][0..bytes.len], bytes);
        stream.len += @intCast(bytes.len);
        // A server's ClientHello is composed into its own answer, which needs
        // the transport parameters `next()` is called with. The bytes wait.
        if (self.role == .server and level == .initial) return;
        return self.drain(level);
    }

    /// Split one level's stream into handshake messages (RFC 8446 §4) and
    /// dispatch each. A partial message stays for the next call.
    fn drain(self: *Tls, level: seam.Level) Error!void {
        const stream = &self.in[@backingInt(level)];
        while (stream.len != 0) {
            // A TLS alert is exactly two bytes of CRYPTO data (RFC 9001 §6).
            // No handshake message is that short, so a two-byte buffer whose
            // first byte is an alert level is one; a sender that split a real
            // message after two bytes would be indistinguishable, and no
            // implementation splits there.
            if (stream.len == 2 and (stream.buf[0] == 1 or stream.buf[0] == 2)) {
                return self.receiveAlert(stream.buf[0..2]);
            }
            if (stream.len < 4) return;
            const body: u32 = (@as(u32, stream.buf[1]) << 16) |
                (@as(u32, stream.buf[2]) << 8) |
                @as(u32, stream.buf[3]);
            const length = 4 + body;
            if (stream.len < length) return;
            try self.receive(level, stream.buf[0..length]);
            const rest = stream.len - length;
            @memmove(stream.buf[0..rest], stream.buf[length..stream.len]);
            stream.len = rest;
        }
    }

    fn receive(self: *Tls, level: seam.Level, message: []const u8) Error!void {
        switch (self.engine) {
            .client => |*client| switch (level) {
                .initial => try client.provide(.plaintext, message),
                .handshake => try client.provideHandshake(.handshake, message),
                .app => try client.provideApplication(.application, message),
            },
            .server => |*server| switch (level) {
                .initial => unreachable, // deferred to `next`, see `absorb`
                .handshake => try server.provideClientFlight(.handshake, message),
                // A server has no post-handshake messages to receive: tickets
                // and key updates are out of scope, and the core has no entry
                // point for them.
                .app => return error.HandshakeFailed,
            },
        }
        try self.capturePeer();
    }

    /// A peer alert turns into the connection's close code and nothing else.
    fn receiveAlert(self: *Tls, bytes: []const u8) Error!void {
        // The core's `provideAlert` refuses any level but the record layer's
        // post-handshake state, and its server has no entry point at all, so
        // the description byte is read here. RFC 8446 §6: level, description.
        self.alert = bytes[1];
        self.failed = true;
        self.failure = crypto_error + bytes[1];
        return error.HandshakeFailed;
    }

    /// Copy out what the core keeps borrowed: the peer's transport parameters
    /// and the selected ALPN, both slices into the message that carried them.
    fn capturePeer(self: *Tls) Error!void {
        const extensions = switch (self.engine) {
            .client => |*client| client.peerExtensions(),
            .server => |*server| server.peerExtensions(),
        };
        for (extensions) |extra| {
            if (extra.extension_type != transport_parameters_type) continue;
            // Captured once: the sink's slices borrow the message that carried
            // them, so a second visit reads whatever that buffer holds now.
            if (self.peer_parameters_len != 0) break;
            if (extra.data.len > self.peer_parameters.len) return error.NoSpace;
            @memcpy(self.peer_parameters[0..extra.data.len], extra.data);
            self.peer_parameters_len = @intCast(extra.data.len);
        }
        const protocol = switch (self.engine) {
            .client => |*client| client.selectedAlpn(),
            .server => |*server| server.selectedAlpn(),
        };
        // Once: `selected_alpn` borrows the EncryptedExtensions (RFC 7301 §3.2),
        // and a later message has overwritten those bytes.
        if (protocol) |name| {
            if (self.alpn_len != 0) return;
            if (name.len > self.alpn.len) return error.NoSpace;
            @memcpy(self.alpn[0..name.len], name);
            self.alpn_len = @intCast(name.len);
        }
    }

    /// Compose whatever the core cannot compose alone, in the order the
    /// handshake needs it.
    fn compose(self: *Tls) anyerror!void {
        switch (self.engine) {
            .client => |*client| {
                if (!self.first_composed) {
                    try self.composeClientHello(client);
                    self.first_composed = true;
                }
                // The core derives the application secrets at the end of this
                // call (§7.1 of RFC 8446), so a caller that installs the 1-RTT
                // space after the Finished is fed gets them.
                if (client.state == .server_finished_verified and !self.finished_composed) {
                    _ = try client.sendClientFinished(self.out);
                    self.finished_composed = true;
                }
            },
            .server => |*server| {
                if (server.state != .wait_client_hello) return;
                const stream = &self.in[@backingInt(seam.Level.initial)];
                const hello = firstMessage(stream) orelse return;
                try self.composeServerFirst(server, hello);
                assert(stream.len == hello.len);
                stream.len = 0;
            },
        }
    }

    fn composeClientHello(self: *Tls, client: *core.Client) anyerror!void {
        const config = switch (self.our_parameters_len) {
            0 => return error.UnexpectedCall,
            else => &self.our_extra,
        };
        _ = try client.startEncoded(
            self.out,
            .init(self.random),
            self.keypairs,
            self.server_name,
            self.offer_alpn,
            config,
        );
    }

    fn composeServerFirst(self: *Tls, server: *core.Server, hello: []const u8) anyerror!void {
        const parsed = try tls.client_hello.parse(hello);
        const suite = preferredSuite(parsed.cipher_suites) orelse return error.HandshakeFailed;
        const share = serverShare(parsed, self.keypairs) orelse return error.HandshakeFailed;
        const server_hello = try tls.server_hello.encodeWithKeyShare(
            self.server_hello,
            self.random,
            parsed.legacy_session_id,
            suite,
            &share,
        );
        try server.provide(.plaintext, hello, suite, server_hello);
        // The client's parameters borrow the ClientHello, which is about to be
        // dropped from the reassembly buffer.
        try self.capturePeer();
        try server.sendFlight(self.credentials.?, null, self.out);
    }

    fn fail(self: *Tls, err: anyerror) seam.Error {
        self.failed = true;
        self.failure = if (self.alert) |description|
            crypto_error + description
        else
            crypto_error + internal_error;
        // A caller-owned buffer that is too small is the caller's error, and
        // the machine names it; everything else is a failed handshake.
        return if (err == error.NoSpace) error.NoSpace else error.HandshakeFailed;
    }
};

fn seamLevel(level: tls.level.Level) seam.Level {
    return switch (level) {
        .plaintext => .initial,
        .handshake => .handshake,
        .application => .app,
        // This driver never asks for early data, so the core never queues any.
        .early => unreachable,
    };
}

/// The first whole handshake message in a level's stream, if there is one.
fn firstMessage(stream: *const Tls.Stream) ?[]const u8 {
    if (stream.len < 4) return null;
    const body: u32 = (@as(u32, stream.buf[1]) << 16) |
        (@as(u32, stream.buf[2]) << 8) |
        @as(u32, stream.buf[3]);
    if (stream.len < 4 + body) return null;
    return stream.buf[0 .. 4 + body];
}

/// The suite this server picks from the client's list. Both entries are suites
/// this package can protect packets with, and the order is this package's
/// preference, not the client's.
fn preferredSuite(offered: []const u8) ?tls.CipherSuite {
    const preference = [_]tls.CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
    for (preference) |suite| {
        const code: u16 = @backingInt(suite);
        var index: usize = 0;
        while (index + 1 < offered.len) : (index += 2) {
            const candidate = (@as(u16, offered[index]) << 8) | offered[index + 1];
            if (candidate == code) return suite;
        }
    }
    return null;
}

/// The key share to answer with: the first group the client sent a share for
/// that this endpoint has keypairs for.
fn serverShare(parsed: tls.client_hello.Parsed, keypairs: tls.KeyPairs) ?tls.server_hello.KeyShare {
    if (parsed.public_key != null) return .{ .x25519 = keypairs.x25519.public_key };
    if (parsed.public_key_p256 != null) return .{ .secp256r1 = keypairs.p256.public_key };
    if (parsed.public_key_p384 != null) {
        const pair = keypairs.p384 orelse return null;
        return .{ .secp384r1 = pair.public_key };
    }
    return null;
}

fn longest(protocols: []const []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    for (protocols) |protocol| {
        if (found == null or protocol.len > found.?.len) found = protocol;
    }
    return found;
}

// -- Tests -------------------------------------------------------------------
//
// The seam's own contract is tested in `handshake.zig`; these are the parts
// that only exist because this driver does: framing, the alert mapping, the
// order of the first message, and the two copies.

const test_random: [32]u8 = @splat(0xa5);

const test_storage = struct {
    var slots: [16]tls.level.Output = undefined;
    var out: [4096]u8 = undefined;
    var initial: [2048]u8 = undefined;
    var handshake: [4096]u8 = undefined;
    var app: [256]u8 = undefined;
    var peer_shares: [core.peer_share_storage_len]u8 = undefined;
    var extension_slots: [1]tls.extension_type.ExtraExtension = undefined;
    var our_parameters: [512]u8 = undefined;
    var peer_parameters: [512]u8 = undefined;
    var alpn: [64]u8 = undefined;
    var server_hello: [256]u8 = undefined;

    fn storage() Storage {
        return .{
            .slots = &slots,
            .out = &out,
            .peer_bytes = .{ .initial = &initial, .handshake = &handshake, .app = &app },
            .peer_shares = &peer_shares,
            .extension_slots = &extension_slots,
            .our_parameters = &our_parameters,
            .peer_parameters = &peer_parameters,
            .alpn = &alpn,
            .server_hello = &server_hello,
        };
    }
};

test "RFC 9000 §20.1, a peer alert becomes a CRYPTO_ERROR code" {
    const storage = test_storage.storage();
    var driver = try Tls.init(storage, .{ .client = .{ .policy = .init } }, test_random);
    defer driver.deinit();
    const seam_driver = driver.driver();

    // handshake_failure (40), fatal. RFC 8446 §6.
    try testing.expectError(
        error.HandshakeFailed,
        seam_driver.feed(.initial, &.{ 2, 40 }),
    );
    try testing.expectEqual(@as(u64, 0x100 + 40), seam_driver.errorCode());
}

test "RFC 8446 §4, a message split across CRYPTO frames is put back together" {
    const storage = test_storage.storage();
    var driver = try Tls.init(storage, .{ .client = .{ .policy = .init } }, test_random);
    defer driver.deinit();
    const seam_driver = driver.driver();

    // A ServerHello header and a truncated body. The driver must not hand the
    // core half a message: a partial read that moves the state is how a
    // handshake ends up retrying from the middle.
    try seam_driver.feed(.initial, &.{ 2, 0, 0 });
    try testing.expectEqual(@as(u32, 3), driver.in[0].len);
    try seam_driver.feed(.initial, &.{0x20});
    try testing.expectEqual(@as(u32, 4), driver.in[0].len);
}

test "RFC 9001 §8.2, transport parameters are refused after the first message" {
    const storage = test_storage.storage();
    var driver = try Tls.init(storage, .{ .client = .{ .policy = .init } }, test_random);
    defer driver.deinit();
    const seam_driver = driver.driver();

    try seam_driver.setTransportParameters("parameters");
    try testing.expectEqualStrings("parameters", driver.our_parameters[0..driver.our_parameters_len]);

    // Composing the ClientHello is what puts them on the wire.
    driver.first_composed = true;
    try testing.expectError(error.UnexpectedCall, seam_driver.setTransportParameters("too late"));
}

test "RFC 8446 §B.4, the server prefers the suite it can protect with" {
    // aes_128_gcm_sha256 (0x1301) and aes_256_gcm_sha384 (0x1302) offered, and
    // chacha20_poly1305_sha256 (0x1303) too: the first is the server's choice.
    const offered = [_]u8{ 0x13, 0x02, 0x13, 0x03, 0x13, 0x01 };
    try testing.expectEqual(tls.CipherSuite.aes_128_gcm_sha256, preferredSuite(&offered).?);

    // Only a suite this package cannot protect with: refused by name.
    const ccm = [_]u8{ 0x13, 0x04 };
    try testing.expect(preferredSuite(&ccm) == null);
}
