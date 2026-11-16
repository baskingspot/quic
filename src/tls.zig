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
//! messages' random fields and the ephemeral keypairs. `Storage(limits)` owns
//! those buffers, sized from four numbers (`Limits`), and the engine with them.
//! A caller that would rather not hold the handshake's flight buffers for a
//! connection's whole life keeps `Fixed(limits)` and hands `Fixed.start` a
//! `Flight` of `Flight.lengths`, from wherever it likes.

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
        credentials: ?Credentials = null,
    },
    server: struct {
        credentials: Credentials,
        alpn: []const []const u8 = &.{},
        /// Asks the client for a certificate under this policy. Null means the
        /// server never asks.
        client_policy: ?tls.certificate.Policy = null,
    },
};

/// Every buffer the driver writes into, as slices. `Storage(limits)` owns them
/// and works the sizes out; this is what `Tls.init` takes for a caller that
/// sizes each one itself. A buffer too small for the job is `error.NoSpace` at
/// the moment of use, never a truncation.
pub const Buffers = struct {
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

pub const Credentials = core.Credentials;

/// Why `Storage.credentials`, `Fixed.decodeChain`, or `Fixed.loadKey` refused
/// a certificate or key.
pub const LoadError = error{
    /// The chain decodes to more than `Limits.chain` DER bytes, or to more
    /// than the buffer it was handed, or has more than `max_certificates`
    /// certificates.
    NoSpace,
    /// No certificate in the PEM, or one that does not decode.
    InvalidCertificate,
    /// The PEM holds no private key this backend can sign with.
    InvalidKey,
};

/// How a client decides whether to believe the server's certificate. There is
/// no default, so no caller compiles a client that verifies nothing by
/// omission.
pub const Trust = union(enum) {
    /// Accept a chain that leads to no trust anchor. The server must still
    /// prove it holds the leaf's key, so this authenticates nothing about who
    /// it is: for self-signed demo and test certificates only.
    insecure,
    /// Verify the chain under this policy: anchors, host name, and time.
    verify: tls.certificate.Policy,

    pub fn policy(self: Trust) tls.certificate.Policy {
        return switch (self) {
            .insecure => policy: {
                var insecure: tls.certificate.Policy = .init;
                insecure.insecure_no_chain_anchor = true;
                break :policy insecure;
            },
            .verify => |verify| verify,
        };
    }
};

/// The four numbers a caller chooses: what has to be bounded before any
/// certificate exists, because the peer decides it. Every buffer the driver
/// needs follows from them and from this endpoint's own certificate
/// (`Fixed`, `Flight.lengths`). Each is checked where it is used: a handshake
/// that exceeds one fails with `error.NoSpace`, never a truncation.
pub const Limits = struct {
    /// The longest certificate chain, in DER bytes summed over its
    /// certificates, that the peer's flight may carry: it sizes the buffer the
    /// peer's Handshake-level messages are reassembled in (`Flight.lengths`),
    /// with the framing TLS adds and the flight's other messages at their
    /// longest allowed for on top. This endpoint's own chain is held to it
    /// too, and is stored in as many bytes as it decodes to.
    chain: u32 = 4096,
    /// The longest ALPN protocol name, in bytes, offered or selected.
    alpn: u8 = 32,
    /// The longest transport parameters, in bytes, this endpoint sends or
    /// accepts from the peer. They ride inside the hellos, so this also sizes
    /// the largest hello.
    parameters: u32 = 512,
    /// The longest message the peer may send after the handshake, in bytes: a
    /// client's NewSessionTicket is the one that is not small.
    post_handshake: u32 = 512,
};

/// The core's queue of outputs: a server's flight is four messages and three
/// level transitions, and the queue is drained between flights. The core
/// offers no bound of its own to derive this from, so it is twice what the
/// longest flight queues.
const output_slots = 16;

/// Certificates in a chain whose framing `Limits.chain` allows for. A chain of
/// more is `error.NoSpace` when loaded.
const max_certificates = 8;

/// Signature schemes a CertificateRequest may list; the core builds it from
/// the crypto backend's list, which is smaller. Pinned by a test against the
/// core's own `flightBufferLen`.
const max_signature_schemes = 16;

/// The largest key share in a ClientHello: an RFC 10024 hybrid, which is what
/// tls's `hybrid_kex.max_client_share_len` bounds (it does not export it).
const hybrid_share_len = 1665;

/// What a ClientHello carries beside the key share and the transport
/// parameters: the classical shares (194 bytes), a server name (up to 253),
/// the supported groups and signature schemes, and the ALPN list.
const hello_slack = 1024;

/// §4.1.3 of RFC 8446's ServerHello, at its longest: the 76 bytes of header,
/// session id echo (32), and extension lengths, the supported_versions
/// extension (6), and a key_share with a P-384 public key (97, the largest
/// classical share) in 105.
const server_hello_len = 76 + 6 + 105;

/// The largest ClientHello either side handles, which the server holds whole
/// until it answers.
fn helloLen(limits: Limits) usize {
    return hybrid_share_len + hello_slack + limits.parameters;
}

/// The largest flight of handshake messages at one level carrying a chain of
/// `chain` DER bytes, mirroring the bound `core.Server.flightBufferLen` demands
/// of a server's buffer once the transport parameters are set: the
/// EncryptedExtensions with the ALPN name and the transport parameters
/// extension (RFC 9001 §8.2), a CertificateRequest, the Certificate, a
/// CertificateVerify sized for an RSA-4096 signature, and the Finished.
fn flightLen(limits: Limits, chain: u32) usize {
    const encrypted_extensions = 4 + 2 + (4 + 2 + 1 + @as(usize, limits.alpn)) + (4 + @as(usize, limits.parameters));
    const certificate_request = 4 + 1 + 2 + 2 + 2 + 2 + 2 * max_signature_schemes;
    const certificate = 4 + 1 + 3 + (3 + 2) * max_certificates + @as(usize, chain);
    const certificate_verify = 4 + 2 + 1 + 2 + 512;
    const finished = 36;
    return encrypted_extensions + certificate_request + certificate + certificate_verify + finished;
}

/// The buffers only the handshake needs, which hold its flights: where the
/// driver composes this endpoint's (`out`, and a server's `server_hello`), and
/// where it reassembles the peer's at the Initial and Handshake levels (§19.6
/// of RFC 9000). `Storage(limits)` holds them inline at their largest; a
/// caller that takes them from an allocator takes `Flight.lengths` of each,
/// which for a server follows from the certificate it actually loaded.
pub const Flight = struct {
    out: []u8,
    peer_initial: []u8,
    peer_handshake: []u8,
    /// Empty for a client.
    server_hello: []u8,

    pub const empty: Flight = .{ .out = &.{}, .peer_initial = &.{}, .peer_handshake = &.{}, .server_hello = &.{} };

    pub const Lengths = struct {
        out: usize,
        peer_initial: usize,
        peer_handshake: usize,
        server_hello: usize,

        pub fn total(self: Lengths) usize {
            return self.out + self.peer_initial + self.peer_handshake + self.server_hello;
        }
    };

    /// What each buffer must hold for `role` under `limits`, when this
    /// endpoint's own chain decodes to `chain` DER bytes: zero for a client
    /// that does not authenticate.
    ///
    /// - `out`: a server's whole flight with that chain, or a client's
    ///   ClientHello, or its own Certificate flight when it has one.
    /// - `peer_initial`: the peer's ClientHello or ServerHello, at the longest
    ///   ClientHello these limits allow.
    /// - `peer_handshake`: the peer's flight with a chain of `limits.chain`.
    /// - `server_hello`: a server's ServerHello.
    pub fn lengths(limits: Limits, role: Role, chain: u32) Lengths {
        assert(chain <= limits.chain);
        const own = flightLen(limits, chain);
        return .{
            .out = switch (role) {
                .server => own,
                .client => if (chain == 0) helloLen(limits) else @max(helloLen(limits), own),
            },
            .peer_initial = helloLen(limits),
            .peer_handshake = flightLen(limits, limits.chain),
            .server_hello = switch (role) {
                .server => server_hello_len,
                .client => 0,
            },
        };
    }
};

/// The part of a TLS driver's storage the limits fix before any certificate
/// exists: the engine, the core's output queue, the post-handshake
/// reassembly, both ends' transport parameters, the ALPN name, the chain's
/// slots, and the key. The handshake's flights are a `Flight` handed to
/// `start`, and a server's chain bytes the buffer handed to `decodeChain`;
/// both must outlive the driver.
///
/// Built in place and never moved: the engine, and the machine holding its
/// driver, point into this struct. A caller reads `engine`; every other field
/// is the engine's backing.
pub fn Fixed(comptime limits: Limits) type {
    comptime {
        assert(limits.chain > 0);
        assert(limits.alpn > 0);
        assert(limits.parameters > 0);
        // A handshake message has a four-byte header.
        assert(limits.post_handshake >= 4);
    }

    return struct {
        const Self = @This();

        engine: Tls,
        slots: [output_slots]tls.level.Output,
        peer_app: [limits.post_handshake]u8,
        peer_shares: [core.peer_share_storage_len]u8,
        extension_slots: [1]tls.extension_type.ExtraExtension,
        our_parameters: [limits.parameters]u8,
        peer_parameters: [limits.parameters]u8,
        selected_alpn: [limits.alpn]u8,
        chain_slots: [max_certificates][]const u8,
        /// How many of `chain_slots` the decoded chain fills.
        chain_count: u8,
        /// Loaded by `loadKey`, freed by `deinit`.
        key: ?tls.signature.PrivateKey,
        running: bool,

        /// Put the storage in its empty state: no chain or key loaded, no
        /// engine running. `deinit` is safe from here on.
        pub fn init(self: *Self) void {
            self.chain_count = 0;
            self.key = null;
            self.running = false;
        }

        /// Decode a PEM certificate chain into `der`, which it borrows until
        /// `deinit`. Returns how many DER bytes it took: the chain is
        /// `der[0..n]`, and a caller that took `der` from an allocator may
        /// shrink it to that. A chain that does not fit `der` is
        /// `error.NoSpace`, and `der` is never longer than `Limits.chain`, so
        /// neither is a chain. Decoding again replaces the chain.
        pub fn decodeChain(self: *Self, der: []u8, certificate_pem: []const u8) LoadError!u32 {
            assert(der.len <= limits.chain);
            assert(!self.running);
            self.chain_count = 0;
            const chain = tls.certificate_chain.CertificateChain.fromPem(
                certificate_pem,
                der,
                &self.chain_slots,
            ) catch |err| return switch (err) {
                error.CertificateBufferTooShort, error.CertificateChainTooLong => error.NoSpace,
                error.NoCertificate,
                error.MissingCertificateEnd,
                error.InvalidCertificateEncoding,
                => error.InvalidCertificate,
            };
            const certificates = chain.slice;
            var length: u32 = 0;
            for (certificates) |certificate| {
                // `fromPem` decodes each certificate right after the last.
                assert(certificate.ptr == der.ptr + length);
                length += @intCast(certificate.len);
            }
            self.chain_count = @intCast(certificates.len);
            return length;
        }

        /// Decode the PEM private key for the chain's leaf. It is kept until
        /// `deinit`.
        pub fn loadKey(self: *Self, key_pem: []const u8) LoadError!void {
            assert(self.key == null);
            self.key = tls.signature.PrivateKey.fromPemAuto(key_pem) catch return error.InvalidKey;
        }

        /// The decoded chain and the loaded key, for a `Config.server`.
        pub fn credentials(self: *Self) Credentials {
            assert(self.chain_count > 0);
            return .{
                .chain = .init(self.chain_slots[0..self.chain_count]),
                .signer = self.key.?.signer(),
            };
        }

        /// Build the engine over `flight` and return its driver. `config` is
        /// borrowed for the driver's lifetime: its ALPN names, server name, and
        /// credentials must outlive it, as must `flight`. A protocol name
        /// longer than `Limits.alpn`, or a `flight` shorter than
        /// `Flight.lengths` asks, is `error.NoSpace` here or at the moment of
        /// use, never a truncation. `random` is the platform's entropy, never
        /// a constant: it is the Hello random, and a repeat is forbidden (RFC
        /// 8446 §4.1.2).
        pub fn start(self: *Self, flight: Flight, config: Config, random: [32]u8) Error!seam.Driver {
            assert(!self.running);
            const names = switch (config) {
                inline else => |role| role.alpn,
            };
            for (names) |name| {
                if (name.len > limits.alpn) return error.NoSpace;
            }
            self.engine = try .init(.{
                .slots = &self.slots,
                .out = flight.out,
                .peer_bytes = .{
                    .initial = flight.peer_initial,
                    .handshake = flight.peer_handshake,
                    .app = &self.peer_app,
                },
                .peer_shares = &self.peer_shares,
                .extension_slots = &self.extension_slots,
                .our_parameters = &self.our_parameters,
                .peer_parameters = &self.peer_parameters,
                .alpn = &self.selected_alpn,
                .server_hello = flight.server_hello,
            }, config, random);
            self.running = true;
            return self.engine.driver();
        }

        /// Zero the secrets and free the key. Safe after `init`, whether or not
        /// `start` or `loadKey` ran.
        pub fn deinit(self: *Self) void {
            if (self.running) self.engine.deinit();
            if (self.key) |*key| key.deinit();
            self.chain_count = 0;
            self.key = null;
            self.running = false;
        }
    };
}

/// A TLS driver and every buffer it writes into, computed from `limits` and
/// owned in place: `Fixed(limits)`, and its flights and chain at their
/// largest, so no allocator is involved. A caller writes
///
///     var storage: Storage(.{}) = undefined;
///     storage.init();
///     defer storage.deinit();
///     const handshake = try storage.start(config, random);
///
/// and hands `handshake` to a machine. Built in place and never moved: the
/// engine, and the machine holding its driver, point into this struct.
///
/// A caller reads `fixed.engine` (the handshake's outcome: `selectedAlpn`,
/// `peerTransportParameters`, `done`). Every other field is the engine's
/// backing, or what the loaded credentials point into, and is not the
/// caller's.
pub fn Storage(comptime limits: Limits) type {
    // One storage serves either role, so each buffer is the larger role's, with
    // this endpoint's own chain as long as the limits allow.
    const server = Flight.lengths(limits, .server, limits.chain);
    const client = Flight.lengths(limits, .client, limits.chain);
    comptime {
        assert(server.peer_initial == client.peer_initial);
        assert(server.peer_handshake == client.peer_handshake);
    }

    return struct {
        const Self = @This();

        fixed: Fixed(limits),
        out: [@max(server.out, client.out)]u8,
        peer_initial: [server.peer_initial]u8,
        peer_handshake: [server.peer_handshake]u8,
        server_hello: [server.server_hello]u8,
        chain_der: [limits.chain]u8,

        /// Put the storage in its empty state. `deinit` is safe from here on.
        pub fn init(self: *Self) void {
            self.fixed.init();
        }

        /// Decode a PEM certificate chain and private key into this storage,
        /// for a `Config.server`. The PEM bytes are not kept; the key is, until
        /// `deinit`.
        pub fn credentials(self: *Self, certificate_pem: []const u8, key_pem: []const u8) LoadError!Credentials {
            _ = try self.fixed.decodeChain(&self.chain_der, certificate_pem);
            try self.fixed.loadKey(key_pem);
            return self.fixed.credentials();
        }

        /// `Fixed.start`, over this storage's flight buffers.
        pub fn start(self: *Self, config: Config, random: [32]u8) Error!seam.Driver {
            return self.fixed.start(.{
                .out = &self.out,
                .peer_initial = &self.peer_initial,
                .peer_handshake = &self.peer_handshake,
                .server_hello = &self.server_hello,
            }, config, random);
        }

        /// Zero the secrets and free the key. Safe after `init`, whether or not
        /// `start` or `credentials` ran.
        pub fn deinit(self: *Self) void {
            self.fixed.deinit();
        }
    };
}

pub const Tls = struct {
    role: Role,
    engine: Engine,
    keypairs: tls.KeyPairs,
    /// The server's certificates and signer. Null for a client.
    credentials: ?Credentials,
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
    /// The traffic secrets the last `secrets` call reported, one pair per
    /// level. The seam lets a driver hand back borrowed bytes and promises they
    /// stay valid until the next call, so the bytes live here: the core returns
    /// its secrets by value, and a slice into that value is dead the moment the
    /// call returns. It reads as working code on a target whose stack happens
    /// not to be reused yet, and as an authentication failure everywhere else.
    handshake_secrets: SecretPair = .{},
    app_secrets: SecretPair = .{},

    const Engine = union(Role) {
        client: core.Client,
        server: core.Server,
    };

    const Stream = struct {
        buf: []u8,
        len: u32 = 0,
    };

    /// One level's secrets, own storage, with the length the suite's hash
    /// gives them (32 for SHA-256, 48 for SHA-384).
    const SecretPair = struct {
        client: [48]u8 = undefined,
        server: [48]u8 = undefined,
        len: u8 = 0,

        fn take(self: *SecretPair, pair: core.HandshakeSecrets) seam.Secrets {
            @memcpy(self.client[0..pair.len], pair.client[0..pair.len]);
            @memcpy(self.server[0..pair.len], pair.server[0..pair.len]);
            self.len = pair.len;
            return .{ .client = self.client[0..pair.len], .server = self.server[0..pair.len] };
        }

        fn zero(self: *SecretPair) void {
            std.crypto.secureZero(u8, &self.client);
            std.crypto.secureZero(u8, &self.server);
            self.len = 0;
        }
    };

    pub const allowed_extensions = [_]tls.extension_type.ExtraExtension{
        .{ .extension_type = transport_parameters_type, .data = &.{} },
    };

    pub fn init(storage: Buffers, config: Config, random: [32]u8) Error!Tls {
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
        self.handshake_secrets.zero();
        self.app_secrets.zero();
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
        // The core returns its secrets by value; copying them here is what makes
        // the returned slices outlive this call, as the seam requires.
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
        const storage = switch (level) {
            .initial => unreachable,
            .handshake => &self.handshake_secrets,
            .app => &self.app_secrets,
        };
        return storage.take(secrets);
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
        // the machine names it, whether this driver found it (`NoSpace`) or
        // tls's encoder did (`BufferTooShort`); everything else is a failed
        // handshake.
        const too_small = err == error.NoSpace or err == error.BufferTooShort;
        return if (too_small) error.NoSpace else error.HandshakeFailed;
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

    fn storage() Buffers {
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

// -- Storage -----------------------------------------------------------------
//
// What `Storage(limits)` derives, and what it does at the edge of its limits.
// The certificate and key are the loopback fixtures, the way
// tests/tls_loopback.zig gets them.

const fixture = struct {
    const certificate = @embedFile("tls_server_crt");
    const key = @embedFile("tls_server_key");
    /// The fixture's one certificate, DER, which is the smallest `Limits.chain`
    /// that holds it.
    const certificate_der = 411;
};

/// Move handshake bytes between two drivers, flight by flight, until neither
/// has more to say.
fn exchange(client: seam.Driver, server: seam.Driver) seam.Error!void {
    while (try carry(client, server) or try carry(server, client)) {}
}

/// Everything `from` has queued, fed to `to`. Whether there was any.
fn carry(from: seam.Driver, to: seam.Driver) seam.Error!bool {
    var moved = false;
    while (try from.next()) |message| {
        try to.feed(message.level, message.bytes);
        moved = true;
    }
    return moved;
}

test "RFC 9001 §4, a Storage of the smallest limits that hold the fixture completes a handshake" {
    const smallest: Limits = .{
        .chain = fixture.certificate_der,
        .alpn = 2,
        .parameters = 64,
        .post_handshake = 4,
    };
    const insecure: Trust = .insecure;
    var client: Storage(smallest) = undefined;
    var server: Storage(smallest) = undefined;
    client.init();
    defer client.deinit();
    server.init();
    defer server.deinit();

    const credentials = try server.credentials(fixture.certificate, fixture.key);
    const server_driver = try server.start(.{ .server = .{
        .credentials = credentials,
        .alpn = &.{"h3"},
    } }, @splat(0x22));
    // A server name at the longest §3 of RFC 6066 allows, and parameters at
    // the limit: the ClientHello is as large as these limits let it be.
    const name: [tls.client_hello.max_server_name_len]u8 = @splat('a');
    const client_driver = try client.start(.{ .client = .{
        .policy = insecure.policy(),
        .server_name = &name,
        .alpn = &.{"h3"},
    } }, @splat(0x11));

    const client_parameters: [smallest.parameters]u8 = @splat(0xc1);
    const server_parameters: [smallest.parameters]u8 = @splat(0x5e);
    try client_driver.setTransportParameters(&client_parameters);
    try server_driver.setTransportParameters(&server_parameters);
    try exchange(client_driver, server_driver);

    try testing.expect(client.fixed.engine.done());
    try testing.expect(server.fixed.engine.done());
    try testing.expectEqualStrings("h3", client.fixed.engine.selectedAlpn().?);
    try testing.expectEqualStrings("h3", server.fixed.engine.selectedAlpn().?);
    try testing.expectEqualSlices(u8, &client_parameters, server.fixed.engine.peerTransportParameters().?);
    try testing.expectEqualSlices(u8, &server_parameters, client.fixed.engine.peerTransportParameters().?);
    try testing.expect(try client_driver.secrets(.app) != null);
    try testing.expect(try server_driver.secrets(.app) != null);
}

test "RFC 8446 §4, a handshake past its Storage limits fails with NoSpace, never a truncation" {
    const limits: Limits = .{ .chain = fixture.certificate_der, .alpn = 2, .parameters = 64 };

    // A chain one byte longer than the limit.
    var short_chain: Storage(.{ .chain = fixture.certificate_der - 1 }) = undefined;
    short_chain.init();
    defer short_chain.deinit();
    try testing.expectError(
        error.NoSpace,
        short_chain.credentials(fixture.certificate, fixture.key),
    );

    // A protocol name longer than the limit, before any byte moves.
    var narrow: Storage(limits) = undefined;
    narrow.init();
    defer narrow.deinit();
    try testing.expectError(
        error.NoSpace,
        narrow.start(.{ .client = .{ .policy = .init, .alpn = &.{"hq-interop"} } }, @splat(0)),
    );

    // Our own parameters, one byte over.
    const client_driver = try narrow.start(.{ .client = .{ .policy = .init, .alpn = &.{"h3"} } }, @splat(0));
    const over: [limits.parameters + 1]u8 = @splat(0);
    try testing.expectError(error.NoSpace, client_driver.setTransportParameters(&over));

    // The peer's parameters, one byte over: the client's `parameters` is 64,
    // and the server's, 128, lets it send 65.
    var wide: Storage(.{ .chain = fixture.certificate_der, .alpn = 2, .parameters = 128 }) = undefined;
    wide.init();
    defer wide.deinit();
    const credentials = try wide.credentials(fixture.certificate, fixture.key);
    const server_driver = try wide.start(.{ .server = .{
        .credentials = credentials,
        .alpn = &.{"h3"},
    } }, @splat(0x22));
    try server_driver.setTransportParameters(&over);
    try client_driver.setTransportParameters("client");
    try testing.expectError(error.NoSpace, exchange(client_driver, server_driver));
    // Nothing of them was kept.
    try testing.expectEqual(null, narrow.fixed.engine.peerTransportParameters());
}

test "RFC 8446 §4.4.2, a server flight longer than the client's limits is NoSpace, and none of it is taken" {
    // Three copies of the fixture make a chain of 1,233 DER bytes, which a
    // server whose limit is that loads, and a client whose limit is one
    // copy cannot reassemble: the Certificate message alone is longer than the
    // whole flight its limits allow for.
    const certificate = fixture.certificate ++ fixture.certificate ++ fixture.certificate;
    const client_limits: Limits = .{ .chain = fixture.certificate_der, .alpn = 2, .parameters = 64 };
    const insecure: Trust = .insecure;
    var client: Storage(client_limits) = undefined;
    var server: Storage(.{ .chain = 3 * fixture.certificate_der, .alpn = 2, .parameters = 64 }) = undefined;
    client.init();
    defer client.deinit();
    server.init();
    defer server.deinit();

    const credentials = try server.credentials(certificate, fixture.key);
    try testing.expectEqual(3, credentials.chain.slice.len);
    const server_driver = try server.start(.{ .server = .{
        .credentials = credentials,
        .alpn = &.{"h3"},
    } }, @splat(0x22));
    const client_driver = try client.start(.{ .client = .{
        .policy = insecure.policy(),
        .alpn = &.{"h3"},
    } }, @splat(0x11));
    try client_driver.setTransportParameters("client");
    try server_driver.setTransportParameters("server");

    try testing.expectError(error.NoSpace, exchange(client_driver, server_driver));
    // The handshake ends as a CRYPTO_ERROR (RFC 9001 §4.8), and the message
    // that did not fit was refused whole: not a byte of it is in the buffer.
    try testing.expectEqual(crypto_error + internal_error, client_driver.errorCode());
    try testing.expectEqual(0, client.fixed.engine.in[@backingInt(seam.Level.handshake)].len);
    try testing.expect(!client.fixed.engine.done());
}

// RFC 8446 §4.3.2, §4.4: the flight `Flight.lengths` allows for is the flight
// the core demands a server's buffer hold, at the limits' extremes, so a later
// tls that grows a message fails here and not in the field.
test "the flight Flight.lengths allows for bounds the core's flightBufferLen" {
    const limits: Limits = .{ .chain = 1000, .alpn = 7 };
    var der: [limits.chain]u8 = undefined;
    var certificates: [max_certificates][]const u8 = undefined;
    const each = limits.chain / max_certificates;
    for (&certificates, 0..) |*certificate, index| certificate.* = der[index * each ..][0..each];
    const credentials: Credentials = .{ .chain = .init(&certificates), .signer = undefined };

    var slots: [output_slots]tls.level.Output = undefined;
    var server: core.Server = .init(&slots);
    defer server.deinit();
    server.requireClientCertificate(.init);
    // RFC 9001 §8.2: the transport parameters ride in the EncryptedExtensions.
    const parameters: [limits.parameters]u8 = @splat(0);
    const extra = [_]tls.extension_type.ExtraExtension{
        .{ .extension_type = transport_parameters_type, .data = &parameters },
    };
    server.sendExtensions(&extra);
    const required = server.flightBufferLen(credentials, "1234567");
    try testing.expect(flightLen(limits, limits.chain) >= required);
}

// RFC 8446 §4.1.3: a ServerHello that echoes the longest session id and answers
// with the largest classical key share fits the buffer set aside for it.
test "server_hello_len holds the longest ServerHello this driver composes" {
    var out: [server_hello_len]u8 = undefined;
    const share: tls.server_hello.KeyShare = .{ .secp384r1 = (try tls.p384.KeyPair.generate()).public_key };
    const session_id: [32]u8 = @splat(0);
    const hello = try tls.server_hello.encodeWithKeyShare(&out, test_random, &session_id, .aes_128_gcm_sha256, &share);
    try testing.expectEqual(server_hello_len, hello.len);
}
