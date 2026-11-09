//! What the seam in `src/handshake.zig` asks of a TLS driver, checked against
//! the package that has to provide one.
//!
//! These are not tests of `baskingspot/tls`. They are the record of where the
//! two packages do not meet yet, written so the day a gap closes this file
//! fails and the driver work resumes instead of being forgotten. Each names the
//! RFC that forces the requirement, and `docs/slop/connection-machine.md` holds
//! the API this repository asked tls for.
//!
//! Developer-only, like the RFC 9001 vectors: the package a consumer fetches
//! does not carry this file. `just test` passes `-Dtls` to build it.

const std = @import("std");
const testing = std.testing;

const quic = @import("quic");
const tls = @import("tls");

/// A client handshake core stopped right where the server's EncryptedExtensions
/// has to land: ClientHello out, ServerHello absorbed, handshake keys derived.
///
/// Initialised in place because `Client` borrows `client_slots`.
const ClientAtEncryptedExtensions = struct {
    slots: [16]tls.level.Output = undefined,
    client: tls.handshake_core.Client = undefined,
    client_hello_buf: [1024]u8 = undefined,
    server_hello_buf: [256]u8 = undefined,
    client_keypair: tls.x25519.KeyPair = undefined,
    server_keypair: tls.x25519.KeyPair = undefined,
    shared: [32]u8 = undefined,

    fn init(self: *ClientAtEncryptedExtensions) !void {
        self.client_keypair = tls.x25519.KeyPair.generate();
        self.server_keypair = tls.x25519.KeyPair.generate();
        const p256_keypair = try tls.p256.KeyPair.generate();

        var policy: tls.certificate.Policy = .init;
        policy.insecure_no_chain_anchor = true;
        self.client = tls.handshake_core.Client.init(&self.slots, policy);

        // The client's own transport parameters, opaque to TLS (RFC 9001 §8.2).
        // Sending them works: this is the direction tls already carries.
        const our_parameters = [_]u8{ 0x01, 0x02, 0x03 };
        const client_hello = try tls.client_hello.encodeWithHybridGroupsAndExtensions(
            &self.client_hello_buf,
            .init(@splat(0x11)),
            self.client_keypair.public_key,
            p256_keypair.public_key,
            null,
            "localhost",
            &.{"h3"},
            &.{},
            null,
            &.{.{ .extension_type = 0x0039, .data = &our_parameters }},
        );
        try self.client.start(client_hello);
        _ = self.client.next();

        const server_hello = try tls.server_hello.encodeWithKeyShare(
            &self.server_hello_buf,
            @splat(0x22),
            &.{},
            .aes_128_gcm_sha256,
            &.{ .x25519 = self.server_keypair.public_key },
        );
        try tls.x25519.sharedSecret(
            self.client_keypair.secret_key,
            self.server_keypair.public_key,
            &self.shared,
        );
        try self.client.provide(.plaintext, server_hello, &self.shared);

        // The two level transitions and the key event that follow ServerHello.
        while (self.client.next()) |_| {}
    }
};

/// The seam's name for a suite tls negotiated. Exhaustive on purpose: tls
/// gaining a suite this package cannot name is a compile error here.
fn seamSuite(suite: tls.CipherSuite) quic.handshake.Suite {
    return switch (suite) {
        .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
        .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
        .aes_256_gcm_sha384 => .aes_256_gcm_sha384,
    };
}

// RFC 8446 §B.4 — three suites are wire code points, and the seam names all
// three. A suite this package cannot protect with is refused by name, never
// substituted.
test "RFC 8446 §B.4: tls's suites satisfy the seam's cipher suite vocabulary" {
    try testing.expectEqual(
        quic.handshake.Suite.aes_128_gcm_sha256,
        seamSuite(.aes_128_gcm_sha256),
    );
    try testing.expectEqual(
        quic.handshake.Suite.chacha20_poly1305_sha256,
        seamSuite(.chacha20_poly1305_sha256),
    );
    try testing.expectEqual(
        quic.handshake.Suite.aes_256_gcm_sha384,
        seamSuite(.aes_256_gcm_sha384),
    );

    try testing.expectEqual(
        quic.protection.Suite.aes_128_gcm,
        try seamSuite(.aes_128_gcm_sha256).protectionSuite(),
    );
    try testing.expectEqual(
        quic.protection.Suite.chacha20_poly1305,
        try seamSuite(.chacha20_poly1305_sha256).protectionSuite(),
    );
    // RFC 8446 §B.4 — TLS_AES_256_GCM_SHA384 needs SHA-384, which this package
    // does not implement. The refusal is the answer, not a quiet downgrade.
    try testing.expectError(
        error.UnsupportedCipherSuite,
        seamSuite(.aes_256_gcm_sha384).protectionSuite(),
    );
}

// RFC 9001 §8.2 — a QUIC client MUST read the server's quic_transport_parameters
// (extension 0x0039) from EncryptedExtensions. The step core passes the
// EncryptedExtensions parser no allowlist and no sink, so the extension every
// QUIC server is required to send fails the handshake here.
test "RFC 9001 §8.2: the client core refuses the server's transport parameters" {
    var peer: ClientAtEncryptedExtensions = .{};
    defer peer.client.deinit();
    try peer.init();

    // EncryptedExtensions carrying one extension: 0x0039 with two opaque bytes.
    const encrypted_extensions = [_]u8{
        0x08, 0x00, 0x00, 0x08, // handshake type, body length
        0x00, 0x06, // extensions length
        0x00, 0x39, 0x00, 0x02, 0xca, 0xfe, // quic_transport_parameters
    };
    try testing.expectError(
        error.UnsupportedExtension,
        peer.client.provideHandshake(.handshake, &encrypted_extensions),
    );
}

// RFC 8446 §4.3.1 — the control for the test above: an EncryptedExtensions with
// no extensions is accepted by the same core in the same state. The rejection
// is the transport parameters, not the message.
test "RFC 8446 §4.3.1: the same core accepts an EncryptedExtensions without them" {
    var peer: ClientAtEncryptedExtensions = .{};
    defer peer.client.deinit();
    try peer.init();

    const encrypted_extensions = [_]u8{
        0x08, 0x00, 0x00, 0x02, // handshake type, body length
        0x00, 0x00, // no extensions
    };
    try peer.client.provideHandshake(.handshake, &encrypted_extensions);
}

// RFC 9001 §8.2 — a QUIC server MUST read the client's quic_transport_parameters
// from the ClientHello. `client_hello.Parsed`, the only ClientHello parse in
// tls, keeps the extensions it recognizes and drops the rest, so the core has
// nowhere to put them. Asserting the absence is the point: a field appearing
// here is the signal to write the server half of the driver.
test "RFC 9001 §8.2: the ClientHello parser keeps no unknown extensions" {
    try testing.expect(!@hasField(tls.client_hello.Parsed, "extensions"));
}

// RFC 8446 §7.1, RFC 9001 §4.1.1 — the server derives "s ap traffic" when it
// sends its Finished, and every 1-RTT packet it sends is protected with it.
// The step core derives and exposes application secrets for the client only, so
// no QUIC server can install its 1-RTT space. A decl appearing here is the
// signal to write the server half of the driver.
test "RFC 8446 §7.1: the core's server has no application secrets" {
    try testing.expect(@hasDecl(tls.handshake_core.Client, "applicationSecrets"));
    try testing.expect(@hasDecl(tls.handshake_core.Server, "handshakeSecrets"));
    try testing.expect(!@hasDecl(tls.handshake_core.Server, "applicationSecrets"));
}
