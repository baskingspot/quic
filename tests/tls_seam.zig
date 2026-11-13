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
    keypairs: tls.KeyPairs = undefined,
    server_keypair: tls.x25519.KeyPair = undefined,

    fn deinit(self: *ClientAtEncryptedExtensions) void {
        self.client.deinit();
        self.keypairs.secureZero();
    }

    fn init(self: *ClientAtEncryptedExtensions) !void {
        self.keypairs = try tls.KeyPairs.init(tls.x25519.KeyPair.generate());
        self.server_keypair = tls.x25519.KeyPair.generate();

        var policy: tls.certificate.Policy = .init;
        policy.insecure_no_chain_anchor = true;
        self.client = tls.handshake_core.Client.init(&self.slots, policy);
        // `KeyPairs` became a public type in the change this pin carries
        // (baskingspot/tls#179); before that the only route was the public
        // field.
        self.client.useKeypairs(self.keypairs);

        // The client's own transport parameters, opaque to TLS (RFC 9001 §8.2).
        // Sending them works: this is the direction tls already carries.
        const our_parameters = [_]u8{ 0x01, 0x02, 0x03 };
        const client_hello = try tls.client_hello.encodeWithHybridGroupsAndExtensions(
            &self.client_hello_buf,
            .init(@splat(0x11)),
            self.keypairs.x25519.public_key,
            self.keypairs.p256.public_key,
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
        // The core derives the shared secret itself from the keypairs it holds,
        // so a consumer cannot hand it a wrong one.
        try self.client.provide(.plaintext, server_hello);

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
    defer peer.deinit();
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
    defer peer.deinit();
    try peer.init();

    const encrypted_extensions = [_]u8{
        0x08, 0x00, 0x00, 0x02, // handshake type, body length
        0x00, 0x00, // no extensions
    };
    try peer.client.provideHandshake(.handshake, &encrypted_extensions);
}

// RFC 8446 §4.2.8 — the core derives the shared secret itself from the
// keypairs it holds, so a caller hands it keypairs and a ClientHello. The type
// has to be nameable from outside the package, or `useKeypairs` and
// `startEncoded` are uncallable: it became public in the change this pin
// carries (baskingspot/tls#179), and the harness above now uses it.
test "RFC 8446 §4.2.8: the keypairs the core takes are a public type" {
    try testing.expect(@hasDecl(tls, "KeyPairs"));
    try testing.expect(@hasDecl(tls.handshake_core.Client, "useKeypairs"));
}

// RFC 9001 §8.2 — a QUIC server MUST read the client's quic_transport_parameters
// from the ClientHello. This is the consumer-level check that the parse path is
// reachable and keeps the bytes verbatim; the server's own use of it is
// `Server.receiveExtensions`.
test "RFC 9001 §8.2: the ClientHello parser keeps a listed extension verbatim" {
    var keypairs = try tls.KeyPairs.init(tls.x25519.KeyPair.generate());
    defer keypairs.secureZero();
    const parameters = [_]u8{ 0xca, 0xfe, 0xba, 0xbe };
    const sent = [_]tls.extension_type.ExtraExtension{
        .{ .extension_type = 0x0039, .data = &parameters },
    };
    var hello_buf: [1024]u8 = undefined;
    const hello = try tls.client_hello.encodeWithHybridGroupsAndExtensions(
        &hello_buf,
        .init(@splat(0x77)),
        keypairs.x25519.public_key,
        keypairs.p256.public_key,
        null,
        "localhost",
        &.{"h3"},
        &.{},
        null,
        &sent,
    );

    const allowed = [_]tls.extension_type.ExtraExtension{
        .{ .extension_type = 0x0039, .data = &.{} },
    };
    var slots: [2]tls.extension_type.ExtraExtension = undefined;
    var sink: tls.extension_type.ExtensionSink = .init(&slots);
    const parsed = try tls.client_hello.parseWithExtensions(hello, .{
        .allowed_extensions = &allowed,
        .received = &sink,
    });
    try testing.expectEqual(@as(usize, 1), parsed.extensions.len);
    try testing.expectEqual(@as(u16, 0x0039), parsed.extensions[0].extension_type);
    try testing.expectEqualSlices(u8, &parameters, parsed.extensions[0].data);
}

// RFC 8446 §7.1, RFC 9001 §4.1.1 — the server derives "s ap traffic" when it
// sends its Finished, and every 1-RTT packet it sends is protected with it. The
// core could not answer this before baskingspot/tls#179, and the driver's server
// half was blocked on it. The derivation and its value are tested in tls; this
// is the consumer-level check that both roles can be asked.
test "RFC 8446 §7.1: both roles hand over application secrets" {
    try testing.expect(@hasDecl(tls.handshake_core.Client, "applicationSecrets"));
    try testing.expect(@hasDecl(tls.handshake_core.Server, "applicationSecrets"));
}
