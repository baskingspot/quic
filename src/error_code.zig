//! QUIC transport error codes, RFC 9000 §20.1.
//!
//! A connection closes with one of these in a CONNECTION_CLOSE frame of type
//! 0x1c, or with an application code in type 0x1d. The registry is open (IANA,
//! §22.5), so an unknown code from a peer is a value, not an error. The
//! CRYPTO_ERROR block carries a TLS alert in its low byte (§20.1), which
//! `cryptoError` and `tlsAlert` move between.

const std = @import("std");
const testing = std.testing;
const frame = @import("frame.zig");

const error_code = @This();

/// The transport error codes, plus anything a peer sends that this build does
/// not know.
pub const Transport = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    _,

    pub fn fromInt(code: u64) Transport {
        return @fromBackingInt(@intCast(code));
    }

    pub fn toInt(self: Transport) u64 {
        return @backingInt(self);
    }
};

/// The first code in the CRYPTO_ERROR block, which runs to 0x01ff.
pub const crypto_error_first: u64 = 0x0100;

/// A TLS alert carried in the CRYPTO_ERROR block: 0x0100 plus the alert byte.
pub fn cryptoError(tls_alert: u8) Transport {
    return @fromBackingInt(@intCast(crypto_error_first + tls_alert));
}

/// The alert inside a CRYPTO_ERROR code, or null for any other code.
pub fn tlsAlert(code: Transport) ?u8 {
    const value = code.toInt();
    if (value < crypto_error_first or value > 0x01ff) return null;
    return @intCast(value - crypto_error_first);
}

/// The code a connection closes with when a frame will not decode (§20.1).
///
/// §12.4 makes an unknown frame type a FRAME_ENCODING_ERROR, and lets an
/// endpoint treat a frame type in a longer-than-needed encoding as a
/// PROTOCOL_VIOLATION. Every other frame error is malformed wire.
pub fn forFrameError(err: frame.Error) Transport {
    return switch (err) {
        error.NonMinimalFrameType => .protocol_violation,
        error.UnknownFrameType,
        error.Truncated,
        error.InvalidAckRange,
        error.InvalidConnectionId,
        error.InvalidRetirePriorTo,
        error.EmptyToken,
        error.InvalidFrameType,
        error.NoSpace,
        => .frame_encoding_error,
    };
}

test "RFC 9000 §20.1, the codes and their values" {
    try testing.expectEqual(@as(u64, 0x00), Transport.no_error.toInt());
    try testing.expectEqual(@as(u64, 0x07), Transport.frame_encoding_error.toInt());
    try testing.expectEqual(@as(u64, 0x0a), Transport.protocol_violation.toInt());
    try testing.expectEqual(@as(u64, 0x10), Transport.no_viable_path.toInt());

    // An unknown code is a code.
    const unknown = Transport.fromInt(0xdead);
    try testing.expectEqual(@as(u64, 0xdead), unknown.toInt());
}

test "RFC 9000 §20.1, CRYPTO_ERROR carries a TLS alert" {
    const code = cryptoError(0x2a);
    try testing.expectEqual(@as(u64, 0x012a), code.toInt());
    try testing.expectEqual(@as(?u8, 0x2a), tlsAlert(code));
    try testing.expectEqual(@as(?u8, null), tlsAlert(.protocol_violation));
    try testing.expectEqual(@as(?u8, null), tlsAlert(Transport.fromInt(0x01ff + 1)));
}

test "RFC 9000 §12.4, a frame error names the code that closes the connection" {
    try testing.expectEqual(
        Transport.frame_encoding_error,
        forFrameError(error.UnknownFrameType),
    );
    try testing.expectEqual(
        Transport.protocol_violation,
        forFrameError(error.NonMinimalFrameType),
    );
    try testing.expectEqual(
        Transport.frame_encoding_error,
        forFrameError(error.InvalidAckRange),
    );
}
