//! QUIC in Zig: sans-I/O packet and frame codecs, transport parameters, and
//! the loss recovery a connection needs.
//!
//! A parser takes the bytes you read off the wire and returns borrowed slices
//! or hands back offsets into your own storage. A writer fills a buffer you
//! own. Nothing here opens a socket, keeps a clock, or allocates: an
//! allocator never enters the API, so a caller sees every byte it pays for.
//!
//! This is RFC 9000, the transport. Packet protection is RFC 9001 and lives in
//! `baskingspot/tls`; every codec here reads and writes plaintext, so a caller
//! does the unprotect step before handing bytes over.

pub const Cursor = @import("Cursor.zig");
pub const Writer = @import("Writer.zig");
pub const error_code = @import("error_code.zig");
pub const hkdf = @import("hkdf.zig");
pub const protection = @import("protection.zig");
pub const frame = @import("frame.zig");
pub const packet = @import("packet.zig");
pub const packet_number = @import("packet_number.zig");
pub const TransportParameters = @import("TransportParameters.zig");
pub const varint = @import("varint.zig");

test {
    _ = @import("Cursor.zig");
    _ = @import("Writer.zig");
    _ = error_code;
    _ = frame;
    _ = hkdf;
    _ = protection;
    _ = packet;
    _ = packet_number;
    _ = TransportParameters;
    _ = varint;
}
