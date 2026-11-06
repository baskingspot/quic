//! QUIC in Zig: sans-I/O packet and frame codecs, transport parameters, and
//! the loss recovery a connection needs.
//!
//! A parser takes the bytes you read off the wire and returns borrowed slices
//! or hands back offsets into your own storage. A writer fills a buffer you
//! own. Nothing here opens a socket, keeps a clock, or allocates: an
//! allocator never enters the API, so a caller sees every byte it pays for.
//!
//! This is RFC 9000, the transport, plus the Initial half of RFC 9001. The
//! codecs read and write plaintext and know nothing about keys; `protection`
//! is the layer that seals a packet, masks its header, and opens the other
//! side's, and it is in this package rather than in `baskingspot/tls` because
//! Initial keys come from the connection ID and need no handshake. The traffic
//! secrets for every other encryption level come from tls, and the handshake
//! that produces them is a separate gate.
//!
//! The two layers compose in one direction only: build frames, seal them, mask
//! the header; then unmask, open, and read frames. `Recovery` sits beside them
//! with the packet numbers, the RTT, and the loss set, and takes its clock from
//! the caller.

pub const Cursor = @import("Cursor.zig");
pub const Writer = @import("Writer.zig");
pub const Congestion = @import("Congestion.zig");
pub const Conn = @import("Conn.zig");
pub const connection_setup = @import("connection_setup.zig");
pub const error_code = @import("error_code.zig");
pub const stream_id = @import("stream_id.zig");
pub const hkdf = @import("hkdf.zig");
pub const protection = @import("protection.zig");
pub const Recovery = @import("Recovery.zig");
pub const RecoveryDriver = @import("RecoveryDriver.zig");
pub const frame = @import("frame.zig");
pub const packet = @import("packet.zig");
pub const packet_number = @import("packet_number.zig");
pub const TransportParameters = @import("TransportParameters.zig");
pub const varint = @import("varint.zig");

pub const SendStream = @import("SendStream.zig");
pub const ReceiveStream = @import("ReceiveStream.zig");
pub const FlowControl = @import("FlowControl.zig");
pub const StreamTable = @import("StreamTable.zig");

test {
    _ = @import("Cursor.zig");
    _ = @import("Writer.zig");
    _ = Congestion;
    _ = Conn;
    _ = connection_setup;
    _ = error_code;
    _ = stream_id;
    _ = frame;
    _ = hkdf;
    _ = @import("InitialSpace.zig");
    _ = protection;
    _ = Recovery;
    _ = RecoveryDriver;
    _ = packet;
    _ = packet_number;
    _ = TransportParameters;
    _ = varint;
    _ = SendStream;
    _ = ReceiveStream;
    _ = FlowControl;
    _ = StreamTable;
}
