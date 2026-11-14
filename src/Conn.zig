//! The connection machine: three packet number spaces, the datagram they
//! arrive in, the streams over them, and the loss detection that decides when a
//! packet is gone.
//!
//! A caller hands over one datagram, and `Datagram` walks it: one datagram may
//! carry several packets end to end (RFC 9000 §12.2), and each packet belongs to
//! the space its form and type name (§12.3). A packet that will not open is
//! dropped and the walk continues (RFC 9001 §5.5).
//!
//! Initial keys come from the connection ID (§5.2 of RFC 9001), so they exist
//! from `init`; the Handshake and application spaces appear when a TLS driver
//! reports their traffic secrets through the `handshake` seam, and a packet for
//! an empty space is `error.NoKeys` for the caller to drop. There is no second
//! notion of "not ready": a space either has keys or it does not exist.
//!
//! Every buffer is the caller's, the clock is a value the caller passes, and
//! nothing allocates. The frames the machine cannot act on are described in
//! `Opened.frames`, because a packet that does not say what it carries cannot be
//! retransmitted by a caller that later learns it was lost.
//!
//! Loss recovery is the caller's too, and lives outside this type: the
//! `Recovery`, its three sent tables, and the three `Recovery.Space` values are
//! all in caller storage, and `Conn` keeps only pointers into them. `Conn.init`
//! returns by value, so a `Recovery` field here would be left behind by the
//! caller's first assignment and every space in the copy would point at the
//! pre-move address. `Config.loss` is the caller's storage instead, which is also
//! what lets a `RecoveryDriver` outlive a moved connection.

const std = @import("std");
const testing = std.testing;
const Cursor = @import("Cursor.zig");
const CryptoStream = @import("CryptoStream.zig");
const FlowControl = @import("FlowControl.zig");
const ReceiveStream = @import("ReceiveStream.zig");
const SendStream = @import("SendStream.zig");
const StreamTable = @import("StreamTable.zig");
const stream_id = @import("stream_id.zig");
const frame = @import("frame.zig");
const TransportParameters = @import("TransportParameters.zig");
const setup = @import("connection_setup.zig");
const seam = @import("handshake.zig");
const packet = @import("packet.zig");
const packet_number = @import("packet_number.zig");
const protection = @import("protection.zig");
const Recovery = @import("Recovery.zig");
const Writer = @import("Writer.zig");
const varint = @import("varint.zig");
const error_code = @import("error_code.zig");

const Conn = @This();

/// Nanoseconds, from the module that measures them.
pub const Duration = Recovery.Duration;

const Range = struct { smallest: u64, largest: u64 };

/// Whether the handshake driver has this endpoint's transport parameters.
/// Two states, and the transition happens once, before the driver may produce a
/// first message (§8.2).
pub const Parameters = enum { pending, handed };

/// How many separate received ranges a space tracks. Eight covers the
/// reordering a handshake sees in practice; beyond it, the oldest range is
/// forgotten, which §13.2.4 allows.
pub const range_capacity = 8;

/// The widest encoding of one integer, from the codec that writes it.
const max_varint_len = varint.size(@intCast(varint.max));

/// The most a gap and its range length can take: two eight-byte varints. A full
/// table holds `range_capacity` ranges, so at most one fewer pair (§19.3.1).
const ack_range_scratch_len = range_capacity * 2 * max_varint_len;

/// The room one ACK frame's own fields need beside the range encode: the type
/// byte, and three varints for `largest`, the delay, and the first range.
const ack_payload_len = ack_range_scratch_len + 32;

pub const Role = enum { client, server };

/// What a connection may still do, once it is over (§10.2 of RFC 9000).
///
/// Three states, not two booleans: "sent a close" and "received one" answer
/// different questions. A closing endpoint may still put a close on the wire in
/// answer to a packet it arrives too late for; a draining endpoint sends nothing
/// at all.
pub const State = enum {
    /// Packets are processed and answered.
    open,
    /// §10.2.1: this endpoint sent a CONNECTION_CLOSE.
    closing,
    /// §10.2.2: the peer's CONNECTION_CLOSE arrived.
    draining,
};

/// The packet number spaces of §12.3. There are three, not four: 0-RTT and
/// 1-RTT packets share the application data space.
pub const SpaceId = enum { initial, handshake, app };

pub const Error = protection.Error ||
    packet.Error ||
    setup.Retry.Error ||
    frame.Error ||
    seam.Error ||
    Recovery.Error ||
    CryptoStream.Error ||
    StreamTable.Error ||
    SendStream.Error ||
    ReceiveStream.Error ||
    FlowControl.Error ||
    error{
        /// No traffic keys are installed for the space. Handshake and application
        /// keys arrive from the TLS driver, and the space is absent until then.
        NoKeys,
        /// The bytes name a version this package does not implement, so the
        /// caller's answer is Version Negotiation, not a connection (§6).
        UnsupportedVersion,
        /// §7.2: the packet that would start a connection is not an Initial.
        NotInitial,
        /// §7.2: a first Initial with no Destination Connection ID names no
        /// endpoint and seeds no Initial keys.
        InvalidConnectionId,
        /// An acknowledgment was asked of a space that has received nothing.
        NothingToAcknowledge,
        /// §4.6: the peer opened more streams than this endpoint advertised. It is
        /// peer-visible, not a dropped packet: the connection closes with
        /// STREAM_LIMIT_ERROR.
        StreamLimit,
        /// §12.4: STREAM frames belong to the application space only.
        WrongFrameSpace,
        /// §2.1: the stream cannot carry data in this direction, or it is the
        /// other endpoint's to open.
        WrongDirection,
        /// §4.6: the peer has not granted credit for another stream of this
        /// kind. This is the caller's own open being refused, never a peer
        /// violation, so it is not a connection error.
        NoStreamCredit,
        /// §19.11: a MAX_STREAMS frame that permits a stream id this protocol
        /// cannot encode, which is FRAME_ENCODING_ERROR for the caller to close
        /// with.
        StreamCountTooLarge,
        /// §7.2: a long header names a different endpoint than the one this
        /// connection sends to. It is not this connection's packet, so the
        /// caller drops it rather than closing anything.
        WrongConnectionId,
        /// §19.20: the peer sent a frame that only one role may send, which is
        /// a connection error (PROTOCOL_VIOLATION) and not a caller mistake.
        ProtocolViolation,
        /// §10.2.1 and §10.2.2: this connection has sent or received a
        /// CONNECTION_CLOSE, so it processes no more packets. Only the close
        /// itself may still be written.
        Closed,
        /// The call only means something to one end of the connection: a server
        /// has no handshake attempt to remember (§6.2).
        WrongRole,
        /// §7.3 and §18.2: the peer's transport parameters are missing, will not
        /// decode, or contradict the connection IDs this endpoint saw. The
        /// connection closes with TRANSPORT_PARAMETER_ERROR (0x08).
        TransportParameter,
    };

/// §4.6: how many streams this endpoint lets the peer open, per direction.
///
/// Two pairs of numbers, not one: `allowed` is what the machine can now hold and
/// grows as slots come free, while `advertised` is what the peer has actually
/// been told. The difference between them is exactly the MAX_STREAMS frame that
/// is owed, which is why deciding is separate from raising here as it is for the
/// data windows.
pub const StreamLimits = struct {
    bidi: u64 = 0,
    uni: u64 = 0,
};

/// Where loss recovery's state lives: the caller's, outside the connection.
///
/// `Conn.init` returns by value, so the caller assigns a `Conn` into its own
/// storage and every field moves. `Recovery.Space` holds a `*Recovery`, so a
/// `Recovery` field inside `Conn` would leave every space pointed at the
/// pre-move address: a dangling pointer that surfaces much later as recovery
/// state changing on its own, with no path back to the cause. The sent tables
/// move for the same reason, because a space keeps a slice of one, and
/// `spaces` holds the values themselves so a `RecoveryDriver` built over them
/// needs no address inside the connection.
///
/// All three tables must be non-empty. The machine records every packet it sends
/// that is ack-eliciting or in flight (RFC 9002 §6.1), and a table that cannot
/// hold one is a packet whose fate nobody reports: `error.NoSpace` at the write,
/// never a silent gap.
pub const Loss = struct {
    /// The connection-wide half of RFC 9002: the RTT estimator (§5) and the PTO
    /// backoff (§6.2.1). Both belong to the path, so an Initial key discard
    /// leaves them alone (A.2).
    shared: *Recovery,
    /// The per-space half, one slot per `SpaceId`, in the caller's storage. The
    /// machine keeps a pointer into these rather than a copy, so a
    /// `RecoveryDriver` built over them survives a `Conn` that moves: the
    /// connection holds no address the driver needs. `Conn.init` places all
    /// three, so a slot is readable before its keys exist and after they are
    /// discarded.
    spaces: *[3]Recovery.Space,
    sent_initial: []Recovery.SentPacket,
    sent_handshake: []Recovery.SentPacket,
    sent_app: []Recovery.SentPacket,

    /// The sent table for one space.
    pub fn table(self: *const Loss, id: SpaceId) []Recovery.SentPacket {
        return switch (id) {
            .initial => self.sent_initial,
            .handshake => self.sent_handshake,
            .app => self.sent_app,
        };
    }
};

/// The peer's initial per-stream limits, named by the transport parameter each
/// one comes from (§18.2).
///
/// Three numbers, not one. §4.1 gives a bidirectional stream a different limit
/// depending on who opened it: `initial_max_stream_data_bidi_remote` is the
/// peer's credit for the streams this endpoint opens, and
/// `initial_max_stream_data_bidi_local` is its credit for the streams it opened
/// itself, which this endpoint joins to answer. A connection can hold both
/// kinds at once.
pub const PeerStreamLimits = struct {
    /// initial_max_stream_data_bidi_remote: a stream this endpoint opens.
    bidi_remote: u64 = 0,
    /// initial_max_stream_data_bidi_local: a stream the peer opened and this
    /// endpoint sends on.
    bidi_local: u64 = 0,
    /// initial_max_stream_data_uni: a one-way stream this endpoint opens.
    uni: u64 = 0,

    /// The limit for a stream this endpoint opens itself.
    fn forOpening(self: PeerStreamLimits, id: u64) u64 {
        return switch (stream_id.direction(id)) {
            .bidi => self.bidi_remote,
            .uni => self.uni,
        };
    }
};

/// What the peer's transport parameters set (§18.2), with every default
/// applied, so a reader never has to know which parameters were absent.
///
/// The machine fills it from the handshake and only reads it afterwards: it is
/// the single source of the limits the peer imposes, and the one place a caller
/// looks to learn the idle timeout or the largest datagram the peer accepts.
/// Durations are nanoseconds, like the rest of this package; the wire carries
/// milliseconds.
pub const PeerParameters = struct {
    /// initial_max_data: the connection-wide send allowance (§4.1).
    max_data: u64 = 0,
    stream_data: PeerStreamLimits = .{},
    /// initial_max_streams_bidi and initial_max_streams_uni (§4.6).
    max_streams: StreamLimits = .{},
    /// §5.3 of RFC 9002 bounds a reported ACK delay by this once the handshake
    /// is confirmed.
    max_ack_delay: Duration = 0,
    /// §19.3: scales the delay field of an ACK frame the peer sends.
    ack_delay_exponent: u8 = 3,
    /// Zero means the peer asked for no idle timeout (§10.1).
    max_idle_timeout: Duration = 0,
    max_udp_payload_size: u64 = 65527,
    active_connection_id_limit: u64 = 2,
    disable_active_migration: bool = false,
    /// Only a server sends one (§18.2).
    stateless_reset_token: ?[16]u8 = null,

    /// Apply the defaults of §18.2 to what a peer sent.
    ///
    /// `decode` already refused an exponent above 20, so the narrowing cannot
    /// lose a bit. The two millisecond values are saturated rather than
    /// wrapped: a 2^62 idle timeout is "never", not a small number.
    pub fn fromDecoded(decoded: *const TransportParameters) PeerParameters {
        std.debug.assert(decoded.ackDelayExponent() <= TransportParameters.max_ack_delay_exponent);
        return .{
            .max_data = decoded.initial_max_data orelse 0,
            .stream_data = .{
                .bidi_remote = decoded.initial_max_stream_data_bidi_remote orelse 0,
                .bidi_local = decoded.initial_max_stream_data_bidi_local orelse 0,
                .uni = decoded.initial_max_stream_data_uni orelse 0,
            },
            .max_streams = .{
                .bidi = decoded.initial_max_streams_bidi orelse 0,
                .uni = decoded.initial_max_streams_uni orelse 0,
            },
            .max_ack_delay = decoded.maxAckDelay() *| std.time.ns_per_ms,
            .ack_delay_exponent = @intCast(decoded.ackDelayExponent()),
            .max_idle_timeout = (decoded.max_idle_timeout orelse 0) *| std.time.ns_per_ms,
            .max_udp_payload_size = decoded.maxUdpPayloadSize(),
            .active_connection_id_limit = decoded.activeConnectionIdLimit(),
            .disable_active_migration = decoded.disable_active_migration,
            .stateless_reset_token = decoded.stateless_reset_token,
        };
    }
};

pub const Config = struct {
    role: Role,
    /// The client's Destination Connection ID: the Initial keys come from it,
    /// and both endpoints derive the same ones (§5.2 of RFC 9001).
    original_destination_connection_id: []const u8,
    /// What this endpoint writes into the packets it sends.
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// The caller's loss recovery state: the estimator and one sent-packet
    /// table per space. It stays outside `Conn`; see `Loss`.
    loss: Loss,
    /// This endpoint's `ack_delay_exponent` (§18.2): the one it advertises, and
    /// so the one the peer scales the delay of the ACKs it sends by. It is ours
    /// to advertise, not a way to read the peer's ACKs: those are decoded with
    /// `PeerParameters.ack_delay_exponent`. The default is the RFC's, and `init`
    /// asserts the bound §18.2 gives it.
    ack_delay_exponent: u8 = 3,
    /// §6.2.1 of RFC 9002: a client that has not seen its peer validate its
    /// address keeps its PTO backoff across acknowledgments. The machine cannot
    /// observe validation, so the caller seeds this and flips the field of the
    /// same name on `Conn` when it happens.
    peer_address_validated: bool = true,
    /// §17.2.2: the address validation token, empty unless a Retry or a
    /// NEW_TOKEN frame gave one. It goes in every Initial packet this endpoint
    /// sends (§8.1.2), and a Retry replaces it.
    token: []const u8 = "",
    /// Where a Retry's connection ID and token are copied to (§17.2.5.3). They
    /// arrive inside the datagram, which the caller reuses for the next one, so
    /// the machine cannot keep pointing at them. Size it for the largest
    /// connection ID plus token this client expects to be handed; a Retry that
    /// does not fit is `error.NoSpace` before any of it is adopted.
    retry_storage: []u8 = "",
    /// Where a client copies the name the server first gives it (§7.2): the
    /// Source Connection ID of the server's first Initial becomes the
    /// Destination Connection ID of everything this endpoint sends after it,
    /// and the datagram it arrived in is reused. Twenty bytes is the most a
    /// version 1 connection ID can be; a name that does not fit is
    /// `error.NoSpace`. A server never needs this: its destination came from
    /// the client's first packet, which `Opening` already copied.
    connection_id_storage: []u8 = "",
    /// The truncation width to use. §17.1 makes this a function of what the
    /// peer has acknowledged; until that lands, the caller picks, and four
    /// bytes is always legal.
    packet_number_len: u3 = 4,
    /// The TLS driver, when this endpoint runs a handshake. Without one the
    /// machine still parses, protects, and acknowledges Initial packets, which
    /// is what the interop tool does.
    tls: ?seam.Driver = null,
    /// This endpoint's transport parameters, already encoded, which the driver
    /// carries opaquely in the handshake (§8.2). Handed to the driver once,
    /// before its first message.
    transport_parameters: []const u8 = "",
    /// Reassembly storage for the CRYPTO stream at each level (§19.6). The
    /// caller sizes it for the largest handshake it expects; a frame that would
    /// reach past what it holds is `error.NoSpace`.
    crypto: CryptoStorage = .{},
    /// Where the CRYPTO bytes this endpoint sends are kept, per level, so a lost
    /// handshake packet can be re-sent (§13.3) and a space can be replayed. The
    /// caller sets the capacity; a message that does not fit is `error.NoSpace`
    /// rather than a truncated flight, and §20.1 closes that connection with
    /// CRYPTO_BUFFER_EXCEEDED, which is the same answer a receiver gives when a
    /// peer's handshake outgrows its buffer. That failure is fatal by design:
    /// there is no retry to make, because the driver's message has already been
    /// taken.
    crypto_sent: CryptoStorage = .{},
    /// The streams this endpoint can hold: the table's slots and the storage
    /// behind them, in the same order. Their length is the stream limit the
    /// machine advertises, so a peer that opens one more is `error.StreamLimit`
    /// (§4.6) rather than a packet anyone drops.
    stream_slots: []StreamTable.Slot = &.{},
    streams: []Stream = &.{},
    /// §4.1: the connection-wide limit this endpoint advertises.
    receive_limit: u64 = 0,
    /// §4.6: the initial MAX_STREAMS counts this endpoint advertised in its
    /// transport parameters, per direction. They are the peer's credit to open
    /// streams, so the machine has to know them to raise them later, and together
    /// they may not exceed the table the caller supplied: a peer that opens what
    /// it was allowed must never find `error.StreamLimit`.
    max_streams_bidi: u64 = 0,
    max_streams_uni: u64 = 0,
    /// The peer's limits for a machine with no driver. With a driver they come
    /// from the handshake and the machine adopts them itself (§7.4), so the two
    /// never coexist: `init` asserts it. Without either, the peer has granted
    /// nothing, which is what its transport parameters say until they arrive.
    peer: ?PeerParameters = null,
};

/// What a server learns from a client's first Initial, before it has a `Conn`.
///
/// §7.2: the Destination Connection ID of that packet names this endpoint.
/// §5.2 of RFC 9001 makes those same bytes the seed of the Initial keys, so
/// pairing them with the wrong datagram is a handshake that never opens.
///
/// Both slices borrow the caller's `storage`, never the datagram: the datagram
/// is a receive buffer, and `protection.openPacket` even rewrites it in place.
/// A connection keeps the client's Source Connection ID for its whole life, and
/// a Retry has to mint a name before the next packet overwrites the one it
/// answered.
pub const Opening = struct {
    /// The client's Destination Connection ID: this endpoint as the client
    /// names it, the seed of both directions' Initial keys, and the value the
    /// original_destination_connection_id transport parameter must echo (§7.3).
    destination_connection_id: []const u8,
    /// The client's Source Connection ID: where this endpoint sends until the
    /// client adopts a different one.
    source_connection_id: []const u8,

    /// Read the identity out of a client's first datagram, copying both
    /// connection IDs into `storage`.
    ///
    /// Only an Initial starts a connection. A short header names one already
    /// open, a Handshake arrives after this endpoint has answered, and a
    /// Version Negotiation packet is never a client's first word (§17.2.1).
    /// A version this package does not implement is `error.UnsupportedVersion`,
    /// which is the caller's cue to answer with `connection_setup`.
    ///
    /// `error.NoSpace` means `storage` cannot hold the two connection IDs, and
    /// it is refused before anything is written.
    pub fn fromDatagram(bytes: []const u8, storage: []u8) Error!Opening {
        const invariant = try packet.parseInvariant(bytes);

        // §17.2.1: a Version Negotiation packet carries neither a version nor a
        // packet type, so the version is read before the type bits mean
        // anything.
        if (invariant.version == .negotiation) return error.NotInitial;
        if (invariant.version != .v1) return error.UnsupportedVersion;

        const kind: packet.Kind = @fromBackingInt(@intCast((invariant.first >> 4) & 0x03));
        if (kind != .initial) return error.NotInitial;

        // §7.2: a client MUST name at least eight bytes in its first Initial.
        // The floor is a server's MAY to enforce, but a zero-length name seeds
        // the keys from nothing and names no endpoint, so this refuses it.
        const destination_length = invariant.destination_connection_id.len;
        if (destination_length == 0) return error.InvalidConnectionId;

        const source_length = invariant.source_connection_id.len;
        if (storage.len < destination_length + source_length) return error.NoSpace;

        // §17.2: both are shortened before the copy, so the two cannot overlap
        // and neither can be moved after this point.
        const destination = storage[0..destination_length];
        @memcpy(destination, invariant.destination_connection_id);
        const source = storage[destination_length..][0..source_length];
        @memcpy(source, invariant.source_connection_id);

        return .{ .destination_connection_id = destination, .source_connection_id = source };
    }

    /// The configuration a server starts from, with this endpoint's own
    /// connection ID.
    ///
    /// `connection_id` is the caller's: the machine holds no entropy, so it
    /// cannot generate one, and §5.1 wants connection IDs unpredictable. `loss`
    /// is the caller's too, and the only field of `Config` with no default. Fill
    /// in the rest — `tls`, the streams, the limits — before `Conn.init`; this
    /// removes only the way to seed the Initial keys and the reply's destination
    /// from the wrong connection ID.
    pub fn serverConfig(self: Opening, connection_id: []const u8, loss: Loss) Config {
        return .{
            .role = .server,
            .loss = loss,
            .original_destination_connection_id = self.destination_connection_id,
            .destination_connection_id = self.source_connection_id,
            .source_connection_id = connection_id,
        };
    }
};

/// A client's configuration: the name it invents for the server, its own, and
/// the loss state that has no default.
///
/// §7.2: a client names the server in its first Initial, and RFC 9001 §5.2 makes
/// those same bytes the seed of the Initial keys, so the two numbers cannot
/// differ. The destination starts as that name and changes only when the server
/// offers a connection ID of its own. Fill in the rest — `tls`, the streams, the
/// limits — before `Conn.init`.
pub fn clientConfig(
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    loss: Loss,
) Config {
    return .{
        .role = .client,
        .loss = loss,
        .original_destination_connection_id = destination_connection_id,
        .destination_connection_id = destination_connection_id,
        .source_connection_id = source_connection_id,
    };
}

/// One stream the machine can hold: the buffers and the per-stream limit, then
/// the two halves the machine builds when the stream opens.
///
/// `send_buffer` and `recv_buffer` are the caller's, and stay theirs: opening a
/// stream fills in `send` and `recv` and never moves a byte. No two of them may
/// share storage, not across two slots and not between the two halves of one
/// stream: a shared buffer is two byte budgets that overwrite each other while
/// neither knows, and `Conn.init` asserts it with `streamsOverlap`.
pub const Stream = struct {
    /// Where the send half's bytes live.
    send_buffer: []u8 = "",
    /// The ring the receive half reassembles into. It must be at least as large
    /// as `limit`, which `Conn.init` asserts: a ring smaller than the window it
    /// advertises is a caller misconfiguration, and catching it there beats a
    /// peer's frame turning into `error.NoSpace` two layers away (§2.2, §4.1).
    recv_buffer: []u8 = "",
    /// §4.1: the per-stream limit this endpoint advertises. A count of bytes,
    /// not the name it shares with `Config.receive_limit`, which is the
    /// connection's.
    recv_limit_bytes: u64 = 0,
    send: SendStream = undefined,
    recv: ReceiveStream = undefined,
    halves: Halves = .unused,

    /// Which halves a slot holds. Exhaustive on purpose: `send` is only valid
    /// when this says so, and a boolean pair could disagree with the slot the
    /// table points at.
    pub const Halves = enum { unused, recv_only, send_only, both };

    pub fn isOpen(self: *const Stream) bool {
        return self.halves != .unused;
    }

    pub fn canSend(self: *const Stream) bool {
        return switch (self.halves) {
            .send_only, .both => true,
            .unused, .recv_only => false,
        };
    }

    pub fn canRecv(self: *const Stream) bool {
        return switch (self.halves) {
            .recv_only, .both => true,
            .unused, .send_only => false,
        };
    }
};

/// Three per-level byte buffers, the caller's. `Config.crypto` is where a
/// level's received CRYPTO data is reassembled and `Config.crypto_sent` is where
/// the bytes this endpoint sent are kept for §13.3.
pub const CryptoStorage = struct {
    initial: []u8 = "",
    handshake: []u8 = "",
    app: []u8 = "",
};

/// The CRYPTO bytes one encryption level has sent, in the caller's storage.
///
/// §13.3 of RFC 9000: "data is sent again in CRYPTO frames with the same
/// offsets" when it is lost, so what a replay needs is the bytes and the offset
/// they start at. Since the machine writes them in order from zero, `len` is
/// both the count and the offset of the next byte.
pub const SentCrypto = struct {
    bytes: []u8 = "",
    /// Wire offset of the next byte to send, and the number of bytes kept.
    len: u32 = 0,
};

pub const Opened = struct {
    space: SpaceId,
    packet_number: u64,
    header_len: u32,
    packet_len: u32,
    /// The frames the machine did not act on, in wire order, borrowed from
    /// `payload`. CRYPTO frames went to the driver, STREAM, RESET_STREAM, and
    /// STOP_SENDING frames to their stream, MAX_DATA, MAX_STREAM_DATA, and
    /// MAX_STREAMS to the allowances they raise, HANDSHAKE_DONE to the
    /// confirmation it reports, and ACK frames to loss recovery, so none of them
    /// appear here. This is what the caller has to handle itself, and it is the
    /// whole of it.
    frames: []frame.Frame,
    /// The streams this packet changed, one record per stream, in the order
    /// their first frame arrived. Borrowed from the caller's `stream_events`
    /// list and empty when no STREAM frame changed what the application can
    /// see.
    streams: []const StreamEvent,
    /// The decrypted payload, borrowed from the caller's plaintext buffer.
    payload: []u8,
};

/// One stream a packet changed.
///
/// The machine knows both facts at the frame that caused them, and a caller
/// otherwise re-derives them by walking the stream table after every packet
/// (§3.2, §4.5). A record appears only when one of the two became true in this
/// packet: a retransmitted frame, or one that fills a gap beyond the read
/// point, changes nothing the caller can act on yet.
pub const StreamEvent = struct {
    stream_id: u64,
    /// The contiguous run from the read point grew, so a read now returns bytes
    /// it would not have returned before.
    readable: bool = false,
    /// The peer's FIN is known and this packet supplied the last byte of it, so
    /// the stream is Data Recvd and a read runs to the final size.
    finished: bool = false,
    /// §3.2: the peer reset the stream, so the receive half is Reset Recvd and
    /// the application reads the code with `ReceiveStream.readReset`.
    reset: bool = false,
    /// §3.5: the peer asked this endpoint to stop sending, and the sending half
    /// is now Reset Sent. The caller owes a RESET_STREAM with this code.
    reset_owed: ?u64 = null,
};

/// One packet number space: its keys, its counters, and the ranges it has
/// received. The connection IDs a packet names belong to the connection, not to
/// a space, because a space can be discarded and the connection keeps going.
///
/// Every space is present from `init` or appears when a TLS driver reports its
/// traffic secrets, and any of them can be discarded. Absent is the only way
/// this type says "no keys"; there is no flag next to it.
pub const Space = struct {
    send_keys: protection.Keys,
    receive_keys: protection.Keys,
    /// RFC 9002 §6.4: the loss state shares the keys' lifetime, so a packet sent
    /// under them is accounted for here and nowhere else. It lives in the
    /// caller's `Loss.spaces`, not in this value: a discard empties it where it
    /// stands, so the address a caller's `RecoveryDriver` holds stays valid even
    /// when the space itself is gone.
    recovery: *Recovery.Space,
    next_packet_number: u64 = 0,
    largest_received: ?u64 = null,
    /// The largest packet number an ACK has been sent for, so a machine does
    /// not acknowledge the same thing twice.
    acked_through: ?u64 = null,
    /// Received packet numbers, descending and merged, for the ACK frame.
    ranges: [range_capacity]Range = undefined,
    range_count: u4 = 0,

    pub fn ackOwed(self: *const Space) bool {
        return self.range_count != 0 and self.acked_through != self.largest_received;
    }

    /// RFC 9001 §4.9: the keys go, and nothing encrypted under them is
    /// reachable afterwards.
    ///
    /// RFC 9002 §6.4 comes first: the sent packets and the loss timer go into
    /// the same grave as the keys, and a timer already armed for this space must
    /// find nothing to fire. The RTT estimate is not touched: it belongs to the
    /// path, not to the space (RFC 9002 A.2).
    pub fn discard(self: *Space) void {
        self.recovery.discard();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.send_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.receive_keys));
        self.next_packet_number = 0;
        self.largest_received = null;
        self.acked_through = null;
        self.range_count = 0;
    }

    /// Note a packet number that arrived, merging it into the ranges an ACK
    /// frame is built from (§19.3.1).
    fn record(self: *Space, pn: u64) void {
        std.debug.assert(self.range_count <= range_capacity);
        var buf: [range_capacity + 1]Range = undefined;
        var count: usize = 0;
        var inserted = false;
        for (self.ranges[0..self.range_count]) |range| {
            if (!inserted and range.largest < pn) {
                buf[count] = .{ .smallest = pn, .largest = pn };
                count += 1;
                inserted = true;
            }
            buf[count] = range;
            count += 1;
        }
        if (!inserted) {
            buf[count] = .{ .smallest = pn, .largest = pn };
            count += 1;
        }

        var merged: usize = 0;
        for (buf[0..count]) |range| {
            if (merged > 0) {
                const previous = &buf[merged - 1];
                if (range.largest +% 1 >= previous.smallest) {
                    previous.smallest = @min(previous.smallest, range.smallest);
                    continue;
                }
            }
            buf[merged] = range;
            merged += 1;
        }

        const kept = @min(merged, range_capacity);
        @memcpy(self.ranges[0..kept], buf[0..kept]);
        self.range_count = @intCast(kept);
    }
};

role: Role,
/// §10.2: where this connection is in its life. A packet that arrives after the
/// close is `error.Closed`, processed no further.
state: State = .open,
/// Where this connection was first used, for the move assertion.
///
/// A caller builds a `RecoveryDriver` over `&conn.app.?.recovery` and the other
/// spaces, so a `Conn` that moves leaves the driver writing through pointers
/// into nobody's storage. `init` returns by value and cannot see the address the
/// caller assigns it to, so the first call that uses the connection records that
/// address and every call after asserts it. A move before the first call is
/// invisible, and harmless: nothing has handed out a pointer into the connection
/// yet.
home: ?*const Conn = null,
packet_number_len: u3,
/// What this endpoint writes into the packets it sends. The connection IDs
/// outlive every space: discarding a space's keys does not change what the peer
/// calls this endpoint.
destination_connection_id: []const u8,
source_connection_id: []const u8,
/// §17.2.2: the token this endpoint puts in its Initial packets. Empty until a
/// Retry (or a caller handing over a NEW_TOKEN value) gives it one.
token: []const u8,
/// The caller's storage that `token` and a Retry's connection ID live in once
/// they have been copied out of the datagram they arrived in.
retry_storage: []u8,
/// The caller's storage for the name the server first gives this endpoint
/// (§7.2), once it has been copied out of the datagram it arrived in.
connection_id_storage: []u8,
/// Whether a server has named this endpoint. §7.2: only the first Initial (or
/// a Retry) changes the client's destination, and a later long header with a
/// different Source Connection ID is discarded, not adopted.
named: bool = false,
/// §4.1.2 of RFC 9001: a client's handshake is confirmed when a HANDSHAKE_DONE
/// frame arrives, which is the machine's fact alone. A server's is confirmed
/// when its TLS handshake completes, which is the driver's.
handshake_done: bool = false,
/// §6.2 and §17.2.5.2: the client's memory of what the server has said, which
/// is what decides whether a Version Negotiation or a Retry still counts. Absent
/// on a server, which never has to remember either.
attempt: ?setup.Client,
/// The caller's loss recovery storage, kept as the handles it is: everything
/// here points outside this value, so a copy of a `Conn` does not copy any state
/// that matters. See `Loss`.
loss: Loss,
/// What the peer's transport parameters set, once they are adopted: from the
/// driver's handshake, or from `Config.peer` when there is none. Null until
/// then, and the 1-RTT space is not installed while it is (§8.2 of RFC 9001).
peer: ?PeerParameters = null,
/// §7.3: the Source Connection ID of the Retry this client accepted, copied into
/// `retry_storage`, which the server's `retry_source_connection_id` must echo.
/// Empty without a Retry, and `attempt` is what says whether there was one.
retry_source_connection_id: []const u8 = "",
/// §4.1: the peer's initial per-stream limits, which every `SendStream` is born
/// with.
send_streams: PeerStreamLimits = .{},
/// The peer's `max_ack_delay`, which bounds a reported delay once the handshake
/// is confirmed (§5.3 of RFC 9002).
max_ack_delay: Duration = 0,
/// §6.2.1 of RFC 9002: a client that has not seen its peer validate its address
/// keeps its PTO backoff across acknowledgments. The caller flips this when the
/// peer's address is validated, because only the caller sees the handshake.
peer_address_validated: bool,
/// Initial keys are derivable from the connection ID alone, so this space
/// exists from `init`, and goes when §17.2.2.1 says it is no longer needed.
initial: ?Space,
/// Handshake keys come from the TLS driver.
handshake: ?Space = null,
/// 1-RTT keys, same.
app: ?Space = null,
/// The handshake driver, when there is one. The machine calls it; it never
/// implements TLS.
tls: ?seam.Driver,
/// Encoded transport parameters for the driver, set before its first message.
transport_parameters: []const u8,
/// Whether the driver has them. Two states, and the transition happens once:
/// they are handed over before the driver may produce a message (§8.2).
parameters: Parameters = .pending,
/// CRYPTO reassembly per level, over the caller's storage, indexed by
/// `SpaceId`.
crypto: [3]CryptoStream,
/// CRYPTO bytes sent per level, over the caller's storage, indexed the same way.
crypto_sent: [3]SentCrypto,
/// The open streams, and the storage behind each one.
stream_table: StreamTable,
streams: []Stream,
/// §4.1: the receive window across all streams, and the send allowance the peer
/// gave.
receive_window: FlowControl,
send_window: FlowControl.Sender,
/// §4.6: the stream counts the peer may open now, and the ones it has been told
/// about.
streams_allowed: StreamLimits,
streams_advertised: StreamLimits,
/// §2.1: how many streams this endpoint has opened, per direction, counting
/// ordinals. An id below it was created at some point; one at or above it never
/// was. `closeStream` frees a slot and the machine keeps no record of the id, so
/// this is the only memory of a stream that is gone.
opened_local: StreamLimits = .{},
/// §4.6: how many streams the peer has permitted this endpoint to open, per
/// direction, counting closed ones. MAX_STREAMS raises it and nothing lowers it.
peer_max_streams: StreamLimits = .{},
/// Whether the driver has them yet. One call, before the first flight.
transport_parameters_set: bool = false,

/// Whether the connection is still at the address it was first used from.
///
/// A pure predicate so the bad shape can be driven in a test: an assertion that
/// cannot be expected is a rule nobody can check.
fn atHome(home: ?*const Conn, self: *const Conn) bool {
    const recorded = home orelse return true;
    return recorded == self;
}

/// Record this connection's address on first use and refuse a later move.
fn pin(self: *Conn) void {
    std.debug.assert(atHome(self.home, self));
    if (self.home == null) self.home = self;
}

pub fn init(config: Config) Conn {
    std.debug.assert(config.packet_number_len >= 1);
    std.debug.assert(config.packet_number_len <= 4);
    // §18.2: an exponent above 20 describes a delay nobody can measure.
    std.debug.assert(config.ack_delay_exponent <= 20);
    // §7.4: with a driver the peer's parameters come from the handshake, and a
    // second source for the same limits is the bug this refuses.
    std.debug.assert(config.tls == null or config.peer == null);

    std.debug.assert(streamsValid(config.stream_slots, config.streams));
    std.debug.assert(lossTablesValid(config.loss));
    // §4.6: credit the table cannot back turns a legal peer into a connection
    // error, so it is refused at construction.
    std.debug.assert(config.max_streams_bidi + config.max_streams_uni <= config.streams.len);

    // §13.3's buffer length is a CRYPTO offset, and offsets are `u32` in this
    // package. A buffer that cannot be addressed is a configuration error.
    std.debug.assert(config.crypto_sent.initial.len <= std.math.maxInt(u32));
    std.debug.assert(config.crypto_sent.handshake.len <= std.math.maxInt(u32));
    std.debug.assert(config.crypto_sent.app.len <= std.math.maxInt(u32));

    const secrets = protection.initialSecrets(config.original_destination_connection_id);
    const suite = protection.Suite.aes_128_gcm;
    const client = protection.deriveKeys(&secrets.client, suite) catch unreachable;
    const server = protection.deriveKeys(&secrets.server, suite) catch unreachable;

    var conn: Conn = .{
        .role = config.role,
        // §6.2: the attempt is built around the Destination Connection ID the
        // first Initial carried, because that is what a Retry's tag covers
        // (§5.8 of RFC 9001). A server never needs it.
        .attempt = if (config.role == .client)
            setup.Client.init(config.original_destination_connection_id)
        else
            null,
        .packet_number_len = config.packet_number_len,
        .destination_connection_id = config.destination_connection_id,
        .source_connection_id = config.source_connection_id,
        .loss = config.loss,
        .token = config.token,
        .retry_storage = config.retry_storage,
        .connection_id_storage = config.connection_id_storage,
        .peer_address_validated = config.peer_address_validated,
        .tls = config.tls,
        .transport_parameters = config.transport_parameters,
        .crypto = .{
            .init(config.crypto.initial),
            .init(config.crypto.handshake),
            .init(config.crypto.app),
        },
        .crypto_sent = .{
            .{ .bytes = config.crypto_sent.initial },
            .{ .bytes = config.crypto_sent.handshake },
            .{ .bytes = config.crypto_sent.app },
        },
        .stream_table = .init(config.stream_slots),
        .streams = config.streams,
        .receive_window = .init(config.receive_limit),
        .send_window = .init(0),
        .streams_allowed = .{
            .bidi = config.max_streams_bidi,
            .uni = config.max_streams_uni,
        },
        .streams_advertised = .{
            .bidi = config.max_streams_bidi,
            .uni = config.max_streams_uni,
        },
        .initial = .{
            .send_keys = if (config.role == .client) client else server,
            .receive_keys = if (config.role == .client) server else client,
            // The handle points at the caller's `Recovery`, never at `Conn`, so
            // returning this value is safe. That is the whole reason `Loss`
            // exists.
            .recovery = placeAllRecovery(config.loss),
        },
    };
    if (config.peer) |peer| conn.adopt(peer);
    return conn;
}

/// The space for `id` with traffic keys installed, or `error.NoKeys` when there
/// is none to act on. A handshake or application space appears when its driver
/// does, and disappears when its keys are discarded; there is no third state.
pub fn spaceFor(self: *Conn, id: SpaceId) Error!*Space {
    self.pin();
    return self.spaceMaybe(id) orelse error.NoKeys;
}

/// The same, for a caller that already knows a missing space is not an error.
fn spaceMaybe(self: *Conn, id: SpaceId) ?*Space {
    self.pin();
    switch (id) {
        .initial => return if (self.initial) |*space| space else null,
        .handshake => return if (self.handshake) |*space| space else null,
        .app => return if (self.app) |*space| space else null,
    }
}

/// Drop a space and its keys: RFC 9001 §4.9 for the Handshake and 1-RTT keys,
/// RFC 9000 §17.2.2.1 for the Initial ones.
///
/// After this the space is absent, so a packet for it is `error.NoKeys` and the
/// datagram walk drops it, which is what a late Initial or a coalesced packet
/// for a level the peer has moved past needs (§12.2). The connection goes on:
/// the connection IDs, the packet number width, and the RTT estimate are the
/// connection's, not the space's.
pub fn discard(self: *Conn, id: SpaceId) Error!void {
    self.pin();
    const space = try self.spaceFor(id);
    space.discard();
    self.clear(id);
}

/// The two moments §17.2.2.1 names can arrive in either order, so discarding a
/// space that is already gone is not an error here.
fn discardIfPresent(self: *Conn, id: SpaceId) void {
    const space = self.spaceMaybe(id) orelse return;
    space.discard();
    self.clear(id);
}

/// Forget everything a space owned. The keys are already zeroed by
/// `Space.discard`; this is the rest.
///
/// §13.3's CRYPTO send buffer goes with them: there is nothing left to replay,
/// and a space that comes back — only a rebuilt Initial, after a Retry — starts
/// its CRYPTO stream at offset zero rather than at a stale one.
fn clear(self: *Conn, id: SpaceId) void {
    switch (id) {
        .initial => self.initial = null,
        .handshake => self.handshake = null,
        .app => self.app = null,
    }
    self.crypto_sent[@backingInt(id)].len = 0;
}

/// Take the first packet of a datagram and return its frames.
///
/// `plaintext` receives the payload. A packet that will not unprotect is an
/// error and leaves the machine untouched, which is what §5.5 requires of a
/// caller that then drops it.
///
/// `events` is the caller's report storage, and it describes this call alone: an
/// ACK frame is acted on here and reported in it, and the next call clears it.
/// `now` is when the datagram arrived, which is what the RTT sample and the loss
/// timer are measured from (RFC 9002 §5.1).
///
/// `error.NoSpace` from here is the caller's sizing, not the peer's: the report
/// has to hold one record per packet the space has in flight, because a call
/// that cannot describe every packet it clears refuses before it starts
/// (RFC 9002 A.7). Size `events` at least as long as that space's table.
///
/// `stream_events` is the caller's storage for which streams this packet
/// changed, one record per stream, returned in `Opened.streams`. It needs one
/// entry per distinct stream a single packet may name, so a table's length is
/// always enough.
pub fn feed(
    self: *Conn,
    datagram: []u8,
    plaintext: []u8,
    frames: []frame.Frame,
    stream_events: []StreamEvent,
    events: *Recovery.Events,
    now: Duration,
) Error!Opened {
    self.pin();
    // §10.2.1 and §10.2.2: a connection that has closed, either way, processes
    // no more frames. The caller decides whether to answer with its close again.
    if (self.state != .open) return error.Closed;

    const raw = try self.open(try self.locate(datagram), plaintext);
    const opened = try self.finish(raw, frames, stream_events, events, now);
    try self.commitPacket(raw.id, raw.packet_number);
    return opened;
}

/// Record the packet, then act on what the driver learned while it was
/// processed.
///
/// Per packet, not per datagram: one datagram may carry the packet that yields
/// a level's keys and the packet that needs them. The server's first flight is
/// Initial plus Handshake in one datagram (RFC 9000 §12.2), and a client's
/// Finished can be coalesced with its first 1-RTT packet, which §4.1.1 of
/// RFC 9001 lets a server send as soon as its own Finished goes out.
///
/// After the packet is accounted for, not before: a server confirms its
/// handshake on the client's Finished, and §4.9.2 discards the Handshake space
/// there, so the space the walk was recording into has to be finished with
/// first.
fn commitPacket(self: *Conn, id: SpaceId, number: u64) Error!void {
    self.commit(id, number);
    // The packet may have closed the connection, which is the one case where
    // there is nothing left to install and no error to report: the caller gets
    // the Opened it asked for.
    if (self.state != .open) return;
    try self.installSpaces();
}

/// One packet of a datagram, located and assigned to a space, before it is
/// unprotected.
const Located = struct {
    /// The space the packet belongs to, from its form and type (§12.3).
    id: SpaceId,
    /// Exactly this packet's bytes. A short header has no Length field, so it
    /// runs to the end of the datagram (§12.2).
    bytes: []u8,
    /// Where the packet number starts, counted from `bytes[0]`.
    pn_offset: u32,
    /// §7.2: the Source Connection ID a long header names, which is what the
    /// recipient puts in its own Destination Connection ID. Null for a short
    /// header, because it carries only the destination.
    source_connection_id: ?[]const u8,
};

fn locate(self: *const Conn, bytes: []u8) Error!Located {
    if (bytes.len == 0) return error.Truncated;

    if (bytes[0] & 0x80 == 0) {
        // §17.3.1: a short header omits the destination connection ID length,
        // so reading one needs the connection and not only its bytes.
        const short = try packet.parseShort(bytes, self.localConnectionIdLen());
        return .{
            .id = .app,
            .bytes = bytes,
            .pn_offset = @intCast(1 + short.destination_connection_id.len),
            .source_connection_id = null,
        };
    }

    const long = try packet.parseLong(bytes);
    if (long.version != .v1) return error.UnsupportedVersion;
    const id: SpaceId = switch (long.kind) {
        .initial => .initial,
        .handshake => .handshake,
        // §12.3 puts 0-RTT in the application space. This build has no 0-RTT
        // keys, so a 0-RTT packet is opened, at best, under 1-RTT keys and
        // fails to authenticate: that is the drop §12.2 asks for.
        .zero_rtt => .app,
        // `parseLong` refuses a Retry, which has no Length field.
        .retry => unreachable,
    };

    return .{
        .id = id,
        .bytes = bytes[0 .. @as(usize, long.body_offset) + long.length],
        .pn_offset = long.body_offset,
        .source_connection_id = long.source_connection_id,
    };
}

/// A packet that opened, before its frames are parsed: the part of `Opened`
/// that says which space and packet number the payload belongs to.
const Raw = struct {
    id: SpaceId,
    packet_number: u64,
    header_len: u32,
    packet_len: u32,
    payload: []u8,
};

/// Unprotect one packet and account for it: the packet number, the received
/// range, and the key discards §17.2.2.1 orders.
fn open(self: *Conn, at: Located, plaintext: []u8) Error!Raw {
    const space = try self.spaceFor(at.id);

    const opened = try protection.openPacket(
        &space.receive_keys,
        at.bytes,
        at.pn_offset,
        space.largest_received,
        plaintext,
    );

    // §7.2: the long header's Source Connection ID is the name the peer uses,
    // and it is only trusted once the packet it arrived in decrypts.
    try self.nameFrom(at);

    // §6.2 and §17.2.5.2: once anything from the server has been processed, a
    // Version Negotiation is discarded and a Retry is too late. A packet that
    // decrypted is the server having spoken, whatever it said inside.
    if (self.attempt) |*attempt| attempt.onServerResponse();

    // §17.2.2.1: a server lets its Initial keys go when it first processes a
    // Handshake packet. A client's moment is the first Handshake packet it
    // sends, which `writeHandshake` covers.
    if (at.id == .handshake and self.role == .server) self.discardIfPresent(.initial);

    // A packet length is a `u32` everywhere else in this package, because a
    // datagram is at most 65527 bytes (§12.2), so the narrowing is total.
    std.debug.assert(at.bytes.len <= std.math.maxInt(u32));
    return .{
        .id = at.id,
        .packet_number = opened.packet_number,
        .header_len = opened.header_len,
        .packet_len = @intCast(at.bytes.len),
        .payload = opened.payload,
    };
}

/// §7.2: learn the name this endpoint sends to, and discard a long header that
/// names somebody else.
///
/// The first Initial (or a Retry before it) sets a client's Destination
/// Connection ID; after that a long header with a different Source Connection ID
/// is not this connection's and is dropped. A server's destination came from the
/// client's first packet, so for it the check is only ever a check. The name is
/// copied out of the receive buffer, which the caller reuses.
fn nameFrom(self: *Conn, at: Located) Error!void {
    const supplied = at.source_connection_id orelse return;
    const same = std.mem.eql(u8, supplied, self.destination_connection_id);

    // A packet that already names this destination confirms the name and needs
    // nothing copied, whatever form it has.
    if (same) {
        self.named = true;
        return;
    }

    if (self.role == .server or self.named) return error.WrongConnectionId;

    // §7.2 names only the first Initial or Retry. A Handshake packet cannot
    // name an endpoint, and its keys cannot exist before the Initial that
    // carried them, so anything else arriving first is not this connection's.
    if (at.id != .initial) return error.WrongConnectionId;

    if (self.connection_id_storage.len < supplied.len) return error.NoSpace;
    const copy = self.connection_id_storage[0..supplied.len];
    @memcpy(copy, supplied);
    self.destination_connection_id = copy;
    self.named = true;
}

/// Parse the payload's frames and act on the ones the machine owns.
///
/// A CRYPTO frame is reassembled per level and handed to the driver (§19.6), a
/// STREAM, RESET_STREAM, or STOP_SENDING frame goes to its stream (§2.1, §3.2,
/// §3.5), MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS raise the credit they name
/// (§19.9 to §19.11), HANDSHAKE_DONE confirms the handshake (§19.20), an ACK is
/// the loss detector's (§6.1 of RFC 9002), and PADDING has no meaning to hand
/// anyone (§19.1). Everything else is written to the caller's array in wire
/// order, because the machine has no home for it yet.
///
/// A frame that will not parse is a connection error (§12.4), not a dropped
/// packet: the datagram walk drops undecryptable packets and nothing else.
fn finish(
    self: *Conn,
    raw: Raw,
    frames: []frame.Frame,
    stream_events: []StreamEvent,
    events: *Recovery.Events,
    now: Duration,
) Error!Opened {
    // A report describes one packet. The loss detector clears it again when it
    // fills it; this is what keeps a packet with no ACK in it from leaving the
    // previous call's records behind for the caller to read twice.
    events.clear();

    var cursor: Cursor = .init(raw.payload);
    var count: usize = 0;
    var stream_count: usize = 0;
    while (!cursor.atEnd()) {
        switch (try frame.read(&cursor)) {
            .crypto => |crypto| try self.feedCrypto(raw.id, crypto.offset, crypto.data),
            .stream => |frame_stream| try self.onStreamFrame(
                raw.id,
                frame_stream,
                stream_events,
                &stream_count,
            ),
            .reset_stream => |reset| try self.onResetStream(
                raw.id,
                reset,
                stream_events,
                &stream_count,
            ),
            .stop_sending => |stop| try self.onStopSending(
                raw.id,
                stop,
                stream_events,
                &stream_count,
            ),
            .ack => |ack| try self.onAck(raw.id, ack, events, now),
            .max_data => |maximum| try self.onMaxDataFrame(raw.id, maximum),
            .max_stream_data => |data| try self.onStreamCredit(
                raw.id,
                data.stream_id,
                data.maximum,
            ),
            .max_streams => |streams| try self.onMaxStreams(raw.id, streams),
            .handshake_done => try self.onHandshakeDone(raw.id),
            .padding => {},
            .connection_close => |value| {
                // §10.2.2: the peer closed, so this endpoint enters the
                // draining state and sends nothing else. The frame still comes
                // back to the caller, which is the only place the code it was
                // given can be reported.
                self.state = .draining;
                if (count == frames.len) return error.NoSpace;
                frames[count] = .{ .connection_close = value };
                count += 1;
            },
            else => |parsed| {
                if (count == frames.len) return error.NoSpace;
                frames[count] = parsed;
                count += 1;
            },
        }
    }

    return .{
        .space = raw.id,
        .packet_number = raw.packet_number,
        .header_len = raw.header_len,
        .packet_len = raw.packet_len,
        .frames = frames[0..count],
        .streams = stream_events[0..stream_count],
        .payload = raw.payload,
    };
}

/// Act on an acknowledgment: the RTT sample, the packets it clears, and the ones
/// it declares lost (RFC 9002 §5, §6.1).
///
/// An ACK acknowledges the space it arrives in (§13.2.1), which is the space the
/// packet that carried it opened in.
fn onAck(
    self: *Conn,
    id: SpaceId,
    ack: frame.Ack,
    events: *Recovery.Events,
    now: Duration,
) Error!void {
    const space = try self.spaceFor(id);

    // §19.3.1: an acknowledgment of a packet number this endpoint never used is
    // not reordering, it is a peer that is broken or lying, and the caller's
    // answer is to close the connection. `next_packet_number` is the first
    // number not yet sent, so everything below it exists.
    if (space.next_packet_number == 0) return error.InvalidAckRange;
    if (ack.largest >= space.next_packet_number) return error.InvalidAckRange;

    var scaled = ack;
    scaled.delay = self.ackDelay(ack.delay);
    try space.recovery.onAckReceived(&scaled, now, self.recoveryOptions(), events);
}

/// §19.3: the wire's ACK Delay is microseconds scaled down by the sender's
/// exponent, and `Recovery` measures nanoseconds. The sender is the peer, so its
/// exponent decodes the field, never ours. Before the peer's parameters arrive
/// the default of §18.2 applies, which is what `PeerParameters` carries.
///
/// Both multiplications saturate: a peer that sends 2^62 microseconds is asking
/// for a delay that never fits, and a saturated delay is one that is never
/// subtracted from the sample (§5.3).
fn ackDelay(self: *const Conn, delay: u64) Duration {
    const exponent = (self.peer orelse PeerParameters{}).ack_delay_exponent;
    const factor = @as(u64, 1) << @intCast(exponent);
    const microseconds = delay *| factor;
    return microseconds *| std.time.ns_per_us;
}

/// The options the loss detector is called with, from the caller's configuration
/// and the one thing only the handshake driver knows.
/// The recovery options this connection's spaces are driven with.
///
/// `RecoveryDriver` takes them on every call, and three of the four facts are
/// the machine's to keep: the peer's `max_ack_delay`, whether its address is
/// validated, and whether the TLS driver has confirmed the handshake. A caller
/// that owns the driver asks here instead of reconstructing them.
/// Whether the handshake is confirmed (§4.1.2 of RFC 9001).
///
/// The two roles learn it differently. A server is confirmed when its TLS
/// handshake completes, which is what the driver reports. A client is confirmed
/// when HANDSHAKE_DONE arrives, which no TLS driver can see, so the driver's
/// word does not make it so; a client MAY also count an acknowledged 1-RTT
/// packet, and this does not.
pub fn handshakeConfirmed(self: *const Conn) bool {
    if (self.handshake_done) return true;
    if (self.role == .client) return false;
    if (self.tls) |tls| return tls.confirmed();
    return false;
}

pub fn recoveryOptions(self: *const Conn) Recovery.Options {
    return .{
        .max_ack_delay = self.max_ack_delay,
        // §5.3: `max_ack_delay` bounds a reported delay only once the handshake
        // is confirmed, and §4.1.2 of RFC 9001 is where both roles learn that.
        .handshake_confirmed = self.handshakeConfirmed(),
        .peer_address_validated = self.peer_address_validated,
    };
}

/// Account for a packet whose payload parsed: its number and the range it fills.
///
/// Deliberately after `finish`, not inside `open`. An acknowledgment is for a
/// packet the machine processed (§13.2), and a packet whose frames did not parse
/// is not one: if parsing fails the connection is closing and the ACK is
/// worthless, but recording it first would also make a caller that retried the
/// parse believe the number had already been seen.
fn commit(self: *Conn, id: SpaceId, number: u64) void {
    const space = self.spaceMaybe(id) orelse {
        // The packet opened in this space and nothing between then and here
        // discards it: a client's Initial keys go on a Handshake send, a
        // server's on a Handshake packet, and both leave this space alone.
        std.debug.assert(false);
        return;
    };
    space.largest_received = if (space.largest_received) |largest|
        @max(largest, number)
    else
        number;
    space.record(number);
}

/// Give CRYPTO bytes to the driver in order, whatever order they arrived in.
///
/// Without a driver the bytes are consumed and go nowhere, which keeps a
/// driver-less machine usable for packet-level work.
fn feedCrypto(self: *Conn, id: SpaceId, offset: u64, data: []const u8) Error!void {
    const tls = self.tls orelse return;

    const delivery = try self.crypto[@backingInt(id)].onData(offset, data);
    const level: seam.Level = switch (id) {
        .initial => .initial,
        .handshake => .handshake,
        .app => .app,
    };
    if (delivery.first.len != 0) try tls.feed(level, delivery.first);
    if (delivery.second.len != 0) try tls.feed(level, delivery.second);
}

/// A datagram, walked one packet at a time.
///
/// §12.2 shapes this in three ways. Long header packets delimit themselves with
/// their Length field, so the next one starts where this one ended; a short
/// header has no Length field, so it runs to the end of the datagram and must
/// be the last packet in it. And a packet that cannot be processed is dropped
/// rather than fatal, which RFC 9001 §5.5 repeats for one that will not
/// unprotect: an attacker corrupting a datagram cannot kill the connection, so
/// the walk goes on to the next packet.
///
/// Every `next` hands out the frames of one packet in the caller's `plaintext`
/// buffer, which is why the caller pulls rather than receives a list: the frames
/// of two packets cannot share one buffer.
pub const Datagram = struct {
    /// The caller's receive buffer, as it arrived. `next` unprotects in place,
    /// because that is what removing header protection is: an XOR over these
    /// bytes.
    bytes: []u8,
    /// The read position, through the one read walker in this package.
    cursor: Cursor,
    /// Packets that the datagram delimited and that did not open: a bad tag, a
    /// space with no keys yet, or bytes with no readable end. Bounded by the
    /// datagram: the smallest packet is over twenty bytes (§17.2), so a 65527
    /// byte datagram cannot reach the `u16` limit, and `next` asserts it.
    dropped: u16 = 0,

    pub fn init(bytes: []u8) Datagram {
        return .{ .bytes = bytes, .cursor = .init(bytes) };
    }

    /// The next packet that opened, or null when there is nothing left to
    /// process. The frames are valid until the next call.
    pub fn next(
        self: *Datagram,
        conn: *Conn,
        plaintext: []u8,
        frames: []frame.Frame,
        stream_events: []StreamEvent,
        events: *Recovery.Events,
        now: Duration,
    ) Error!?Opened {
        conn.pin();
        // The same rule as `feed`: a closed connection walks nothing.
        if (conn.state != .open) return error.Closed;

        while (self.cursor.remaining() > 0) {
            const rest = self.bytes[self.cursor.pos..];
            const at = conn.locate(rest) catch {
                // The packet has no readable end, so there is no boundary to
                // find the next one at. The rest of the datagram goes with it.
                std.debug.assert(self.dropped < std.math.maxInt(u16));
                std.debug.assert(self.dropped < std.math.maxInt(u16));
                self.dropped += 1;
                self.cursor.pos = @intCast(self.bytes.len);
                return null;
            };
            _ = self.cursor.skip(@intCast(at.bytes.len));

            const raw = conn.open(at, plaintext) catch |err| switch (err) {
                // The plaintext buffer is the caller's to size, and running out
                // of it is not the peer's doing: report it, do not drop it.
                error.NoSpace => return err,
                else => {
                    std.debug.assert(self.dropped < std.math.maxInt(u16));
                    self.dropped += 1;
                    continue;
                },
            };
            // Once the packet opened, a bad frame is a connection error, not a
            // packet to skip: the peer's own bytes arrived intact and say
            // something invalid (§12.4).
            const opened = try conn.finish(raw, frames, stream_events, events, now);
            try conn.commitPacket(raw.id, raw.packet_number);
            return opened;
        }
        return null;
    }
};

/// Install the packet number spaces the driver has reported traffic secrets
/// for, and act on the handshake's confirmation.
///
/// This is not writing a packet. A server whose driver has nothing to say calls
/// this after it has read the handshake's bytes, because that is what makes its
/// application space exist; the alternative was calling `writeHandshake` and
/// getting null back, which made a key installation look like a send.
///
/// It hands the driver this endpoint's transport parameters once (§8.2), builds
/// whichever of Handshake and 1-RTT is missing and reported (§7.1 of RFC 9001),
/// and discards the Handshake keys once the handshake is confirmed (§4.9.2): a
/// server learns that here, from its TLS driver, and a client learns it where a
/// HANDSHAKE_DONE frame lands. A driver that has already reported everything
/// makes it a no-op, so a caller may call it after every packet. Without a
/// driver it does nothing.
pub fn installSpaces(self: *Conn) Error!void {
    self.pin();
    if (self.state != .open) return error.Closed;
    const tls = self.tls orelse return;

    switch (self.parameters) {
        // §8.2: ours go out in the first message, so the driver takes them
        // before it is asked for one.
        .pending => {
            std.debug.assert(ownParametersAgree(self));
            try tls.setTransportParameters(self.transport_parameters);
            self.parameters = .handed;
        },
        .handed => {},
    }
    if (self.peer == null) try self.adoptPeer(tls);
    try self.installSecrets(tls);

    // §4.9.2: the Handshake keys go with confirmation, whichever way this
    // endpoint learned it. `installSpaces` runs on the handshake's own call, so
    // a server's completion is noticed here; a client's HANDSHAKE_DONE is
    // noticed where the frame lands.
    if (self.handshakeConfirmed()) self.discardIfPresent(.handshake);
}

/// Adopt the peer's transport parameters the moment the driver has them.
///
/// Null from the driver means they have not arrived (a client before the
/// server's EncryptedExtensions), and the call is a no-op until they do. Once
/// they have, they are decoded, checked against what this endpoint saw on the
/// wire (§7.3), and become the limits every stream is born with. Anything wrong
/// with them is `error.TransportParameter`, whatever the decoder called it:
/// the caller's answer is one close code, TRANSPORT_PARAMETER_ERROR (§20.1).
///
/// §7.4 puts the adoption before the first stream: the limits are read when a
/// stream opens, so the assertions state that nothing opened or sent before them.
fn adoptPeer(self: *Conn, tls: seam.Driver) Error!void {
    std.debug.assert(self.peer == null);
    const bytes = (try tls.peerTransportParameters()) orelse return;

    // The decoder's role is the endpoint reading: a server refuses the four
    // parameters only a server may send (§18.2).
    const reader: TransportParameters.Role = switch (self.role) {
        .client => .client,
        .server => .server,
    };
    var decoded: TransportParameters = .{};
    TransportParameters.decode(bytes, reader, &decoded) catch return error.TransportParameter;
    try self.checkIdentity(&decoded);

    // §7.4: the limits are read at the first stream and the first byte, so
    // nothing may have used the old zeros.
    std.debug.assert(self.send_window.sent == 0);
    std.debug.assert(self.opened_local.bidi == 0);
    std.debug.assert(self.opened_local.uni == 0);
    self.adopt(.fromDecoded(&decoded));
}

/// §7.3: the connection IDs in the peer's parameters must be the ones this
/// endpoint saw in the packets, or an on-path attacker rewrote them.
///
/// Both roles check `initial_source_connection_id`, which must name the peer as
/// this endpoint addresses it. A client also checks the two a server alone
/// sends: `original_destination_connection_id` must be the name the client's
/// first Initial carried, and `retry_source_connection_id` must be the Retry's
/// Source Connection ID when there was a Retry and absent when there was none.
/// A server never receives those two, because the decoder refuses them.
fn checkIdentity(self: *const Conn, decoded: *const TransportParameters) Error!void {
    const initial_source = decoded.initial_source_connection_id orelse
        return error.TransportParameter;
    if (!std.mem.eql(u8, initial_source, self.destination_connection_id)) {
        return error.TransportParameter;
    }
    if (self.role == .server) return;

    const attempt = self.attempt.?;
    const original = decoded.original_destination_connection_id orelse
        return error.TransportParameter;
    if (!std.mem.eql(u8, original, attempt.original_destination_connection_id)) {
        return error.TransportParameter;
    }

    // A Retry's Source Connection ID can be zero-length, so "was there one" is
    // the attempt's memory and not the length of the copy.
    const retry_source = decoded.retry_source_connection_id;
    if (!attempt.retried) {
        if (retry_source != null) return error.TransportParameter;
        return;
    }
    const echoed = retry_source orelse return error.TransportParameter;
    if (!std.mem.eql(u8, echoed, self.retry_source_connection_id)) {
        return error.TransportParameter;
    }
}

/// Make the peer's parameters the limits this connection works under (§4.1,
/// §4.6, §5.3 of RFC 9002). Called once, before any stream or data.
fn adopt(self: *Conn, peer: PeerParameters) void {
    std.debug.assert(self.peer == null);
    self.peer = peer;
    self.send_window = .init(peer.max_data);
    self.send_streams = peer.stream_data;
    self.peer_max_streams = peer.max_streams;
    self.max_ack_delay = peer.max_ack_delay;
}

/// Whether the parameters this endpoint hands the driver say what its
/// configuration does: the receive window, the stream counts, and its own
/// connection ID. A peer enforces what the bytes say and this machine enforces
/// what the configuration says, so a mismatch is a connection that closes a
/// legal peer.
///
/// Total, like `streamsValid`: bytes that do not decode do not agree, and no
/// input is an error. The bytes are decoded as the peer would read them, which
/// is the opposite role's reading.
fn ownParametersAgree(self: *const Conn) bool {
    const reader: TransportParameters.Role = switch (self.role) {
        .client => .server,
        .server => .client,
    };
    var decoded: TransportParameters = .{};
    TransportParameters.decode(self.transport_parameters, reader, &decoded) catch return false;

    if ((decoded.initial_max_data orelse 0) != self.receive_window.window) return false;
    if ((decoded.initial_max_streams_bidi orelse 0) != self.streams_advertised.bidi) return false;
    if ((decoded.initial_max_streams_uni orelse 0) != self.streams_advertised.uni) return false;
    const source = decoded.initial_source_connection_id orelse return false;
    return std.mem.eql(u8, source, self.source_connection_id);
}

/// Drain one handshake message into a packet.
///
/// The machine's half of the TLS seam's sending side: it installs the spaces
/// the driver has reported secrets for (`installSpaces`), then writes the next
/// message as a CRYPTO frame at the level the driver chose. The caller drains
/// until this returns null, one packet per call.
///
/// `frames` is the caller's scratch for the CRYPTO frame and `out` the
/// datagram, because the machine owns no buffer of its own. Null means the
/// driver has nothing to send, which is also how a caller learns the handshake
/// has no more bytes after the spaces were installed.
///
/// `now` dates the packet: handshake bytes are ack-eliciting and in flight like
/// any other (§6.1 of RFC 9002).
pub fn writeHandshake(self: *Conn, frames: []u8, out: []u8, now: Duration) Error!?u32 {
    // Before the driver is asked: a message taken from it cannot be given back.
    try self.installSpaces();
    const tls = self.tls orelse return null;

    const message = (try tls.next()) orelse return null;
    const id: SpaceId = switch (message.level) {
        .initial => .initial,
        .handshake => .handshake,
        .app => .app,
    };

    _ = try self.spaceFor(id);

    // §13.3: the bytes are kept so a lost packet's CRYPTO data can be sent again
    // at the same offset, and so a rebuilt space can replay them. The capacity is
    // the caller's, and a message that does not fit is refused by name here,
    // before any of it goes on the wire: half a ClientHello fails at the far end
    // and says nothing useful there. The driver's message is consumed by the
    // `next` above, so this is the caller's CRYPTO_BUFFER_EXCEEDED (§20.1), not
    // a call to retry.
    const sent = &self.crypto_sent[@backingInt(id)];
    if (message.bytes.len > sent.bytes.len - @as(usize, sent.len)) return error.NoSpace;
    const offset: u64 = sent.len;

    var writer: Writer = .init(frames);
    try frame.write(&writer, .{ .crypto = .{ .offset = offset, .data = message.bytes } });

    const total = try self.writeFrames(id, writer.written(), out, .data(now));

    // After the seal: a frame that never left must not be replayed as though it
    // had, or the peer would see the same offset twice with different data the
    // next time the machine composed it.
    std.debug.assert(message.bytes.len <= std.math.maxInt(u32));
    @memcpy(sent.bytes[sent.len..][0..message.bytes.len], message.bytes);
    sent.len += @intCast(message.bytes.len);

    // §17.2.2.1: the client's Initial keys go when its first Handshake packet
    // is sent. The packet is sealed; nothing needs them again.
    if (id == .handshake and self.role == .client) self.discardIfPresent(.initial);

    return total;
}

/// What a loss in `id`'s space needs to be re-sent: the CRYPTO bytes this
/// endpoint has sent there, from offset zero (§13.3).
///
/// The machine cannot know which of them were acknowledged — an ACK names packet
/// numbers, and mapping those back to frames is the packet-to-frame table this
/// design deliberately does not keep — so a replay is the whole flight, and the
/// peer discards the parts it already has by offset (§19.6).
///
/// Idempotent on purpose: the answer is what has been sent in the space, so a
/// caller that calls twice gets the same bytes and does not have to remember
/// whether it already replayed. Empty for a space with no keys, so a discarded
/// space never hands back stale handshake bytes.
pub fn replayCrypto(self: *const Conn, id: SpaceId) []const u8 {
    const sent = self.crypto_sent[@backingInt(id)];
    return sent.bytes[0..sent.len];
}

/// Install every space the driver can give secrets for, once each. A driver may
/// report a level on every call; the machine asks only while a space is missing.
fn installSecrets(self: *Conn, tls: seam.Driver) Error!void {
    if (self.handshake != null and self.app != null) return;

    // The suite is asked for only where a secret exists to protect with it, and
    // never defaulted: a machine that picked a suite would protect packets the
    // peer cannot read. Asked before any secret, the driver's answer is a
    // placeholder — a TLS client does not know the suite until ServerHello
    // (RFC 8446 §4.1.3) — so acting on it would refuse a connection over a
    // suite nobody chose. Each level asks for itself, because the application
    // secrets arrive after the handshake and the answer is final by then.
    if (self.handshake == null) {
        if (try tls.secrets(.handshake)) |secrets| {
            try self.installSpace(.handshake, secrets, try tls.suite().protectionSuite());
        }
    }
    if (self.app == null) {
        if (try tls.secrets(.app)) |secrets| {
            // RFC 9001 §8.2: never 1-RTT on guessed limits. The peer's
            // parameters are adopted first, and a driver that reports the
            // application secrets without them has skipped the extension.
            if (self.peer == null) return error.TransportParameter;
            try self.installSpace(.app, secrets, try tls.suite().protectionSuite());
        }
    }
}

/// Build a space from the secrets a driver reported, with the suite it
/// negotiated.
fn installSpace(
    self: *Conn,
    id: SpaceId,
    secrets: seam.Secrets,
    suite: protection.Suite,
) Error!void {
    std.debug.assert(id != .initial);
    const client = try protection.deriveKeys(secrets.client, suite);
    const server = try protection.deriveKeys(secrets.server, suite);
    const space: Space = .{
        .send_keys = if (self.role == .client) client else server,
        .receive_keys = if (self.role == .client) server else client,
        .recovery = placeRecovery(self.loss, id),
    };
    switch (id) {
        // Initial keys are derived from the connection ID in `init`, and a
        // driver never has them (§5.2).
        .initial => unreachable,
        .handshake => self.handshake = space,
        .app => self.app = space,
    }
}

/// Whether the stream configuration can honour the limits it advertises.
///
/// Three invariants, all of them the caller's numbers rather than a peer's
/// frames. §4.1: a stream may not advertise a window it cannot hold, so a ring
/// shorter than its limit would turn a legal frame into backpressure. And a
/// limit with no ring behind it describes a stream that claims to receive and
/// cannot. The table needs one slot per stream it may hold, or `open` fails at
/// runtime with a table that was never going to fit.
///
/// The third is identity: no two byte budgets may share storage. Two slots over
/// one ring, or a send buffer that is also the receive ring, is one stream's
/// bytes landing where another's already are, and neither half can detect it.
/// It is the same bug class as two loss tables over one buffer, which
/// `lossTablesValid` refuses for the same reason.
///
/// Kept as a predicate rather than an inline loop so a test can drive every bad
/// shape directly: the assertion at `init` is a programmer-error check, and
/// there is no way to expect a panic in this Zig version.
fn streamsValid(slots: []const StreamTable.Slot, streams: []const Stream) bool {
    if (slots.len != streams.len) return false;
    for (streams, 0..) |*entry, index| {
        if (entry.recv_buffer.len == 0) {
            if (entry.recv_limit_bytes != 0) return false;
        } else {
            if (entry.recv_buffer.len < entry.recv_limit_bytes) return false;
        }

        // A stream's own two halves first, then every slot after this one; the
        // pair before it was compared when it was this one. Comparing a stream
        // with itself would report its send buffer against itself, so the two
        // halves are asked separately.
        if (buffersOverlap(entry.send_buffer, entry.recv_buffer)) return false;
        for (streams[index + 1 ..]) |*other| {
            if (streamsOverlap(entry, other)) return false;
        }
    }
    return true;
}

/// Whether any of two streams' byte budgets share storage.
fn streamsOverlap(a: *const Stream, b: *const Stream) bool {
    if (buffersOverlap(a.send_buffer, b.send_buffer)) return true;
    if (buffersOverlap(a.send_buffer, b.recv_buffer)) return true;
    if (buffersOverlap(a.recv_buffer, b.send_buffer)) return true;
    if (buffersOverlap(a.recv_buffer, b.recv_buffer)) return true;
    return false;
}

/// Whether two caller byte buffers share any storage.
///
/// An empty buffer holds nothing, so it overlaps nothing, whichever address it
/// was sliced from.
fn buffersOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0) return false;
    if (b.len == 0) return false;

    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    return a_start < b_start + b.len and b_start < a_start + a.len;
}

/// Whether every space has a sent table to record into.
///
/// `Recovery.space` refuses an empty slice, because a space with no table would
/// report no lost packets and the caller would never learn to resend them. That
/// is a configuration error, so it is asserted once at `init` rather than
/// surfacing as a write that cannot proceed. A predicate, like `streamsValid`,
/// so the shapes can be tested without expecting a panic.
fn lossTablesValid(loss: Loss) bool {
    if (loss.sent_initial.len == 0) return false;
    if (loss.sent_handshake.len == 0) return false;
    if (loss.sent_app.len == 0) return false;

    // Two spaces over one table would overwrite each other's records, and a
    // record holds the packet number its own space uses: a caller that handed
    // the same buffer to, say, Initial and Handshake would see the two space's
    // losses reported as each other's. A buffer per space is the configuration
    // this type asks for, so overlapping ones are refused here.
    if (tablesOverlap(loss.sent_initial, loss.sent_handshake)) return false;
    if (tablesOverlap(loss.sent_initial, loss.sent_app)) return false;
    if (tablesOverlap(loss.sent_handshake, loss.sent_app)) return false;
    return true;
}

/// Build one space's loss state into the caller's storage and point at it.
///
/// Every creation of a `Conn.Space` goes through here, so there is exactly one
/// place that knows where the state lives and no space can hold a copy.
fn placeRecovery(loss: Loss, id: SpaceId) *Recovery.Space {
    const place = &loss.spaces[@backingInt(id)];
    place.* = loss.shared.space(loss.table(id));
    return place;
}

/// Place all three spaces and return the Initial one.
///
/// `init` is the first caller, and it places Handshake and 1-RTT too even
/// though their keys do not exist yet: a `RecoveryDriver` is built over the
/// whole array, and a slot that was never written is an uninitialized read
/// waiting for the first timer query. Keys arriving later replace the loss
/// state where it stands.
fn placeAllRecovery(loss: Loss) *Recovery.Space {
    var initial: *Recovery.Space = undefined;
    for (std.enums.values(SpaceId)) |id| {
        const placed = placeRecovery(loss, id);
        if (id == .initial) initial = placed;
    }
    return initial;
}

/// Whether two caller tables share any storage.
fn tablesOverlap(a: []const Recovery.SentPacket, b: []const Recovery.SentPacket) bool {
    const size = @sizeOf(Recovery.SentPacket);
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    const a_end = a_start + a.len * size;
    const b_end = b_start + b.len * size;
    return a_start < b_end and b_start < a_end;
}

/// The stream with `id`, or null when it is not open.
pub fn stream(self: *Conn, id: u64) ?*Stream {
    self.pin();
    const slot = self.stream_table.get(id) orelse return null;
    return streamOf(slot);
}

fn streamOf(slot: *StreamTable.Slot) *Stream {
    if (slot.recv) |recv| return @fieldParentPtr("recv", recv);
    return @fieldParentPtr("send", slot.send.?);
}

fn freeStream(self: *Conn) ?usize {
    for (self.streams, 0..) |*entry, index| {
        if (!entry.isOpen()) return index;
    }
    return null;
}

/// Open a stream this endpoint initiates (§2.1), with a send half and, for a
/// bidirectional stream, a receive half too.
///
/// The sender's initial limit is the peer's, from
/// `PeerParameters.stream_data`'s `bidi_remote` or `uni` depending on the stream's kind;
/// MAX_STREAM_DATA raises it through `Stream.send.onMaxStreamData`. An id the
/// peer initiates is `error.WrongDirection`: that stream already exists on the
/// receive side, and `joinStream` is how its sending half comes into being.
pub fn openStream(self: *Conn, id: u64) Error!*Stream {
    self.pin();
    if (self.stream_table.get(id) != null) return error.AlreadyOpen;

    const initiator: stream_id.Initiator = switch (self.role) {
        .client => .client,
        .server => .server,
    };
    // §2.1: the two low bits say who opens a stream, and this endpoint may only
    // open its own.
    if (stream_id.initiator(id) != initiator) return error.WrongDirection;

    // §4.6: "An endpoint MUST NOT open more streams than permitted by the
    // current stream limit set by its peer." The count includes closed streams,
    // so it is the ordinal of the id that has to fit, not how many are open.
    const credit = switch (stream_id.direction(id)) {
        .bidi => self.peer_max_streams.bidi,
        .uni => self.peer_max_streams.uni,
    };
    if (stream_id.index(id) >= credit) return error.NoStreamCredit;

    const index = self.freeStream() orelse return error.StreamLimit;
    const entry = &self.streams[index];
    entry.send = SendStream.init(id, entry.send_buffer, self.send_streams.forOpening(id));
    entry.halves = .send_only;

    if (stream_id.direction(id) == .bidi) {
        entry.recv = ReceiveStream.init(id, entry.recv_buffer, entry.recv_limit_bytes);
        entry.halves = .both;
        _ = try self.stream_table.open(id, &entry.send, &entry.recv);
    } else {
        _ = try self.stream_table.open(id, &entry.send, null);
    }
    self.noteOpened(id);
    return entry;
}

/// Record that a locally initiated stream existed, so a frame for it can be told
/// from a frame for a stream that never did.
fn noteOpened(self: *Conn, id: u64) void {
    const ordinal = stream_id.index(id);
    switch (stream_id.direction(id)) {
        .bidi => self.opened_local.bidi = @max(self.opened_local.bidi, ordinal + 1),
        .uni => self.opened_local.uni = @max(self.opened_local.uni, ordinal + 1),
    }
}

/// Whether this endpoint ever opened the locally initiated stream `id`.
///
/// A slot can be freed by `closeStream`, and §3.3 lets a delayed frame for the
/// old stream arrive after that. The high-water mark is what separates "never
/// created", which §19.5 and §19.8 make a connection error, from "created,
/// closed, and forgotten", which is a frame to ignore.
fn everOpened(self: *const Conn, id: u64) bool {
    const ordinal = stream_id.index(id);
    return switch (stream_id.direction(id)) {
        .bidi => ordinal < self.opened_local.bidi,
        .uni => ordinal < self.opened_local.uni,
    };
}

/// Take up the sending half of a stream the peer opened, so this endpoint can
/// answer on the same stream (§2.1).
///
/// Not the same act as `openStream`: nothing is created, the slot the peer's
/// frames already opened is reused, and the limit is the peer's
/// `initial_max_stream_data_bidi_local`, which the machine adopted into
/// `peer.stream_data` rather than being handed again. A one-way stream the
/// peer opened is `error.WrongDirection`, because §2.1 gives its only direction
/// to the peer.
pub fn joinStream(self: *Conn, id: u64) Error!*Stream {
    self.pin();
    const slot = self.stream_table.get(id) orelse return error.NotOpen;
    if (slot.send != null) return error.AlreadyOpen;
    if (stream_id.direction(id) != .bidi) return error.WrongDirection;

    const existing = streamOf(slot);
    std.debug.assert(existing.halves == .recv_only);
    existing.send = SendStream.init(id, existing.send_buffer, self.send_streams.bidi_local);
    existing.halves = .both;
    slot.send = &existing.send;
    return existing;
}

/// The stream for an incoming STREAM frame, opening it if this is the first
/// frame on it.
///
/// §2.1: a stream exists as soon as a frame for it arrives, so an unknown id is
/// the ordinary case and never an error. A full table is `error.StreamLimit`,
/// which the peer must see: §4.6 closes the connection with STREAM_LIMIT_ERROR.
fn streamFor(self: *Conn, id: u64) Error!*Stream {
    if (self.stream_table.get(id)) |slot| return streamOf(slot);

    const index = self.freeStream() orelse return error.StreamLimit;
    const entry = &self.streams[index];
    entry.recv = ReceiveStream.init(id, entry.recv_buffer, entry.recv_limit_bytes);
    entry.halves = .recv_only;
    _ = try self.stream_table.open(id, null, &entry.recv);
    return entry;
}

/// §4.6: free a stream's slot once both halves are finished, so the credit it
/// spent can be offered to the peer again.
///
/// The caller decides this, because it is the only one that knows the
/// application is finished with the stream: the machine can see that every byte
/// arrived and every acknowledgment came back, but not that nobody wants the
/// bytes any more. A stream that is not finished is refused rather than dropped,
/// because freeing its slot early would let the peer's next frame on that stream
/// open it again over the same buffers.
pub fn closeStream(self: *Conn, id: u64) Error!void {
    self.pin();
    const entry = self.stream(id) orelse return error.NotOpen;
    if (!streamFinished(entry)) return error.StreamState;

    try self.stream_table.close(id);
    // The buffers are the caller's and stay; the state is this slot's to lose,
    // so the next stream can use it.
    entry.halves = .unused;
    entry.send = undefined;
    entry.recv = undefined;

    // §4.6: a stream the peer opened spent its credit, and freeing the slot is
    // what lets that credit come back. A stream this endpoint opened frees a slot
    // and grants nothing, because no credit was spent on it.
    const local: stream_id.Initiator = switch (self.role) {
        .client => .client,
        .server => .server,
    };
    if (stream_id.isLocal(id, local)) return;
    switch (stream_id.direction(id)) {
        .bidi => self.streams_allowed.bidi += 1,
        .uni => self.streams_allowed.uni += 1,
    }
}

/// Whether both halves of a stream are in a terminal state (§3.1, §3.2): the
/// send side has nothing left to acknowledge, and the receive side has nothing
/// left to read.
fn streamFinished(entry: *const Stream) bool {
    const send_done = switch (entry.halves) {
        .send_only, .both => switch (entry.send.state) {
            .data_recvd, .reset_recvd => true,
            .ready, .send, .data_sent, .reset_sent => false,
        },
        .unused, .recv_only => true,
    };
    if (!send_done) return false;
    return switch (entry.halves) {
        .recv_only, .both => switch (entry.recv.state) {
            .data_read, .reset_read => true,
            .recv, .size_known, .data_recvd, .reset_recvd => false,
        },
        .unused, .send_only => true,
    };
}

fn onStreamFrame(
    self: *Conn,
    space: SpaceId,
    frame_stream: frame.Stream,
    stream_events: []StreamEvent,
    stream_count: *usize,
) Error!void {
    // §12.4: Initial and Handshake packets carry no STREAM frames.
    if (space != .app) return error.WrongFrameSpace;

    // §19.8: a STREAM frame for a send-only stream, or for a locally initiated
    // stream this endpoint never created, is STREAM_STATE_ERROR. A stream it
    // created and has since closed is a delayed frame to ignore (§3.3), which
    // `everOpened` is what tells apart.
    if (self.stream(frame_stream.id)) |known| {
        if (!known.canRecv()) return error.StreamState;
    } else if (locallyInitiated(self, frame_stream.id)) {
        if (!everOpened(self, frame_stream.id)) return error.StreamState;
        return;
    }

    const entry = try self.streamFor(frame_stream.id);
    const before = entry.recv.highest;
    // §3.2: what the application can see is the contiguous run from its read
    // point, so that end and the Data Recvd state are what a report is about.
    // Both are read before the frame lands; the transitions afterwards are the
    // facts the caller could not have known.
    const readable_before = entry.recv.contiguous_end;
    const done_before = entry.recv.state == .data_recvd;
    switch (try entry.recv.onData(frame_stream.offset, frame_stream.data, frame_stream.fin)) {
        .accepted => {},
        // The ring is smaller than the window this stream advertised. The
        // caller sized both, and the machine cannot honour a limit it cannot
        // hold; §4.1 makes that the caller's number to get right, not a silent
        // truncation here.
        .backpressure => return error.NoSpace,
    }

    // §4.1: the connection window counts the highest offset reached on every
    // stream, so what moves it is the delta of this stream's own highest. The
    // counter inside the stream is the only thing that may raise it, and this
    // subtraction is the one place the two meet: assert it here rather than
    // trusting a reordering inside `ReceiveStream` never to lower it.
    std.debug.assert(entry.recv.highest >= before);
    try self.receive_window.onStreamProgress(entry.recv.highest - before);

    const news: StreamEvent = .{
        .stream_id = frame_stream.id,
        .readable = entry.recv.contiguous_end > readable_before,
        .finished = entry.recv.state == .data_recvd and !done_before,
    };
    // A frame that only filled a gap beyond the read point, or repeated bytes,
    // changes no answer the application can see yet.
    if (!news.readable and !news.finished) return;
    try noteStreamEvent(stream_events, stream_count, news);
}

/// §19.4: the peer gave up on the sending half of a stream it opened.
///
/// The receive half ends in Reset Recvd and the application reads the code with
/// `ReceiveStream.readReset`. §4.5 applies to the final size the frame names, so
/// a size that disagrees with one already known is FINAL_SIZE_ERROR and one past
/// the advertised limit is FLOW_CONTROL_ERROR, both from `onReset`.
fn onResetStream(
    self: *Conn,
    space: SpaceId,
    reset: frame.ResetStream,
    stream_events: []StreamEvent,
    stream_count: *usize,
) Error!void {
    // §12.4: RESET_STREAM belongs to the application space.
    if (space != .app) return error.WrongFrameSpace;

    // §19.4: a RESET_STREAM for a send-only stream is STREAM_STATE_ERROR. A
    // unidirectional stream this endpoint opened has no receive half to reset,
    // and the peer cannot have sent data on it.
    if (sendOnly(self, reset.stream_id)) return error.StreamState;

    const entry = try self.streamFor(reset.stream_id);
    const already_reset = entry.recv.state == .reset_recvd;
    try entry.recv.onReset(reset.error_code, reset.final_size);
    // §3.2: a duplicate that arrives after the application consumed the reset
    // changes nothing, so it is reported to nobody.
    if (already_reset) return;
    if (entry.recv.state != .reset_recvd) return;

    try noteStreamEvent(stream_events, stream_count, .{
        .stream_id = reset.stream_id,
        .reset = true,
    });
}

/// The stream a §3.2 flow-control frame names, opening or joining it if the
/// frame is allowed to.
///
/// §3.2: MAX_STREAM_DATA and STOP_SENDING both open a bidirectional stream the
/// peer initiated, and either can arrive before any STREAM frame does. A frame
/// for a locally initiated stream that was never created is STREAM_STATE_ERROR;
/// one for a stream this endpoint opened and has since closed is a delayed frame
/// to ignore (§3.3), which `null` is.
fn streamForCredit(self: *Conn, id: u64) Error!?*Stream {
    if (self.stream(id)) |entry| {
        if (entry.canSend()) return entry;
        // §2.1: a bidirectional stream the peer opened is ours to send on too,
        // and joining it is what creates that half.
        const joined = try self.joinStream(id);
        return joined;
    }

    if (locallyInitiated(self, id)) {
        if (!everOpened(self, id)) return error.StreamState;
        return null;
    }

    _ = try self.streamFor(id);
    const joined = try self.joinStream(id);
    return joined;
}

/// §19.9: the peer raised the connection-wide allowance.
fn onMaxDataFrame(self: *Conn, space: SpaceId, maximum: u64) Error!void {
    // §12.4: the flow-control frames belong to the application space.
    if (space != .app) return error.WrongFrameSpace;
    self.onMaxData(maximum);
}

/// §19.10: the peer raised a stream's allowance, which is credit to send.
///
/// Same rules as STOP_SENDING about which stream can exist: a receive-only
/// stream is STREAM_STATE_ERROR, a locally initiated one that was never created
/// is too, and a peer-initiated bidirectional stream is opened by the frame.
fn onStreamCredit(
    self: *Conn,
    space: SpaceId,
    id: u64,
    maximum: u64,
) Error!void {
    // §12.4: the flow-control frames belong to the application space.
    if (space != .app) return error.WrongFrameSpace;
    if (receiveOnly(self, id)) return error.StreamState;

    const entry = (try self.streamForCredit(id)) orelse return;
    entry.send.onMaxStreamData(maximum);
}

/// §19.20: the server has confirmed the handshake, and §4.9.2 of RFC 9001 says
/// the Handshake keys go with that.
///
/// Only a client receives this frame. A server that sees one has a peer
/// pretending to be this endpoint, which is PROTOCOL_VIOLATION.
fn onHandshakeDone(self: *Conn, space: SpaceId) Error!void {
    // §12.4: HANDSHAKE_DONE is a 1-RTT frame.
    if (space != .app) return error.WrongFrameSpace;
    if (self.role == .server) return error.ProtocolViolation;

    self.handshake_done = true;
    self.discardIfPresent(.handshake);
}

/// §19.11: the peer raised how many streams this endpoint may open.
///
/// The count is cumulative over the connection's life and includes the streams
/// already closed, so it is a high-water mark and never a concurrent count. A
/// frame that does not raise it is ignored (§4.6); one that permits a stream id
/// §17.1 cannot encode is FRAME_ENCODING_ERROR.
fn onMaxStreams(self: *Conn, space: SpaceId, value: frame.MaxStreams) Error!void {
    // §12.4: MAX_STREAMS belongs to the application space.
    if (space != .app) return error.WrongFrameSpace;
    // §19.11: "This value cannot exceed 2^60", because a stream id is four
    // times the ordinal and has to fit in 62 bits.
    if (value.maximum > max_streams) return error.StreamCountTooLarge;

    switch (value.direction) {
        .bidi => self.peer_max_streams.bidi = @max(self.peer_max_streams.bidi, value.maximum),
        .uni => self.peer_max_streams.uni = @max(self.peer_max_streams.uni, value.maximum),
    }
}

/// §19.11: the largest MAX_STREAMS count that can describe a stream id.
const max_streams: u64 = 1 << 60;

/// §19.5: the peer will not read this stream any more.
///
/// The sending half is reset in place (`SendStream.onStopSending`), and the
/// caller owes the RESET_STREAM that says so; the machine composes no frame the
/// caller did not ask for. The report carries the code for that frame.
fn onStopSending(
    self: *Conn,
    space: SpaceId,
    stop: frame.StopSending,
    stream_events: []StreamEvent,
    stream_count: *usize,
) Error!void {
    // §12.4: STOP_SENDING belongs to the application space.
    if (space != .app) return error.WrongFrameSpace;

    // §19.5: a receive-only stream is one this endpoint can never send on, and
    // a locally initiated stream that was never opened has no sending half to
    // stop. Both are STREAM_STATE_ERROR.
    if (receiveOnly(self, stop.stream_id)) return error.StreamState;

    const entry = (try self.streamForCredit(stop.stream_id)) orelse return;
    const owed = try entry.send.onStopSending(stop.error_code);
    // A stream already in Data Sent keeps the request for later (§3.5), and one
    // that is already reset or terminal owes nothing.
    if (!owed) return;
    try noteStreamEvent(stream_events, stream_count, .{
        .stream_id = stop.stream_id,
        .reset_owed = stop.error_code,
    });
}

/// Whether this endpoint may never receive on `id`: a unidirectional stream it
/// opened itself.
fn sendOnly(self: *const Conn, id: u64) bool {
    if (stream_id.direction(id) != .uni) return false;
    return locallyInitiated(self, id);
}

/// Whether this endpoint may never send on `id`: a unidirectional stream the
/// peer opened.
fn receiveOnly(self: *const Conn, id: u64) bool {
    if (stream_id.direction(id) != .uni) return false;
    return !locallyInitiated(self, id);
}

fn locallyInitiated(self: *const Conn, id: u64) bool {
    const local: stream_id.Initiator = switch (self.role) {
        .client => .client,
        .server => .server,
    };
    return stream_id.initiator(id) == local;
}

/// Record one stream's change in the caller's list.
///
/// One record per stream: a packet may carry several frames for one stream, and
/// the flags are facts about the packet rather than about the frame. A list too
/// small to name a stream the packet changed is `error.NoSpace`, never a
/// silently missing record.
fn noteStreamEvent(events: []StreamEvent, count: *usize, event: StreamEvent) Error!void {
    for (events[0..count.*]) |*existing| {
        if (existing.stream_id != event.stream_id) continue;
        existing.readable = existing.readable or event.readable;
        existing.finished = existing.finished or event.finished;
        existing.reset = existing.reset or event.reset;
        if (event.reset_owed) |code| existing.reset_owed = code;
        return;
    }

    if (count.* == events.len) return error.NoSpace;
    events[count.*] = event;
    count.* += 1;
}

/// One stream's share of a packet: how much of it the caller wants written, in
/// the caller's order.
pub const Offer = struct {
    stream_id: u64,
    /// The most bytes of this stream to put in this packet.
    length: u32,
};

/// One STREAM frame a packed packet carried (§19.8).
pub const Written = struct {
    stream_id: u64,
    /// The wire offset of the first byte, which is the stream's own cursor and
    /// not the caller's offer.
    offset: u64,
    /// How many bytes went. Zero for the frame that carries only the FIN.
    length: u32,
    fin: bool,
};

/// How much of an offer list one packet used.
///
/// The shape is the contract: a caller that has five streams to fill and room
/// for three is told exactly where to resume, so a packet is never wasted on a
/// refusal when part of it would have gone.
pub const Consumed = struct {
    /// Offers the machine is finished with: everything sendable went in. A
    /// stream with nothing to send is finished with too, so it cannot block the
    /// list behind it. The caller resumes at this index.
    taken: u32,
    /// Bytes of `offers[taken]` that went in, when the machine stopped inside
    /// that offer rather than finishing it. Zero when the next offer was not
    /// touched at all, so the caller re-offers it unchanged.
    partial: u32,
};

/// What one packed packet carried, and the number the peer will call it by.
pub const Packet = struct {
    /// How many bytes of `out` are the packet.
    length: u32,
    /// The packet number these frames went out under. The machine is the only
    /// party that knows it, and a resend queue needs the pairing to answer
    /// "which frames were in packet 5" when that packet is declared lost.
    number: u64,
    /// One record per STREAM frame, in wire order, borrowed from the caller's
    /// storage.
    frames: []const Written,
    /// How much of the caller's list this packet used.
    consumed: Consumed,
    /// Payload room this packet was given and did not use, when its offer list
    /// ran out before the room did. Zero when the packet stopped on an offer
    /// that would not fit: it was then full for the list it was given, and the
    /// bytes reserved for that offer's header are not room a caller could use.
    /// A caller reads this to know whether the congestion window it granted
    /// bought everything the application had.
    remaining: u32,
};

/// What a packing call is given.
pub const Packing = struct {
    /// The streams to fill from, in the caller's order. This is scheduling, and
    /// the machine does not do it: which stream deserves the next byte is the
    /// caller's policy, like congestion control and retransmission.
    offers: []const Offer,
    /// The caller's scratch for the encoded frames, as in `writeHandshake`.
    frames: []u8,
    /// Where the packet is sealed.
    out: []u8,
    /// One record per offer, so it must be at least as long as `offers`.
    written: []Written,
    /// The payload bytes the caller will allow here: its congestion window and
    /// its MTU decision, neither of which the machine owns. The packet is also
    /// bounded by what `out` can carry and by the peer's connection-wide
    /// allowance (§4.1).
    max_payload: u32,
    /// When the packet leaves.
    now: Duration,
};

/// Seal one packet carrying the caller's offers, in order, as STREAM frames.
///
/// The machine packs; it does not schedule. The caller says which streams and
/// how much of each, the machine writes what fits and reports exactly what it
/// consumed, and the caller re-offers from there. Two answers, not one: `null`
/// means nothing fit at all — the window had no room — while a returned packet
/// means the window had room and it was used, even if only part of one offer
/// went in.
///
/// Every refusal is decided before a stream's cursor moves, because a segment
/// that was taken and not written is data the peer will never be sent.
///
/// `Packet.remaining` is the other half of that report: how much of the payload
/// room this packet was given it did not use. The budget comes from the caller's
/// congestion controller, which the machine does not own, so a caller writing
/// several packets asks the controller again and uses `remaining` to learn
/// whether the last packet was worth the window it spent.
pub fn writeStreams(self: *Conn, packing: Packing) Error!?Packet {
    if (self.state != .open) return error.Closed;
    // The packet this writes is a 1-RTT one, and the sent table has to have room
    // for it: §6.1 of RFC 9002 records every packet that asks for an
    // acknowledgment.
    const space = try self.spaceFor(.app);
    if (packing.offers.len == 0) return null;
    std.debug.assert(packing.written.len >= packing.offers.len);

    // Every offer is checked before any segment is taken, so an error cannot
    // leave one stream's cursor ahead of a packet that never left.
    for (packing.offers) |offer| {
        const entry = self.stream(offer.stream_id) orelse return error.NotOpen;
        if (!entry.canSend()) return error.NotOpen;
    }

    // §4.1 and §4.2: three numbers bound this packet — the peer's
    // connection-wide allowance, the caller's budget, and what the output buffer
    // can carry after the header, the packet number, and the tag.
    const allowed: u64 = @min(packing.max_payload, self.send_window.available());
    const room: u32 = @intCast(@min(
        allowed,
        @min(@as(u64, packing.frames.len), appPayloadRoom(self, packing.out)),
    ));
    if (room == 0) return null;
    if (!space.recovery.hasRoom()) return error.NoSpace;

    const number = space.next_packet_number;
    var writer: Writer = .init(packing.frames);
    var count: usize = 0;
    var taken: u32 = 0;
    var partial: u32 = 0;

    for (packing.offers) |offer| {
        const entry = self.stream(offer.stream_id) orelse unreachable;
        const offered = entry.send.peekSegment(offer.length) orelse {
            // Nothing sendable: the offer is finished with, so the caller moves
            // past it instead of offering it again forever.
            taken += 1;
            continue;
        };

        const overhead = streamFrameOverhead(offer.stream_id, offered.offset);
        const left = room - writer.pos;
        if (left <= overhead) break;
        const capacity = left - overhead;
        const length: u32 = @intCast(@min(@as(u64, offered.data.len), capacity));

        // §19.8: FIN rides only the frame that reaches the final size, which is
        // why trimming an offer can drop the flag and `nextSegment` decides.
        const segment = entry.send.nextSegment(length) orelse unreachable;
        // The overhead above is an upper bound on the frame's own bytes, and the
        // data was clamped to what is left after it, so this cannot run out.
        frame.write(&writer, .{ .stream = .{
            .id = offer.stream_id,
            .offset = segment.offset,
            .data = segment.data,
            .fin = segment.fin,
            .length_present = true,
        } }) catch unreachable;
        try self.send_window.onSent(segment.data.len);

        packing.written[count] = .{
            .stream_id = offer.stream_id,
            .offset = segment.offset,
            .length = @intCast(segment.data.len),
            .fin = segment.fin,
        };
        count += 1;

        if (segment.data.len != offered.data.len) {
            partial = @intCast(segment.data.len);
            break;
        }
        taken += 1;
    }

    // Nothing went in: no packet, no packet number, and no stream moved.
    if (count == 0) return null;

    const length = try self.writeFrames(.app, writer.written(), packing.out, .data(packing.now));
    return .{
        .length = length,
        .number = number,
        .frames = packing.written[0..count],
        .consumed = .{ .taken = taken, .partial = partial },
        // §19.8 frames reserve their widest header before the data is measured,
        // so a packet that stopped on an offer has bytes in hand that no next
        // frame could use. That is a full packet, not room for the caller.
        .remaining = if (taken == packing.offers.len) room - writer.pos else 0,
    };
}

/// The most a STREAM frame for `id` at `offset` costs before its data: the type
/// byte, the stream ID, the offset, and a length varint at its widest (§19.8).
fn streamFrameOverhead(stream_id_value: u64, offset: u64) u32 {
    const size = 1 + varint.size(@intCast(stream_id_value)) +
        varint.size(@intCast(offset)) + max_varint_len;
    return @intCast(size);
}

/// How many payload bytes a 1-RTT packet in `out` can carry: the buffer, less
/// the short header (§17.3.1), the packet number, and the tag.
fn appPayloadRoom(self: *const Conn, out: []u8) u32 {
    const overhead = 1 + self.destination_connection_id.len +
        @as(usize, self.packet_number_len) + protection.tag_length;
    if (out.len <= overhead) return 0;
    return @intCast(@min(out.len - overhead, std.math.maxInt(u32)));
}

/// §4.2: apply a MAX_DATA the peer sent, raising the connection-wide allowance.
pub fn onMaxData(self: *Conn, limit: u64) void {
    self.pin();
    self.send_window.onMaxData(limit);
}

/// §4.2: the MAX_DATA and every MAX_STREAM_DATA the application's reads have
/// made due, in that order, written into `out` and returned as a prefix of it.
///
/// Reading a receive ring is the caller's act, so consumption is the only thing
/// that opens a window, and this is where the machine notices it. No limit
/// moves here: a frame that never leaves is a window the peer does not have, so
/// `onFlowControlSent` records the raises after the caller puts them on the
/// wire. Until then the same frames come back, which is what makes a caller
/// that ran out of packet room simply try again.
pub fn flowControlOwed(self: *Conn, out: []frame.Frame) []frame.Frame {
    self.pin();
    var count: usize = 0;

    if (self.receive_window.nextLimit(self.consumedBytes())) |limit| {
        if (count == out.len) return out[0..count];
        out[count] = .{ .max_data = limit };
        count += 1;
    }

    // §4.2: one frame per stream, in stream ID order, so two calls that see the
    // same state build the same list in the same places.
    for (self.stream_table.iterator()) |slot| {
        const recv = slot.recv orelse continue;
        const limit = recv.nextMaxStreamData() orelse continue;
        if (count == out.len) break;
        out[count] = .{ .max_stream_data = .{ .stream_id = recv.id, .maximum = limit } };
        count += 1;
    }

    // §4.6: freed streams are credit the peer may have again. Only what has
    // risen is sent, and the two directions are separate counters, so one frame
    // per direction at most.
    if (self.streams_allowed.bidi > self.streams_advertised.bidi) {
        if (count == out.len) return out[0..count];
        out[count] = .{ .max_streams = .{
            .direction = .bidi,
            .maximum = self.streams_allowed.bidi,
        } };
        count += 1;
    }
    if (self.streams_allowed.uni > self.streams_advertised.uni) {
        if (count == out.len) return out[0..count];
        out[count] = .{ .max_streams = .{
            .direction = .uni,
            .maximum = self.streams_allowed.uni,
        } };
        count += 1;
    }
    return out[0..count];
}

/// §4.2: record that `frames` went on the wire, so their limits apply. A limit
/// only ever rises here, the same rule a receiver applies to a MAX frame it
/// reads.
pub fn onFlowControlSent(self: *Conn, frames: []const frame.Frame) void {
    self.pin();
    for (frames) |value| {
        switch (value) {
            .max_data => |limit| self.receive_window.raise(limit),
            .max_stream_data => |data| {
                const entry = self.stream(data.stream_id) orelse continue;
                if (data.maximum > entry.recv.limit) entry.recv.limit = data.maximum;
            },
            // The same rule as MAX_DATA: a limit only ever rises, so a repeated
            // or reordered frame cannot walk the credit back.
            .max_streams => |limits| switch (limits.direction) {
                .bidi => self.streams_advertised.bidi = @max(self.streams_advertised.bidi, limits.maximum),
                .uni => self.streams_advertised.uni = @max(self.streams_advertised.uni, limits.maximum),
            },
            else => {},
        }
    }
}

/// §6.2: what a client does with a Version Negotiation packet.
///
/// The packet is not part of a connection — a server sends it before it has one,
/// and this package speaks one version — so it never reaches `feed`. The caller
/// parses it and asks; the machine remembers whether the server has said
/// anything else first, which is the rule that makes the answer `.ignore`.
///
/// The return type of `setup.VersionNegotiation.Action` has no "different
/// version" in it: a client that supports only the version it tried abandons the
/// attempt (§6.2), so a caller cannot negotiate into a version this package
/// cannot speak.
pub fn onVersionNegotiation(
    self: *Conn,
    response: *const packet.VersionNegotiation,
) Error!setup.VersionNegotiation.Action {
    self.pin();
    const attempt = if (self.attempt) |*attempt| attempt else return error.WrongRole;
    // The version this machine speaks, which is the only one it is built for.
    return attempt.onVersionNegotiation(response, .v1);
}

/// §17.2.5.2: what a client does with a Retry packet.
///
/// `retry` is the parsed packet and `raw` the bytes it came from, because the
/// integrity tag covers the bytes (§5.8 of RFC 9001). `.ignored` means the Retry
/// arrived after the server had already spoken, or after a 1-RTT packet, or is a
/// second one; `.accepted` means the connection has been rekeyed and its
/// handshake bytes are waiting in `replayCrypto(.initial)`.
///
/// The rekey does not go through `Conn.discard`: that forgets the level's CRYPTO
/// bytes, and the ClientHello this Retry exists to re-send lives in exactly that
/// buffer.
pub fn onRetry(self: *Conn, retry: *const packet.Retry, raw: []const u8) Error!setup.Client.Outcome {
    self.pin();
    const attempt = if (self.attempt) |*attempt| attempt else return error.WrongRole;

    // §17.2.5.2: a Retry that does not name this endpoint's own connection ID is
    // discarded. Checked before the integrity tag, like the state checks in
    // `Client.onRetry`, because it costs nothing and settles the question.
    if (!std.mem.eql(u8, retry.destination_connection_id, self.source_connection_id)) return .ignored;

    // The connection ID and token point into the datagram, which the caller will
    // reuse. Refused before anything is adopted, so a configuration too small for
    // them cannot half-accept a Retry.
    const adopted = retry.source_connection_id.len + retry.token.len;
    if (adopted > self.retry_storage.len) return error.NoSpace;

    const outcome = try attempt.onRetry(retry, raw);
    if (outcome == .ignored) return outcome;

    // §17.2.5.3: the client copies the Retry's Source Connection ID into the
    // Destination it uses from then on, and the token into every Initial it
    // sends. Both are copied out of the datagram first, because nothing here may
    // keep a pointer into it.
    const connection_id = retry.source_connection_id;
    @memcpy(self.retry_storage[0..connection_id.len], connection_id);
    @memcpy(self.retry_storage[connection_id.len..][0..retry.token.len], retry.token);
    self.destination_connection_id = self.retry_storage[0..connection_id.len];
    self.retry_source_connection_id = self.destination_connection_id;
    self.token = self.retry_storage[connection_id.len..][0..retry.token.len];

    self.rekeyInitial(self.destination_connection_id);
    return outcome;
}

/// RFC 9001 §5.2 with §17.2.5.3: the Initial keys come from the Destination
/// Connection ID, so a Retry means new keys, and the packet number does not
/// restart.
fn rekeyInitial(self: *Conn, destination_connection_id: []const u8) void {
    const secrets = protection.initialSecrets(destination_connection_id);
    const suite = protection.Suite.aes_128_gcm;
    const client = protection.deriveKeys(&secrets.client, suite) catch unreachable;
    const server = protection.deriveKeys(&secrets.server, suite) catch unreachable;

    // §17.2.5.2 lets a client accept a Retry only before anything arrived from
    // the server, and its Initial keys only go once it has sent a Handshake
    // packet, which needs that flight first. So the space is always here, and the
    // assert says so rather than letting a rejected Retry resurrect dead keys.
    std.debug.assert(self.initial != null);

    // §17.2.5.3: "A client MUST NOT reset the packet number for any packet
    // number space after processing a Retry packet." The counter is the one
    // thing the old space keeps.
    const next_packet_number = self.initial.?.next_packet_number;

    // A live space over the caller's table again: the packets sent under the old
    // keys were never seen by the server, so they are dropped rather than
    // declared lost, and a fresh `Recovery.Space` says exactly that. The RTT
    // estimate is the path's and is not touched (RFC 9002 A.2). The received
    // ranges are empty because a Retry is only accepted before anything arrived
    // (§17.2.5.2).
    self.initial = .{
        .send_keys = if (self.role == .client) client else server,
        .receive_keys = if (self.role == .client) server else client,
        .recovery = placeRecovery(self.loss, .initial),
        .next_packet_number = next_packet_number,
    };
}

/// §6.2.1 of RFC 9002: the peer has validated this endpoint's address, so an
/// acknowledgment may reset the PTO backoff again.
///
/// Only the caller can see this happen: it is the handshake, or a token the
/// caller's own anti-amplification policy accepts, and this machine owns
/// neither.
pub fn onPeerAddressValidated(self: *Conn) void {
    self.pin();
    self.peer_address_validated = true;
}

/// The bytes the application has taken out of every receive ring. §4.2 ties the
/// connection window to what was consumed, not to what arrived, because credit
/// the rings cannot back is credit this endpoint would have to refuse.
fn consumedBytes(self: *Conn) u64 {
    var consumed: u64 = 0;
    for (self.stream_table.iterator()) |slot| {
        const recv = slot.recv orelse continue;
        consumed += recv.read_offset;
    }
    return consumed;
}

/// The length of this endpoint's own connection ID: what the peer echoes as the
/// destination of the packets it sends, and what a short header leaves off the
/// wire (§17.3.1). Connection IDs do not change in this build, so the one the
/// connection was configured with is the one every packet from the peer names.
fn localConnectionIdLen(self: *const Conn) u32 {
    return @intCast(self.source_connection_id.len);
}

/// What a writer knows about a packet that is about to leave, and the machine
/// cannot: when it goes, whether it asks the peer for an acknowledgment, and
/// whether congestion control counts it. The machine never parses what it just
/// sealed, so these are the caller's answers.
///
/// Two flags in one struct rather than two positional arguments, because a caller
/// that swapped them would produce packets that are acknowledged but never counted
/// as in flight, or the reverse, and nothing on the wire would say so.
pub const Write = struct {
    /// When the packet leaves (§5.1 of RFC 9002 dates every sent packet).
    now: Duration,
    /// §13.2.1: the packet carries a frame that provokes an acknowledgment.
    ack_eliciting: bool,
    /// §7.1: the packet's bytes count against the congestion window.
    in_flight: bool,

    /// A packet carrying data: it asks for an acknowledgment and congestion
    /// control counts it. Every frame this machine writes except an ACK has that
    /// shape.
    pub fn data(now: Duration) Write {
        return .{ .now = now, .ack_eliciting = true, .in_flight = true };
    }
};

/// Seal a packet in `id`'s space carrying `frames`, which the caller already
/// encoded.
///
/// Initial and Handshake packets get a long header; an application packet gets
/// a short one, because §17.3 allows no other form for 1-RTT.
///
/// A packet that is ack-eliciting or in flight is recorded in `id`'s sent table
/// with its send time and size, which is what an incoming acknowledgment and the
/// loss timer later work on (§6.1 of RFC 9002). A full table is `error.NoSpace`
/// before anything is sealed, so the machine is left as it was found and the
/// caller's buffer holds no half packet.
pub fn writeFrames(self: *Conn, id: SpaceId, frames: []const u8, out: []u8, write: Write) Error!u32 {
    self.pin();
    // §10.2.1: a closing endpoint sends nothing but CONNECTION_CLOSE, and this
    // is where every other frame this machine writes goes out.
    if (self.state != .open) return error.Closed;
    return self.sealFrames(id, frames, out, write);
}

/// The body of `writeFrames`, without the closing check: the close itself has to
/// go out while the connection is already closing (§10.2.1 lets a closing
/// endpoint answer a late packet, and the answer is another CONNECTION_CLOSE).
fn sealFrames(self: *Conn, id: SpaceId, frames: []const u8, out: []u8, write: Write) Error!u32 {
    const space = try self.spaceFor(id);
    const pn = space.next_packet_number;
    const pn_len = self.packet_number_len;

    std.debug.assert(frames.len <= std.math.maxInt(u32));
    const tracked = write.ack_eliciting or write.in_flight;

    var writer: Writer = .init(out);
    const pn_offset = switch (id) {
        .initial, .handshake => (try packet.writeLong(&writer, .{
            .kind = if (id == .initial) .initial else .handshake,
            .destination_connection_id = self.destination_connection_id,
            .source_connection_id = self.source_connection_id,
            .packet_number_len = pn_len,
            .body_len = @as(u32, pn_len) + @as(u32, @intCast(frames.len)) + protection.tag_length,
            // §17.2.2: only an Initial carries one, which `writeLong` enforces
            // too.
            .token = if (id == .initial) self.token else "",
        })).packet_number,
        .app => (try packet.writeShort(&writer, .{
            .destination_connection_id = self.destination_connection_id,
            .packet_number_len = pn_len,
        })).packet_number,
    };
    try packet_number.write(&writer, pn, pn_len);

    const total: u32 = pn_offset + @as(u32, pn_len) + @as(u32, @intCast(frames.len)) + protection.tag_length;

    // Both refusals come before anything is sealed or recorded: a buffer too
    // small for the packet is the caller's number to fix, and a full table is a
    // packet whose frames nobody could ever be told to resend. Neither may leave
    // the sent table holding a record of a packet that never left.
    if (out.len < total) return error.NoSpace;
    if (tracked and !space.recovery.hasRoom()) return error.NoSpace;

    const sealed = try protection.sealPacket(&space.send_keys, pn, pn_offset, pn_len, frames, out);
    std.debug.assert(sealed == total);

    if (tracked) try space.recovery.onPacketSent(
        pn,
        write.now,
        write.ack_eliciting,
        write.in_flight,
        total,
    );

    space.next_packet_number += 1;

    // §17.2.5.2: a Retry that arrives after this endpoint has sent a 1-RTT
    // packet is discarded, because the handshake has plainly moved on.
    if (id == .app) {
        if (self.attempt) |*attempt| attempt.onOneRttSent();
    }

    return sealed;
}

/// Whether an acknowledgment is owed in `id`'s space: something has been
/// received there since the last one was sent. A space with no keys owes
/// nothing, because nothing in it can have arrived.
pub fn ackOwed(self: *Conn, id: SpaceId) bool {
    // §10.2.2: a draining endpoint sends nothing, so nothing is owed.
    if (self.state != .open) return false;
    const space = self.spaceMaybe(id) orelse return false;
    return space.ackOwed();
}

/// Every space that owes an acknowledgment right now, in the order to send them:
/// Initial, Handshake, then 1-RTT (§13.2.1), written into the caller's array.
///
/// The summary `flowControlOwed` is for the window frames, so a caller draining
/// datagrams does not have to know the three-space enum to ask each one in turn.
/// A space with no keys, or whose newest packet was already acknowledged, does
/// not appear, and a closed connection owes nothing. A caller whose array is
/// shorter than the list gets a prefix, and the rest is still owed the next time
/// it asks: the answer is recomputed, not consumed.
pub fn acksOwed(self: *Conn, out: []SpaceId) []const SpaceId {
    var count: usize = 0;
    for (std.enums.values(SpaceId)) |id| {
        if (count == out.len) break;
        if (!self.ackOwed(id)) continue;
        out[count] = id;
        count += 1;
    }
    return out[0..count];
}

/// Seal a packet carrying one ACK frame for everything received in `id`'s
/// space. An ACK is sent in the space it acknowledges (§13.2.1).
///
/// `now` goes with it because every packet is sent at a time, even one no loss
/// detector will ever ask about.
pub fn writeAck(self: *Conn, id: SpaceId, out: []u8, now: Duration) Error!u32 {
    if (self.state != .open) return error.Closed;
    const space = try self.spaceFor(id);

    var payload: [ack_payload_len]u8 = undefined;
    const bytes = try ackPayload(space, &payload);

    // §13.2.1 and §7.1 of RFC 9002: an acknowledgment on its own is neither
    // ack-eliciting nor in flight, so nothing will ever report it lost.
    const total = try self.writeFrames(id, bytes, out, .{ .now = now, .ack_eliciting = false, .in_flight = false });
    space.acked_through = space.largest_received;
    return total;
}

/// The payload of one ACK frame describing everything `space` has received.
///
/// Split from `writeAck` so that the widest frame a full range table can produce
/// can be read back by a test without a peer: the scratch is sized from
/// `range_capacity`, and this is where the two are held in step.
fn ackPayload(space: *const Space, payload: []u8) Error![]const u8 {
    if (space.range_count == 0) return error.NothingToAcknowledge;

    var scratch: [ack_range_scratch_len]u8 = undefined;
    var scratch_writer: Writer = .init(&scratch);
    const first = space.ranges[0];
    var previous_smallest = first.smallest;
    var index: usize = 1;
    while (index < space.range_count) : (index += 1) {
        const range = space.ranges[index];
        std.debug.assert(previous_smallest >= range.largest + 2);
        // Each value is below 2^62, so eight bytes hold it and the scratch,
        // sized for every pair at eight bytes, cannot run out.
        varint.write(&scratch_writer, previous_smallest - range.largest - 2) catch unreachable;
        varint.write(&scratch_writer, range.largest - range.smallest) catch unreachable;
        previous_smallest = range.smallest;
    }

    const ack: frame.Ack = .{
        .largest = first.largest,
        .delay = 0,
        .first_range = first.largest - first.smallest,
        .range_count = space.range_count - 1,
        .bytes = scratch_writer.written(),
        .ecn = null,
    };

    var writer: Writer = .init(payload);
    try frame.write(&writer, .{ .ack = ack });
    return writer.written();
}

/// What to tell the peer when the connection stops (§19.19 of RFC 9000).
pub const Close = struct {
    /// The transport error code of §20.1, or the application's own code when
    /// `application` is set.
    error_code: u64,
    /// §19.19's two frame types: 0x1d is the application's, and it has no frame
    /// type field because an application error cannot name a transport frame.
    application: bool = false,
    /// §19.19: the frame type that triggered a transport close, or 0 when the
    /// caller cannot say which one it was.
    frame_type: u64 = 0,
    /// Diagnostic text for the peer's log. This machine never reads it back.
    reason: []const u8 = "",
};

/// Seal a packet carrying one CONNECTION_CLOSE frame, and put the connection in
/// the closing state (§10.2.1).
///
/// The space is the highest-numbered one that has keys, because the peer may
/// already have discarded the lower ones (§4.9.2 of RFC 9001). `frames` is the
/// caller's scratch for the encoded frame, as in `writeStream`.
///
/// A call while already closing is not an error: §10.2.1 lets a closing endpoint
/// answer a packet that arrives too late, and this is the answer. It is not
/// required; a caller that would rather resend the packet it already has is
/// allowed to as well (§12.3 carves that out explicitly).
pub fn close(self: *Conn, args: Close, frames: []u8, out: []u8, now: Duration) Error!u32 {
    self.pin();
    const id: SpaceId = if (self.app != null)
        .app
    else if (self.handshake != null)
        .handshake
    else
        .initial;
    // §10.2.2: a draining endpoint sends no packets at all, not even this one.
    if (self.state == .draining) return error.Closed;
    // Refused by name before anything is sealed when no space has keys yet.
    if (self.spaceMaybe(id) == null) return error.NoKeys;

    var writer: Writer = .init(frames);
    try frame.write(&writer, .{ .connection_close = .{
        .application = args.application,
        .error_code = args.error_code,
        .frame_type = if (args.application) null else args.frame_type,
        .reason = args.reason,
    } });

    // §13.2.1 and §7.1 of RFC 9002: acknowledgments, PADDING, and
    // CONNECTION_CLOSE alone are neither ack-eliciting nor in flight, so the
    // packet is not recorded and nothing will ever call it lost.
    const total = try self.sealFrames(id, writer.written(), out, .{
        .now = now,
        .ack_eliciting = false,
        .in_flight = false,
    });
    self.state = .closing;
    return total;
}

/// A payload of `n` PING frames (§19.2): one byte, no fields, and nothing for
/// the machine to act on, which makes it the cheapest valid thing a test can
/// seal into a packet.
fn pings(comptime n: usize) [n]u8 {
    return @splat(0x01);
}
test "RFC 9000 §6.2, a version negotiation counts only before the server has spoken" {
    const dcid = [_]u8{0x91};
    var first_loss: LossTables = .{};
    var fresh: Conn = .init(.{
        .role = .client,
        .loss = first_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x92},
    });
    var second_loss: LossTables = .{};
    var answered: Conn = .init(.{
        .role = .client,
        .loss = second_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x92},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x92},
        .source_connection_id = &dcid,
    });

    // The versions a server might offer: one this package cannot speak, and the
    // one it does.
    const other = [_]u8{ 0xfa, 0x0a, 0x0a, 0x0a };
    const offers: packet.VersionNegotiation = .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
        .versions = &other,
    };
    const ours = [_]u8{ 0x00, 0x00, 0x00, 0x01 };
    const lists_v1: packet.VersionNegotiation = .{
        .destination_connection_id = &.{},
        .source_connection_id = &.{},
        .versions = &ours,
    };

    // §6.2: the packet never reaches `feed`, so the caller parses it and asks.
    // A client that supports only the version it tried abandons the attempt;
    // there is no other action in the type.
    try testing.expectEqual(
        setup.VersionNegotiation.Action.abandon,
        try fresh.onVersionNegotiation(&offers),
    );

    // The version the client selected may not appear in the list at all, so a
    // packet that lists it is invalid and discarded before anything else.
    try testing.expectEqual(
        setup.VersionNegotiation.Action.ignore,
        try fresh.onVersionNegotiation(&lists_v1),
    );

    // Once anything at all has arrived from the server, the negotiation is too
    // late, whichever version it names.
    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    const sent = try server.writeFrames(.initial, &pings(1), &datagram, .data(0));
    _ = try answered.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(
        setup.VersionNegotiation.Action.ignore,
        try answered.onVersionNegotiation(&offers),
    );

    // A server has no attempt to remember, and says so instead of pretending.
    try testing.expectError(error.WrongRole, server.onVersionNegotiation(&offers));
}

test "RFC 9000 §17.2.5.2, a 1-RTT packet ends the window for a Retry" {
    const dcid = [_]u8{0x93};
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x94},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x94},
        .source_connection_id = &dcid,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x51);
    const server_secret: [protection.secret_length]u8 = @splat(0x52);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [256]u8 = undefined;
    try testing.expect(!client.attempt.?.one_rtt_sent);
    // A packet in the application space is 1-RTT, and from then on a Retry is
    // discarded however well it validates.
    _ = try client.writeFrames(.app, &pings(1), &datagram, .data(0));
    try testing.expect(client.attempt.?.one_rtt_sent);
}

test "RFC 9000 §13.3, sent CRYPTO bytes are kept and the replay is idempotent" {
    const dcid = [_]u8{ 0x95, 0x96 };
    const hello = "ClientHello bytes";
    const finished = "Finished bytes";
    const client_secret: [protection.secret_length]u8 = @splat(0x61);
    const server_secret: [protection.secret_length]u8 = @splat(0x62);
    var stub: seam.Stub = .{
        .outbox = &.{
            .{ .level = .initial, .bytes = hello },
            .{ .level = .handshake, .bytes = finished },
        },
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
    };
    var sent_initial: [64]u8 = undefined;
    var sent_handshake: [64]u8 = undefined;
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x97},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x97}),
        .crypto_sent = .{ .initial = &sent_initial, .handshake = &sent_handshake },
    });

    var frames: [128]u8 = undefined;
    var datagram: [512]u8 = undefined;
    _ = (try client.writeHandshake(&frames, &datagram, 0)) orelse return error.TestUnexpectedResult;

    // §13.3: the bytes are kept where they went out, from offset zero, because
    // the driver will not offer them a second time.
    try testing.expectEqualStrings(hello, client.replayCrypto(.initial));
    // The same call twice is the same answer: a caller does not have to remember
    // whether it already replayed, and the flight is not consumed by asking.
    try testing.expectEqualStrings(hello, client.replayCrypto(.initial));
    // A level with nothing sent has nothing to replay.
    try testing.expectEqual(@as(usize, 0), client.replayCrypto(.handshake).len);

    // The second message is Handshake-level, and sending it takes the client's
    // Initial keys (§17.2.2.1). The Initial bytes go with them: a discarded
    // space hands back nothing rather than a flight nobody can read.
    _ = (try client.writeHandshake(&frames, &datagram, 0)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(finished, client.replayCrypto(.handshake));
    try testing.expect(client.initial == null);
    try testing.expectEqual(@as(usize, 0), client.replayCrypto(.initial).len);
}

test "RFC 9000 §20.1, a CRYPTO send buffer too small refuses the message" {
    const dcid = [_]u8{0x98};
    const hello = "ClientHello bytes that do not fit";
    const client_secret: [protection.secret_length]u8 = @splat(0x63);
    const server_secret: [protection.secret_length]u8 = @splat(0x64);
    var stub: seam.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = hello }},
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
    };
    var sent_initial: [8]u8 = undefined;
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x99},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x99}),
        .crypto_sent = .{ .initial = &sent_initial },
    });

    var frames: [128]u8 = undefined;
    var datagram: [512]u8 = undefined;
    const before = client.initial.?.next_packet_number;

    // The capacity is the caller's and the machine respects it: a message that
    // does not fit is refused before any of it is framed, because half a
    // ClientHello fails at the far end and says nothing useful there. §20.1 gives
    // the caller CRYPTO_BUFFER_EXCEEDED to close with.
    try testing.expectError(error.NoSpace, client.writeHandshake(&frames, &datagram, 0));
    // Nothing left: the packet number did not move and there is nothing to
    // replay. A truncated frame here would look like a sent flight.
    try testing.expectEqual(before, client.initial.?.next_packet_number);
    try testing.expectEqual(@as(usize, 0), client.replayCrypto(.initial).len);
}

test "RFC 9000 §8.1.2, every Initial a client sends carries the token" {
    const dcid = [_]u8{ 0xa1, 0xa2 };
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xa3},
        .token = "address-validation",
    });

    var datagram: [256]u8 = undefined;
    const sent = try client.writeFrames(.initial, &pings(1), &datagram, .data(0));
    const long = try packet.parseLong(datagram[0..sent]);
    // §8.1.2: "The client MUST include the token in all Initial packets it
    // sends, unless a Retry replaces the token with a newer one."
    try testing.expectEqualStrings("address-validation", long.token);
    // §17.2.2: no other packet type has a token field, and `writeLong` refuses
    // one, so a machine that ever set this for another space would fail loudly.
    const secret: [protection.secret_length]u8 = @splat(0x55);
    const keys = protection.deriveKeys(&secret, .aes_128_gcm) catch unreachable;
    plantSpace(&client, .handshake, keys, keys);
    var other: [256]u8 = undefined;
    const handshake = try client.writeFrames(.handshake, &pings(1), &other, .data(0));
    try testing.expectEqualStrings("", (try packet.parseLong(other[0..handshake])).token);
}

test "RFC 9000 §17.2.5.3, a Retry rekeys the Initial space and keeps its packet number" {
    const dcid = [_]u8{ 0xb1, 0xb2 };
    const client_scid = [_]u8{ 0xb3, 0xb4 };
    const retry_scid = [_]u8{ 0xb5, 0xb6, 0xb7 };
    const hello = "ClientHello bytes";
    const client_secret: [protection.secret_length]u8 = @splat(0x71);
    const server_secret: [protection.secret_length]u8 = @splat(0x72);
    var stub: seam.Stub = .{
        .outbox = &.{.{ .level = .initial, .bytes = hello }},
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
    };
    var sent_initial: [64]u8 = undefined;
    var retry_storage: [64]u8 = undefined;
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &client_scid,
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &client_scid),
        .crypto_sent = .{ .initial = &sent_initial },
        .retry_storage = &retry_storage,
    });

    var frames: [128]u8 = undefined;
    var datagram: [512]u8 = undefined;
    _ = (try client.writeHandshake(&frames, &datagram, 0)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 1), client.initial.?.next_packet_number);

    // The server challenges (§17.2.5), naming its own connection ID and a token.
    var retry_bytes: [256]u8 = undefined;
    const retry_length = try setup.Retry.write(&retry_bytes, &dcid, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &retry_scid,
        .token = "retry-token",
    });
    const retry = try packet.parseRetry(try packet.parseInvariant(retry_bytes[0..retry_length]));

    // §17.2.5.2: the tag validates against the client's first Destination
    // Connection ID, which is why the machine kept it as the "original" one.
    try testing.expectEqual(
        setup.Client.Outcome.accepted,
        try client.onRetry(&retry, retry_bytes[0..retry_length]),
    );
    try testing.expectEqualSlices(u8, &retry_scid, client.destination_connection_id);
    try testing.expectEqualStrings("retry-token", client.token);
    // §17.2.5.3: the packet number is not reset, and it did not restart here.
    try testing.expectEqual(@as(u64, 1), client.initial.?.next_packet_number);
    // §13.3: the ClientHello survives the rekey, because it is the thing the
    // Retry exists to make the client send again.
    try testing.expectEqualStrings(hello, client.replayCrypto(.initial));

    // The connection ID and token were borrowed from the datagram, and the caller
    // reuses that buffer for the next packet. The machine copied them, so
    // overwriting the bytes it read changes nothing about what it sends.
    @memset(retry_bytes[0..retry_length], 0xee);

    // The keys are the ones the server derives from its own Source Connection ID
    // (§5.2 of RFC 9001), which is what makes the retried Initial readable at
    // all. The client re-sends its flight at offset zero under the new keys, and
    // the server opens it and sees packet number 1: continued, not restarted.
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &retry_scid,
        .destination_connection_id = &client_scid,
        .source_connection_id = &retry_scid,
    });
    var payload: [128]u8 = undefined;
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .crypto = .{
        .offset = 0,
        .data = client.replayCrypto(.initial),
    } });
    const resent = try client.writeFrames(.initial, writer.written(), &datagram, .data(0));

    const long = try packet.parseLong(datagram[0..resent]);
    try testing.expectEqualStrings("retry-token", long.token);
    try testing.expectEqualSlices(u8, &retry_scid, long.destination_connection_id);

    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var plaintext: [512]u8 = undefined;
    var frames_in: [8]frame.Frame = undefined;
    const opened = try server.feed(datagram[0..resent], &plaintext, &frames_in, &stream_events, &report, 0);
    try testing.expectEqual(.initial, opened.space);
    try testing.expectEqual(@as(u64, 1), opened.packet_number);
}

test "RFC 9000 §17.2.5.2, a Retry that is not ours, or is late, is ignored" {
    const dcid = [_]u8{0xb8};
    const client_scid = [_]u8{ 0xb9, 0xba };
    const retry_scid = [_]u8{ 0xbb, 0xbc };
    var retry_storage: [64]u8 = undefined;
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &client_scid,
        .connection_id_storage = &adopted_cid,
        .retry_storage = &retry_storage,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &client_scid,
        .source_connection_id = &retry_scid,
    });

    var retry_bytes: [256]u8 = undefined;
    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var frames: [8]frame.Frame = undefined;

    // A Retry that names some other connection: discarded before its tag is even
    // checked, and the connection is untouched.
    const elsewhere = [_]u8{ 0xcc, 0xcd };
    const wrong_length = try setup.Retry.write(&retry_bytes, &dcid, .{
        .destination_connection_id = &elsewhere,
        .source_connection_id = &retry_scid,
        .token = "retry-token",
    });
    const wrong = try packet.parseRetry(try packet.parseInvariant(retry_bytes[0..wrong_length]));
    try testing.expectEqual(setup.Client.Outcome.ignored, try client.onRetry(&wrong, retry_bytes[0..wrong_length]));
    try testing.expectEqualSlices(u8, &dcid, client.destination_connection_id);
    try testing.expectEqualStrings("", client.token);

    // The same Retry, correctly addressed, after anything at all has arrived
    // from the server: too late (§17.2.5.2).
    const sent = try server.writeFrames(.initial, &pings(1), &datagram, .data(0));
    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    _ = try client.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);
    // §7.2: that Initial named the server, so the destination is its Source
    // Connection ID now.
    try testing.expectEqualSlices(u8, &retry_scid, client.destination_connection_id);

    const length = try setup.Retry.write(&retry_bytes, &dcid, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &retry_scid,
        .token = "retry-token",
    });
    const late = try packet.parseRetry(try packet.parseInvariant(retry_bytes[0..length]));
    try testing.expectEqual(setup.Client.Outcome.ignored, try client.onRetry(&late, retry_bytes[0..length]));
    // The late Retry changed nothing: the name the server gave still stands.
    try testing.expectEqualSlices(u8, &retry_scid, client.destination_connection_id);

    // A server has no attempt, and says so rather than pretending it ignored a
    // packet it was never meant to see.
    try testing.expectError(error.WrongRole, server.onRetry(&late, retry_bytes[0..length]));
}

test "RFC 9000 §4.6, a finished stream returns its credit as MAX_STREAMS" {
    const dcid = [_]u8{0xc1};
    var ring: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{ .{ .recv_buffer = &ring, .recv_limit_bytes = 64 }, .{} };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xc2},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0xc2},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
        .max_streams_bidi = 1,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x31);
    const server_secret: [protection.secret_length]u8 = @splat(0x32);
    installApp(&client, &server, client_secret, server_secret);

    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var owed: [4]frame.Frame = undefined;

    // Nothing has closed, so nothing is owed.
    try testing.expectEqual(@as(usize, 0), server.flowControlOwed(&owed).len);

    // The peer opens stream 0 and finishes it.
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = "done",
        .fin = true,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    _ = try server.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);

    // The receive half has every byte but the application has not read it, so
    // the stream is not finished and freeing its slot is refused: a peer's next
    // frame would open it again on the same buffers.
    try testing.expectError(error.StreamState, server.closeStream(0));

    const entry = server.stream(0) orelse return error.TestUnexpectedResult;
    var read_buffer: [16]u8 = undefined;
    const read = try entry.recv.readInto(&read_buffer);
    try testing.expectEqualStrings("done", read_buffer[0..read]);

    try server.closeStream(0);
    try testing.expect(server.stream(0) == null);

    // §4.6: the credit comes back as a raise the caller can send, and only once.
    const due = server.flowControlOwed(&owed);
    try testing.expectEqual(@as(usize, 1), due.len);
    try testing.expectEqual(frame.Direction.bidi, due[0].max_streams.direction);
    try testing.expectEqual(@as(u64, 2), due[0].max_streams.maximum);
    // Deciding is not raising: until the frame leaves, it is still owed.
    try testing.expectEqual(@as(usize, 1), server.flowControlOwed(&owed).len);
    try testing.expectEqual(@as(u64, 1), server.streams_advertised.bidi);

    server.onFlowControlSent(due);
    try testing.expectEqual(@as(u64, 2), server.streams_advertised.bidi);
    try testing.expectEqual(@as(usize, 0), server.flowControlOwed(&owed).len);

    // A frame that names a lower count cannot walk the credit back.
    server.onFlowControlSent(&.{.{ .max_streams = .{ .direction = .bidi, .maximum = 1 } }});
    try testing.expectEqual(@as(u64, 2), server.streams_advertised.bidi);
}

test "RFC 9000 §4.6, closing a stream this endpoint opened grants no credit" {
    const dcid = [_]u8{0xc3};
    var send_buffer: [64]u8 = undefined;
    var ring: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .send_buffer = &send_buffer, .recv_buffer = &ring, .recv_limit_bytes = 64 },
        .{},
    };
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xc4},
        .stream_slots = &slots,
        .streams = &streams,
        .peer = .{ .max_data = 64, .stream_data = .{ .uni = 64 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
        .max_streams_bidi = 1,
    });

    var owed: [4]frame.Frame = undefined;

    // A locally opened unidirectional stream — the client's first is 2 — written
    // and acknowledged to its final size, so its only half is terminal.
    const entry = try client.openStream(2);
    try entry.send.write("bytes");
    try entry.send.finish();
    var sent: u64 = 0;
    while (entry.send.nextSegment(64)) |next| {
        sent += next.data.len;
        try entry.send.onAck(next.offset, @intCast(next.data.len));
    }
    try testing.expectEqual(@as(u64, 5), sent);
    try testing.expectEqual(SendStream.State.data_recvd, entry.send.state);

    try client.closeStream(2);
    try testing.expect(client.stream(2) == null);
    // §4.6: the slot is free again, but the peer never spent credit on this
    // stream, so no MAX_STREAMS is owed and none may be invented.
    try testing.expectEqual(@as(usize, 0), client.flowControlOwed(&owed).len);
    try testing.expectEqual(@as(u64, 1), client.streams_allowed.bidi);
    try testing.expectEqual(@as(u64, 0), client.streams_allowed.uni);
}

test "RFC 9000 §19.3.1, received numbers become the ACK ranges the wire wants" {
    const dcid = [_]u8{ 1, 2, 3 };
    var loss: LossTables = .{};
    var conn: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{4},
    });

    // 10, 11, 12 arrive together: one range, no pairs.
    conn.initial.?.record(10);
    conn.initial.?.record(11);
    conn.initial.?.record(12);
    try testing.expectEqual(@as(u4, 1), conn.initial.?.range_count);
    try testing.expectEqual(@as(u64, 12), conn.initial.?.ranges[0].largest);
    try testing.expectEqual(@as(u64, 10), conn.initial.?.ranges[0].smallest);

    var scratch: [ack_payload_len]u8 = undefined;
    var cursor: Cursor = .init(try ackPayload(&conn.initial.?, &scratch));
    var ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, 12), ack.largest);
    try testing.expectEqual(@as(u64, 2), ack.first_range);
    try testing.expectEqual(@as(u64, 0), ack.range_count);

    // A gap at 13 through 19 and a later range at 20..21.
    conn.initial.?.record(20);
    conn.initial.?.record(21);
    try testing.expectEqual(@as(u4, 2), conn.initial.?.range_count);
    try testing.expectEqual(@as(u64, 21), conn.initial.?.ranges[0].largest);
    try testing.expectEqual(@as(u64, 12), conn.initial.?.ranges[1].largest);

    var second: [ack_payload_len]u8 = undefined;
    cursor = .init(try ackPayload(&conn.initial.?, &second));
    ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, 21), ack.largest);
    try testing.expectEqual(@as(u64, 1), ack.first_range);
    try testing.expectEqual(@as(u64, 1), ack.range_count);

    // The seven unacknowledged numbers between the ranges are encoded as a gap
    // of six (§19.3.1).
    var ranges = ack.ranges();
    const range = (try ranges.next()).?;
    try testing.expectEqual(@as(u64, 6), range.gap);
    try testing.expectEqual(@as(u64, 2), range.length);
}

test "RFC 9000 §19.3.1, a number that bridges two ranges merges them" {
    const dcid = [_]u8{5};
    var loss: LossTables = .{};
    var conn: Conn = .init(.{
        .role = .server,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{6},
    });

    conn.initial.?.record(10);
    conn.initial.?.record(8);
    try testing.expectEqual(@as(u4, 2), conn.initial.?.range_count);

    // 9 closes the gap: one range, 8 through 10.
    conn.initial.?.record(9);
    try testing.expectEqual(@as(u4, 1), conn.initial.?.range_count);
    try testing.expectEqual(@as(u64, 10), conn.initial.?.ranges[0].largest);
    try testing.expectEqual(@as(u64, 8), conn.initial.?.ranges[0].smallest);

    // A duplicate changes nothing.
    conn.initial.?.record(9);
    try testing.expectEqual(@as(u4, 1), conn.initial.?.range_count);
}

test "a full range table forgets the oldest range and only that" {
    const dcid = [_]u8{7};
    var loss: LossTables = .{};
    var conn: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{8},
    });

    // Two more isolated ranges than the table holds, one per ten numbers.
    var index: u64 = 0;
    while (index < range_capacity + 2) : (index += 1) conn.initial.?.record(index * 10);

    try testing.expectEqual(@as(u4, range_capacity), conn.initial.?.range_count);
    // §13.2.4 allows forgetting: the newest is kept and the oldest two are gone.
    try testing.expectEqual(@as(u64, (range_capacity + 1) * 10), conn.initial.?.ranges[0].largest);
    try testing.expectEqual(@as(u64, 20), conn.initial.?.ranges[range_capacity - 1].largest);

    var scratch: [ack_payload_len]u8 = undefined;
    var cursor: Cursor = .init(try ackPayload(&conn.initial.?, &scratch));
    const ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, range_capacity - 1), ack.range_count);
}

test "fuzz the datagram walk" {
    // The parser an attacker reaches: any bytes, any length, with keys they did
    // not choose. Nothing here may panic, and a packet that opens is either
    // acted on or dropped by name.
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            const dcid = [_]u8{ 0x4f, 0x50, 0x51 };
            var loss: LossTables = .{};
            var conn: Conn = .init(.{
                .role = .server,
                .loss = loss.value(),
                .original_destination_connection_id = &dcid,
                .destination_connection_id = &.{ 0x52, 0x53 },
                .source_connection_id = &dcid,
            });

            var bytes: [1500]u8 = undefined;
            const input = bytes[0..smith.slice(&bytes)];

            var acked: [16]Recovery.SentPacket = undefined;
            var lost: [16]Recovery.SentPacket = undefined;
            var report: Recovery.Events = .init(&acked, &lost);
            var stream_events: [16]StreamEvent = undefined;
            var plaintext: [1500]u8 = undefined;
            var frames: [16]frame.Frame = undefined;

            var walk: Datagram = .init(input);
            while (true) {
                const opened = walk.next(
                    &conn,
                    &plaintext,
                    &frames,
                    &stream_events,
                    &report,
                    0,
                ) catch |err| switch (err) {
                    // §12.4: a frame inside a packet that opened is a connection
                    // error, which is a value here, not a crash.
                    error.NoSpace => return,
                    else => return,
                };
                // The frames borrow the plaintext buffer, so the next call
                // invalidates them; the walk only needs to reach the end.
                if (opened == null) return;
            }
        }
    }.run, .{});
}

test "RFC 9000 §19.8, a packed packet reports its number and the frames it carried" {
    const dcid = [_]u8{ 0xd1, 0xd2 };
    var client_send_a: [64]u8 = undefined;
    var client_send_b: [64]u8 = undefined;
    var client_ring: [64]u8 = undefined;
    var client_ring_b: [64]u8 = undefined;
    var client_slots: [2]StreamTable.Slot = undefined;
    var client_streams: [2]Conn.Stream = .{
        .{ .send_buffer = &client_send_a, .recv_buffer = &client_ring, .recv_limit_bytes = 64 },
        .{ .send_buffer = &client_send_b, .recv_buffer = &client_ring_b, .recv_limit_bytes = 64 },
    };
    var server_ring: [64]u8 = undefined;
    var server_ring_b: [64]u8 = undefined;
    var server_slots: [2]StreamTable.Slot = undefined;
    var server_streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &server_ring, .recv_limit_bytes = 64 },
        .{ .recv_buffer = &server_ring_b, .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xd3},
        .stream_slots = &client_slots,
        .streams = &client_streams,
        .peer = .{
            .max_data = 64,
            .stream_data = .{ .bidi_remote = 64, .bidi_local = 64 },
            .max_streams = .{ .bidi = 8, .uni = 8 },
        },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0xd3},
        .source_connection_id = &dcid,
        .stream_slots = &server_slots,
        .streams = &server_streams,
        .receive_limit = 1024,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x41);
    const server_secret: [protection.secret_length]u8 = @splat(0x42);
    installApp(&client, &server, client_secret, server_secret);

    const first = try client.openStream(0);
    try first.send.write("alpha");
    const second = try client.openStream(4);
    try second.send.write("beta");

    var offers = [_]Offer{
        .{ .stream_id = 0, .length = 64 },
        .{ .stream_id = 4, .length = 64 },
    };
    var written: [2]Written = undefined;
    var frame_bytes: [256]u8 = undefined;
    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var parsed: [8]frame.Frame = undefined;
    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;

    const flight = (try client.writeStreams(.{
        .offers = &offers,
        .frames = &frame_bytes,
        .out = &datagram,
        .written = &written,
        .max_payload = 512,
        .now = 0,
    })) orelse return error.TestUnexpectedResult;

    // The caller's order is the wire order, and each record says where in the
    // stream the bytes came from and how many went.
    try testing.expectEqual(@as(u64, 0), flight.number);
    try testing.expectEqual(@as(usize, 2), flight.frames.len);
    try testing.expectEqual(@as(u64, 0), flight.frames[0].stream_id);
    try testing.expectEqual(@as(u64, 0), flight.frames[0].offset);
    try testing.expectEqual(@as(u32, 5), flight.frames[0].length);
    try testing.expectEqual(@as(u64, 4), flight.frames[1].stream_id);
    try testing.expectEqual(@as(u32, 4), flight.frames[1].length);
    try testing.expectEqual(Consumed{ .taken = 2, .partial = 0 }, flight.consumed);

    // The peer reads both streams out of that one packet.
    _ = try server.feed(datagram[0..flight.length], &plaintext, &parsed, &stream_events, &report, 0);
    const received = server.stream(4) orelse return error.TestUnexpectedResult;
    var read: [16]u8 = undefined;
    const count = try received.recv.readInto(&read);
    try testing.expectEqualStrings("beta", read[0..count]);

    // And the number the machine reported is the number the acknowledgment
    // names, which is the whole point: the caller's record of packet 0 can now
    // be dropped, or that record can be resent if packet 0 is declared lost.
    const ack = try server.writeAck(.app, &datagram, 0);
    _ = try client.feed(datagram[0..ack], &plaintext, &parsed, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(flight.number, report.ackedPackets()[0].packet_number);
}

test "RFC 9000 §4.1, a packet that fits part of an offer says where to resume" {
    const dcid = [_]u8{0xd4};
    var send_buffer: [64]u8 = undefined;
    var ring: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .send_buffer = &send_buffer, .recv_buffer = &ring, .recv_limit_bytes = 64 },
        .{},
    };
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xd5},
        .stream_slots = &slots,
        .streams = &streams,
        .peer = .{
            .max_data = 64,
            .stream_data = .{ .bidi_remote = 64, .bidi_local = 64 },
            .max_streams = .{ .bidi = 8, .uni = 8 },
        },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x43);
    installApp(&client, &client, client_secret, client_secret);

    const entry = try client.openStream(0);
    try entry.send.write("0123456789abcdefghij");

    var written: [1]Written = undefined;
    var frame_bytes: [256]u8 = undefined;
    var datagram: [512]u8 = undefined;

    // A budget of 20 payload bytes: the frame's own header takes 11 at its
    // widest, so nine bytes of the stream go in and the rest waits.
    var offers = [_]Offer{.{ .stream_id = 0, .length = 20 }};
    const first = (try client.writeStreams(.{
        .offers = &offers,
        .frames = &frame_bytes,
        .out = &datagram,
        .written = &written,
        .max_payload = 20,
        .now = 0,
    })) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 9), first.frames[0].length);
    // The offer was not finished, and the answer says exactly how much of it
    // went: the caller re-offers the last eleven bytes rather than all twenty.
    try testing.expectEqual(Consumed{ .taken = 0, .partial = 9 }, first.consumed);
    // The budget was spent to the byte, so the packet was not cut short by a
    // lack of data: the caller's congestion window bought something.
    try testing.expectEqual(@as(u32, 0), first.remaining);

    // The re-offer, from where the machine said to resume.
    offers[0].length = 20 - first.consumed.partial;
    const second = (try client.writeStreams(.{
        .offers = offers[first.consumed.taken..],
        .frames = &frame_bytes,
        .out = &datagram,
        .written = &written,
        .max_payload = 512,
        .now = 0,
    })) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 1), second.number);
    try testing.expectEqual(@as(u32, 11), second.frames[0].length);
    // §19.8: the offset is the stream's, not the caller's, so the peer sees the
    // second half exactly where the first ended.
    try testing.expectEqual(@as(u64, 9), second.frames[0].offset);
    try testing.expectEqual(Consumed{ .taken = 1, .partial = 0 }, second.consumed);
    // Every byte the stream had went in and the offer list ended. The window
    // allowed 55 payload bytes here (the peer's 64 less the 9 already sent) and
    // the frame took 15, so 40 is what the peer's window left rather than what
    // the packet wasted: a caller can tell the two apart at the call site.
    try testing.expectEqual(@as(u32, 40), second.remaining);
}

test "RFC 9000 §4.1, a window with no room is a different answer from a used one" {
    const dcid = [_]u8{0xd6};
    var send_buffer: [64]u8 = undefined;
    var ring: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .send_buffer = &send_buffer, .recv_buffer = &ring, .recv_limit_bytes = 64 },
        .{},
    };
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xd7},
        .stream_slots = &slots,
        .streams = &streams,
        .peer = .{
            .max_data = 64,
            .stream_data = .{ .bidi_remote = 64, .bidi_local = 64 },
            .max_streams = .{ .bidi = 8, .uni = 8 },
        },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x44);
    installApp(&client, &client, client_secret, client_secret);

    const entry = try client.openStream(0);
    _ = try entry.send.write("bytes");

    var written: [1]Written = undefined;
    var frame_bytes: [256]u8 = undefined;
    var datagram: [512]u8 = undefined;
    const packing: Packing = .{
        .offers = &.{.{ .stream_id = 0, .length = 64 }},
        .frames = &frame_bytes,
        .out = &datagram,
        .written = &written,
        .max_payload = 0,
        .now = 0,
    };

    // Null, because nothing fit at all — not a partial packet with no frames.
    try testing.expect((try client.writeStreams(packing)) == null);
    // And nothing moved: no bytes were marked sent and no packet number was
    // spent on a packet that did not leave.
    try testing.expectEqual(@as(u64, 0), entry.send.sent);
    try testing.expectEqual(@as(u64, 0), client.app.?.next_packet_number);

    // With room, the same call is a packet.
    var roomy = packing;
    roomy.max_payload = 512;
    try testing.expect((try client.writeStreams(roomy)) != null);
    try testing.expectEqual(@as(u64, 5), entry.send.sent);
}

/// The caller's side of the timer, which only the tests here exercise: a
/// connection owns no timer, so "when do I wake up" is asked of `RecoveryDriver`
/// over the spaces the machine owns.
const RecoveryDriver = @import("RecoveryDriver.zig");

/// One endpoint's loss state, where a caller keeps it: outside `Conn`.
///
/// A test never reads these tables; `report` is what it reads. They exist so that
/// every `Conn` in this file is built the way a caller must build one, including
/// the three tables `Recovery.Space` records into.
const LossTables = struct {
    shared: Recovery = .{},
    spaces: [3]Recovery.Space = undefined,
    sent_initial: [16]Recovery.SentPacket = undefined,
    sent_handshake: [16]Recovery.SentPacket = undefined,
    sent_app: [16]Recovery.SentPacket = undefined,

    /// The handles for `Conn.Config.loss`, pointing at this local's storage.
    fn value(self: *LossTables) Conn.Loss {
        return .{
            .shared = &self.shared,
            .spaces = &self.spaces,
            .sent_initial = &self.sent_initial,
            .sent_handshake = &self.sent_handshake,
            .sent_app = &self.sent_app,
        };
    }
};

test "RFC 9001 §5.2, two machines exchange an Initial and one acknowledges" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xc1, 0xc2 },
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0xc1, 0xc2 },
        .source_connection_id = &.{ 0x5e, 0x5e },
    });

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;

    // Nothing has arrived yet, so there is nothing to acknowledge.
    try testing.expectError(error.NothingToAcknowledge, server.writeAck(.initial, &datagram, 0));

    const payload = pings(4);
    var frames: [8]frame.Frame = undefined;

    const sent = try client.writeFrames(.initial, &payload, &datagram, .data(0));
    const at_server = try server.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(.initial, at_server.space);
    try testing.expectEqual(@as(u64, 0), at_server.packet_number);
    // §19.1 and §19.2: padding and PING have nothing for the machine to do, so
    // they are the frames the machine hands to the caller.
    try testing.expectEqual(@as(usize, 4), at_server.frames.len);
    try testing.expect(at_server.frames[0] == .ping);

    // §13.2.1: the one question a caller asks is which spaces owe an
    // acknowledgment, and the answer is the list of spaces rather than three
    // calls it has to remember to make. Only Initial has anything here, and the
    // Handshake space has no keys, so it cannot appear.
    var due: [3]SpaceId = undefined;
    try testing.expectEqualSlices(SpaceId, &.{.initial}, server.acksOwed(&due));

    // The server answers with an ACK for packet 0.
    const ack_len = try server.writeAck(.initial, &datagram, 0);
    try testing.expect(!server.ackOwed(.initial));
    try testing.expectEqual(@as(usize, 0), server.acksOwed(&due).len);

    // §13.2: the acknowledgment is the machine's to act on, so it leaves the
    // packet as a sent-packet record rather than as an event for the caller.
    const at_client = try client.feed(datagram[0..ack_len], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_client.frames.len);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(@as(u64, 0), report.ackedPackets()[0].packet_number);
    try testing.expectEqual(@as(usize, 0), client.initial.?.recovery.inFlight().len);
}

test "RFC 9000 §7.2, a server is built from the datagram that called it" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;

    // The client invents a name for the server, which is also the seed of the
    // Initial keys (RFC 9001 §5.2). Eight bytes because §7.2 asks for at least
    // that many in a first Initial.
    const named_server = [_]u8{ 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &named_server,
        .destination_connection_id = &named_server,
        .source_connection_id = &.{ 0xc1, 0xc2 },
    });

    const payload = pings(4);
    var datagram: [512]u8 = undefined;
    const sent = try client.writeFrames(.initial, &payload, &datagram, .data(0));

    // The server reads the identity out of those bytes, and calls itself
    // something the client has never seen.
    var id_storage: [40]u8 = undefined;
    const opening = try Opening.fromDatagram(datagram[0..sent], &id_storage);
    try testing.expectEqualSlices(u8, &named_server, opening.destination_connection_id);
    try testing.expectEqualSlices(u8, &.{ 0xc1, 0xc2 }, opening.source_connection_id);

    const own_name = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    var server_loss: LossTables = .{};
    var server: Conn = .init(opening.serverConfig(&own_name, server_loss.value()));
    try testing.expectEqualSlices(u8, &.{ 0xc1, 0xc2 }, server.destination_connection_id);
    try testing.expectEqualSlices(u8, &own_name, server.source_connection_id);

    // The proof that the pairing is right: the Initial opens under the keys the
    // client's name seeded. Any other connection ID here is a packet that will
    // not decrypt.
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    const at_server = try server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(.initial, at_server.space);
    try testing.expectEqual(@as(u64, 0), at_server.packet_number);

    // A short header names a connection that is already open, so there is no
    // identity to read out of it.
    var short: [24]u8 = @splat(0);
    short[0] = 0x40;
    try testing.expectError(error.NotLongHeader, Opening.fromDatagram(&short, &id_storage));

    // A Handshake arrives after this endpoint has answered, and a Retry is this
    // endpoint's own packet.
    const handshake = [_]u8{ 0xe0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0 };
    try testing.expectError(error.NotInitial, Opening.fromDatagram(&handshake, &id_storage));
    const retry = [_]u8{ 0xf0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0 };
    try testing.expectError(error.NotInitial, Opening.fromDatagram(&retry, &id_storage));

    // §17.2.1: a Version Negotiation packet has no version and no type, and a
    // version this package does not implement is the caller's cue to answer with
    // Version Negotiation (§6).
    const negotiation = [_]u8{ 0xc0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0 };
    try testing.expectError(error.NotInitial, Opening.fromDatagram(&negotiation, &id_storage));
    const unknown = [_]u8{ 0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0 };
    try testing.expectError(error.UnsupportedVersion, Opening.fromDatagram(&unknown, &id_storage));

    // §7.2: with no Destination Connection ID the first Initial names nobody
    // and seeds nothing.
    const unnamed = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0 };
    try testing.expectError(error.InvalidConnectionId, Opening.fromDatagram(&unnamed, &id_storage));

    // The two names have to fit the caller's storage together, and a refusal
    // writes nothing.
    var tight: [9]u8 = @splat(0xff);
    try testing.expectError(error.NoSpace, Opening.fromDatagram(datagram[0..sent], &tight));
    const untouched: [9]u8 = @splat(0xff);
    try testing.expectEqualSlices(u8, &untouched, &tight);
}

test "RFC 9000 §13.2.1, the acknowledgment summary lists the spaces in order" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x71, 0x72 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0x73, 0x74 },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0x73, 0x74 },
        .source_connection_id = &.{ 0x75, 0x76 },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x77);
    const server_secret: [protection.secret_length]u8 = @splat(0x78);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;

    // One Initial and one 1-RTT packet arrive, each with a PING.
    const payload = pings(1);
    const initial_len = try client.writeFrames(.initial, &payload, &datagram, .data(0));
    _ = try server.feed(datagram[0..initial_len], &plaintext, &frames, &stream_events, &report, 0);
    const app_len = try client.writeFrames(.app, &payload, &datagram, .data(0));
    _ = try server.feed(datagram[0..app_len], &plaintext, &frames, &stream_events, &report, 0);

    // §13.2.1: an acknowledgment goes in the space it acknowledges, so the
    // summary names both spaces, lowest first.
    var due: [3]SpaceId = undefined;
    try testing.expectEqualSlices(SpaceId, &.{ .initial, .app }, server.acksOwed(&due));

    // A list that cannot hold them all is a prefix, and nothing is consumed: the
    // rest is still owed the next time the caller asks.
    var one: [1]SpaceId = undefined;
    try testing.expectEqualSlices(SpaceId, &.{.initial}, server.acksOwed(&one));

    // Answering the first space leaves only the second.
    _ = try server.writeAck(.initial, &datagram, 0);
    try testing.expectEqualSlices(SpaceId, &.{.app}, server.acksOwed(&due));

    // §10.2.2: a connection that has closed owes nothing at all.
    var close_frames: [64]u8 = undefined;
    _ = try server.close(.{ .error_code = 0, .reason = "done" }, &close_frames, &datagram, 0);
    try testing.expectEqual(@as(usize, 0), server.acksOwed(&due).len);
    try testing.expect(!server.ackOwed(.app));
}

test "RFC 9000 §7.2, a client adopts the name the server's first Initial gives" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;

    // The client invents an eight-byte name for the server, as §7.2 asks. The
    // server calls itself four bytes, which is the length a short header has to
    // know without a Length field (§17.3.1).
    const invented = [_]u8{ 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1 };
    const server_name = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const client_name = [_]u8{ 0xc1, 0xc2 };

    var adopted: [20]u8 = undefined;
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &invented,
        .destination_connection_id = &invented,
        .source_connection_id = &client_name,
        .connection_id_storage = &adopted,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &invented,
        .destination_connection_id = &client_name,
        .source_connection_id = &server_name,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x21);
    const server_secret: [protection.secret_length]u8 = @splat(0x22);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    const payload = pings(1);

    // The server's first Initial names it, and the client sends to that name
    // from then on.
    const flight = try server.writeFrames(.initial, &payload, &datagram, .data(0));
    _ = try client.feed(datagram[0..flight], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqualSlices(u8, &server_name, client.destination_connection_id);

    // The buffer the name arrived in is about to be reused. The adoption copied
    // it, so a short header now carries the server's four bytes and the server,
    // which reads the length from its own name, parses it.
    const app_len = try client.writeFrames(.app, &payload, &datagram, .data(0));
    const at_server = try server.feed(datagram[0..app_len], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(.app, at_server.space);

    // §7.2: a later long header with a different Source Connection ID is
    // discarded, not adopted, and the datagram walk counts it as a drop.
    var imposter_loss: LossTables = .{};
    var imposter: Conn = .init(.{
        .role = .server,
        .loss = imposter_loss.value(),
        .original_destination_connection_id = &invented,
        .destination_connection_id = &client_name,
        .source_connection_id = &.{ 0x31, 0x32, 0x33, 0x34 },
    });
    const imposter_flight = try imposter.writeFrames(.initial, &payload, &datagram, .data(0));
    var walk: Datagram = .init(datagram[0..imposter_flight]);
    try testing.expect((try walk.next(&client, &plaintext, &frames, &stream_events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 1), walk.dropped);
    try testing.expectEqualSlices(u8, &server_name, client.destination_connection_id);

    // A caller that did not size the copy cannot adopt, and the failure is its
    // own sizing rather than a packet to drop.
    var tight: [3]u8 = undefined;
    var fresh_loss: LossTables = .{};
    var fresh: Conn = .init(.{
        .role = .client,
        .loss = fresh_loss.value(),
        .original_destination_connection_id = &invented,
        .destination_connection_id = &invented,
        .source_connection_id = &client_name,
        .connection_id_storage = &tight,
    });
    const again = try server.writeFrames(.initial, &payload, &datagram, .data(0));
    try testing.expectError(error.NoSpace, fresh.feed(
        datagram[0..again],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
}

test "RFC 9000 §12.3, a Handshake packet opens in the handshake space" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 3, 1, 4, 1, 5 };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xa1, 0xa2 },
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0xa1, 0xa2 },
        .source_connection_id = &dcid,
    });

    // What the TLS driver will do: both sides get the Handshake keys from the
    // handshake secrets, client and server halves crossed.
    const client_secret: [protection.secret_length]u8 = @splat(0x11);
    const server_secret: [protection.secret_length]u8 = @splat(0x22);
    installHandshake(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;

    const payload = pings(3);
    var frames: [8]frame.Frame = undefined;

    const sent = try client.writeFrames(.handshake, &payload, &datagram, .data(0));
    const opened = try server.feed(datagram[0..sent], &plaintext, &frames, &stream_events, &report, 0);

    try testing.expectEqual(.handshake, opened.space);
    try testing.expectEqual(@as(usize, 3), opened.frames.len);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);
    try testing.expectEqual(@as(?u64, 0), server.handshake.?.largest_received);
    // Not the Initial space: a server that has processed a Handshake packet has
    // let those keys go (§17.2.2.1).
    try testing.expectEqual(@as(?Space, null), server.initial);
    try testing.expect(server.ackOwed(.handshake));
    try testing.expect(!server.ackOwed(.initial));

    // And the acknowledgment is a Handshake packet, which is the only space the
    // client can read it in (§13.2.1). It clears the client's own Handshake
    // record and leaves the Initial space alone, which is what makes the
    // acknowledgment land in the right space's loss state.
    const ack_len = try server.writeAck(.handshake, &datagram, 0);
    const at_client = try client.feed(datagram[0..ack_len], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_client.frames.len);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(@as(usize, 0), client.handshake.?.recovery.inFlight().len);
    try testing.expectEqual(@as(?u64, null), client.initial.?.largest_received);
}

test "RFC 9000 §12.3, a space with no keys is an error and not a second kind of empty" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 2, 7, 1, 8 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x01},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x01},
        .source_connection_id = &.{0x02},
    });

    // The client learns the Handshake secrets and the server does not, which is
    // the window between the driver reporting them and nothing.
    const client_secret: [protection.secret_length]u8 = @splat(0x33);
    const server_secret: [protection.secret_length]u8 = @splat(0x44);
    installHandshake(&client, &client, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    const payload = pings(3);
    var frames: [8]frame.Frame = undefined;
    const sent = try client.writeFrames(.handshake, &payload, &datagram, .data(0));

    try testing.expectError(error.NoKeys, server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
    try testing.expectError(error.NoKeys, server.writeFrames(.handshake, "\x01", &datagram, .data(0)));
    try testing.expectError(error.NoKeys, server.writeAck(.app, &datagram, 0));
    // Nothing was recorded, so nothing is owed.
    try testing.expect(!server.ackOwed(.handshake));
    try testing.expect(!server.ackOwed(.app));
}

test "RFC 9001 §4.9, a discarded space keeps no keys and no counters" {
    const dcid = [_]u8{ 0xd1, 0xd2 };
    var conn_loss: LossTables = .{};
    const conn: Conn = .init(.{
        .role = .server,
        .loss = conn_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xd3},
    });

    // A space that has been used: counters, a received range, and an
    // acknowledgment already sent.
    var space = conn.initial.?;
    space.next_packet_number = 9;
    space.largest_received = 7;
    space.record(7);
    space.acked_through = 7;
    try testing.expect(!space.ackOwed());

    space.discard();

    const zeros: [32]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zeros, &space.send_keys.key);
    try testing.expectEqualSlices(u8, &zeros, &space.receive_keys.key);
    try testing.expectEqualSlices(u8, &zeros, &space.send_keys.hp);
    try testing.expectEqualSlices(u8, &zeros, &space.receive_keys.hp);
    try testing.expectEqual(@as(u64, 0), space.next_packet_number);
    try testing.expectEqual(@as(?u64, null), space.largest_received);
    try testing.expectEqual(@as(?u64, null), space.acked_through);
    try testing.expectEqual(@as(u4, 0), space.range_count);
}

test "RFC 9000 §17.2.2.1, a packet for a discarded space is dropped and the connection goes on" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0xe1, 0xe2 };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xea},
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0xea},
        .source_connection_id = &dcid,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0xdd);
    const server_secret: [protection.secret_length]u8 = @splat(0xee);
    installHandshake(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    const payload = pings(3);

    // The server has read an Initial, and §17.2.2.1 says it can let the keys go
    // once it processes a Handshake packet. It does, and then the late Initial
    // that arrives next is dropped rather than decrypted under a dead key.
    const stale = try client.writeFrames(.initial, &payload, &datagram, .data(0));
    _ = try server.feed(datagram[0..stale], &plaintext, &frames, &stream_events, &report, 0);
    try server.discard(.initial);
    try testing.expectError(error.NoKeys, server.spaceFor(.initial));
    try testing.expect(!server.ackOwed(.initial));
    try testing.expectError(error.NoKeys, server.writeFrames(.initial, "\x01", &datagram, .data(0)));

    const late = try client.writeFrames(.initial, &payload, &datagram, .data(0));
    var walk: Datagram = .init(datagram[0..late]);
    try testing.expect((try walk.next(&server, &plaintext, &frames, &stream_events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 1), walk.dropped);

    // The rest of the connection is untouched: the Handshake space opens what
    // the client sends there, because the connection IDs are the connection's.
    const handshake = try client.writeFrames(.handshake, &payload, &datagram, .data(0));
    const opened = try server.feed(datagram[0..handshake], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 3), opened.frames.len);
    try testing.expectEqual(@as(?u64, 0), server.handshake.?.largest_received);

    // And the server can still write: discarding a space does not take the
    // connection's identity or its packet number width with it.
    const ack = try server.writeAck(.handshake, &datagram, 0);
    const at_client = try client.feed(datagram[0..ack], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_client.frames.len);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(@as(usize, 0), client.handshake.?.recovery.inFlight().len);
}

test "RFC 9001 §4.9.2, the Handshake keys can go while the application keys stay" {
    const dcid = [_]u8{ 0xf1, 0xf2 };
    var conn_loss: LossTables = .{};
    var conn: Conn = .init(.{
        .role = .client,
        .loss = conn_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xfa},
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x01);
    const server_secret: [protection.secret_length]u8 = @splat(0x02);
    installHandshake(&conn, &conn, client_secret, server_secret);
    installApp(&conn, &conn, client_secret, server_secret);

    try conn.discard(.handshake);
    try testing.expectError(error.NoKeys, conn.spaceFor(.handshake));
    try testing.expectError(error.NoKeys, conn.discard(.handshake));
    // 1-RTT traffic is the point of discarding the Handshake keys, so it is
    // still there.
    try testing.expect(conn.app != null);
    try testing.expect(conn.initial != null);
}

test "RFC 9000 §17.3.1, the application space writes a short header and opens one" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    // A short header omits the connection ID length, so the two ends have to
    // agree on it: the client names the server's ID and the server names the
    // client's.
    const server_id = [_]u8{ 0x51, 0x52, 0x53 };
    const client_id = [_]u8{ 0x61, 0x62 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &server_id,
        .source_connection_id = &client_id,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &client_id,
        .source_connection_id = &server_id,
    });

    const client_secret: [protection.secret_length]u8 = @splat(0x55);
    const server_secret: [protection.secret_length]u8 = @splat(0x66);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    const payload = pings(2);

    const sent = try client.writeFrames(.app, &payload, &datagram, .data(0));
    // §17.3.1: the form bit is clear, and the destination connection ID has no
    // length on the wire.
    try testing.expectEqual(@as(u8, 0x00), datagram[0] & 0x80);
    try testing.expectEqualSlices(u8, &server_id, datagram[1..][0..server_id.len]);

    const opened = try server.feed(datagram[0..sent], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(.app, opened.space);
    try testing.expectEqual(@as(usize, 2), opened.frames.len);
    try testing.expectEqual(@as(?u64, 0), server.app.?.largest_received);
    try testing.expectEqual(@as(?u64, null), server.initial.?.largest_received);
    // The whole rest of the datagram is the packet: a short header has no
    // Length field (§12.2).
    try testing.expectEqual(@as(u32, @intCast(sent)), opened.packet_len);
}

test "RFC 9000 §19.3, eight received ranges do not overflow the ACK path" {
    const dcid = [_]u8{ 0xaa, 0xbb };
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xcc},
    });

    // Ranges wide enough that both the gap to the next one and the run length
    // need eight-byte varints: the widest ACK a full range table can produce.
    const run: u64 = 1 << 56;
    const spacing: u64 = 2 * run + 8;
    var index: usize = 0;
    while (index < range_capacity) : (index += 1) {
        const smallest: u64 = 4 + (range_capacity - 1 - index) * spacing;
        server.initial.?.ranges[index] = .{ .smallest = smallest, .largest = smallest + run };
        server.initial.?.range_count += 1;
    }
    server.initial.?.largest_received = server.initial.?.ranges[0].largest;

    // The frame reads back into exactly the ranges it was built from. The
    // reader is the one a peer uses, and it refuses a range whose gap or length
    // does not fit, so this is what says the scratch held every pair at the
    // widest encoding a full table can produce.
    var payload: [ack_payload_len]u8 = undefined;
    const bytes = try ackPayload(&server.initial.?, &payload);
    var cursor: Cursor = .init(bytes);
    const ack = (try frame.read(&cursor)).ack;
    try testing.expectEqual(@as(u64, range_capacity - 1), ack.range_count);
    try testing.expectEqual(server.initial.?.ranges[0].largest, ack.largest);
    try testing.expectEqual(run, ack.first_range);
    try testing.expect(cursor.atEnd());

    var smallest = ack.largest - ack.first_range;
    try testing.expectEqual(server.initial.?.ranges[0].smallest, smallest);
    var ranges = ack.ranges();
    var walked: usize = 0;
    while (try ranges.next()) |range| : (walked += 1) {
        const range_largest = smallest - range.gap - 2;
        smallest = range_largest - range.length;
        try testing.expectEqual(server.initial.?.ranges[walked + 1].largest, range_largest);
        try testing.expectEqual(server.initial.?.ranges[walked + 1].smallest, smallest);
    }
    try testing.expectEqual(@as(usize, range_capacity - 1), walked);

    // And the same ACK still seals into a packet.
    var out: [512]u8 = undefined;
    try testing.expect(try server.writeAck(.initial, &out, 0) > 0);
}

test "RFC 9001 §4.9.2, a stub driver takes a client from Initial to 1-RTT" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x71, 0x72 };
    const client_secret: [protection.secret_length]u8 = @splat(0x5a);
    const server_secret: [protection.secret_length]u8 = @splat(0x5b);
    const app_client_secret: [protection.secret_length]u8 = @splat(0x5c);
    const app_server_secret: [protection.secret_length]u8 = @splat(0x5d);

    const hello = "ClientHello bytes in one CRYPTO frame";
    const finished = "Finished bytes";

    // Both ends stand in for baskingspot/tls: the same secrets on each, the
    // client with two messages to send, and each recording what it is fed.
    var client_stub: seam.Stub = .{
        .outbox = &.{
            .{ .level = .initial, .bytes = hello },
            .{ .level = .handshake, .bytes = finished },
        },
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
        .app_secrets = .{ .client = &app_client_secret, .server = &app_server_secret },
        .alpn_protocol = "h3",
        .peer_parameters = identityParameters(.server, &dcid, &dcid),
    };
    var server_stub: seam.Stub = .{
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
        .app_secrets = .{ .client = &app_client_secret, .server = &app_server_secret },
        .peer_parameters = identityParameters(.client, &dcid, &.{0x7a}),
    };

    // CRYPTO reassembly storage, which the caller owns (§19.6), and the buffer
    // its own handshake bytes are kept in so a loss can be replayed (§13.3).
    var initial_crypto: [128]u8 = undefined;
    var handshake_crypto: [128]u8 = undefined;
    var client_sent_initial: [128]u8 = undefined;
    var client_sent_handshake: [128]u8 = undefined;

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x7a},
        .tls = client_stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x7a}),
        .crypto_sent = .{ .initial = &client_sent_initial, .handshake = &client_sent_handshake },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x7a},
        // The same bytes the client puts in a destination: a short header
        // carries no length, so the two ends have to agree on one (§17.3.1).
        .source_connection_id = &dcid,
        .tls = server_stub.driver(),
        .transport_parameters = identityParameters(.server, &dcid, &dcid),
        .crypto = .{ .initial = &initial_crypto, .handshake = &handshake_crypto },
    });

    var datagram: [512]u8 = undefined;
    var payload: [256]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    // The ClientHello leaves in an Initial packet, and the driver had this
    // endpoint's transport parameters before it produced that message (§8.2).
    const first = (try client.writeHandshake(&payload, &datagram, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expect(client_stub.parameters_set);
    try testing.expectEqualSlices(
        u8,
        client.transport_parameters,
        client_stub.parameters[0..client_stub.parameters_len],
    );
    // The stub reported both levels up front, so the machine installed them
    // before it needed them; the Initial keys are still here, because no
    // Handshake packet has gone out yet.
    try testing.expect(client.initial != null);

    // The server unprotects it, reassembles the CRYPTO frame, and hands the
    // bytes to its driver at the level the packet belonged to.
    const at_server = try server.feed(datagram[0..first], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_server.frames.len);
    try testing.expectEqual(seam.Level.initial, server_stub.fed_level.?);
    try testing.expectEqualStrings(hello, server_stub.fed[0..server_stub.fed_len]);

    // The server's own driver has nothing to send, and installing the spaces it
    // reported is a separate call from writing a packet: that is how its
    // Handshake and 1-RTT keys arrive.
    try server.installSpaces();
    try testing.expect(server.handshake != null);
    try testing.expect(server.app != null);

    // The Finished bytes go out in a Handshake packet, in a space the machine
    // built from the driver's secrets. §17.2.2.1 then takes the client's
    // Initial keys, because its first Handshake packet has been sent.
    const second = (try client.writeHandshake(&payload, &datagram, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expect(client.handshake != null);
    try testing.expectEqual(@as(?Space, null), client.initial);

    const at_server_handshake = try server.feed(datagram[0..second], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_server_handshake.frames.len);
    try testing.expectEqual(seam.Level.handshake, server_stub.fed_level.?);
    // A new level starts its CRYPTO stream at zero again (§19.6).
    try testing.expectEqualStrings(finished, server_stub.fed[hello.len..server_stub.fed_len]);
    // And the server's Initial keys went when it processed that packet.
    try testing.expectEqual(@as(?Space, null), server.initial);

    // The driver has nothing left to send, and 1-RTT traffic flows both ways.
    try testing.expect((try client.writeHandshake(&payload, &datagram, 0)) == null);
    try testing.expectEqualStrings("h3", client.tls.?.alpn().?);

    const app_payload = pings(2);
    const app_packet = try client.writeFrames(.app, &app_payload, &datagram, .data(0));
    const opened_app = try server.feed(datagram[0..app_packet], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 2), opened_app.frames.len);

    // §4.1.2 of RFC 9001: a client's handshake is confirmed by HANDSHAKE_DONE,
    // and the TLS driver's completion is the server's confirmation, not the
    // client's. A stub that claims confirmed moves nothing here.
    client_stub.confirmed = true;
    try client.installSpaces();
    try testing.expect(client.handshake != null);
    try testing.expect(!client.handshakeConfirmed());

    // §4.9.2: the frame is what takes the Handshake keys, and 1-RTT carries on.
    var done_payload: [16]u8 = undefined;
    var done_writer: Writer = .init(&done_payload);
    try frame.write(&done_writer, .{ .handshake_done = {} });
    const done = try server.writeFrames(.app, done_writer.written(), &datagram, .data(0));
    const at_done = try client.feed(datagram[0..done], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_done.frames.len);
    try testing.expect(client.handshakeConfirmed());
    try testing.expectEqual(@as(?Space, null), client.handshake);
    try testing.expect(client.app != null);
    try testing.expectError(error.NoKeys, client.writeFrames(.handshake, "\x01", &datagram, .data(0)));
    _ = try client.writeFrames(.app, &app_payload, &datagram, .data(0));
}

/// A client over a stub driver that has both levels' secrets and whatever the
/// peer's parameters say, for the tests of what the machine adopts. Streams are
/// two slots of 64 bytes, enough to open one and write to it.
const AdoptionFixture = struct {
    const dcid = [_]u8{ 0xc1, 0xc2 };
    const client_cid = [_]u8{0xc3};
    const handshake_secret: [protection.secret_length]u8 = @splat(0xc4);
    const app_secret: [protection.secret_length]u8 = @splat(0xc5);

    stub: seam.Stub,
    loss: LossTables = .{},
    send_bytes: [2][64]u8 = undefined,
    recv_bytes: [2][64]u8 = undefined,
    slots: [2]StreamTable.Slot = undefined,
    streams: [2]Conn.Stream = undefined,
    retry_storage: [64]u8 = undefined,

    fn init(peer: ?[]const u8) AdoptionFixture {
        return .{ .stub = .{
            .handshake_secrets = .{ .client = &handshake_secret, .server = &handshake_secret },
            .app_secrets = .{ .client = &app_secret, .server = &app_secret },
            .peer_parameters = peer,
        } };
    }

    /// The client, over this fixture's storage. The fixture must not move after.
    fn client(self: *AdoptionFixture) Conn {
        for (&self.streams, 0..) |*entry, index| entry.* = .{
            .send_buffer = &self.send_bytes[index],
            .recv_buffer = &self.recv_bytes[index],
            .recv_limit_bytes = 64,
        };
        return .init(.{
            .role = .client,
            .loss = self.loss.value(),
            .original_destination_connection_id = &dcid,
            .destination_connection_id = &dcid,
            .source_connection_id = &client_cid,
            .tls = self.stub.driver(),
            .transport_parameters = identityParameters(.client, &dcid, &client_cid),
            .stream_slots = &self.slots,
            .streams = &self.streams,
            .retry_storage = &self.retry_storage,
        });
    }

    /// The server's parameters as it would send them, echoing this client's
    /// first Destination Connection ID unless `parameters` says otherwise.
    fn serverParameters(buffer: []u8, parameters: TransportParameters) []const u8 {
        var full = parameters;
        if (full.initial_source_connection_id == null) full.initial_source_connection_id = &dcid;
        if (full.original_destination_connection_id == null) {
            full.original_destination_connection_id = &dcid;
        }
        return encodeParameters(buffer, .server, full);
    }
};

test "RFC 9000 §7.4, the server's initial_max_data bounds the client's first STREAM frame" {
    var buffer: [128]u8 = undefined;
    var fixture: AdoptionFixture = .init(AdoptionFixture.serverParameters(&buffer, .{
        .initial_max_data = 20,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = 1,
    }));
    var client = fixture.client();

    // Nothing is known until the driver's parameters are adopted, and then they
    // are the limits, with the defaults of §18.2 for what the server left out.
    try testing.expect(client.peer == null);
    try client.installSpaces();
    try testing.expectEqual(@as(u64, 20), client.peer.?.max_data);
    try testing.expectEqual(@as(u64, 20), client.send_window.limit);
    try testing.expectEqual(Recovery.ms(25), client.max_ack_delay);

    const opened = try client.openStream(0);
    try opened.send.write("thirty-two bytes of stream data..");
    var offers = [_]Conn.Offer{.{ .stream_id = 0, .length = 33 }};
    var written: [1]Written = undefined;
    var frame_bytes: [128]u8 = undefined;
    var out: [256]u8 = undefined;
    const packet_out = (try client.writeStreams(.{
        .offers = &offers,
        .frames = &frame_bytes,
        .out = &out,
        .written = &written,
        .max_payload = 128,
        .now = 0,
    })) orelse return error.TestUnexpectedResult;

    // The offer was 33 bytes and the server allowed 20 in all, so the frame is
    // cut short. The machine reserves the frame's widest header (11 bytes) out
    // of the allowance, which is why it is 9 and not 20.
    try testing.expect(packet_out.length > 0);
    try testing.expectEqual(@as(u32, 9), written[0].length);
    try testing.expectEqual(@as(u64, 9), client.send_window.sent);
}

test "RFC 9000 §4.6, initial_max_streams_bidi of zero refuses openStream" {
    var buffer: [128]u8 = undefined;
    var fixture: AdoptionFixture = .init(AdoptionFixture.serverParameters(&buffer, .{
        .initial_max_data = 64,
        .initial_max_stream_data_uni = 64,
        .initial_max_streams_bidi = 0,
        .initial_max_streams_uni = 1,
    }));
    var client = fixture.client();
    try client.installSpaces();

    // The credit is per direction: no bidirectional stream may open, and the
    // one-way credit the server did grant is still there.
    try testing.expectError(error.NoStreamCredit, client.openStream(0));
    _ = try client.openStream(2);
    try testing.expectError(error.NoStreamCredit, client.openStream(6));
}

test "RFC 9000 §7.3, a client refuses an original_destination_connection_id that does not echo" {
    var buffer: [128]u8 = undefined;
    var fixture: AdoptionFixture = .init(AdoptionFixture.serverParameters(&buffer, .{
        .original_destination_connection_id = &.{ 0xc1, 0xff },
    }));
    var client = fixture.client();

    // TRANSPORT_PARAMETER_ERROR, and nothing from the parameters was adopted.
    try testing.expectError(error.TransportParameter, client.installSpaces());
    try testing.expect(client.peer == null);
    try testing.expectEqual(@as(?Space, null), client.app);

    // The same bytes with the right name are accepted, so the refusal was the
    // name and not the parameters around it.
    fixture.stub.peer_parameters = AdoptionFixture.serverParameters(&buffer, .{});
    try client.installSpaces();
    try testing.expect(client.peer != null);
    try testing.expect(client.app != null);
}

test "RFC 9000 §7.3, initial_source_connection_id is required and must name the peer" {
    var buffer: [128]u8 = undefined;
    var fixture: AdoptionFixture = .init(AdoptionFixture.serverParameters(&buffer, .{
        .initial_source_connection_id = &.{ 0xc1, 0xff },
    }));
    var client = fixture.client();
    try testing.expectError(error.TransportParameter, client.installSpaces());

    // Absent is as wrong as different: the parameter is mandatory (§7.3).
    fixture.stub.peer_parameters = encodeParameters(&buffer, .server, .{
        .original_destination_connection_id = &AdoptionFixture.dcid,
    });
    try testing.expectError(error.TransportParameter, client.installSpaces());
    try testing.expect(client.peer == null);

    // A server checks the same parameter on a client's, against the Source
    // Connection ID it addresses.
    const server_dcid = [_]u8{0xc6};
    var server_stub: seam.Stub = .{
        .peer_parameters = encodeParameters(&buffer, .client, .{
            .initial_source_connection_id = &.{0xc7},
        }),
    };
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &server_dcid,
        .destination_connection_id = &.{0xc8},
        .source_connection_id = &server_dcid,
        .tls = server_stub.driver(),
        .transport_parameters = identityParameters(.server, &server_dcid, &server_dcid),
    });
    try testing.expectError(error.TransportParameter, server.installSpaces());
    try testing.expect(server.peer == null);
}

test "RFC 9000 §7.3, retry_source_connection_id without a Retry is TRANSPORT_PARAMETER_ERROR" {
    var buffer: [128]u8 = undefined;
    var fixture: AdoptionFixture = .init(AdoptionFixture.serverParameters(&buffer, .{
        .retry_source_connection_id = &.{0xc9},
    }));
    var client = fixture.client();
    try testing.expectError(error.TransportParameter, client.installSpaces());
    try testing.expect(client.peer == null);
}

test "RFC 9000 §7.3, after a Retry the server's retry_source_connection_id must echo it" {
    const retry_scid = [_]u8{ 0xca, 0xcb };
    var buffer: [128]u8 = undefined;
    var fixture: AdoptionFixture = .init(null);
    var client = fixture.client();

    var retry_bytes: [256]u8 = undefined;
    const retry_length = try setup.Retry.write(&retry_bytes, &AdoptionFixture.dcid, .{
        .destination_connection_id = &AdoptionFixture.client_cid,
        .source_connection_id = &retry_scid,
        .token = "retry-token",
    });
    const retry = try packet.parseRetry(try packet.parseInvariant(retry_bytes[0..retry_length]));
    try testing.expectEqual(
        setup.Client.Outcome.accepted,
        try client.onRetry(&retry, retry_bytes[0..retry_length]),
    );
    // The Retry's bytes are the datagram's, which the caller reuses; the machine
    // kept its own copy.
    @memset(retry_bytes[0..retry_length], 0xee);
    try testing.expectEqualSlices(u8, &retry_scid, client.retry_source_connection_id);

    // The server's first Initial after the Retry comes from the name it gave.
    const answered: TransportParameters = .{ .initial_source_connection_id = &retry_scid };

    // Absent after a Retry is as wrong as a different one.
    fixture.stub.peer_parameters = AdoptionFixture.serverParameters(&buffer, answered);
    try testing.expectError(error.TransportParameter, client.installSpaces());

    var wrong = answered;
    wrong.retry_source_connection_id = &.{ 0xca, 0xff };
    fixture.stub.peer_parameters = AdoptionFixture.serverParameters(&buffer, wrong);
    try testing.expectError(error.TransportParameter, client.installSpaces());

    // Echoing the Retry's Source Connection ID is what is accepted.
    var right = answered;
    right.retry_source_connection_id = &retry_scid;
    fixture.stub.peer_parameters = AdoptionFixture.serverParameters(&buffer, right);
    try client.installSpaces();
    try testing.expect(client.peer != null);
}

test "RFC 9001 §8.2, the 1-RTT space waits for the peer's parameters" {
    var fixture: AdoptionFixture = .init(null);
    var client = fixture.client();

    // The driver has the application secrets and no parameters, which is a
    // handshake that skipped the extension: Handshake keys are fine, 1-RTT on
    // guessed limits is not.
    try testing.expectError(error.TransportParameter, client.installSpaces());
    try testing.expect(client.handshake != null);
    try testing.expectEqual(@as(?Space, null), client.app);
    try testing.expect(client.peer == null);

    // Once they arrive the same call installs it.
    var buffer: [128]u8 = undefined;
    fixture.stub.peer_parameters = AdoptionFixture.serverParameters(&buffer, .{});
    try client.installSpaces();
    try testing.expect(client.app != null);
    try testing.expect(client.peer != null);
}

test "RFC 9000 §18.2, a malformed parameter set is TRANSPORT_PARAMETER_ERROR" {
    var fixture: AdoptionFixture = .init(&.{ 0x03, 0x01 });
    var client = fixture.client();
    try testing.expectError(error.TransportParameter, client.installSpaces());
    try testing.expect(client.peer == null);
}

test "RFC 9000 §18.2, the peer's parameters carry their defaults and units" {
    const decoded: TransportParameters = .{
        .max_idle_timeout = 30_000,
        .max_ack_delay = 26,
        .ack_delay_exponent = 5,
        .disable_active_migration = true,
        .stateless_reset_token = @splat(0x7e),
    };
    const peer: PeerParameters = .fromDecoded(&decoded);
    try testing.expectEqual(Recovery.ms(30_000), peer.max_idle_timeout);
    try testing.expectEqual(Recovery.ms(26), peer.max_ack_delay);
    try testing.expectEqual(@as(u8, 5), peer.ack_delay_exponent);
    try testing.expect(peer.disable_active_migration);
    try testing.expectEqual(@as(u8, 0x7e), peer.stateless_reset_token.?[0]);
    // Absent parameters are their defaults, not zero.
    try testing.expectEqual(@as(u64, 65527), peer.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 2), peer.active_connection_id_limit);

    const empty: PeerParameters = .fromDecoded(&.{});
    try testing.expectEqual(Recovery.ms(25), empty.max_ack_delay);
    try testing.expectEqual(@as(u8, 3), empty.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 0), empty.max_data);
    try testing.expectEqual(@as(Duration, 0), empty.max_idle_timeout);

    // A timeout too large for nanoseconds is "never", not a small number.
    const huge: TransportParameters = .{ .max_idle_timeout = (1 << 62) - 1 };
    try testing.expectEqual(std.math.maxInt(u64), PeerParameters.fromDecoded(&huge).max_idle_timeout);
}

test "RFC 9000 §18.2, the parameters this endpoint sends must agree with its configuration" {
    var loss: LossTables = .{};
    const dcid = [_]u8{0xd1};
    var buffer: [128]u8 = undefined;
    var conn: Conn = .init(.{
        .role = .server,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0xd2},
        .source_connection_id = &dcid,
        .receive_limit = 4096,
        .max_streams_bidi = 0,
        .max_streams_uni = 0,
    });

    // No parameters, undecodable ones, and a window that differs are all
    // disagreement; only the exact numbers and connection ID agree.
    try testing.expect(!ownParametersAgree(&conn));
    conn.transport_parameters = &.{ 0x03, 0x01 };
    try testing.expect(!ownParametersAgree(&conn));
    conn.transport_parameters = encodeParameters(&buffer, .server, .{
        .initial_source_connection_id = &dcid,
        .initial_max_data = 4095,
    });
    try testing.expect(!ownParametersAgree(&conn));
    conn.transport_parameters = encodeParameters(&buffer, .server, .{
        .initial_source_connection_id = &dcid,
        .initial_max_data = 4096,
        .initial_max_streams_bidi = 1,
    });
    try testing.expect(!ownParametersAgree(&conn));
    conn.transport_parameters = encodeParameters(&buffer, .server, .{
        .initial_source_connection_id = &.{0xd9},
        .initial_max_data = 4096,
    });
    try testing.expect(!ownParametersAgree(&conn));
    conn.transport_parameters = encodeParameters(&buffer, .server, .{
        .initial_source_connection_id = &dcid,
        .initial_max_data = 4096,
    });
    try testing.expect(ownParametersAgree(&conn));
}

test "RFC 9000 §19.20, only a server sends HANDSHAKE_DONE" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x91, 0x92 };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x93},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x93},
        .source_connection_id = &dcid,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x94);
    const server_secret: [protection.secret_length]u8 = @splat(0x95);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [16]u8 = undefined;
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .handshake_done = {} });

    // §19.20: a server that receives one has a peer answering as this endpoint,
    // which is PROTOCOL_VIOLATION rather than a frame to hand upstairs.
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.ProtocolViolation, server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    // §12.4: and it belongs to the application space in either role.
    const wrong_space = try server.writeFrames(.initial, writer.written(), &datagram, .data(0));
    try testing.expectError(error.WrongFrameSpace, client.feed(
        datagram[0..wrong_space],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
}

test "RFC 9000 §20.1, a driver failure carries the CRYPTO_ERROR to close with" {
    const dcid = [_]u8{0x81};
    var stub: seam.Stub = .{ .fail_next = true, .failure = 0x100 + 80 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x8a},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x8a}),
    });

    var datagram: [512]u8 = undefined;
    var frames: [256]u8 = undefined;
    // The alert is one error, and the code the caller closes with is the
    // CRYPTO_ERROR value the driver named, not a table of alerts here.
    try testing.expectError(error.HandshakeFailed, client.writeHandshake(&frames, &datagram, 0));
    try testing.expectEqual(@as(u64, 0x150), client.tls.?.errorCode());
}

test "RFC 8446 §B.4, a suite a driver reports before it is negotiated is not acted on" {
    const dcid = [_]u8{0x96};
    const sha384: [48]u8 = @splat(0x44);
    // Before ServerHello a client has no negotiated suite, so a real driver's
    // answer here is a placeholder. This one is deliberately a suite the
    // package cannot protect with, and the machine must not refuse a handshake
    // over an answer it has no secret to use (§4.1.3 of RFC 8446).
    var stub: seam.Stub = .{ .cipher_suite = .aes_256_gcm_sha384 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x9c},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x9c}),
    });

    try client.installSpaces();
    try testing.expectEqual(@as(?Space, null), client.handshake);
    try testing.expectEqual(@as(?Space, null), client.app);

    // The moment a secret exists, the reported suite is the one that would
    // protect it, and it is still refused by name rather than substituted.
    stub.handshake_secrets = .{ .client = &sha384, .server = &sha384 };
    try testing.expectError(error.UnsupportedCipherSuite, client.installSpaces());
}

test "RFC 8446 §B.4, a suite this package cannot do is refused, never substituted" {
    const dcid = [_]u8{0x95};
    const sha384: [48]u8 = @splat(0x33);
    var stub: seam.Stub = .{
        .cipher_suite = .aes_256_gcm_sha384,
        .handshake_secrets = .{ .client = &sha384, .server = &sha384 },
    };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x9b},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x9b}),
    });

    // The driver says AES-256-GCM, which needs SHA-384 and is not implemented.
    // The machine refuses by name rather than deriving AES-128-GCM and hoping
    // the peer notices.
    try testing.expectError(error.UnsupportedCipherSuite, client.installSpaces());
    try testing.expectEqual(@as(?Space, null), client.handshake);
    try testing.expectEqual(@as(?Space, null), client.app);
}

test "RFC 9001 §5.1, a driver's 48-byte secret is refused rather than truncated" {
    const dcid = [_]u8{0x91};
    const sha384: [48]u8 = @splat(0x33);
    var stub: seam.Stub = .{
        .handshake_secrets = .{ .client = &sha384, .server = &sha384 },
    };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x9a},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &.{0x9a}),
    });

    // A driver that says AES-128-GCM and hands out a 48-byte secret has told two
    // different stories; `deriveKeys` refuses the length, so no space is built
    // from a key schedule that does not belong to it.
    try testing.expectError(error.SecretLengthMismatch, client.installSpaces());
    try testing.expectEqual(@as(?Space, null), client.handshake);
    try testing.expectEqual(@as(?Space, null), client.app);
}

test "an endpoint with no driver has no handshake to write" {
    const dcid = [_]u8{0xa1};
    var conn_loss: LossTables = .{};
    var conn: Conn = .init(.{
        .role = .server,
        .loss = conn_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xaa},
    });

    var datagram: [512]u8 = undefined;
    var frames: [256]u8 = undefined;
    try conn.installSpaces();
    try testing.expect((try conn.writeHandshake(&frames, &datagram, 0)) == null);
}

test "RFC 9000 §19.6, CRYPTO frames that arrive out of order reach the driver in order" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x61, 0x62 };
    const client_secret: [protection.secret_length]u8 = @splat(0x31);
    const server_secret: [protection.secret_length]u8 = @splat(0x32);
    var stub: seam.Stub = .{
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
    };
    var initial_crypto: [64]u8 = undefined;

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x6a},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x6a},
        .source_connection_id = &.{0x6b},
        .tls = stub.driver(),
        .transport_parameters = identityParameters(.server, &dcid, &.{0x6b}),
        .crypto = .{ .initial = &initial_crypto },
    });

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    // The second half of the message first: it is buffered, not delivered.
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .crypto = .{ .offset = 6, .data = "world" } });
    const sent_late = try client.writeFrames(.initial, writer.written(), &datagram, .data(0));
    _ = try server.feed(datagram[0..sent_late], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(u32, 0), stub.fed_calls);

    // The frame before it fills the gap and both halves leave in order.
    var head_writer: Writer = .init(&payload);
    try frame.write(&head_writer, .{ .crypto = .{ .offset = 0, .data = "hello " } });
    const sent_early = try client.writeFrames(.initial, head_writer.written(), &datagram, .data(0));
    const opened = try server.feed(datagram[0..sent_early], &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    try testing.expectEqual(@as(u32, 1), stub.fed_calls);
    try testing.expectEqualStrings("hello world", stub.fed[0..stub.fed_len]);
}

test "RFC 9000 §12.4, a frame that will not parse is an error and not a dropped packet" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{0x63};
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x6c},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x6c},
        .source_connection_id = &.{0x6d},
    });

    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    // 0x3f is a one-byte frame type the registry does not define.
    const bad = [_]u8{0x3f};
    const sent = try client.writeFrames(.initial, &bad, &datagram, .data(0));

    // The packet opened: its bytes are the peer's and they say something
    // invalid, which closes the connection (§12.4). Nothing is dropped.
    var walk: Datagram = .init(datagram[0..sent]);
    try testing.expectError(error.UnknownFrameType, walk.next(
        &server,
        &plaintext,
        &events,
        &stream_events,
        &report,
        0,
    ));
    try testing.expectEqual(@as(u16, 0), walk.dropped);
    // §13.2: a packet the machine did not process is not one it acknowledges,
    // so the range table never heard about this number.
    try testing.expectEqual(@as(?u64, null), server.initial.?.largest_received);
    try testing.expect(!server.ackOwed(.initial));

    // The same through one packet. Unprotecting mutates the datagram, so this
    // is a fresh packet rather than the same bytes again.
    const again = try client.writeFrames(.initial, &bad, &datagram, .data(0));
    try testing.expectError(error.UnknownFrameType, server.feed(
        datagram[0..again],
        &plaintext,
        &events,
        &stream_events,
        &report,
        0,
    ));
}

test "a stream configuration that cannot hold its own limits is refused" {
    var ring: [64]u8 = undefined;
    var other_ring: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;

    const Case = struct { slots: []const StreamTable.Slot, streams: []const Stream, valid: bool };
    const cases = [_]Case{
        // Nothing configured, and slots that match.
        .{ .slots = &slots, .streams = &.{ .{}, .{} }, .valid = true },
        // A ring that holds exactly the window it advertises.
        .{ .slots = &slots, .streams = &.{ .{ .recv_buffer = &ring, .recv_limit_bytes = 64 }, .{} }, .valid = true },
        // A ring one byte short of it: §4.1 says it cannot hold what it says.
        .{ .slots = &slots, .streams = &.{ .{ .recv_buffer = &ring, .recv_limit_bytes = 65 }, .{} }, .valid = false },
        // A limit with no ring behind it.
        .{ .slots = &slots, .streams = &.{ .{ .recv_limit_bytes = 8 }, .{} }, .valid = false },
        // A ring with a zero limit is a stream that receives nothing.
        .{ .slots = &slots, .streams = &.{ .{ .recv_buffer = &ring, .recv_limit_bytes = 0 }, .{} }, .valid = true },
        // One slot short of the streams it would have to hold.
        .{ .slots = slots[0..1], .streams = &.{ .{}, .{} }, .valid = false },
        // Two slots over one ring: each stream reassembles where the other
        // already has bytes.
        .{ .slots = &slots, .streams = &.{
            .{ .recv_buffer = &ring, .recv_limit_bytes = 64 },
            .{ .recv_buffer = &ring, .recv_limit_bytes = 64 },
        }, .valid = false },
        // The two halves of one bidirectional stream over one buffer.
        .{ .slots = &slots, .streams = &.{
            .{ .send_buffer = &ring, .recv_buffer = &ring, .recv_limit_bytes = 64 },
            .{},
        }, .valid = false },
        // Another stream's send buffer is this stream's ring.
        .{ .slots = &slots, .streams = &.{
            .{ .send_buffer = &ring, .recv_buffer = &other_ring, .recv_limit_bytes = 64 },
            .{ .recv_buffer = &ring, .recv_limit_bytes = 64 },
        }, .valid = false },
        // A partial overlap is still an overlap, not just an identical slice.
        .{ .slots = &slots, .streams = &.{
            .{ .send_buffer = ring[0..16], .recv_buffer = &other_ring, .recv_limit_bytes = 64 },
            .{ .send_buffer = ring[8..32], .recv_buffer = &other_ring, .recv_limit_bytes = 64 },
        }, .valid = false },
        // Abutting is not overlapping: one ends exactly where the next begins.
        .{ .slots = &slots, .streams = &.{
            .{ .send_buffer = ring[0..32], .recv_buffer = &.{}, .recv_limit_bytes = 0 },
            .{ .send_buffer = ring[32..64], .recv_buffer = &other_ring, .recv_limit_bytes = 64 },
        }, .valid = true },
        // Each stream with its own storage is the configuration this type asks
        // for.
        .{ .slots = &slots, .streams = &.{
            .{ .send_buffer = &other_ring, .recv_buffer = &ring, .recv_limit_bytes = 64 },
            .{},
        }, .valid = true },
    };

    for (cases) |case| {
        try testing.expectEqual(case.valid, streamsValid(case.slots, case.streams));
    }
}

test "RFC 9000 §2.1, opening a stream takes the peer's limit for it" {
    const dcid = [_]u8{ 0x41, 0x42 };
    var client_rings: [2][8]u8 = .{ undefined, undefined };
    var client_slots: [2]StreamTable.Slot = undefined;
    var client_streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &client_rings[0], .recv_limit_bytes = 8 },
        .{ .recv_buffer = &client_rings[1], .recv_limit_bytes = 8 },
    };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x43},
        .stream_slots = &client_slots,
        .streams = &client_streams,
        .peer = .{ .stream_data = .{ .bidi_remote = 10, .uni = 30 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
    });

    var server_rings: [2][8]u8 = .{ undefined, undefined };
    var server_slots: [2]StreamTable.Slot = undefined;
    var server_streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &server_rings[0], .recv_limit_bytes = 8 },
        .{ .recv_buffer = &server_rings[1], .recv_limit_bytes = 8 },
    };
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x43},
        .source_connection_id = &dcid,
        .stream_slots = &server_slots,
        .streams = &server_streams,
        .peer = .{ .stream_data = .{ .bidi_remote = 11, .bidi_local = 20 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
    });

    // §4.1: a bidirectional stream this endpoint opens carries the limit the
    // peer named for the streams it receives, and a one-way stream carries the
    // one-way number. Two different transport parameters, two different limits.
    try testing.expectEqual(@as(u64, 10), (try client.openStream(0)).send.limit);
    try testing.expectEqual(@as(u64, 30), (try client.openStream(2)).send.limit);
    try testing.expectEqual(@as(u64, 11), (try server.openStream(1)).send.limit);

    // §2.1: the low bits say who opens a stream. Stream 1 is the server's, and
    // stream 0 is the client's; each endpoint refuses the other's.
    try testing.expectError(error.WrongDirection, client.openStream(1));
    try testing.expectError(error.WrongDirection, server.openStream(0));

    // Joining is not opening: with no slot behind the id there is no stream to
    // widen, and a stream this endpoint opened itself has its sending half
    // already.
    try testing.expectError(error.NotOpen, server.joinStream(0));
    try testing.expectError(error.AlreadyOpen, server.joinStream(1));
    try testing.expectError(error.AlreadyOpen, client.openStream(0));
}

test "RFC 9000 §2.1, a STREAM frame for an unknown stream opens it" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x21, 0x22 };
    var ring: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{ .{ .recv_buffer = &ring, .recv_limit_bytes = 64 }, .{} };

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2a},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2a},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
        .peer = .{ .stream_data = .{ .bidi_local = 64 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x25);
    const server_secret: [protection.secret_length]u8 = @splat(0x26);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 0,
        .data = "hello stream",
        .fin = true,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));

    const opened = try server.feed(datagram[0..sent], &plaintext, &events, &stream_events, &report, 0);
    // The machine has a home for STREAM frames now, so none come back.
    try testing.expectEqual(@as(usize, 0), opened.frames.len);

    const entry = server.stream(4) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(ReceiveStream.State.data_recvd, entry.recv.state);

    var read_buffer: [32]u8 = undefined;
    const read = try entry.recv.readInto(&read_buffer);
    try testing.expectEqualStrings("hello stream", read_buffer[0..read]);
    // §4.1: the connection window counts the highest offset, not the bytes.
    try testing.expectEqual(@as(u64, 12), server.receive_window.used);

    // §2.1: the server answers on the same stream by joining it, which reuses
    // the slot the frame opened and takes the peer's bidi_local limit rather
    // than a number handed in again.
    const joined = try server.joinStream(4);
    try testing.expect(joined == entry);
    try testing.expectEqual(Conn.Stream.Halves.both, joined.halves);
    try testing.expectEqual(@as(u64, 64), joined.send.limit);
    try testing.expectEqual(SendStream.State.ready, joined.send.state);
    try testing.expectError(error.AlreadyOpen, server.joinStream(4));
}

test "RFC 9000 §3.2, a packet reports the streams it made readable" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [8]StreamEvent = undefined;
    const dcid = [_]u8{ 0x31, 0x32 };
    var rings: [2][64]u8 = .{ undefined, undefined };
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &rings[0], .recv_limit_bytes = 64 },
        .{ .recv_buffer = &rings[1], .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x3a},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x3a},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x35);
    const server_secret: [protection.secret_length]u8 = @splat(0x36);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [128]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var writer: Writer = .init(&payload);

    // In order and without FIN: the stream is readable for the first time.
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 0,
        .data = "hello",
        .fin = false,
        .length_present = true,
    } });
    const first_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const first = try server.feed(datagram[0..first_sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 1), first.streams.len);
    try testing.expectEqual(@as(u64, 4), first.streams[0].stream_id);
    try testing.expect(first.streams[0].readable);
    try testing.expect(!first.streams[0].finished);

    // Past a gap: the bytes are held, and nothing the application can read has
    // changed, so there is no record and no reason to look at the stream.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 10,
        .data = "world",
        .fin = false,
        .length_present = true,
    } });
    const held_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const held = try server.feed(datagram[0..held_sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), held.streams.len);

    // Filling the gap joins the two runs into one readable extent.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 5,
        .data = "abcde",
        .fin = false,
        .length_present = true,
    } });
    const joined_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const joined = try server.feed(datagram[0..joined_sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 1), joined.streams.len);
    try testing.expect(joined.streams[0].readable);
    try testing.expect(!joined.streams[0].finished);

    // §3.2: the FIN arrives alone at the final size, which completes the
    // stream. That is the second fact, and the stream is not readable again.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 15,
        .data = "",
        .fin = true,
        .length_present = true,
    } });
    const done_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const done = try server.feed(datagram[0..done_sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 1), done.streams.len);
    try testing.expect(!done.streams[0].readable);
    try testing.expect(done.streams[0].finished);

    // A retransmission the peer sent before its acknowledgment arrived is
    // accepted and reported to nobody: it changed no answer.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 0,
        .data = "hello",
        .fin = false,
        .length_present = true,
    } });
    const again_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const again = try server.feed(datagram[0..again_sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 0), again.streams.len);

    // One record per stream: two frames for stream 8 in one packet are one
    // fact, with the FIN making both flags true.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 8,
        .offset = 0,
        .data = "ab",
        .fin = false,
        .length_present = true,
    } });
    try frame.write(&writer, .{ .stream = .{
        .id = 8,
        .offset = 2,
        .data = "cd",
        .fin = true,
        .length_present = true,
    } });
    const pair_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const pair = try server.feed(datagram[0..pair_sent], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(usize, 1), pair.streams.len);
    try testing.expectEqual(@as(u64, 8), pair.streams[0].stream_id);
    try testing.expect(pair.streams[0].readable);
    try testing.expect(pair.streams[0].finished);

    // A list with no room refuses instead of losing the fact.
    var none: [0]StreamEvent = .{};
    var count: usize = 0;
    try testing.expectError(error.NoSpace, noteStreamEvent(&none, &count, .{
        .stream_id = 0,
        .readable = true,
        .finished = false,
    }));
    try testing.expectEqual(@as(usize, 0), count);
}

test "RFC 9000 §19.4, a reset ends the receive half and the application reads the code" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x51, 0x52 };
    var rings: [2][64]u8 = .{ undefined, undefined };
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &rings[0], .recv_limit_bytes = 64 },
        .{ .recv_buffer = &rings[1], .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x53},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x53},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
        .peer = .{ .stream_data = .{ .bidi_remote = 64, .bidi_local = 64 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x54);
    const server_secret: [protection.secret_length]u8 = @splat(0x55);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var writer: Writer = .init(&payload);

    // §19.4: the client gives up on stream 4 and names the bytes it will never
    // send. The machine ends the receive half and says so; nothing is left for
    // the caller's frame list.
    try frame.write(&writer, .{ .reset_stream = .{
        .stream_id = 4,
        .error_code = 0x1234,
        .final_size = 10,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const opened = try server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    try testing.expectEqual(@as(usize, 1), opened.streams.len);
    try testing.expectEqual(@as(u64, 4), opened.streams[0].stream_id);
    try testing.expect(opened.streams[0].reset);
    try testing.expect(!opened.streams[0].readable);

    const entry = server.stream(4) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(ReceiveStream.State.reset_recvd, entry.recv.state);
    try testing.expectEqual(@as(?u64, 10), entry.recv.final_size);

    // §4.5: the final size a reset names cannot change, and a second reset with
    // a different one is FINAL_SIZE_ERROR.
    writer = .init(&payload);
    try frame.write(&writer, .{ .reset_stream = .{
        .stream_id = 4,
        .error_code = 0x1235,
        .final_size = 12,
    } });
    const changed = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.FinalSize, server.feed(
        datagram[0..changed],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    // The same reset again changes nothing, so it is reported to nobody.
    writer = .init(&payload);
    try frame.write(&writer, .{ .reset_stream = .{
        .stream_id = 4,
        .error_code = 0x1234,
        .final_size = 10,
    } });
    const again = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const repeated = try server.feed(
        datagram[0..again],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), repeated.streams.len);

    // The application takes the code, which is the only place it is kept.
    try testing.expectEqual(@as(u64, 0x1234), try entry.recv.readReset());

    // §19.4: a send-only stream has no receive half to reset: stream 3 is the
    // server's own one-way stream.
    writer = .init(&payload);
    try frame.write(&writer, .{ .reset_stream = .{
        .stream_id = 3,
        .error_code = 1,
        .final_size = 0,
    } });
    const wrong_way = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..wrong_way],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    // §4.1: a final size past the advertised window is FLOW_CONTROL_ERROR.
    writer = .init(&payload);
    try frame.write(&writer, .{ .reset_stream = .{
        .stream_id = 8,
        .error_code = 2,
        .final_size = 65,
    } });
    const too_big = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.FlowControl, server.feed(
        datagram[0..too_big],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
}

test "RFC 9000 §19.5, stop sending resets the sending half and owes a reset" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x61, 0x62 };
    var rings: [2][64]u8 = .{ undefined, undefined };
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &rings[0], .recv_limit_bytes = 64 },
        .{ .recv_buffer = &rings[1], .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x63},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x63},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
        .peer = .{ .stream_data = .{ .bidi_remote = 64, .bidi_local = 64 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x64);
    const server_secret: [protection.secret_length]u8 = @splat(0x65);
    installApp(&client, &server, client_secret, server_secret);

    // The server's own bidirectional stream, which it has sent nothing on yet.
    const own = try server.openStream(1);
    try testing.expectEqual(SendStream.State.ready, own.send.state);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var writer: Writer = .init(&payload);

    // §3.5: the peer stops reading, and the machine resets the sending half in
    // place. The RESET_STREAM is the caller's to send, with the code it asked
    // for.
    try frame.write(&writer, .{ .stop_sending = .{ .stream_id = 1, .error_code = 0x99 } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const opened = try server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    try testing.expectEqual(@as(usize, 1), opened.streams.len);
    try testing.expectEqual(@as(?u64, 0x99), opened.streams[0].reset_owed);
    try testing.expectEqual(SendStream.State.reset_sent, own.send.state);
    try testing.expectEqual(@as(?u64, 0x99), own.send.reset_code);

    // §19.5: a receive-only stream is one this endpoint can never send on, and a
    // locally initiated stream that was never opened has no sending half to
    // stop. Both are STREAM_STATE_ERROR.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stop_sending = .{ .stream_id = 2, .error_code = 1 } });
    const one_way = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..one_way],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    writer = .init(&payload);
    try frame.write(&writer, .{ .stop_sending = .{ .stream_id = 5, .error_code = 1 } });
    const unopened = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..unopened],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    // §3.2: a STOP_SENDING for a peer-initiated stream that no frame has
    // reached yet opens it, sending half included, so the request has a home.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stop_sending = .{ .stream_id = 8, .error_code = 7 } });
    const early = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const fresh_opened = try server.feed(
        datagram[0..early],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(?u64, 7), fresh_opened.streams[0].reset_owed);

    const fresh = server.stream(8) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Conn.Stream.Halves.both, fresh.halves);
    try testing.expectEqual(@as(u64, 64), fresh.send.limit);
    try testing.expectEqual(SendStream.State.reset_sent, fresh.send.state);
}

test "RFC 9000 §19.11, the peer's MAX_STREAMS is the credit to open" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x8b, 0x8c };
    var rings: [2][64]u8 = .{ undefined, undefined };
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &rings[0], .recv_limit_bytes = 64 },
        .{ .recv_buffer = &rings[1], .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x8d},
        .stream_slots = &slots,
        .streams = &streams,
        .peer = .{ .stream_data = .{ .bidi_remote = 64, .uni = 64 }, .max_streams = .{ .bidi = 1 } },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x8d},
        .source_connection_id = &dcid,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x8e);
    const server_secret: [protection.secret_length]u8 = @splat(0x8f);
    installApp(&client, &server, client_secret, server_secret);

    // §4.6: the credit is a count of streams, so ordinal 0 fits one and ordinal
    // 1 does not; a one-way stream has its own, which is zero here.
    _ = try client.openStream(0);
    try testing.expectError(error.NoStreamCredit, client.openStream(4));
    try testing.expectError(error.NoStreamCredit, client.openStream(2));

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var writer: Writer = .init(&payload);

    // §19.11: the frame raises the count, and the machine is where it lands.
    try frame.write(&writer, .{ .max_streams = .{ .direction = .bidi, .maximum = 2 } });
    const raised = try server.writeFrames(.app, writer.written(), &datagram, .data(0));
    const opened = try client.feed(
        datagram[0..raised],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    _ = try client.openStream(4);

    // §4.6: a smaller count is loss or reordering, and it is ignored.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_streams = .{ .direction = .bidi, .maximum = 1 } });
    const lowered = try server.writeFrames(.app, writer.written(), &datagram, .data(0));
    _ = try client.feed(datagram[0..lowered], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(u64, 2), client.peer_max_streams.bidi);
    try testing.expectError(error.NoStreamCredit, client.openStream(8));

    // §19.11: a count that permits a stream id this protocol cannot name is
    // FRAME_ENCODING_ERROR for the caller to close with.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_streams = .{
        .direction = .bidi,
        .maximum = (1 << 60) + 1,
    } });
    const too_many = try server.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamCountTooLarge, client.feed(
        datagram[0..too_many],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    // §12.4: MAX_STREAMS belongs to the application space.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_streams = .{ .direction = .bidi, .maximum = 4 } });
    const wrong_space = try server.writeFrames(.initial, writer.written(), &datagram, .data(0));
    try testing.expectError(error.WrongFrameSpace, client.feed(
        datagram[0..wrong_space],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
}

test "RFC 9000 §19.9, a peer's MAX_DATA raises the connection allowance" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x81, 0x82 };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x83},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x83},
        .source_connection_id = &dcid,
        .peer = .{ .max_data = 64 },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x84);
    const server_secret: [protection.secret_length]u8 = @splat(0x85);
    installApp(&client, &server, client_secret, server_secret);

    // §4.1: the peer's connection-wide allowance starts at what it advertised,
    // and the frame raises it where the machine keeps it.
    try testing.expectEqual(@as(u64, 64), server.send_window.available());

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .max_data = 4096 });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const opened = try server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    try testing.expectEqual(@as(u64, 4096), server.send_window.available());

    // §12.4: MAX_DATA belongs to the application space, and one in an Initial is
    // a connection error rather than a frame the caller has to police.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_data = 8192 });
    const wrong_space = try client.writeFrames(.initial, writer.written(), &datagram, .data(0));
    try testing.expectError(error.WrongFrameSpace, server.feed(
        datagram[0..wrong_space],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
}

test "RFC 9000 §19.10, a peer's credit reaches the stream it names" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x86, 0x87 };
    var rings: [2][64]u8 = .{ undefined, undefined };
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &rings[0], .recv_limit_bytes = 64 },
        .{ .recv_buffer = &rings[1], .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x88},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x88},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
        .peer = .{ .stream_data = .{ .bidi_remote = 10, .bidi_local = 20 }, .max_streams = .{ .bidi = 8, .uni = 8 } },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x89);
    const server_secret: [protection.secret_length]u8 = @splat(0x8a);
    installApp(&client, &server, client_secret, server_secret);

    const own = try server.openStream(1);
    try testing.expectEqual(@as(u64, 10), own.send.limit);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var writer: Writer = .init(&payload);

    // §19.10: the limit on a stream this endpoint opened moves where the stream
    // keeps it, and the frame is no longer the caller's to dispatch.
    try frame.write(&writer, .{ .max_stream_data = .{ .stream_id = 1, .maximum = 100 } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const opened = try server.feed(
        datagram[0..sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    try testing.expectEqual(@as(u64, 100), own.send.limit);

    // §4.1: a limit that does not increase is ignored, not an error.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_stream_data = .{ .stream_id = 1, .maximum = 50 } });
    const lower = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    _ = try server.feed(datagram[0..lower], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(@as(u64, 100), own.send.limit);

    // §19.10: a receive-only stream, and a locally initiated stream that was
    // never created, are both STREAM_STATE_ERROR.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_stream_data = .{ .stream_id = 2, .maximum = 100 } });
    const one_way = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..one_way],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    writer = .init(&payload);
    try frame.write(&writer, .{ .max_stream_data = .{ .stream_id = 5, .maximum = 100 } });
    const unopened = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..unopened],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    // §3.2: a MAX_STREAM_DATA for a peer-initiated stream opens it, sending half
    // included, and the limit it names is the credit the new half starts with.
    writer = .init(&payload);
    try frame.write(&writer, .{ .max_stream_data = .{ .stream_id = 8, .maximum = 100 } });
    const early = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    _ = try server.feed(datagram[0..early], &plaintext, &frames, &stream_events, &report, 0);

    const fresh = server.stream(8) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Conn.Stream.Halves.both, fresh.halves);
    try testing.expectEqual(@as(u64, 100), fresh.send.limit);
}

test "RFC 9000 §3.3, a frame for a stream this endpoint closed is ignored" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x71, 0x72 };
    var rings: [2][64]u8 = .{ undefined, undefined };
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &rings[0], .recv_limit_bytes = 64 },
        .{ .recv_buffer = &rings[1], .recv_limit_bytes = 64 },
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x73},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x73},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
        .peer = .{
            .stream_data = .{ .bidi_remote = 64, .uni = 64, .bidi_local = 64 },
            .max_streams = .{ .bidi = 8, .uni = 8 },
        },
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x74);
    const server_secret: [protection.secret_length]u8 = @splat(0x75);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;

    // The server opens stream 1 and its one-way stream 3, and finishes 1: the
    // sending half is reset and acknowledged, the receiving half ends with the
    // peer's FIN and is read out.
    const own = try server.openStream(1);
    try own.send.reset(0);
    try own.send.onResetAcked();
    _ = try server.openStream(3);

    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 1,
        .offset = 0,
        .data = "",
        .fin = true,
        .length_present = true,
    } });
    const fin_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    _ = try server.feed(
        datagram[0..fin_sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    var read_buffer: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try own.recv.readInto(&read_buffer));
    try server.closeStream(1);
    try testing.expect(server.stream(1) == null);

    // §3.3: a STREAM frame delayed past the close arrives for an id the table no
    // longer holds. It was created, so it is not a violation, and there is
    // nothing left to deliver it to.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 1,
        .offset = 0,
        .data = "late",
        .fin = false,
        .length_present = true,
    } });
    const late_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const late = try server.feed(
        datagram[0..late_sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), late.frames.len);
    try testing.expectEqual(@as(usize, 0), late.streams.len);
    try testing.expect(server.stream(1) == null);

    // The same delayed frame as a STOP_SENDING is ignored for the same reason.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stop_sending = .{ .stream_id = 1, .error_code = 3 } });
    const stop_sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    const stopped = try server.feed(
        datagram[0..stop_sent],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    );
    try testing.expectEqual(@as(usize, 0), stopped.streams.len);

    // §19.8: a STREAM frame for a send-only stream this endpoint still holds is
    // STREAM_STATE_ERROR, and so is one for a locally initiated id it never
    // opened. Stream 3 is the server's own one-way stream; stream 5 it has never
    // created.
    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 3,
        .offset = 0,
        .data = "x",
        .fin = false,
        .length_present = true,
    } });
    const send_only = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..send_only],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));

    writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 5,
        .offset = 0,
        .data = "x",
        .fin = false,
        .length_present = true,
    } });
    const never = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    try testing.expectError(error.StreamState, server.feed(
        datagram[0..never],
        &plaintext,
        &frames,
        &stream_events,
        &report,
        0,
    ));
}

test "RFC 9000 §4.2, reading a ring is what makes a window raise due" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{0x24};
    var ring: [64]u8 = undefined;
    var slots: [1]StreamTable.Slot = undefined;
    var streams: [1]Conn.Stream = .{.{ .recv_buffer = &ring, .recv_limit_bytes = 64 }};

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2c},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2c},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 64,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x29);
    const server_secret: [protection.secret_length]u8 = @splat(0x2a);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [128]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    var owed: [4]frame.Frame = undefined;

    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 0,
        .data = &@as([60]u8, @splat(0x5a)),
        .fin = false,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));
    _ = try server.feed(datagram[0..sent], &plaintext, &events, &stream_events, &report, 0);

    // §4.2: arriving bytes open nothing. The window is tied to what the
    // application consumed, so a peer cannot make the receiver advertise credit
    // it has not read.
    try testing.expectEqual(@as(usize, 0), server.flowControlOwed(&owed).len);

    const entry = server.stream(4) orelse
        return error.TestUnexpectedResult;
    var read_buffer: [64]u8 = undefined;
    const read = try entry.recv.readInto(&read_buffer);
    try testing.expectEqual(@as(usize, 60), read);

    // 60 of the 64 advertised bytes are read, so 4 of credit are left: under
    // half a window. Both windows slide to 60 consumed plus their size.
    const due = server.flowControlOwed(&owed);
    try testing.expectEqual(@as(usize, 2), due.len);
    try testing.expectEqual(@as(u64, 124), due[0].max_data);
    try testing.expectEqual(@as(u64, 4), due[1].max_stream_data.stream_id);
    try testing.expectEqual(@as(u64, 124), due[1].max_stream_data.maximum);

    // Deciding is not raising: until the caller says the frames left, the same
    // ones are still due.
    try testing.expectEqual(@as(usize, 2), server.flowControlOwed(&owed).len);
    try testing.expectEqual(@as(u64, 64), server.receive_window.limit);
    try testing.expectEqual(@as(u64, 64), entry.recv.limit);

    server.onFlowControlSent(due);
    try testing.expectEqual(@as(u64, 124), server.receive_window.limit);
    try testing.expectEqual(@as(u64, 124), entry.recv.limit);
    try testing.expectEqual(@as(usize, 0), server.flowControlOwed(&owed).len);

    // §4.2: a late or damaged frame cannot lower a limit.
    server.onFlowControlSent(&.{.{ .max_data = 8 }});
    try testing.expectEqual(@as(u64, 124), server.receive_window.limit);
}

test "RFC 9000 §4.6, a full stream table is peer-visible and not a dropped packet" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{0x23};
    var ring: [64]u8 = undefined;
    var slots: [1]StreamTable.Slot = undefined;
    var streams: [1]Conn.Stream = .{.{ .recv_buffer = &ring, .recv_limit_bytes = 64 }};

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2b},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2b},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x27);
    const server_secret: [protection.secret_length]u8 = @splat(0x28);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    // Two streams in one packet, and room for one.
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = "a",
        .fin = true,
        .length_present = true,
    } });
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 0,
        .data = "b",
        .fin = true,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));

    // §4.6: the connection closes with STREAM_LIMIT_ERROR, so the caller must
    // see it. The walk does not swallow it the way it swallows a bad tag.
    var walk: Datagram = .init(datagram[0..sent]);
    try testing.expectError(error.StreamLimit, walk.next(&server, &plaintext, &events, &stream_events, &report, 0));
    try testing.expectEqual(@as(u16, 0), walk.dropped);
}

test "RFC 9000 §4.1, a peer past the stream limit is a connection error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x24, 0x25 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2c},
    });
    var ring: [64]u8 = undefined;
    var slots: [1]StreamTable.Slot = undefined;
    var streams: [1]Conn.Stream = .{.{ .recv_buffer = &ring, .recv_limit_bytes = 4 }};
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2c},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 1024,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x29);
    const server_secret: [protection.secret_length]u8 = @splat(0x2a);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    // The stream's limit is 4 and the frame ends at 5 (§4.1).
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = "hello",
        .fin = false,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));

    try testing.expectError(error.FlowControl, server.feed(
        datagram[0..sent],
        &plaintext,
        &events,
        &stream_events,
        &report,
        0,
    ));
    // The connection window was not touched: the stream refused it first.
    try testing.expectEqual(@as(u64, 0), server.receive_window.used);
}

test "RFC 9000 §4.1, a peer past the connection limit is a connection error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x26, 0x27 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2d},
    });
    var ring_a: [64]u8 = undefined;
    var ring_b: [64]u8 = undefined;
    var slots: [2]StreamTable.Slot = undefined;
    var streams: [2]Conn.Stream = .{
        .{ .recv_buffer = &ring_a, .recv_limit_bytes = 64 },
        .{ .recv_buffer = &ring_b, .recv_limit_bytes = 64 },
    };
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2d},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
        .receive_limit = 8,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x2b);
    const server_secret: [protection.secret_length]u8 = @splat(0x2c);
    installApp(&client, &server, client_secret, server_secret);

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    // Each stream is inside its own limit; together they pass the connection's.
    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = "12345",
        .fin = false,
        .length_present = true,
    } });
    try frame.write(&writer, .{ .stream = .{
        .id = 4,
        .offset = 0,
        .data = "67890",
        .fin = false,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.app, writer.written(), &datagram, .data(0));

    try testing.expectError(error.FlowControl, server.feed(
        datagram[0..sent],
        &plaintext,
        &events,
        &stream_events,
        &report,
        0,
    ));
    // The first stream's five bytes were counted before the second blew it.
    try testing.expectEqual(@as(u64, 5), server.receive_window.used);
}

test "RFC 9000 §12.4, a STREAM frame in an Initial packet is a connection error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{0x28};
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2e},
    });
    var ring: [64]u8 = undefined;
    var slots: [1]StreamTable.Slot = undefined;
    var streams: [1]Conn.Stream = .{.{ .recv_buffer = &ring, .recv_limit_bytes = 64 }};
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2e},
        .source_connection_id = &dcid,
        .stream_slots = &slots,
        .streams = &streams,
    });

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    var writer: Writer = .init(&payload);
    try frame.write(&writer, .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = "x",
        .fin = false,
        .length_present = true,
    } });
    const sent = try client.writeFrames(.initial, writer.written(), &datagram, .data(0));

    try testing.expectError(error.WrongFrameSpace, server.feed(
        datagram[0..sent],
        &plaintext,
        &events,
        &stream_events,
        &report,
        0,
    ));
    try testing.expect(server.stream(0) == null);
}

test "RFC 9000 §19.8, a segment out of the send half goes out in a STREAM frame" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x29, 0x2a };
    var send_buffer: [64]u8 = undefined;
    var client_ring: [64]u8 = undefined;
    var client_slots: [2]StreamTable.Slot = undefined;
    var client_streams: [2]Conn.Stream = .{
        .{ .send_buffer = &send_buffer, .recv_buffer = &client_ring, .recv_limit_bytes = 64 },
        .{},
    };

    var receive_ring: [64]u8 = undefined;
    var server_slots: [2]StreamTable.Slot = undefined;
    var server_streams: [2]Conn.Stream = .{ .{ .recv_buffer = &receive_ring, .recv_limit_bytes = 64 }, .{} };

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x2f},
        .stream_slots = &client_slots,
        .streams = &client_streams,
        .peer = .{
            .max_data = 64,
            .stream_data = .{ .bidi_remote = 64, .bidi_local = 64 },
            .max_streams = .{ .bidi = 8, .uni = 8 },
        },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x2f},
        .source_connection_id = &dcid,
        .stream_slots = &server_slots,
        .streams = &server_streams,
        .receive_limit = 64,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x2d);
    const server_secret: [protection.secret_length]u8 = @splat(0x2e);
    installApp(&client, &server, client_secret, server_secret);

    const entry = try client.openStream(0);
    try entry.send.write("stream bytes");
    try entry.send.finish();

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    var written: [1]Written = undefined;
    const flight = (try client.writeStreams(.{
        .offers = &.{.{ .stream_id = 0, .length = 64 }},
        .frames = &payload,
        .out = &datagram,
        .written = &written,
        .max_payload = 64,
        .now = 0,
    })) orelse return error.TestUnexpectedResult;
    // §19.8: the description says which packet the bytes went out under, and the
    // FIN rode on the segment that reached the final size.
    try testing.expectEqual(@as(u64, 0), flight.number);
    try testing.expectEqual(@as(usize, 1), flight.frames.len);
    try testing.expectEqual(@as(u64, 0), flight.frames[0].stream_id);
    try testing.expectEqual(@as(u32, 12), flight.frames[0].length);
    try testing.expect(flight.frames[0].fin);
    try testing.expectEqual(Consumed{ .taken = 1, .partial = 0 }, flight.consumed);

    _ = try server.feed(datagram[0..flight.length], &plaintext, &events, &stream_events, &report, 0);

    const received = server.stream(0) orelse
        return error.TestUnexpectedResult;
    // The FIN rode on the segment that reached the final size (§19.8), so the
    // stream knows its size before anything is read.
    try testing.expectEqual(ReceiveStream.State.data_recvd, received.recv.state);

    var read_buffer: [32]u8 = undefined;
    const read = try received.recv.readInto(&read_buffer);
    try testing.expectEqualStrings("stream bytes", read_buffer[0..read]);
    try testing.expectEqual(ReceiveStream.State.data_read, received.recv.state);
    // §4.1: the send allowance moved with the bytes.
    try testing.expectEqual(@as(u64, 12), client.send_window.sent);
}

test "RFC 9000 §12.2, a server flight of Initial and Handshake in one datagram" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x0d, 0x0e };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x0a},
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x0a},
        .source_connection_id = &.{0x0b},
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x77);
    const server_secret: [protection.secret_length]u8 = @splat(0x88);
    installHandshake(&client, &server, client_secret, server_secret);

    // The flight the server cannot know the client can read: both levels in
    // one datagram, because it is one datagram's worth of network.
    var flight: [1024]u8 = undefined;
    const initial_payload = pings(3);
    const handshake_payload = pings(2);
    const initial_len = try server.writeFrames(.initial, &initial_payload, &flight, .data(0));
    const handshake_len = try server.writeFrames(.handshake, &handshake_payload, flight[initial_len..], .data(0));
    var datagram: Datagram = .init(flight[0 .. initial_len + handshake_len]);

    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    const first = (try datagram.next(&client, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.initial, first.space);
    try testing.expectEqual(@as(usize, 3), first.frames.len);
    try testing.expectEqual(@as(?u64, 0), client.initial.?.largest_received);
    try testing.expectEqual(@as(?u64, null), client.handshake.?.largest_received);

    const second = (try datagram.next(&client, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.handshake, second.space);
    try testing.expectEqual(@as(usize, 2), second.frames.len);
    try testing.expectEqual(@as(?u64, 0), client.handshake.?.largest_received);

    try testing.expect((try datagram.next(&client, &plaintext, &events, &stream_events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
    // Both spaces are accounted for separately, which is what the client needs
    // to answer each level with an ACK of its own (§13.2.1).
    try testing.expect(client.ackOwed(.initial));
    try testing.expect(client.ackOwed(.handshake));
}

test "RFC 9001 §4.1.1, a coalesced 1-RTT packet opens once the Finished is fed" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x3d, 0x3e };
    const client_cid = [_]u8{0x3a};
    const client_secret: [protection.secret_length]u8 = @splat(0x66);
    const server_secret: [protection.secret_length]u8 = @splat(0x67);
    const app_client_secret: [protection.secret_length]u8 = @splat(0x68);
    const app_server_secret: [protection.secret_length]u8 = @splat(0x69);

    var client_stub: seam.Stub = .{
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
        .app_secrets = .{ .client = &app_client_secret, .server = &app_server_secret },
        .peer_parameters = identityParameters(.server, &dcid, &dcid),
    };
    // A real driver derives the application secrets from the peer's Finished
    // (§7.1 of RFC 8446), so this one holds them back until the handshake's
    // bytes arrive. That is what makes the install's timing observable: the
    // 1-RTT packet is coalesced behind the packet carrying that Finished.
    var server_stub: seam.Stub = .{
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
        .app_secrets = .{ .client = &app_client_secret, .server = &app_server_secret },
        .app_secrets_after_feed = true,
        .peer_parameters = identityParameters(.client, &dcid, &client_cid),
    };

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &client_cid,
        .tls = client_stub.driver(),
        .transport_parameters = identityParameters(.client, &dcid, &client_cid),
    });
    var server_loss: LossTables = .{};
    var server_crypto: [128]u8 = undefined;
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &client_cid,
        .source_connection_id = &dcid,
        .tls = server_stub.driver(),
        .transport_parameters = identityParameters(.server, &dcid, &dcid),
        .crypto = .{ .handshake = &server_crypto },
    });

    try client.installSpaces();
    try server.installSpaces();
    try testing.expect(server.handshake != null);
    // Not yet: nothing has told this endpoint that the handshake's last message
    // arrived, so there is no 1-RTT space to read with.
    try testing.expectEqual(@as(?Space, null), server.app);

    // The client's Finished and its first 1-RTT packet in one datagram, which
    // §12.2 of RFC 9000 allows and §4.1.1 of RFC 9001 lets it send.
    var flight: [1024]u8 = undefined;
    var frames_buf: [64]u8 = undefined;
    var writer: Writer = .init(&frames_buf);
    try frame.write(&writer, .{ .crypto = .{ .offset = 0, .data = "Finished bytes" } });
    const handshake_len = try client.writeFrames(.handshake, writer.written(), &flight, .data(0));
    const app_len = try client.writeFrames(.app, &pings(1), flight[handshake_len..], .data(0));

    var datagram: Datagram = .init(flight[0 .. handshake_len + app_len]);
    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    const finished = (try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.handshake, finished.space);
    try testing.expectEqual(@as(u32, 1), server_stub.fed_calls);
    // The driver learned what it needed from this packet's bytes, and the
    // machine installed the level before locating the next packet. A machine
    // that waited for the caller's next write would drop the packet below.
    try testing.expect(server.app != null);

    const one_rtt = (try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.app, one_rtt.space);
    try testing.expectEqual(@as(usize, 1), one_rtt.frames.len);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
}

test "RFC 9001 §5.5, a packet that will not unprotect is dropped and the next is processed" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 0x1d, 0x1e };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x1a},
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x1a},
        .source_connection_id = &dcid,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x99);
    const server_secret: [protection.secret_length]u8 = @splat(0xaa);
    installHandshake(&client, &server, client_secret, server_secret);

    var flight: [1024]u8 = undefined;
    const initial_len = try server.writeFrames(.initial, &pings(3), &flight, .data(0));
    const handshake_len = try server.writeFrames(.handshake, &pings(2), flight[initial_len..], .data(0));
    var datagram: Datagram = .init(flight[0 .. initial_len + handshake_len]);

    // A bit in the Initial's authentication tag. An attacker on the path can do
    // this to any datagram, so it must cost exactly one packet.
    datagram.bytes[initial_len - 8] ^= 0x01;

    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    const opened = (try datagram.next(&client, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.handshake, opened.space);
    try testing.expectEqual(@as(usize, 2), opened.frames.len);
    try testing.expectEqual(@as(?u64, null), client.initial.?.largest_received);
    try testing.expectEqual(@as(?u64, 0), client.handshake.?.largest_received);
    try testing.expectEqual(@as(u16, 1), datagram.dropped);
    try testing.expect(!client.ackOwed(.initial));
    try testing.expect(client.ackOwed(.handshake));
}

test "RFC 9000 §12.2, a short header ends the datagram and nothing is read past it" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const server_id = [_]u8{ 0x31, 0x32 };
    const client_id = [_]u8{ 0x41, 0x42 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &server_id,
        .source_connection_id = &client_id,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &server_id,
        .destination_connection_id = &client_id,
        .source_connection_id = &server_id,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0xbb);
    const server_secret: [protection.secret_length]u8 = @splat(0xcc);
    installApp(&client, &server, client_secret, server_secret);

    // A long header, then a short one: legal, and the short one is last
    // because its length is the rest of the datagram.
    var flight: [1024]u8 = undefined;
    const initial_len = try client.writeFrames(.initial, &pings(2), &flight, .data(0));
    const app_len = try client.writeFrames(.app, &pings(3), flight[initial_len..], .data(0));
    var datagram: Datagram = .init(flight[0 .. initial_len + app_len]);

    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    const initial = (try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.initial, initial.space);
    try testing.expectEqual(@as(usize, 2), initial.frames.len);
    const app = (try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.app, app.space);
    try testing.expectEqual(@as(usize, 3), app.frames.len);
    // The whole tail of the datagram belonged to that packet.
    try testing.expectEqual(@as(u32, @intCast(app_len)), app.packet_len);
    try testing.expect((try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
}

test "RFC 9000 §12.2, bytes with no readable end stop the walk without an error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{0x5d};
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x5a},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x5a},
        .source_connection_id = &.{0x5b},
    });

    var flight: [512]u8 = undefined;
    const initial_len = try client.writeFrames(.initial, &pings(3), &flight, .data(0));
    // A long header cut off inside its connection ID: no Length field, so
    // nothing says where the packet would have ended.
    const junk = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02 };
    @memcpy(flight[initial_len..][0..junk.len], &junk);
    var datagram: Datagram = .init(flight[0 .. initial_len + junk.len]);

    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    const opened = (try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 3), opened.frames.len);
    try testing.expect((try datagram.next(&server, &plaintext, &events, &stream_events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 1), datagram.dropped);
}

test "RFC 9000 §12.2, coalesced packets: only the first is taken, the length says where it ends" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 1, 2, 3 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 9, 9 },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 9, 9 },
        .source_connection_id = &.{ 7, 7 },
    });

    var plaintext: [512]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    var combined: [1024]u8 = undefined;
    const first = try client.writeFrames(.initial, &pings(2), &combined, .data(0));
    const second = try client.writeFrames(.initial, &pings(2), combined[first..], .data(0));

    const opened = try server.feed(&combined, &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(u32, @intCast(first)), opened.packet_len);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);

    // The caller continues where the machine said the packet ended.
    const tail = combined[opened.packet_len..][0 .. first + second - opened.packet_len];
    const next = try server.feed(tail, &plaintext, &events, &stream_events, &report, 0);
    try testing.expectEqual(@as(u64, 1), next.packet_number);
}

test "RFC 9001 §5.5, a packet that will not unprotect changes nothing" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    const dcid = [_]u8{ 4, 5, 6 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 1, 1 },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 1, 1 },
        .source_connection_id = &.{ 2, 2 },
    });

    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var events: [8]frame.Frame = undefined;
    const sent = try client.writeFrames(.initial, &pings(4), &datagram, .data(0));

    // One bit in the ciphertext, far from the header sample.
    datagram[sent - 20] ^= 0x01;
    try testing.expectError(
        error.AuthenticationFailed,
        server.feed(datagram[0..sent], &plaintext, &events, &stream_events, &report, 0),
    );
    try testing.expect(!server.ackOwed(.initial));
    try testing.expectEqual(@as(?u64, null), server.initial.?.largest_received);
}

test "a connection pins the address it is used from" {
    const dcid = [_]u8{ 0x81, 0x82 };
    var loss: LossTables = .{};
    var conn: Conn = .init(clientConfig(&dcid, &.{0x83}, loss.value()));

    // Nothing is recorded until the connection is used: `init` returns by value
    // and cannot see the address the caller gives it.
    try testing.expectEqual(@as(?*const Conn, null), conn.home);
    try testing.expect(atHome(null, &conn));

    // The first call records it, and a second call from the same address is
    // fine.
    var none: [0]frame.Frame = .{};
    _ = conn.flowControlOwed(&none);
    try testing.expectEqual(@as(*const Conn, &conn), conn.home.?);
    try testing.expect(atHome(conn.home, &conn));

    // A copy at another address is what the assertion refuses: a
    // `RecoveryDriver` built over the first one holds `&conn.app.?.recovery`,
    // and the copy's spaces are somewhere else.
    var moved = conn;
    try testing.expect(!atHome(moved.home, &moved));
}

test "a client's configuration seeds its keys from the name it invented" {
    const dcid = [_]u8{ 0x84, 0x85 };
    var loss: LossTables = .{};
    const config = clientConfig(&dcid, &.{0x86}, loss.value());

    try testing.expectEqual(Role.client, config.role);
    // RFC 9001 §5.2: the Initial keys come from the original Destination
    // Connection ID, and §7.2 makes that the same name the client puts in its
    // first packet. One constructor is what keeps the two from disagreeing.
    try testing.expectEqualSlices(u8, &dcid, config.original_destination_connection_id);
    try testing.expectEqualSlices(u8, &dcid, config.destination_connection_id);
    try testing.expectEqualSlices(u8, &.{0x86}, config.source_connection_id);

    // Everything else is the caller's to fill in, and the defaults still build.
    const client: Conn = .init(config);
    try testing.expect(client.initial != null);
}

test "the loss state stays outside the machine, so a copy of it still works" {
    const dcid = [_]u8{ 0x77, 0x78 };
    var loss: LossTables = .{};
    const client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x79},
    });

    // `Conn.init` returns by value, so the caller's assignment is a move. Every
    // space names the caller's `Recovery`, never the `Conn`, and this is the
    // assertion that says so: a `Recovery` field inside `Conn` would leave these
    // pointing at the pre-move address, which is the bug that shows up days
    // later as recovery state changing on its own.
    try testing.expect(client.initial.?.recovery.shared == &loss.shared);
    var moved = client;
    try testing.expect(moved.initial.?.recovery.shared == &loss.shared);

    // The storage is shared, not copied: what the copy records lands in the
    // caller's table, and the slice is the same one both spaces hold.
    var datagram: [512]u8 = undefined;
    _ = try moved.writeFrames(.initial, &pings(2), &datagram, .data(0));
    try testing.expectEqual(@as(usize, 1), moved.initial.?.recovery.inFlight().len);
    try testing.expectEqual(@as(u64, 0), loss.sent_initial[0].packet_number);

    // And so is the estimator, which is the one piece a copy could silently
    // break: a sample taken through the copy is the connection's sample.
    moved.initial.?.recovery.shared.rtt.onSample(0, Recovery.ms(50), 0, .{});
    try testing.expectEqual(Recovery.ms(50), loss.shared.rtt.smoothed);
    try testing.expectEqual(Recovery.ms(50), client.initial.?.recovery.shared.rtt.latest);
}

test "RFC 9002 §6.2.1, a driver over the caller's spaces outlives the connection" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);

    const dcid = [_]u8{ 0x91, 0x92 };
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x93},
    });

    // One ack-eliciting packet in flight arms the Initial space's probe timeout.
    var datagram: [512]u8 = undefined;
    _ = try client.writeFrames(.initial, &pings(2), &datagram, .data(0));

    // The driver is built over the caller's three spaces, which is where the
    // loss state lives now: no address inside the connection is needed, and
    // `init` placed all three so the two without keys are still readable.
    var handles: [3]*Recovery.Space = .{
        &loss.spaces[0],
        &loss.spaces[1],
        &loss.spaces[2],
    };
    var driver: RecoveryDriver = .init(&loss.shared, &handles);
    const options = client.recoveryOptions();
    const before = driver.deadline(options);
    try testing.expectEqual(Recovery.TimerKind.probe, before.kind);
    try testing.expectEqual(@as(usize, 0), before.space);

    // A copy of the connection at another address still points at the same loss
    // state, and the driver, which never knew the connection, is unaffected.
    const moved = client;
    try testing.expect(moved.initial.?.recovery == &loss.spaces[0]);
    const after = driver.deadline(options);
    try testing.expectEqual(before.at, after.at);
    try testing.expectEqual(before.space, after.space);

    // And it can fire: the probe is the Initial space's, from the caller's
    // storage.
    const fired = (try driver.poll(before.at, options, .client, &report)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(Recovery.TimeoutKind.probe, fired.kind);
    try testing.expectEqual(@as(usize, 0), fired.space);
}

test "RFC 9002 §6.1.1, an acknowledgment is what declares the gap lost" {
    const dcid = [_]u8{ 0x7a, 0x7b };
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;

    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x7c},
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x7c},
        .source_connection_id = &.{0x7d},
    });

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    const ms = Recovery.ms;

    // Four packets leave at the same instant. Only the last reaches the server:
    // the loss set is what an acknowledgment of a later packet establishes,
    // never what a timer guesses.
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(ms(10)));
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(ms(10)));
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(ms(10)));
    try testing.expectEqual(@as(usize, 3), client.initial.?.recovery.inFlight().len);

    const fourth = try client.writeFrames(.initial, &pings(1), &datagram, .data(ms(10)));
    _ = try server.feed(datagram[0..fourth], &plaintext, &frames, &stream_events, &report, ms(20));
    const ack_len = try server.writeAck(.initial, &datagram, ms(20));

    // §6.1.1: three packets newer than 0 are not needed; one acknowledgment of
    // packet 3 with nothing else in flight puts packet 0 outside the threshold.
    const at_client = try client.feed(datagram[0..ack_len], &plaintext, &frames, &stream_events, &report, ms(20));
    try testing.expectEqual(@as(usize, 0), at_client.frames.len);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(@as(u64, 3), report.ackedPackets()[0].packet_number);
    try testing.expectEqual(@as(usize, 1), report.lostPackets().len);
    try testing.expectEqual(@as(u64, 0), report.lostPackets()[0].packet_number);
    // §7.1: the lost bytes are the size of the packet that went missing, which is
    // what a congestion controller reacts to.
    try testing.expect(report.lost_bytes > 0);

    // The two in between stay in flight: one acknowledgment is not enough to call
    // them lost, and the time threshold is the timer's business (§6.1.2).
    try testing.expectEqual(@as(usize, 2), client.initial.?.recovery.inFlight().len);
    // §5.1: the sample is the packet 3 round trip, and it is the connection's.
    try testing.expectEqual(ms(10), client_loss.shared.rtt.latest);
}

test "RFC 9002 §6.2.1, a probe timeout is armed over the machine's own space" {
    const dcid = [_]u8{ 0x7e, 0x7f };
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);

    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x80},
    });

    var datagram: [512]u8 = undefined;
    const ms = Recovery.ms;
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(ms(10)));

    // The caller's side of the timer: a driver over the spaces the machine owns.
    // The machine holds no clock, so this is where "when do I wake up" lives.
    var spaces = [_]*Recovery.Space{client.initial.?.recovery};
    var driver: RecoveryDriver = .init(&loss.shared, &spaces);

    // §6.2.1 with no sample yet: smoothed 333ms and variance 166.5ms, so the
    // period is 999ms after the last ack-eliciting packet went out.
    const timer = driver.deadline(.{});
    try testing.expectEqual(Recovery.TimerKind.probe, timer.kind);
    try testing.expectEqual(ms(10) + ms(999), timer.at);
    try testing.expect((try driver.poll(ms(10) + ms(998), .{}, .client, &report)) == null);

    // §6.2.4: a client that has not confirmed the handshake sends two probes.
    const fired = (try driver.poll(timer.at, .{}, .client, &report)).?;
    try testing.expectEqual(Recovery.TimeoutKind.probe, fired.kind);
    try testing.expectEqual(@as(u8, 2), fired.probes);
    // §6.2.1: the backoff doubled, and it doubled across the connection.
    try testing.expectEqual(ms(10) + ms(1998), driver.deadline(.{}).at);
    try testing.expectEqual(@as(u5, 1), loss.shared.pto_count);
}

test "a loss configuration with an empty table is refused" {
    var shared: Recovery = .{};
    var first: [4]Recovery.SentPacket = undefined;
    var second: [4]Recovery.SentPacket = undefined;
    var third: [4]Recovery.SentPacket = undefined;
    const none: []Recovery.SentPacket = first[0..0];

    const Case = struct {
        sent_initial: []Recovery.SentPacket,
        sent_handshake: []Recovery.SentPacket,
        sent_app: []Recovery.SentPacket,
        valid: bool,
    };
    const cases = [_]Case{
        .{ .sent_initial = &first, .sent_handshake = &second, .sent_app = &third, .valid = true },
        // A space with no table is a space whose lost packets nobody reports, so
        // each of the three has to be there.
        .{ .sent_initial = none, .sent_handshake = &second, .sent_app = &third, .valid = false },
        .{ .sent_initial = &first, .sent_handshake = none, .sent_app = &third, .valid = false },
        .{ .sent_initial = &first, .sent_handshake = &second, .sent_app = none, .valid = false },
        // Two spaces over one table: the records would overwrite each other and
        // the packet numbers would stop meaning anything.
        .{ .sent_initial = &first, .sent_handshake = &first, .sent_app = &third, .valid = false },
        // Half of one table and the other half, which is what a caller splitting
        // a buffer by hand looks like.
        .{ .sent_initial = first[0..2], .sent_handshake = first[2..4], .sent_app = &third, .valid = true },
    };

    var spaces: [3]Recovery.Space = undefined;
    for (cases) |case| {
        const loss: Loss = .{
            .shared = &shared,
            .spaces = &spaces,
            .sent_initial = case.sent_initial,
            .sent_handshake = case.sent_handshake,
            .sent_app = case.sent_app,
        };
        try testing.expectEqual(case.valid, lossTablesValid(loss));
        try testing.expectEqual(case.sent_app.len, loss.table(.app).len);
    }
}

test "RFC 9000 §19.3.1, an acknowledgment of a packet never sent is a connection error" {
    const dcid = [_]u8{ 0x81, 0x82 };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x83},
        .connection_id_storage = &adopted_cid,
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x83},
        .source_connection_id = &.{0x84},
    });

    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;

    // The client sends one packet. The server claims to have received packet 6,
    // which the client never used: not reordering, a broken or lying peer.
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(0));
    server.initial.?.largest_received = 6;
    server.initial.?.record(6);
    const ack_len = try server.writeAck(.initial, &datagram, 0);

    try testing.expectError(
        error.InvalidAckRange,
        client.feed(datagram[0..ack_len], &plaintext, &frames, &stream_events, &report, 0),
    );
    // The acknowledgement was refused before the estimator moved.
    try testing.expectEqual(@as(bool, false), client_loss.shared.rtt.first);
    try testing.expectEqual(@as(usize, 1), client.initial.?.recovery.inFlight().len);
}

test "a full sent table refuses the packet instead of forgetting it" {
    const dcid = [_]u8{0x85};
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x86},
    });

    var datagram: [256]u8 = undefined;
    var index: usize = 0;
    while (index < loss.sent_initial.len) : (index += 1) {
        _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(0));
    }

    // The table is the caller's number, and a packet that cannot be recorded is
    // one whose frames are never reported lost. So the write refuses by name,
    // and the packet number did not move: nothing was sent.
    const before = client.initial.?.next_packet_number;
    try testing.expectError(
        error.NoSpace,
        client.writeFrames(.initial, &pings(1), &datagram, .data(0)),
    );
    try testing.expectEqual(before, client.initial.?.next_packet_number);

    // §13.2.1: an acknowledgment on its own is neither ack-eliciting nor in
    // flight, so it takes no room in the table even when the table is full.
    try testing.expectEqual(@as(usize, 0), report.ackedPackets().len);
}

test "RFC 9000 §19.3, a received ACK delay is scaled by the peer's exponent, not ours" {
    const dcid = [_]u8{ 0x87, 0x88 };
    var client_loss: LossTables = .{};
    var adopted_cid: [20]u8 = undefined;
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x89},
        .connection_id_storage = &adopted_cid,
        // Ours is what this endpoint advertises, and the peer scales by its own:
        // the two differ here so reading the wrong one changes every number below.
        .ack_delay_exponent = 5,
        .peer = .{ .ack_delay_exponent = 3 },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x89},
        .source_connection_id = &.{0x8a},
    });

    // The unit conversion itself, including the operator that keeps a hostile
    // 2^62 from wrapping into a small delay.
    try testing.expectEqual(Recovery.ms(8), client.ackDelay(1000));
    try testing.expectEqual(std.math.maxInt(u64), client.ackDelay(std.math.maxInt(u64)));

    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var payload: [64]u8 = undefined;
    var writer: Writer = .init(&payload);
    const ms = Recovery.ms;

    // A first sample with no delay: smoothed 100ms, variance 50ms, min 100ms.
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(0));
    try frame.write(&writer, .{ .ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    } });
    const quiet: Write = .{ .now = 0, .ack_eliciting = false, .in_flight = false };
    const first = try server.writeFrames(.initial, writer.written(), &datagram, quiet);
    _ = try client.feed(datagram[0..first], &plaintext, &frames, &stream_events, &report, ms(100));
    try testing.expectEqual(ms(100), client_loss.shared.rtt.smoothed);

    // A second sample of 200ms whose ACK reports 1000 microseconds: at exponent
    // 3 that is 8ms, so the adjusted sample is 192ms. Without the scaling the
    // smoothed RTT would come out at 112.375ms instead of 111.5ms.
    _ = try client.writeFrames(.initial, &pings(1), &datagram, .data(ms(100)));
    writer = .init(&payload);
    try frame.write(&writer, .{ .ack = .{
        .largest = 1,
        .delay = 1000,
        .first_range = 0,
        .range_count = 0,
        .bytes = &.{},
        .ecn = null,
    } });
    const second = try server.writeFrames(.initial, writer.written(), &datagram, quiet);
    _ = try client.feed(datagram[0..second], &plaintext, &frames, &stream_events, &report, ms(300));
    // `latest` is the raw sample; the delay is subtracted from the value the
    // average takes (§5.3), not from the round trip itself.
    try testing.expectEqual(ms(200), client_loss.shared.rtt.latest);
    try testing.expectEqual(ms(111) + 500_000, client_loss.shared.rtt.smoothed);
}

test "RFC 9000 §10.2.1, a close is written once and nothing is processed after it" {
    const dcid = [_]u8{ 0x8b, 0x8c };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x8d},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x8d},
        .source_connection_id = &dcid,
    });

    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var scratch: [64]u8 = undefined;

    // A packet built before the close, for the "nothing is processed" check
    // below: unprotecting mutates a datagram in place, so each feed needs its own
    // bytes and this one is made while the machine still writes.
    var late: [256]u8 = undefined;
    const late_length = try client.writeFrames(.initial, &pings(1), &late, .data(0));

    // Only the Initial space has keys, so that is where the close goes: §10.2.1
    // asks for the highest-numbered space this endpoint can protect a packet in.
    const length = try client.close(.{
        .error_code = error_code.Transport.protocol_violation.toInt(),
        .frame_type = 0x08,
        .reason = "bad frames",
    }, &scratch, &datagram, 0);
    try testing.expectEqual(State.closing, client.state);
    // §13.2.1 and §7.1 of RFC 9002: a CONNECTION_CLOSE alone is neither
    // ack-eliciting nor in flight, so nothing in the sent table will ever be
    // reported lost for it.
    try testing.expectEqual(@as(usize, 1), client.initial.?.recovery.inFlight().len);

    // The peer reads it, learns the code, and enters the draining state.
    const opened = try server.feed(datagram[0..length], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(.initial, opened.space);
    try testing.expectEqual(State.draining, server.state);
    try testing.expectEqual(@as(usize, 1), opened.frames.len);
    const received = opened.frames[0].connection_close;
    try testing.expectEqual(error_code.Transport.protocol_violation.toInt(), received.error_code);
    try testing.expectEqual(@as(?u64, 0x08), received.frame_type);
    try testing.expectEqualStrings("bad frames", received.reason);
    try testing.expect(!received.application);

    // §10.2.1: a closing endpoint processes nothing more. §10.2.2: neither does
    // a draining one, and it sends nothing at all.
    try testing.expectError(
        error.Closed,
        client.feed(late[0..late_length], &plaintext, &frames, &stream_events, &report, 0),
    );
    try testing.expectError(
        error.Closed,
        server.feed(late[0..late_length], &plaintext, &frames, &stream_events, &report, 0),
    );
    try testing.expectError(
        error.Closed,
        client.writeFrames(.initial, &pings(1), &datagram, .data(0)),
    );
    try testing.expectError(
        error.Closed,
        server.writeFrames(.initial, &pings(1), &datagram, .data(0)),
    );
    try testing.expectError(error.Closed, server.writeAck(.initial, &datagram, 0));
    try testing.expect(!server.ackOwed(.initial));

    // §10.2.1: a closing endpoint answers a packet that arrives too late. The
    // answer is another CONNECTION_CLOSE, and it is the one write a closed
    // connection still makes. §10.2.2: a draining one sends nothing at all.
    try testing.expect(try client.close(.{ .error_code = 0 }, &scratch, &datagram, 0) > 0);
    try testing.expectError(
        error.Closed,
        server.close(.{ .error_code = 0 }, &scratch, &datagram, 0),
    );
    // A stream segment is not consumed by a connection that cannot send it.
    var described: [1]Written = undefined;
    try testing.expectError(
        error.Closed,
        client.writeStreams(.{
            .offers = &.{.{ .stream_id = 0, .length = 64 }},
            .frames = &scratch,
            .out = &datagram,
            .written = &described,
            .max_payload = 64,
            .now = 0,
        }),
    );
    try testing.expectError(error.Closed, client.writeHandshake(&scratch, &datagram, 0));
}

test "RFC 9000 §19.19, an application close carries the application's code" {
    const dcid = [_]u8{0x8e};
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x8f},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x8f},
        .source_connection_id = &dcid,
    });
    const client_secret: [protection.secret_length]u8 = @splat(0x41);
    const server_secret: [protection.secret_length]u8 = @splat(0x42);
    installApp(&client, &server, client_secret, server_secret);

    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    var stream_events: [16]StreamEvent = undefined;
    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var frames: [8]frame.Frame = undefined;
    var scratch: [64]u8 = undefined;

    // 1-RTT keys exist, so the close goes there and the peer reads it in the
    // application space (§10.2.1).
    const length = try client.close(.{ .application = true, .error_code = 0x42 }, &scratch, &datagram, 0);
    const opened = try server.feed(datagram[0..length], &plaintext, &frames, &stream_events, &report, 0);
    try testing.expectEqual(.app, opened.space);
    const received = opened.frames[0].connection_close;
    try testing.expect(received.application);
    try testing.expectEqual(@as(u64, 0x42), received.error_code);
    // §19.19: an application close has no frame type field at all.
    try testing.expectEqual(@as(?u64, null), received.frame_type);
    try testing.expectEqual(State.draining, server.state);
}

/// The transport parameters an endpoint that sets no limits must still send
/// (§7.3): its own connection ID, and from a server the one the client first
/// addressed. Built at compile time so a test can hand the slice to a config
/// without a buffer to keep alive; the same bytes are what a stub reports as
/// the peer's.
fn identityParameters(
    comptime sender: TransportParameters.Role,
    comptime original: []const u8,
    comptime source: []const u8,
) []const u8 {
    const bytes = comptime blk: {
        var buffer: [64]u8 = undefined;
        var writer: Writer = .init(&buffer);
        const parameters: TransportParameters = .{
            .original_destination_connection_id = if (sender == .server) original else null,
            .initial_source_connection_id = source,
        };
        TransportParameters.encode(&writer, parameters, sender) catch unreachable;
        const written = buffer[0..writer.written().len].*;
        break :blk written;
    };
    return &bytes;
}

/// `parameters` encoded as `sender` would send them, into the test's buffer.
fn encodeParameters(
    buffer: []u8,
    sender: TransportParameters.Role,
    parameters: TransportParameters,
) []const u8 {
    var writer: Writer = .init(buffer);
    TransportParameters.encode(&writer, parameters, sender) catch unreachable;
    return writer.written();
}

/// Stand in for the TLS driver: hand an endpoint a space directly, with the
/// keys crossed the way its role needs them. Tests that run the seam use
/// `handshake.Stub` instead and let the machine install the space.
fn plantSpace(conn: *Conn, id: SpaceId, send: protection.Keys, receive: protection.Keys) void {
    std.debug.assert(id != .initial);
    // What a driver fills in: the keys for the level, and nothing else. The
    // counters, the ranges, and the loss handle start where the connection
    // leaves them: a reinstall keeps the table the caller gave for the space.
    const installed: Space = .{
        .send_keys = send,
        .receive_keys = receive,
        .recovery = placeRecovery(conn.loss, id),
    };
    switch (id) {
        .initial => unreachable,
        .handshake => conn.handshake = installed,
        .app => conn.app = installed,
    }
}

fn installHandshake(
    client: *Conn,
    server: *Conn,
    client_secret: [protection.secret_length]u8,
    server_secret: [protection.secret_length]u8,
) void {
    installPaired(client, server, .handshake, client_secret, server_secret);
}

fn installApp(
    client: *Conn,
    server: *Conn,
    client_secret: [protection.secret_length]u8,
    server_secret: [protection.secret_length]u8,
) void {
    installPaired(client, server, .app, client_secret, server_secret);
}

fn installPaired(
    client: *Conn,
    server: *Conn,
    id: SpaceId,
    client_secret: [protection.secret_length]u8,
    server_secret: [protection.secret_length]u8,
) void {
    const client_keys = protection.deriveKeys(&client_secret, .aes_128_gcm) catch unreachable;
    const server_keys = protection.deriveKeys(&server_secret, .aes_128_gcm) catch unreachable;
    plantSpace(client, id, client_keys, server_keys);
    plantSpace(server, id, server_keys, client_keys);
}
