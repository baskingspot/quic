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
//! Loss recovery is the caller's too, and lives outside this type. `Recovery.Space`
//! holds a `*Recovery`, and `Conn.init` returns by value, so a `Recovery` field
//! here would be left behind by the caller's first assignment and every space in
//! the copy would point at the pre-move address. `Config.loss` is the caller's
//! storage instead, and `Conn` keeps only the handles built from it.

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
const seam = @import("handshake.zig");
const packet = @import("packet.zig");
const packet_number = @import("packet_number.zig");
const protection = @import("protection.zig");
const Recovery = @import("Recovery.zig");
/// The caller's side of the timer, which the tests exercise from this file: a
/// connection owns no timer, so "when do I wake up" is asked of the driver over
/// the spaces it owns.
const RecoveryDriver = @import("RecoveryDriver.zig");
const Writer = @import("Writer.zig");
const varint = @import("varint.zig");

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

/// The packet number spaces of §12.3. There are three, not four: 0-RTT and
/// 1-RTT packets share the application data space.
pub const SpaceId = enum { initial, handshake, app };

pub const Error = protection.Error ||
    packet.Error ||
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
        UnsupportedVersion,
        /// An acknowledgment was asked of a space that has received nothing.
        NothingToAcknowledge,
        /// §4.6: the peer opened more streams than this endpoint advertised. It is
        /// peer-visible, not a dropped packet: the connection closes with
        /// STREAM_LIMIT_ERROR.
        StreamLimit,
        /// §12.4: STREAM frames belong to the application space only.
        WrongFrameSpace,
    };

/// Where loss recovery's state lives: the caller's, outside the connection.
///
/// `Conn.init` returns by value, so the caller assigns a `Conn` into its own
/// storage and every field moves. `Recovery.Space` holds a `*Recovery`, so a
/// `Recovery` field inside `Conn` would leave every space pointed at the
/// pre-move address: a dangling pointer that surfaces much later as recovery
/// state changing on its own, with no path back to the cause. The sent tables
/// move for the same reason, because a space keeps a slice of one.
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
    /// This endpoint's `ack_delay_exponent` (§18.2), which scales the delay
    /// field of an ACK frame it receives from microseconds to the resolution it
    /// was measured at. The default is the RFC's, and `init` asserts the
    /// bound §18.2 gives it.
    ack_delay_exponent: u8 = 3,
    /// The peer's `max_ack_delay` in nanoseconds, from its transport parameters
    /// (§18.2). §5.3 of RFC 9002 uses it to bound a reported delay once the
    /// handshake is confirmed, and §7.6.1 uses it in the persistent congestion
    /// period; zero is what the Initial and Handshake spaces have by definition.
    max_ack_delay: Duration = 0,
    /// §6.2.1 of RFC 9002: a client that has not seen its peer validate its
    /// address keeps its PTO backoff across acknowledgments. The machine cannot
    /// observe validation, so the caller seeds this and flips the field of the
    /// same name on `Conn` when it happens.
    peer_address_validated: bool = true,
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
    /// The streams this endpoint can hold: the table's slots and the storage
    /// behind them, in the same order. Their length is the stream limit the
    /// machine advertises, so a peer that opens one more is `error.StreamLimit`
    /// (§4.6) rather than a packet anyone drops.
    stream_slots: []StreamTable.Slot = &.{},
    streams: []Stream = &.{},
    /// §4.1: the connection-wide limit this endpoint advertises, and the one the
    /// peer advertised in its transport parameters.
    receive_limit: u64 = 0,
    send_limit: u64 = 0,
};

/// One stream the machine can hold: the buffers and the per-stream limit, then
/// the two halves the machine builds when the stream opens.
///
/// `send_buffer` and `recv_buffer` are the caller's, and stay theirs: opening a
/// stream fills in `send` and `recv` and never moves a byte.
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
    state: State = .unused,

    /// Which halves a slot holds. Exhaustive on purpose: `send` is only valid
    /// when `state` says so, and a boolean pair could disagree with the slot the
    /// table points at.
    pub const State = enum { unused, recv_only, send_only, both };

    pub fn isOpen(self: *const Stream) bool {
        return self.state != .unused;
    }

    pub fn canSend(self: *const Stream) bool {
        return switch (self.state) {
            .send_only, .both => true,
            .unused, .recv_only => false,
        };
    }
};

pub const CryptoStorage = struct {
    initial: []u8 = "",
    handshake: []u8 = "",
    app: []u8 = "",
};

pub const Opened = struct {
    space: SpaceId,
    packet_number: u64,
    header_len: u32,
    packet_len: u32,
    /// The frames the machine did not act on, in wire order, borrowed from
    /// `payload`. CRYPTO frames went to the driver, STREAM frames to their
    /// stream, and ACK frames to loss recovery, so none of the three appear
    /// here. This is what the caller has to handle itself, and it is the whole
    /// of it.
    frames: []frame.Frame,
    /// The decrypted payload, borrowed from the caller's plaintext buffer.
    payload: []u8,
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
    /// under them is accounted for here and nowhere else. The handle is always
    /// present because the caller always supplies a table; a discard empties it
    /// where it stands, which keeps the address a caller's `RecoveryDriver`
    /// holds valid.
    recovery: Recovery.Space,
    next_packet_number: u64 = 0,
    largest_received: ?u64 = null,
    /// The largest packet number an ACK has been sent for, so a machine does
    /// not acknowledge the same thing twice.
    acked_through: ?u64 = null,
    /// Received packet numbers, descending and merged, for the ACK frame.
    ranges: [range_capacity]Range = undefined,
    range_count: u4 = 0,
    /// How much CRYPTO data this endpoint has sent in this space: the offset
    /// the next CRYPTO frame starts at (§19.6).
    crypto_sent_bytes: u64 = 0,

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
        self.crypto_sent_bytes = 0;
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
packet_number_len: u3,
/// What this endpoint writes into the packets it sends. The connection IDs
/// outlive every space: discarding a space's keys does not change what the peer
/// calls this endpoint.
destination_connection_id: []const u8,
source_connection_id: []const u8,
/// The caller's loss recovery storage, kept as the handles it is: everything
/// here points outside this value, so a copy of a `Conn` does not copy any state
/// that matters. See `Loss`.
loss: Loss,
/// §18.2: how the delay field of an incoming ACK is scaled.
ack_delay_exponent: u8,
/// The peer's `max_ack_delay`, which bounds a reported delay once the handshake
/// is confirmed (§5.3 of RFC 9002).
max_ack_delay: Duration,
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
/// The open streams, and the storage behind each one.
stream_table: StreamTable,
streams: []Stream,
/// §4.1: the receive window across all streams, and the send allowance the peer
/// gave.
receive_window: FlowControl,
send_window: FlowControl.Sender,
/// Whether the driver has them yet. One call, before the first flight.
transport_parameters_set: bool = false,

pub fn init(config: Config) Conn {
    std.debug.assert(config.packet_number_len >= 1);
    std.debug.assert(config.packet_number_len <= 4);
    // §18.2: an exponent above 20 describes a delay nobody can measure.
    std.debug.assert(config.ack_delay_exponent <= 20);

    std.debug.assert(streamsValid(config.stream_slots, config.streams));
    std.debug.assert(lossTablesValid(config.loss));

    const secrets = protection.initialSecrets(config.original_destination_connection_id);
    const suite = protection.Suite.aes_128_gcm;
    const client = protection.deriveKeys(&secrets.client, suite) catch unreachable;
    const server = protection.deriveKeys(&secrets.server, suite) catch unreachable;

    return .{
        .role = config.role,
        .packet_number_len = config.packet_number_len,
        .destination_connection_id = config.destination_connection_id,
        .source_connection_id = config.source_connection_id,
        .loss = config.loss,
        .ack_delay_exponent = config.ack_delay_exponent,
        .max_ack_delay = config.max_ack_delay,
        .peer_address_validated = config.peer_address_validated,
        .tls = config.tls,
        .transport_parameters = config.transport_parameters,
        .crypto = .{
            .init(config.crypto.initial),
            .init(config.crypto.handshake),
            .init(config.crypto.app),
        },
        .stream_table = .init(config.stream_slots),
        .streams = config.streams,
        .receive_window = .init(config.receive_limit),
        .send_window = .init(config.send_limit),
        .initial = .{
            .send_keys = if (config.role == .client) client else server,
            .receive_keys = if (config.role == .client) server else client,
            // The handle points at the caller's `Recovery`, never at `Conn`, so
            // returning this value is safe. That is the whole reason `Loss`
            // exists.
            .recovery = config.loss.shared.space(config.loss.sent_initial),
        },
    };
}

/// The space for `id` with traffic keys installed, or `error.NoKeys` when there
/// is none to act on. A handshake or application space appears when its driver
/// does, and disappears when its keys are discarded; there is no third state.
pub fn spaceFor(self: *Conn, id: SpaceId) Error!*Space {
    return self.spaceMaybe(id) orelse error.NoKeys;
}

/// The same, for a caller that already knows a missing space is not an error.
fn spaceMaybe(self: *Conn, id: SpaceId) ?*Space {
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

fn clear(self: *Conn, id: SpaceId) void {
    switch (id) {
        .initial => self.initial = null,
        .handshake => self.handshake = null,
        .app => self.app = null,
    }
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
pub fn feed(
    self: *Conn,
    datagram: []u8,
    plaintext: []u8,
    frames: []frame.Frame,
    events: *Recovery.Events,
    now: Duration,
) Error!Opened {
    const raw = try self.open(try self.locate(datagram), plaintext);
    const opened = try self.finish(raw, frames, events, now);
    self.commit(raw.id, raw.packet_number);
    return opened;
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

/// Parse the payload's frames and act on the ones the machine owns.
///
/// A CRYPTO frame is reassembled per level and handed to the driver (§19.6), a
/// STREAM frame goes to its stream (§2.1), an ACK is the loss detector's (§6.1 of
/// RFC 9002), and PADDING has no meaning to hand anyone (§19.1). Everything else
/// is written to the caller's array in wire order, because the machine has no home
/// for it yet.
///
/// A frame that will not parse is a connection error (§12.4), not a dropped
/// packet: the datagram walk drops undecryptable packets and nothing else.
fn finish(
    self: *Conn,
    raw: Raw,
    frames: []frame.Frame,
    events: *Recovery.Events,
    now: Duration,
) Error!Opened {
    // A report describes one packet. The loss detector clears it again when it
    // fills it; this is what keeps a packet with no ACK in it from leaving the
    // previous call's records behind for the caller to read twice.
    events.clear();

    var cursor: Cursor = .init(raw.payload);
    var count: usize = 0;
    while (!cursor.atEnd()) {
        switch (try frame.read(&cursor)) {
            .crypto => |crypto| try self.feedCrypto(raw.id, crypto.offset, crypto.data),
            .stream => |frame_stream| try self.onStreamFrame(raw.id, frame_stream),
            .ack => |ack| try self.onAck(raw.id, ack, events, now),
            .padding => {},
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

/// §18.2: the wire's ACK Delay is microseconds scaled down by the sender's
/// exponent, and `Recovery` measures nanoseconds. Both multiplications saturate:
/// a peer that sends 2^62 microseconds is asking for a delay that never fits, and
/// a saturated delay is one that is never subtracted from the sample (§5.3).
fn ackDelay(self: *const Conn, delay: u64) Duration {
    const factor = @as(u64, 1) << @intCast(self.ack_delay_exponent);
    const microseconds = delay *| factor;
    return microseconds *| std.time.ns_per_us;
}

/// The options the loss detector is called with, from the caller's configuration
/// and the one thing only the handshake driver knows.
fn recoveryOptions(self: *const Conn) Recovery.Options {
    return .{
        .max_ack_delay = self.max_ack_delay,
        // §5.3: `max_ack_delay` bounds a reported delay only once the handshake is
        // confirmed, and confirmation is the driver's to report (§4.1.2 of RFC
        // 9001).
        .handshake_confirmed = if (self.tls) |tls| tls.confirmed() else false,
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
        events: *Recovery.Events,
        now: Duration,
    ) Error!?Opened {
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
            const opened = try conn.finish(raw, frames, events, now);
            conn.commit(raw.id, raw.packet_number);
            return opened;
        }
        return null;
    }
};

/// Drain one handshake message into a packet.
///
/// The machine's half of the TLS seam: it hands the driver its transport
/// parameters once, installs the spaces the driver has reported secrets for,
/// discards the Handshake keys once `confirmed` says to (§4.9.2 of RFC 9001),
/// and writes the next message as a CRYPTO frame at the level the driver chose.
/// The caller drains until this returns null, one packet per call.
///
/// `frames` is the caller's scratch for the CRYPTO frame and `out` the
/// datagram, because the machine owns no buffer of its own. Null means the
/// driver has nothing to send, which is also how a caller learns the handshake
/// has no more bytes after the spaces were installed.
///
/// `now` dates the packet: handshake bytes are ack-eliciting and in flight like
/// any other (§6.1 of RFC 9002).
pub fn writeHandshake(self: *Conn, frames: []u8, out: []u8, now: Duration) Error!?u32 {
    const tls = self.tls orelse return null;

    switch (self.parameters) {
        // §8.2: ours go out in the first message, so the driver takes them
        // before it is asked for one.
        .pending => {
            try tls.setTransportParameters(self.transport_parameters);
            self.parameters = .handed;
        },
        .handed => {},
    }
    try self.installSecrets(tls);

    if (tls.confirmed()) self.discardIfPresent(.handshake);

    const message = (try tls.next()) orelse return null;
    const id: SpaceId = switch (message.level) {
        .initial => .initial,
        .handshake => .handshake,
        .app => .app,
    };

    const space = try self.spaceFor(id);
    const offset = space.crypto_sent_bytes;

    var writer: Writer = .init(frames);
    try frame.write(&writer, .{ .crypto = .{ .offset = offset, .data = message.bytes } });

    const total = try self.writeFrames(id, writer.written(), out, .data(now));
    space.crypto_sent_bytes = offset + message.bytes.len;

    // §17.2.2.1: the client's Initial keys go when its first Handshake packet
    // is sent. The packet is sealed; nothing needs them again.
    if (id == .handshake and self.role == .client) self.discardIfPresent(.initial);

    return total;
}

/// Install every space the driver can give secrets for, once each. A driver may
/// report a level on every call; the machine asks only while a space is missing.
fn installSecrets(self: *Conn, tls: seam.Driver) Error!void {
    if (self.handshake != null and self.app != null) return;

    // Asked once per install and never defaulted: a machine that picked a suite
    // would protect packets the peer cannot read.
    const suite = try tls.suite().protectionSuite();
    if (self.handshake == null) {
        if (try tls.secrets(.handshake)) |secrets| try self.installSpace(.handshake, secrets, suite);
    }
    if (self.app == null) {
        if (try tls.secrets(.app)) |secrets| try self.installSpace(.app, secrets, suite);
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
        .recovery = self.loss.shared.space(self.loss.table(id)),
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
/// Two invariants, both of them the caller's numbers rather than a peer's
/// frames. §4.1: a stream may not advertise a window it cannot hold, so a ring
/// shorter than its limit would turn a legal frame into backpressure. And a
/// limit with no ring behind it describes a stream that claims to receive and
/// cannot. The table needs one slot per stream it may hold, or `open` fails at
/// runtime with a table that was never going to fit.
///
/// Kept as a predicate rather than an inline loop so a test can drive every bad
/// shape directly: the assertion at `init` is a programmer-error check, and
/// there is no way to expect a panic in this Zig version.
fn streamsValid(slots: []const StreamTable.Slot, streams: []const Stream) bool {
    if (slots.len != streams.len) return false;
    for (streams) |entry| {
        if (entry.recv_buffer.len == 0) {
            if (entry.recv_limit_bytes != 0) return false;
        } else {
            if (entry.recv_buffer.len < entry.recv_limit_bytes) return false;
        }
    }
    return true;
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
    return true;
}

/// The stream with `id`, or null when it is not open.
pub fn stream(self: *Conn, id: u64) ?*Stream {
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
/// bidirectional stream, a receive half too. `send_limit` is the peer's initial
/// per-stream limit from its transport parameters; MAX_STREAM_DATA raises it
/// through `Stream.send.onMaxStreamData`.
pub fn openStream(self: *Conn, id: u64, send_limit: u64) Error!*Stream {
    if (self.stream_table.get(id)) |slot| {
        // A bidirectional stream the peer opened is ours to send on as well.
        if (slot.send != null) return error.AlreadyOpen;
        const existing = streamOf(slot);
        std.debug.assert(existing.state == .recv_only);
        existing.send = SendStream.init(id, existing.send_buffer, send_limit);
        existing.state = .both;
        slot.send = &existing.send;
        return existing;
    }

    const index = self.freeStream() orelse return error.StreamLimit;
    const entry = &self.streams[index];
    entry.send = SendStream.init(id, entry.send_buffer, send_limit);
    entry.state = .send_only;

    if (stream_id.direction(id) == .bidi) {
        entry.recv = ReceiveStream.init(id, entry.recv_buffer, entry.recv_limit_bytes);
        entry.state = .both;
        _ = try self.stream_table.open(id, &entry.send, &entry.recv);
    } else {
        _ = try self.stream_table.open(id, &entry.send, null);
    }
    return entry;
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
    entry.state = .recv_only;
    _ = try self.stream_table.open(id, null, &entry.recv);
    return entry;
}

fn onStreamFrame(self: *Conn, space: SpaceId, frame_stream: frame.Stream) Error!void {
    // §12.4: Initial and Handshake packets carry no STREAM frames.
    if (space != .app) return error.WrongFrameSpace;

    const entry = try self.streamFor(frame_stream.id);
    const before = entry.recv.highest;
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
}

/// Seal the next segment of `id`'s send half into one packet.
///
/// Null means there is nothing sendable now: the stream has no new bytes, or the
/// peer's connection-wide allowance is used up. §4.1 limits compose, so the
/// segment is clamped by both the stream's limit (inside `nextSegment`) and the
/// connection's.
pub fn writeStream(self: *Conn, id: u64, max_len: u32, frames: []u8, out: []u8, now: Duration) Error!?u32 {
    const entry = self.stream(id) orelse return error.NotOpen;
    if (!entry.canSend()) return error.NotOpen;

    const allowance = self.send_window.available();
    if (allowance == 0) return null;
    const length: u32 = @intCast(@min(max_len, allowance));

    const segment = entry.send.nextSegment(length) orelse return null;
    var writer: Writer = .init(frames);
    try frame.write(&writer, .{ .stream = .{
        .id = id,
        .offset = segment.offset,
        .data = segment.data,
        .fin = segment.fin,
        .length_present = true,
    } });

    const total = try self.writeFrames(.app, writer.written(), out, .data(now));
    try self.send_window.onSent(segment.data.len);
    return total;
}

/// §4.2: apply a MAX_DATA the peer sent, raising the connection-wide allowance.
pub fn onMaxData(self: *Conn, limit: u64) void {
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
    return out[0..count];
}

/// §4.2: record that `frames` went on the wire, so their limits apply. A limit
/// only ever rises here, the same rule a receiver applies to a MAX frame it
/// reads.
pub fn onFlowControlSent(self: *Conn, frames: []const frame.Frame) void {
    for (frames) |value| {
        switch (value) {
            .max_data => |limit| self.receive_window.raise(limit),
            .max_stream_data => |data| {
                const entry = self.stream(data.stream_id) orelse continue;
                if (data.maximum > entry.recv.limit) entry.recv.limit = data.maximum;
            },
            else => {},
        }
    }
}

/// §6.2.1 of RFC 9002: the peer has validated this endpoint's address, so an
/// acknowledgment may reset the PTO backoff again.
///
/// Only the caller can see this happen: it is the handshake, or a token the
/// caller's own anti-amplification policy accepts, and this machine owns
/// neither.
pub fn onPeerAddressValidated(self: *Conn) void {
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

    /// §13.2.1: acknowledgments and PADDING alone. The peer does not answer it
    /// and no congestion controller counts it, so the loss detector never sees
    /// it and it takes no room in the caller's table.
    pub fn acknowledgment(now: Duration) Write {
        return .{ .now = now, .ack_eliciting = false, .in_flight = false };
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
    return sealed;
}

/// Whether an acknowledgment is owed in `id`'s space: something has been
/// received there since the last one was sent. A space with no keys owes
/// nothing, because nothing in it can have arrived.
pub fn ackOwed(self: *Conn, id: SpaceId) bool {
    const space = self.spaceMaybe(id) orelse return false;
    return space.ackOwed();
}

/// Seal a packet carrying one ACK frame for everything received in `id`'s
/// space. An ACK is sent in the space it acknowledges (§13.2.1).
///
/// `now` goes with it because every packet is sent at a time, even one no loss
/// detector will ever ask about.
pub fn writeAck(self: *Conn, id: SpaceId, out: []u8, now: Duration) Error!u32 {
    const space = try self.spaceFor(id);

    var payload: [ack_payload_len]u8 = undefined;
    const bytes = try ackPayload(space, &payload);

    const total = try self.writeFrames(id, bytes, out, .acknowledgment(now));
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

/// A payload of `n` PING frames (§19.2): one byte, no fields, and nothing for
/// the machine to act on, which makes it the cheapest valid thing a test can
/// seal into a packet.
fn pings(comptime n: usize) [n]u8 {
    return @splat(0x01);
}
/// One endpoint's loss state, where a caller keeps it: outside `Conn`.
///
/// A test never reads these tables; `report` is what it reads. They exist so that
/// every `Conn` in this file is built the way a caller must build one, including
/// the three tables `Recovery.Space` records into.
const LossTables = struct {
    shared: Recovery = .{},
    sent_initial: [16]Recovery.SentPacket = undefined,
    sent_handshake: [16]Recovery.SentPacket = undefined,
    sent_app: [16]Recovery.SentPacket = undefined,

    /// The handles for `Conn.Config.loss`, pointing at this local's storage.
    fn value(self: *LossTables) Conn.Loss {
        return .{
            .shared = &self.shared,
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
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xc1, 0xc2 },
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
    const at_server = try server.feed(datagram[0..sent], &plaintext, &frames, &report, 0);
    try testing.expectEqual(.initial, at_server.space);
    try testing.expectEqual(@as(u64, 0), at_server.packet_number);
    // §19.1 and §19.2: padding and PING have nothing for the machine to do, so
    // they are the frames the machine hands to the caller.
    try testing.expectEqual(@as(usize, 4), at_server.frames.len);
    try testing.expect(at_server.frames[0] == .ping);
    try testing.expect(server.ackOwed(.initial));

    // The server answers with an ACK for packet 0.
    const ack_len = try server.writeAck(.initial, &datagram, 0);
    try testing.expect(!server.ackOwed(.initial));

    // §13.2: the acknowledgment is the machine's to act on, so it leaves the
    // packet as a sent-packet record rather than as an event for the caller.
    const at_client = try client.feed(datagram[0..ack_len], &plaintext, &frames, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_client.frames.len);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(@as(u64, 0), report.ackedPackets()[0].packet_number);
    try testing.expectEqual(@as(usize, 0), client.initial.?.recovery.inFlight().len);
}

test "RFC 9000 §12.3, a Handshake packet opens in the handshake space" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    const dcid = [_]u8{ 3, 1, 4, 1, 5 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{ 0xa1, 0xa2 },
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{ 0xa1, 0xa2 },
        .source_connection_id = &.{ 0xb1, 0xb2 },
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
    const opened = try server.feed(datagram[0..sent], &plaintext, &frames, &report, 0);

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
    const at_client = try client.feed(datagram[0..ack_len], &plaintext, &frames, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_client.frames.len);
    try testing.expectEqual(@as(usize, 1), report.ackedPackets().len);
    try testing.expectEqual(@as(usize, 0), client.handshake.?.recovery.inFlight().len);
    try testing.expectEqual(@as(?u64, null), client.initial.?.largest_received);
}

test "RFC 9000 §12.3, a space with no keys is an error and not a second kind of empty" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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

    try testing.expectError(error.NoKeys, server.feed(datagram[0..sent], &plaintext, &frames, &report, 0));
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
    space.crypto_sent_bytes = 1234;
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
    try testing.expectEqual(@as(u64, 0), space.crypto_sent_bytes);
    try testing.expectEqual(@as(?u64, null), space.largest_received);
    try testing.expectEqual(@as(?u64, null), space.acked_through);
    try testing.expectEqual(@as(u4, 0), space.range_count);
}

test "RFC 9000 §17.2.2.1, a packet for a discarded space is dropped and the connection goes on" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    const dcid = [_]u8{ 0xe1, 0xe2 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0xea},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0xea},
        .source_connection_id = &.{0xeb},
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
    _ = try server.feed(datagram[0..stale], &plaintext, &frames, &report, 0);
    try server.discard(.initial);
    try testing.expectError(error.NoKeys, server.spaceFor(.initial));
    try testing.expect(!server.ackOwed(.initial));
    try testing.expectError(error.NoKeys, server.writeFrames(.initial, "\x01", &datagram, .data(0)));

    const late = try client.writeFrames(.initial, &payload, &datagram, .data(0));
    var walk: Datagram = .init(datagram[0..late]);
    try testing.expect((try walk.next(&server, &plaintext, &frames, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 1), walk.dropped);

    // The rest of the connection is untouched: the Handshake space opens what
    // the client sends there, because the connection IDs are the connection's.
    const handshake = try client.writeFrames(.handshake, &payload, &datagram, .data(0));
    const opened = try server.feed(datagram[0..handshake], &plaintext, &frames, &report, 0);
    try testing.expectEqual(@as(usize, 3), opened.frames.len);
    try testing.expectEqual(@as(?u64, 0), server.handshake.?.largest_received);

    // And the server can still write: discarding a space does not take the
    // connection's identity or its packet number width with it.
    const ack = try server.writeAck(.handshake, &datagram, 0);
    const at_client = try client.feed(datagram[0..ack], &plaintext, &frames, &report, 0);
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

    const opened = try server.feed(datagram[0..sent], &plaintext, &events, &report, 0);
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
    };
    var server_stub: seam.Stub = .{
        .handshake_secrets = .{ .client = &client_secret, .server = &server_secret },
        .app_secrets = .{ .client = &app_client_secret, .server = &app_server_secret },
    };

    // CRYPTO reassembly storage, which the caller owns (§19.6).
    var initial_crypto: [128]u8 = undefined;
    var handshake_crypto: [128]u8 = undefined;

    var client_loss: LossTables = .{};

    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x7a},
        .tls = client_stub.driver(),
        .transport_parameters = "our parameters",
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
    try testing.expectEqualStrings("our parameters", client_stub.parameters[0..client_stub.parameters_len]);
    // The stub reported both levels up front, so the machine installed them
    // before it needed them; the Initial keys are still here, because no
    // Handshake packet has gone out yet.
    try testing.expect(client.initial != null);

    // The server unprotects it, reassembles the CRYPTO frame, and hands the
    // bytes to its driver at the level the packet belonged to.
    const at_server = try server.feed(datagram[0..first], &plaintext, &events, &report, 0);
    try testing.expectEqual(@as(usize, 0), at_server.frames.len);
    try testing.expectEqual(seam.Level.initial, server_stub.fed_level.?);
    try testing.expectEqualStrings(hello, server_stub.fed[0..server_stub.fed_len]);

    // The server's own driver has nothing to send, but the call installs the
    // spaces its secrets describe, which is how its Handshake keys arrive.
    try testing.expect((try server.writeHandshake(&payload, &datagram, 0)) == null);
    try testing.expect(server.handshake != null);
    try testing.expect(server.app != null);

    // The Finished bytes go out in a Handshake packet, in a space the machine
    // built from the driver's secrets. §17.2.2.1 then takes the client's
    // Initial keys, because its first Handshake packet has been sent.
    const second = (try client.writeHandshake(&payload, &datagram, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expect(client.handshake != null);
    try testing.expectEqual(@as(?Space, null), client.initial);

    const at_server_handshake = try server.feed(datagram[0..second], &plaintext, &events, &report, 0);
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
    const opened_app = try server.feed(datagram[0..app_packet], &plaintext, &events, &report, 0);
    try testing.expectEqual(@as(usize, 2), opened_app.frames.len);

    // §4.9.2: confirmation takes the Handshake keys, and 1-RTT carries on.
    client_stub.confirmed = true;
    try testing.expect((try client.writeHandshake(&payload, &datagram, 0)) == null);
    try testing.expectEqual(@as(?Space, null), client.handshake);
    try testing.expect(client.app != null);
    try testing.expectError(error.NoKeys, client.writeFrames(.handshake, "\x01", &datagram, .data(0)));
    _ = try client.writeFrames(.app, &app_payload, &datagram, .data(0));
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
    });

    var datagram: [512]u8 = undefined;
    var frames: [256]u8 = undefined;
    // The alert is one error, and the code the caller closes with is the
    // CRYPTO_ERROR value the driver named, not a table of alerts here.
    try testing.expectError(error.HandshakeFailed, client.writeHandshake(&frames, &datagram, 0));
    try testing.expectEqual(@as(u64, 0x150), client.tls.?.errorCode());
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
    });

    var datagram: [512]u8 = undefined;
    var frames: [256]u8 = undefined;
    // The driver says AES-256-GCM, which needs SHA-384 and is not implemented.
    // The machine refuses by name rather than deriving AES-128-GCM and hoping
    // the peer notices.
    try testing.expectError(error.UnsupportedCipherSuite, client.writeHandshake(&frames, &datagram, 0));
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
    });

    var datagram: [512]u8 = undefined;
    var frames: [256]u8 = undefined;
    // A driver that says AES-128-GCM and hands out a 48-byte secret has told two
    // different stories; `deriveKeys` refuses the length, so no space is built
    // from a key schedule that does not belong to it.
    try testing.expectError(error.SecretLengthMismatch, client.writeHandshake(&frames, &datagram, 0));
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
    try testing.expect((try conn.writeHandshake(&frames, &datagram, 0)) == null);
}

test "RFC 9000 §19.6, CRYPTO frames that arrive out of order reach the driver in order" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
    _ = try server.feed(datagram[0..sent_late], &plaintext, &events, &report, 0);
    try testing.expectEqual(@as(u32, 0), stub.fed_calls);

    // The frame before it fills the gap and both halves leave in order.
    var head_writer: Writer = .init(&payload);
    try frame.write(&head_writer, .{ .crypto = .{ .offset = 0, .data = "hello " } });
    const sent_early = try client.writeFrames(.initial, head_writer.written(), &datagram, .data(0));
    const opened = try server.feed(datagram[0..sent_early], &plaintext, &events, &report, 0);
    try testing.expectEqual(@as(usize, 0), opened.frames.len);
    try testing.expectEqual(@as(u32, 1), stub.fed_calls);
    try testing.expectEqualStrings("hello world", stub.fed[0..stub.fed_len]);
}

test "RFC 9000 §12.4, a frame that will not parse is an error and not a dropped packet" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
    try testing.expectError(error.UnknownFrameType, walk.next(&server, &plaintext, &events, &report, 0));
    try testing.expectEqual(@as(u16, 0), walk.dropped);
    // §13.2: a packet the machine did not process is not one it acknowledges,
    // so the range table never heard about this number.
    try testing.expectEqual(@as(?u64, null), server.initial.?.largest_received);
    try testing.expect(!server.ackOwed(.initial));

    // The same through one packet. Unprotecting mutates the datagram, so this
    // is a fresh packet rather than the same bytes again.
    const again = try client.writeFrames(.initial, &bad, &datagram, .data(0));
    try testing.expectError(error.UnknownFrameType, server.feed(datagram[0..again], &plaintext, &events, &report, 0));
}

test "a stream configuration that cannot hold its own limits is refused" {
    var ring: [64]u8 = undefined;
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
    };

    for (cases) |case| {
        try testing.expectEqual(case.valid, streamsValid(case.slots, case.streams));
    }
}

test "RFC 9000 §2.1, a STREAM frame for an unknown stream opens it" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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

    const opened = try server.feed(datagram[0..sent], &plaintext, &events, &report, 0);
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
}

test "RFC 9000 §4.2, reading a ring is what makes a window raise due" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
    _ = try server.feed(datagram[0..sent], &plaintext, &events, &report, 0);

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
    try testing.expectError(error.StreamLimit, walk.next(&server, &plaintext, &events, &report, 0));
    try testing.expectEqual(@as(u16, 0), walk.dropped);
}

test "RFC 9000 §4.1, a peer past the stream limit is a connection error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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

    try testing.expectError(error.FlowControl, server.feed(datagram[0..sent], &plaintext, &events, &report, 0));
    // The connection window was not touched: the stream refused it first.
    try testing.expectEqual(@as(u64, 0), server.receive_window.used);
}

test "RFC 9000 §4.1, a peer past the connection limit is a connection error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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

    try testing.expectError(error.FlowControl, server.feed(datagram[0..sent], &plaintext, &events, &report, 0));
    // The first stream's five bytes were counted before the second blew it.
    try testing.expectEqual(@as(u64, 5), server.receive_window.used);
}

test "RFC 9000 §12.4, a STREAM frame in an Initial packet is a connection error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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

    try testing.expectError(error.WrongFrameSpace, server.feed(datagram[0..sent], &plaintext, &events, &report, 0));
    try testing.expect(server.stream(0) == null);
}

test "RFC 9000 §19.8, a segment out of the send half goes out in a STREAM frame" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
        .send_limit = 64,
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

    const entry = try client.openStream(0, 64);
    _ = try entry.send.write("stream bytes");
    try entry.send.end();

    var datagram: [512]u8 = undefined;
    var plaintext: [512]u8 = undefined;
    var payload: [64]u8 = undefined;
    var events: [8]frame.Frame = undefined;

    const sent = (try client.writeStream(0, 64, &payload, &datagram, 0)) orelse
        return error.TestUnexpectedResult;
    _ = try server.feed(datagram[0..sent], &plaintext, &events, &report, 0);

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
    const dcid = [_]u8{ 0x0d, 0x0e };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x0a},
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

    const first = (try datagram.next(&client, &plaintext, &events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.initial, first.space);
    try testing.expectEqual(@as(usize, 3), first.frames.len);
    try testing.expectEqual(@as(?u64, 0), client.initial.?.largest_received);
    try testing.expectEqual(@as(?u64, null), client.handshake.?.largest_received);

    const second = (try datagram.next(&client, &plaintext, &events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.handshake, second.space);
    try testing.expectEqual(@as(usize, 2), second.frames.len);
    try testing.expectEqual(@as(?u64, 0), client.handshake.?.largest_received);

    try testing.expect((try datagram.next(&client, &plaintext, &events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
    // Both spaces are accounted for separately, which is what the client needs
    // to answer each level with an ACK of its own (§13.2.1).
    try testing.expect(client.ackOwed(.initial));
    try testing.expect(client.ackOwed(.handshake));
}

test "RFC 9001 §5.5, a packet that will not unprotect is dropped and the next is processed" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
    const dcid = [_]u8{ 0x1d, 0x1e };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x1a},
    });
    var server_loss: LossTables = .{};
    var server: Conn = .init(.{
        .role = .server,
        .loss = server_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &.{0x1a},
        .source_connection_id = &.{0x1b},
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
    const opened = (try datagram.next(&client, &plaintext, &events, &report, 0)) orelse
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
    const initial = (try datagram.next(&server, &plaintext, &events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.initial, initial.space);
    try testing.expectEqual(@as(usize, 2), initial.frames.len);
    const app = (try datagram.next(&server, &plaintext, &events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(.app, app.space);
    try testing.expectEqual(@as(usize, 3), app.frames.len);
    // The whole tail of the datagram belonged to that packet.
    try testing.expectEqual(@as(u32, @intCast(app_len)), app.packet_len);
    try testing.expect((try datagram.next(&server, &plaintext, &events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 0), datagram.dropped);
}

test "RFC 9000 §12.2, bytes with no readable end stop the walk without an error" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
    const opened = (try datagram.next(&server, &plaintext, &events, &report, 0)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 3), opened.frames.len);
    try testing.expect((try datagram.next(&server, &plaintext, &events, &report, 0)) == null);
    try testing.expectEqual(@as(u16, 1), datagram.dropped);
}

test "RFC 9000 §12.2, coalesced packets: only the first is taken, the length says where it ends" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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

    const opened = try server.feed(&combined, &plaintext, &events, &report, 0);
    try testing.expectEqual(@as(u32, @intCast(first)), opened.packet_len);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);

    // The caller continues where the machine said the packet ended.
    const tail = combined[opened.packet_len..][0 .. first + second - opened.packet_len];
    const next = try server.feed(tail, &plaintext, &events, &report, 0);
    try testing.expectEqual(@as(u64, 1), next.packet_number);
}

test "RFC 9001 §5.5, a packet that will not unprotect changes nothing" {
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
        server.feed(datagram[0..sent], &plaintext, &events, &report, 0),
    );
    try testing.expect(!server.ackOwed(.initial));
    try testing.expectEqual(@as(?u64, null), server.initial.?.largest_received);
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

test "RFC 9002 §6.1.1, an acknowledgment is what declares the gap lost" {
    const dcid = [_]u8{ 0x7a, 0x7b };
    var acked: [16]Recovery.SentPacket = undefined;
    var lost: [16]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);

    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x7c},
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
    _ = try server.feed(datagram[0..fourth], &plaintext, &frames, &report, ms(20));
    const ack_len = try server.writeAck(.initial, &datagram, ms(20));

    // §6.1.1: three packets newer than 0 are not needed; one acknowledgment of
    // packet 3 with nothing else in flight puts packet 0 outside the threshold.
    const at_client = try client.feed(datagram[0..ack_len], &plaintext, &frames, &report, ms(20));
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
    var spaces = [_]*Recovery.Space{&client.initial.?.recovery};
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
    var sent: [4]Recovery.SentPacket = undefined;
    const none: []Recovery.SentPacket = sent[0..0];

    const Case = struct {
        sent_initial: []Recovery.SentPacket,
        sent_handshake: []Recovery.SentPacket,
        sent_app: []Recovery.SentPacket,
        valid: bool,
    };
    const cases = [_]Case{
        .{ .sent_initial = &sent, .sent_handshake = &sent, .sent_app = &sent, .valid = true },
        // A space with no table is a space whose lost packets nobody reports, so
        // each of the three has to be there.
        .{ .sent_initial = none, .sent_handshake = &sent, .sent_app = &sent, .valid = false },
        .{ .sent_initial = &sent, .sent_handshake = none, .sent_app = &sent, .valid = false },
        .{ .sent_initial = &sent, .sent_handshake = &sent, .sent_app = none, .valid = false },
    };

    for (cases) |case| {
        const loss: Loss = .{
            .shared = &shared,
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
        .source_connection_id = &.{0x84},
    });

    var acked: [8]Recovery.SentPacket = undefined;
    var lost: [8]Recovery.SentPacket = undefined;
    var report: Recovery.Events = .init(&acked, &lost);
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
        client.feed(datagram[0..ack_len], &plaintext, &frames, &report, 0),
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

test "RFC 9000 §18.2, a received ACK delay is scaled by this endpoint's exponent" {
    const dcid = [_]u8{ 0x87, 0x88 };
    var client_loss: LossTables = .{};
    var client: Conn = .init(.{
        .role = .client,
        .loss = client_loss.value(),
        .original_destination_connection_id = &dcid,
        .destination_connection_id = &dcid,
        .source_connection_id = &.{0x89},
        .ack_delay_exponent = 3,
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
    const first = try server.writeFrames(.initial, writer.written(), &datagram, .acknowledgment(0));
    _ = try client.feed(datagram[0..first], &plaintext, &frames, &report, ms(100));
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
    const second = try server.writeFrames(.initial, writer.written(), &datagram, .acknowledgment(0));
    _ = try client.feed(datagram[0..second], &plaintext, &frames, &report, ms(300));
    // `latest` is the raw sample; the delay is subtracted from the value the
    // average takes (§5.3), not from the round trip itself.
    try testing.expectEqual(ms(200), client_loss.shared.rtt.latest);
    try testing.expectEqual(ms(111) + 500_000, client_loss.shared.rtt.smoothed);
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
        .recovery = conn.loss.shared.space(conn.loss.table(id)),
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
