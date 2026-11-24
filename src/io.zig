//! `std.Io.net` with QUIC underneath: an `Endpoint` that accepts or connects,
//! a `Connection` that multiplexes, and a `Stream` you read, write, shut down,
//! and close. docs/slop/api-sketch.md is the contract.
//!
//! `Io` owns concurrency, so nothing here is a loop, a pump, or a flush. A
//! connection runs two tasks of its own (see `io/Core.zig` for why two, and why
//! `Io.concurrent` rather than `Io.async`): one receives datagrams and feeds the
//! machine, the other sends what is owed and fires the loss, probe, and idle
//! timers. A `Stream` call takes the connection's mutex, does its part, and
//! either returns or parks on its stream's `Io.Condition`, cancelable like any
//! other `Io` wait.
//!
//! `Endpoint(Sizing(limits))` holds the buffers one connection needs whatever
//! it does, and is built in place because the machine inside refuses to move.
//! Streams are what a connection may or may not use, so their buffers come from
//! a pool over the allocator `listen` or `connect` is handed, and only while a
//! stream is live or the peer may open one. A `FixedBufferAllocator` and a
//! preheated pool (`SizingLimits.preheat`) keep the whole of it bounded and off
//! the heap; see `Endpoint.listen`.
//!
//! TLS is part of QUIC, so an endpoint builds its own handshake: a server is
//! handed a certificate and key (PEM) and its ALPN names, a client the server's
//! name, its ALPN names, and how far to trust the certificate. The driver and
//! what the limits fix before any certificate exists (`quic-tls`'s `Fixed`)
//! are in the `Sizing`, sized by `SizingLimits.tls`. The handshake's flights,
//! and a server's certificate chain, come from the same allocator as the
//! streams, in `listen` or `connect`, sized from the certificate actually
//! loaded. The machine in `quic` stays crypto-free; this module is where it
//! meets TLS.
//!
//! What it does not do yet, by name: congestion control (it sends what the
//! peer's flow control allows), Version Negotiation and Retry (a client drops
//! both, a server answers neither), connection migration, PATH_CHALLENGE,
//! NEW_TOKEN, and new connection IDs (all dropped), the anti-amplification limit,
//! and more than one connection per endpoint, because a driver is one
//! handshake's worth of state.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
pub const IpAddress = Io.net.IpAddress;
pub const ShutdownHow = Io.net.ShutdownHow;

const driver = @import("quic-tls");
/// How a client decides whether to believe a server's certificate.
pub const Trust = driver.Trust;
const quic = @import("quic");
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const StreamTable = quic.StreamTable;
const TransportParameters = quic.TransportParameters;
const frame = quic.frame;
pub const Direction = quic.stream_id.Direction;

const Core = @import("io/Core.zig");
/// Why a connection ended, which every operation on it returns from then on:
/// `error.ConnectionClosed` and `error.IdleTimeout`, the socket's errors, and
/// the machine's transport errors by name (`error.HandshakeFailed`,
/// `error.FlowControl`, `error.StreamLimit`, ...).
pub const ConnectionError = Core.Failure;

/// What `Endpoint.listen` can refuse: a certificate or key that does not load
/// (`error.InvalidCertificate`, `error.InvalidKey`), anything that exceeds
/// `SizingLimits.tls` (`error.NoSpace`), such as a certificate chain longer
/// than `tls.chain` DER bytes, and an allocator that cannot supply the
/// handshake's buffers, the stream table, and the pool (`error.OutOfMemory`).
pub const ListenError = driver.LoadError || driver.Error || Allocator.Error;
pub const AcceptError = ConnectionError || Io.ConcurrentError || TransportParameters.Error;
pub const ConnectError = ConnectionError || Io.ConcurrentError || TransportParameters.Error ||
    driver.Error || Allocator.Error;

/// The numbers a caller chooses. Every other length follows from them.
pub const SizingLimits = struct {
    /// The most streams live at once, both directions and both initiators: the
    /// length of the machine's stream table, which `listen` and `connect`
    /// allocate whole. A stream's buffers are allocated only while it lives.
    streams: u16 = 4,
    /// Each stream's receive ring and send buffer, and so the per-stream window
    /// this endpoint advertises (§4.1). The send buffer does not wrap: a stream
    /// carries at most this many bytes out over its life.
    stream_ring: u32 = 4096,
    /// Sent packets tracked per packet number space for loss recovery.
    sent_packets: u16 = 32,
    /// CRYPTO reassembly and replay at the Initial and Handshake levels, each
    /// way. The application level is smaller: it receives post-handshake
    /// messages into `tls.post_handshake` bytes, and a peer's bytes further
    /// ahead of what arrived in order than that, which includes any one
    /// message longer, end the connection with `error.NoSpace`. It sends
    /// nothing, because nothing this package runs sends CRYPTO there (no
    /// 0-RTT, no tickets, no post-handshake authentication), so a message the
    /// driver queues there is `error.NoSpace` before any of it is framed.
    crypto: u32 = 4096,
    /// One datagram, in and out, and the max_udp_payload_size advertised.
    datagram: u16 = 1500,
    /// What the handshake may carry: certificate chain, ALPN name, transport
    /// parameters, and post-handshake messages. Four numbers of their own,
    /// each a bound on what the peer decides, and the chain one on this
    /// endpoint's own certificate too.
    tls: driver.Limits = .{},
    /// Stream slots (`StreamSlot`, one stream's two buffers) the pool takes from
    /// the allocator in `listen` or `connect`, before anything runs. With
    /// enough of them no stream ever allocates; with fewer the pool grows on
    /// demand.
    preheat: u16 = 0,
    /// §4.6: the streams the peer may open before the application accepts
    /// any, advertised as initial_max_streams_bidi when the caller's parameters
    /// name no stream count. Each one is a slot taken from the pool in `listen`
    /// or `connect`, because a peer's first frame lands in its buffers, and
    /// each stream the application accepts lets the peer open one more.
    peer_initial: u16 = 1,
};

/// The most frames one packet may carry that the machine hands back rather
/// than acts on (PING, NEW_CONNECTION_ID, ...). A packet with more is closed
/// with INTERNAL_ERROR, because the machine reports `error.NoSpace`.
const frames_per_packet = 64;

/// §17.2: a version 1 connection ID is at most 20 bytes.
const max_connection_id = 20;

/// This endpoint's own connection IDs, and the one a client invents for the
/// server: §7.2 asks for at least 8 bytes there, and §5.1 for unpredictable
/// ones everywhere.
const own_id_len = 8;

/// Room for this endpoint's encoded transport parameters.
const parameter_capacity = 256;

/// Every buffer one connection needs whatever it does, sized from `limits`:
/// the loss tables and the STREAM records beside them, the CRYPTO buffers, the
/// shell's own sent-frame records, the frame lists, the datagram scratch, and
/// the TLS driver with what its limits fix. The streams' buffers are
/// `StreamSlot`s, pooled, and the handshake's flights and a server's
/// certificate chain are allocated too, by `listen` or `connect`.
pub fn Sizing(comptime limits_given: SizingLimits) type {
    comptime {
        assert(limits_given.streams > 0);
        assert(limits_given.stream_ring > 0);
        assert(limits_given.peer_initial <= limits_given.streams);
        assert(limits_given.sent_packets > 0);
        assert(limits_given.crypto > 0);
        // IPv6's minimum path, 1280 bytes less 48 of headers. It holds the
        // padded Initial this shell writes (`Core.initial_payload_floor`).
        assert(limits_given.datagram >= 1232);
    }
    const streams = limits_given.streams;
    const ring = limits_given.stream_ring;
    const sent = limits_given.sent_packets;
    const datagram = limits_given.datagram;

    return struct {
        const Self = @This();

        pub const limits = limits_given;
        /// §4.1: the connection window, every ring full.
        pub const receive_limit: u64 = @as(u64, streams) * ring;

        /// One stream's buffers, the item the endpoint's pool hands out: what
        /// it sends, which does not wrap, and the ring it receives into.
        pub const StreamSlot = struct {
            send: [ring]u8,
            recv: [ring]u8,
        };

        pub const Pool = std.heap.MemoryPool(StreamSlot);

        /// What one entry of the stream table costs, allocated whole by
        /// `listen` or `connect` whether a stream ever uses it or not: the
        /// machine's stream state, the table's slot, and the shell's.
        pub const table_entry_bytes = @sizeOf(Conn.Stream) + @sizeOf(StreamTable.Slot) + @sizeOf(Core.Slot);

        /// The alignment `listenBytes`, `connect_bytes`, and
        /// `allocation_bytes` assume of a `FixedBufferAllocator`'s memory:
        /// the strictest of the arrays and the pool's blocks it hands out.
        pub const allocation_alignment: usize = @max(
            @alignOf(StreamTable.Slot),
            @alignOf(Conn.Stream),
            @alignOf(Core.Slot),
            arena_node_alignment,
            Pool.item_alignment.toByteUnits(),
        );

        /// Exactly what `listen` takes from a `FixedBufferAllocator` over
        /// memory aligned to `allocation_alignment` that holds nothing else,
        /// when the parameters name no stream count and the certificate chain
        /// decodes to `chain` DER bytes: the handshake's buffers, the chain,
        /// the stream table, and the pool (`reserve`). One byte less is
        /// `error.OutOfMemory` from `listen`.
        pub fn listenBytes(chain: u32) usize {
            const flight = driver.Flight.lengths(limits_given.tls, .server, chain);
            return reserve(chain + flight.total());
        }

        /// Exactly what `connect` takes, as `listenBytes` is for `listen`. A
        /// client loads no certificate, so this is one number.
        pub const connect_bytes: usize = reserve(driver.Flight.lengths(limits_given.tls, .client, 0).total());

        /// The most `listen` or `connect` takes, the chain at its limit: the
        /// size of memory for an endpoint whose certificate is not known when
        /// it is compiled.
        pub const allocation_bytes: usize = @max(listenBytes(limits_given.tls.chain), connect_bytes);

        /// Where a `FixedBufferAllocator` that has handed out `handshake` bytes
        /// of `u8` ends once `listen` or `connect` has taken the stream table,
        /// three arrays each aligned on its own, and the pool with `preheat`
        /// slots, or `peer_initial` if that is more, since each of those is
        /// armed at once.
        ///
        /// The pool keeps its slots in a `std.heap.ArenaAllocator`, followed
        /// here step by step as Zig 0.17.1 runs it: the first slot takes a
        /// block half again as large as a header, the slot's alignment, the
        /// slot, and 16 bytes, and each slot after it that does not fit grows the block in place,
        /// as it does on a `FixedBufferAllocator`, past one slot's room the
        /// failed attempt left unused. So past the first, a slot costs two.
        fn reserve(handshake: usize) usize {
            var end = handshake;
            end = mem.alignForward(usize, end, @alignOf(StreamTable.Slot)) + streams * @sizeOf(StreamTable.Slot);
            end = mem.alignForward(usize, end, @alignOf(Conn.Stream)) + streams * @sizeOf(Conn.Stream);
            end = mem.alignForward(usize, end, @alignOf(Core.Slot)) + streams * @sizeOf(Core.Slot);
            if (pooled == 0) return end;

            const size = Pool.item_size;
            const alignment = Pool.item_alignment.toByteUnits();
            const node = mem.alignForward(usize, end, arena_node_alignment);
            const first = arena_header + alignment + size + 16;
            var block = mem.alignForward(usize, first + first / 2, 2);
            // Offsets into the block's buffer, which starts after the header.
            const buffer = node + arena_header;
            var used = mem.alignForward(usize, buffer, alignment) - buffer + size;
            for (1..pooled) |_| {
                used = mem.alignForward(usize, buffer + used, alignment) - buffer + size;
                if (arena_header + used <= block) continue;
                used = mem.alignForward(usize, buffer + used, alignment) - buffer + size;
                block = mem.alignForward(usize, arena_header + used, 2);
            }
            return node + block;
        }

        const pooled: usize = @max(limits_given.preheat, limits_given.peer_initial);
        /// The arena's block header, three words in Zig 0.17.1, and its
        /// alignment.
        const arena_header = 3 * @sizeOf(usize);
        const arena_node_alignment = @alignOf(usize);

        loss_state: Recovery = .{},
        spaces: [3]Recovery.Space = undefined,
        sent: [3][sent]Recovery.SentPacket = undefined,
        /// The STREAM ranges each tracked 1-RTT packet carried, one per slot of
        /// the 1-RTT sent table, which `Conn` resends from when one is lost.
        sent_streams: [sent]Conn.SentStreams = undefined,
        acked: [sent]Recovery.SentPacket = undefined,
        lost: [sent]Recovery.SentPacket = undefined,
        /// CRYPTO reassembly at the Initial and Handshake levels.
        crypto_in: [2][limits_given.crypto]u8 = undefined,
        /// CRYPTO reassembly at the application level, where only
        /// post-handshake messages arrive.
        crypto_in_app: [limits_given.tls.post_handshake]u8 = undefined,
        /// What this endpoint sent at the Initial and Handshake levels, for
        /// §13.3. The application level has none (`cryptoSent`).
        crypto_sent: [2][limits_given.crypto]u8 = undefined,
        connection_ids: [2 * max_connection_id]u8 = undefined,
        adopted_id: [max_connection_id]u8 = undefined,
        original_id: [own_id_len]u8 = undefined,
        own_id: [own_id_len]u8 = undefined,
        parameter_bytes: [parameter_capacity]u8 = undefined,
        /// One record per tracked 1-RTT packet, for the RESET_STREAM or
        /// STOP_SENDING this shell composes itself.
        records: [sent]Core.Record = undefined,
        datagram_in: [datagram]u8 = undefined,
        datagram_out: [datagram]u8 = undefined,
        plaintext: [datagram]u8 = undefined,
        scratch: [datagram]u8 = undefined,
        frames: [frames_per_packet]frame.Frame = undefined,
        stream_events: [streams]Conn.StreamEvent = undefined,
        /// MAX_DATA, one MAX_STREAM_DATA per stream, two MAX_STREAMS.
        control: [streams + 3]frame.Frame = undefined,
        offers: [streams]Conn.Offer = undefined,
        written: [streams]Conn.Written = undefined,
        /// The TLS driver and what the limits fix of its storage. Its flights
        /// are the endpoint's, from the allocator.
        tls: driver.Fixed(limits_given.tls) = undefined,

        fn prepare(self: *Self) void {
            self.loss_state = .{};
            self.tls.init();
        }

        fn loss(self: *Self) Conn.Loss {
            return .{
                .shared = &self.loss_state,
                .spaces = &self.spaces,
                .sent_initial = &self.sent[0],
                .sent_handshake = &self.sent[1],
                .sent_app = &self.sent[2],
                .sent_streams = &self.sent_streams,
            };
        }

        /// `Conn.Config.crypto`: where each level's CRYPTO data is reassembled.
        fn cryptoReceived(self: *Self) Conn.CryptoStorage {
            return .{
                .initial = &self.crypto_in[0],
                .handshake = &self.crypto_in[1],
                .app = &self.crypto_in_app,
            };
        }

        /// `Conn.Config.crypto_sent`. The application level is left empty on
        /// purpose: a client's post-handshake messages are received, not sent,
        /// and 0-RTT and post-handshake authentication are out of scope. A
        /// message the driver queues there anyway, such as the answer the core
        /// composes to a KeyUpdate, is `error.NoSpace` from
        /// `Conn.writeHandshake` before any of it is framed.
        fn cryptoSent(self: *Self) Conn.CryptoStorage {
            return .{ .initial = &self.crypto_sent[0], .handshake = &self.crypto_sent[1] };
        }

        fn coreStorage(self: *Self) Core.Storage {
            return .{
                .datagram_in = &self.datagram_in,
                .datagram_out = &self.datagram_out,
                .plaintext = &self.plaintext,
                .scratch = &self.scratch,
                .frames = &self.frames,
                .stream_events = &self.stream_events,
                .control = &self.control,
                .offers = &self.offers,
                .written = &self.written,
                .records = &self.records,
            };
        }

        /// The caller's transport parameters with every number this sizing
        /// decides written over: the windows, the datagram size, and, when the
        /// caller named neither stream count, `peer_initial` bidirectional
        /// streams for the peer.
        fn advertised(given: TransportParameters) TransportParameters {
            var parameters = given;
            parameters.initial_max_data = receive_limit;
            parameters.initial_max_stream_data_bidi_local = ring;
            parameters.initial_max_stream_data_bidi_remote = ring;
            parameters.initial_max_stream_data_uni = ring;
            parameters.max_udp_payload_size = datagram;
            if (given.initial_max_streams_bidi == null and given.initial_max_streams_uni == null) {
                parameters.initial_max_streams_bidi = limits_given.peer_initial;
            }
            return parameters;
        }
    };
}

/// One QUIC endpoint over one UDP socket, holding one connection's storage:
/// `Server` in `std.Io.net`, plus `connect` for the client side.
///
/// Built in place and never moved: `listen` or `connect` fills it, and the
/// machine and both tasks point into it until `deinit`.
pub fn Endpoint(comptime S: type) type {
    return struct {
        const Self = @This();

        sizing: S,
        core: Core,
        driver: quic.handshake.Driver,
        parameters: TransportParameters,
        /// What the handshake's buffers, the stream table, and the pool come
        /// from, until `deinit`.
        allocator: Allocator,
        /// The handshake's flights, `driver.Flight.lengths` of each.
        flight: driver.Flight,
        /// A server's certificate chain, exactly the DER bytes it decoded to.
        /// Empty for a client.
        chain: []u8,
        /// Every stream's buffers. A slot destroyed goes back on the pool's
        /// free list, never to the allocator, until `deinit`.
        pool: S.Pool,
        /// How many slots the pool has taken from the allocator, live or free.
        pool_capacity: u32,
        table: []StreamTable.Slot,

        pub const Listen = struct {
            io: Io,
            /// A bound UDP socket. The endpoint owns it: `deinit` closes it.
            socket: Io.net.Socket,
            /// The certificate chain, leaf first, in PEM. Decoded into memory
            /// from the allocator, so it need not outlive `listen`.
            certificate: []const u8,
            /// The private key for the leaf, in PEM, likewise.
            key: []const u8,
            /// The protocols this server speaks, in its order of preference.
            /// Borrowed: the slice and the names must outlive the endpoint.
            alpn: []const []const u8 = &.{},
            /// This endpoint's limits. The windows, the stream counts when both
            /// are null, and max_udp_payload_size come from the sizing; the
            /// connection IDs from the handshake. max_idle_timeout also bounds
            /// a handshake that goes nowhere, and without one `accept` waits
            /// until it is canceled.
            parameters: TransportParameters = .{},
        };

        pub const Connect = struct {
            io: Io,
            /// A bound UDP socket. The endpoint owns it: `deinit` closes it.
            socket: Io.net.Socket,
            peer: IpAddress,
            /// The name sent in server_name_indication, when there is one.
            /// Borrowed, as `alpn` is.
            server_name: ?[]const u8 = null,
            /// The protocols offered, in order; the server picks. Borrowed.
            alpn: []const []const u8 = &.{},
            /// There is no default: a client states whether it verifies.
            trust: Trust,
            /// As in `Listen`.
            parameters: TransportParameters = .{},
        };

        /// Start listening on `config.socket`, with the certificate and key
        /// loaded. Nothing is read until `accept`. The endpoint owns the socket
        /// from here, so `deinit` follows a failed `listen` too.
        ///
        /// `allocator` is where the handshake's buffers and the streams come
        /// from, and its failure is the one new way to fail. Here and in
        /// `connect` it supplies, in this order:
        ///
        /// 1. A server's certificate chain, exactly the DER bytes it decodes
        ///    to. It is decoded first into no more than `tls.chain` bytes, or
        ///    the PEM's length if that is less, and shrunk to fit; a chain
        ///    longer than `tls.chain` is `error.NoSpace`, before anything else
        ///    is taken.
        /// 2. The handshake's flights, `driver.Flight.lengths` of each: what
        ///    this endpoint composes (a server's flight follows from its
        ///    chain), and where the peer's Initial and Handshake messages are
        ///    reassembled (they follow from `tls`).
        /// 3. The stream table, `S.table_entry_bytes` for each of `streams`.
        /// 4. The pool, which takes `preheat` slots at once and hands the
        ///    peer's credit (`peer_initial`, or the parameters' stream counts)
        ///    a slot each.
        ///
        /// After that it is called only when `openStream` or `acceptStream`
        /// finds the pool empty (`S.StreamSlot`, two `stream_ring` buffers),
        /// from whichever task holds the connection's mutex, and never because
        /// of anything the peer sends. A slot freed goes back to the pool, not
        /// to the allocator; everything goes back at `deinit`.
        ///
        /// So a `FixedBufferAllocator` with `preheat` at least the slots in use
        /// at once is an endpoint with no heap at all, through this same API:
        /// every byte reserved up front, nothing allocated once it runs, and an
        /// open past the reserve `error.OutOfMemory` rather than a surprise.
        /// Slots in use at once are the live streams plus the peer's backlog
        /// (`peer_initial`): a client making N requests one after another
        /// needs `1 + peer_initial`, and a server answering N peer streams at
        /// once `N + peer_initial`.
        ///
        /// The reserve, over memory aligned to `S.allocation_alignment` and
        /// when the parameters name no stream count, is `S.listenBytes(chain)`
        /// for a chain of `chain` DER bytes, `S.connect_bytes` for a client,
        /// and `S.allocation_bytes`, the larger of them with the chain at its
        /// limit, when the certificate is not known until run time. Each is
        /// exact: one byte less is `error.OutOfMemory` from `listen` or
        /// `connect`. It is the four steps above, each aligned to what it
        /// holds:
        ///
        ///     chain + Flight.lengths(tls, role, chain).total()
        ///         + streams * S.table_entry_bytes
        ///         + 24 + (2 * slots - 1) * @sizeOf(S.StreamSlot)
        ///
        /// where `slots` is `max(preheat, peer_initial)`, at least two, and 24
        /// is the header of the pool's arena block. The arena leaves one
        /// slot's room behind each time it grows that block in place (Zig
        /// 0.17.1), so past the first a slot costs two. A single slot takes the
        /// arena's first block instead, half again `24 + 8 + slot + 16`
        /// (12,360 bytes with the default ring), and none takes nothing.
        ///
        /// For one concurrent peer stream, a server answering one stream at a
        /// time with the default limits needs two slots (`preheat = 2`, which
        /// `peer_initial = 1` makes `1 + 1`). With tls's fixture certificate
        /// (411 DER bytes) `listen` takes 411 + 10,317 of handshake (out 1,622,
        /// peer Initial 3,201, peer Handshake 5,307, ServerHello 187), then
        /// 4 * 736 = 2,944 of table, then 24 + 3 * 8,192 = 24,600 of pool:
        /// `S.listenBytes(411)` = 38,272. The client's `connect` takes 11,709
        /// of handshake (out 3,201, peer Initial 3,201, peer Handshake 5,307),
        /// 3 of alignment, and the same table and pool: `S.connect_bytes` =
        /// 39,256. With the chain at its 4,096-byte limit, `S.allocation_bytes`
        /// = 45,648. The allocator is the endpoint's alone: give each endpoint
        /// its own.
        pub fn listen(self: *Self, allocator: Allocator, config: Listen) ListenError!void {
            const nowhere: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
            self.prepare(allocator, config.io, config.socket, nowhere, config.parameters);
            const credentials = try self.loadCredentials(config.certificate, config.key);
            try self.allocateFlight(.server);
            self.driver = try self.startTls(config.io, .{ .server = .{
                .credentials = credentials,
                .alpn = config.alpn,
            } });
            try self.allocateStreams();
        }

        /// Wait for a client's first Initial, build the connection from it,
        /// and return once its handshake is done (§7.2).
        ///
        /// A datagram that cannot start a connection is dropped and the wait
        /// goes on, with the endpoint exactly as it was (§8.1): one under 1200
        /// bytes (§14.1), one whose first packet is not a version 1 Initial
        /// with a destination connection ID, and one whose first packet does
        /// not open under the Initial keys. A handshake that fails after that
        /// returns its error, and the endpoint is spent: its driver was that
        /// handshake's. `deinit` it either way.
        pub fn accept(self: *Self, io: Io) AcceptError!Connection {
            assert(self.core.phase == .listening);
            while (self.core.phase == .listening) try self.receiveFirst(io);
            errdefer self.core.stop(io);
            try self.core.awaitEstablished(io);
            return .{ .core = &self.core };
        }

        /// Take one datagram off the socket. Only one whose first packet opens
        /// under the Initial keys begins the connection (§8.1); any other
        /// returns with the endpoint untouched: `phase` is still `listening`,
        /// `core.peer` is not set, and nothing was handed to the machine or the
        /// driver. `sizing.connection_ids` and the datagram buffers are scratch
        /// until `begin`, so a refused datagram leaves them written and
        /// meaningless.
        fn receiveFirst(self: *Self, io: Io) AcceptError!void {
            assert(self.core.phase == .listening);
            const sizing = &self.sizing;
            const message = try self.core.socket.receive(io, &sizing.datagram_in);
            if (message.data.len < Conn.min_initial_datagram) return;
            const opening = Conn.Opening.fromDatagram(message.data, &sizing.connection_ids) catch return;
            opening.authenticate(message.data, &sizing.scratch, &sizing.plaintext) catch return;
            try self.begin(io, opening, message.data, message.from);
        }

        /// Connect to `config.peer` and return once the handshake is done. The
        /// endpoint owns the socket from here, so `deinit` follows a failed
        /// `connect` too. `allocator` is as in `listen`.
        pub fn connect(self: *Self, allocator: Allocator, config: Connect) ConnectError!Connection {
            const io = config.io;
            self.prepare(allocator, io, config.socket, config.peer, config.parameters);
            try self.allocateFlight(.client);
            self.driver = try self.startTls(io, .{ .client = .{
                .policy = config.trust.policy(),
                .server_name = config.server_name,
                .alpn = config.alpn,
            } });
            try self.allocateStreams();
            const sizing = &self.sizing;
            io.random(&sizing.original_id);
            io.random(&sizing.own_id);

            var parameters = self.parameters;
            parameters.initial_source_connection_id = &sizing.own_id;
            var config_conn = self.machine(Conn.clientConfig(&sizing.original_id, &sizing.own_id, sizing.loss()));
            config_conn.connection_id_storage = &sizing.adopted_id;
            config_conn.transport_parameters = try self.encode(parameters, .client);

            try self.core.begin(config_conn, null);
            errdefer self.core.stop(io);
            try self.core.awaitEstablished(io);
            return .{ .core = &self.core };
        }

        /// Cancel the connection's tasks, return only once neither runs, close
        /// the socket, and give back everything the allocator supplied. No
        /// CONNECTION_CLOSE: that is `Connection.close`.
        pub fn deinit(self: *Self, io: Io) void {
            self.core.stop(io);
            self.sizing.tls.deinit();
            self.core.socket.close(io);
            self.pool.deinit(self.allocator);
            self.allocator.free(self.core.storage.slots);
            self.allocator.free(self.core.storage.streams);
            self.allocator.free(self.table);
            self.allocator.free(self.flight.server_hello);
            self.allocator.free(self.flight.peer_handshake);
            self.allocator.free(self.flight.peer_initial);
            self.allocator.free(self.flight.out);
            self.allocator.free(self.chain);
            self.* = undefined;
        }

        fn prepare(
            self: *Self,
            allocator: Allocator,
            io: Io,
            socket: Io.net.Socket,
            peer: IpAddress,
            parameters: TransportParameters,
        ) void {
            self.sizing.prepare();
            self.parameters = S.advertised(parameters);
            // §4.6: credit the table cannot back turns a legal peer into a
            // connection error, which `Conn.init` refuses too.
            const bidi = self.parameters.initial_max_streams_bidi orelse 0;
            const uni = self.parameters.initial_max_streams_uni orelse 0;
            assert(bidi + uni <= S.limits.streams);
            // Empty first, so `deinit` frees what exists whichever allocation
            // after this fails.
            self.allocator = allocator;
            self.flight = .empty;
            self.chain = &.{};
            self.pool = .empty;
            self.pool_capacity = 0;
            self.table = &.{};
            self.core.init(.{
                .io = io,
                .socket = socket,
                .peer = peer,
                .storage = self.sizing.coreStorage(),
                .events = .init(&self.sizing.acked, &self.sizing.lost),
                .loss = self.sizing.loss(),
                .idle_timeout_ms = self.parameters.max_idle_timeout orelse 0,
                .pool = .{ .context = self, .create = createSlot, .destroy = destroySlot },
                .peer_streams = .{ .bidi = bidi, .uni = uni },
            });
        }

        /// Decode the certificate chain into exactly the bytes it takes, and
        /// load the key. The chain is decoded first into no more than the PEM
        /// (which always holds its DER) or `tls.chain`, whichever is less, and
        /// that is then shrunk to fit: in place where the allocator can, which
        /// a `FixedBufferAllocator` always can for its newest allocation, and
        /// otherwise by decoding again into an allocation of the exact size.
        fn loadCredentials(self: *Self, certificate: []const u8, key: []const u8) ListenError!driver.Credentials {
            const tls = &self.sizing.tls;
            self.chain = try self.allocator.alloc(u8, @min(certificate.len, S.limits.tls.chain));
            const used = try tls.decodeChain(self.chain, certificate);
            if (self.allocator.resize(self.chain, used)) {
                self.chain = self.chain[0..used];
            } else {
                self.allocator.free(self.chain);
                self.chain = &.{};
                self.chain = try self.allocator.alloc(u8, used);
                const again = try tls.decodeChain(self.chain, certificate);
                assert(again == used);
            }
            try tls.loadKey(key);
            return tls.credentials();
        }

        /// The handshake's flights, before the stream table, so the pool is
        /// still the newest allocation once they are taken. A server's follow
        /// from the chain it loaded.
        fn allocateFlight(self: *Self, role: driver.Role) Allocator.Error!void {
            const lengths = driver.Flight.lengths(S.limits.tls, role, @intCast(self.chain.len));
            self.flight.out = try self.allocator.alloc(u8, lengths.out);
            self.flight.peer_initial = try self.allocator.alloc(u8, lengths.peer_initial);
            self.flight.peer_handshake = try self.allocator.alloc(u8, lengths.peer_handshake);
            self.flight.server_hello = try self.allocator.alloc(u8, lengths.server_hello);
        }

        /// The stream table whole, then the pool: last, so that on a
        /// `FixedBufferAllocator` the pool's block is the newest allocation and
        /// grows in place. Then every stream the peer may open has its buffers
        /// before the first datagram can open it (§4.6).
        fn allocateStreams(self: *Self) Allocator.Error!void {
            const count = S.limits.streams;
            self.table = try self.allocator.alloc(StreamTable.Slot, count);
            const streams = try self.allocator.alloc(Conn.Stream, count);
            const slots = self.allocator.alloc(Core.Slot, count) catch |err| {
                self.allocator.free(streams);
                return err;
            };
            self.core.attach(streams, slots);
            self.pool = try .initCapacity(self.allocator, S.limits.preheat);
            self.pool_capacity = S.limits.preheat;
            const bidi = self.parameters.initial_max_streams_bidi orelse 0;
            const uni = self.parameters.initial_max_streams_uni orelse 0;
            try self.core.arm(@intCast(bidi + uni));
        }

        /// `Core.Pool.create`: a slot off the free list, or a new one.
        fn createSlot(context: *anyopaque) Allocator.Error!Core.Buffers {
            const self: *Self = @ptrCast(@alignCast(context));
            const grows = self.pool.free_list.first == null;
            const slot = try self.pool.create(self.allocator);
            if (grows) self.pool_capacity += 1;
            return .{ .send = &slot.send, .recv = &slot.recv };
        }

        /// `Core.Pool.destroy`: back on the free list, from the buffers alone.
        fn destroySlot(context: *anyopaque, buffers: Core.Buffers) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(buffers.send.len == S.limits.stream_ring);
            const send: *[S.limits.stream_ring]u8 = buffers.send[0..S.limits.stream_ring];
            const slot: *S.StreamSlot = @fieldParentPtr("send", send);
            assert(buffers.recv.ptr == &slot.recv);
            self.pool.destroy(@alignCast(slot));
        }

        /// Build the handshake in the sizing, over the flights. The Hello
        /// random and the ephemeral keys come from the platform, never from a
        /// constant.
        fn startTls(self: *Self, io: Io, config: driver.Config) driver.Error!quic.handshake.Driver {
            var random: [32]u8 = undefined;
            io.random(&random);
            return self.sizing.tls.start(self.flight, config, random);
        }

        /// A server's machine, named by the client's first Initial (§7.2),
        /// with parameters that echo it (§7.3). `first` has already opened
        /// (`Opening.authenticate`), and `from` sent it.
        ///
        /// The one step that can fail before the machine exists, `encode`, runs
        /// before `peer` is set, so an error here leaves the endpoint
        /// listening.
        fn begin(
            self: *Self,
            io: Io,
            opening: Conn.Opening,
            first: []u8,
            from: IpAddress,
        ) AcceptError!void {
            const sizing = &self.sizing;
            io.random(&sizing.own_id);
            var parameters = self.parameters;
            parameters.original_destination_connection_id = opening.destination_connection_id;
            parameters.initial_source_connection_id = &sizing.own_id;
            var config = self.machine(opening.serverConfig(&sizing.own_id, sizing.loss()));
            config.transport_parameters = try self.encode(parameters, .server);
            self.core.peer = from;
            try self.core.begin(config, first);
        }

        /// Fill in what every machine this endpoint builds shares.
        fn machine(self: *Self, base: Conn.Config) Conn.Config {
            const sizing = &self.sizing;
            var config = base;
            config.tls = self.driver;
            config.crypto = sizing.cryptoReceived();
            config.crypto_sent = sizing.cryptoSent();
            config.stream_slots = self.table;
            config.streams = self.core.storage.streams;
            config.receive_limit = S.receive_limit;
            config.max_streams_bidi = self.parameters.initial_max_streams_bidi orelse 0;
            config.max_streams_uni = self.parameters.initial_max_streams_uni orelse 0;
            return config;
        }

        fn encode(
            self: *Self,
            parameters: TransportParameters,
            role: TransportParameters.Role,
        ) TransportParameters.Error![]const u8 {
            var writer: quic.Writer = .init(&self.sizing.parameter_bytes);
            try TransportParameters.encode(&writer, parameters, role);
            return writer.written();
        }
    };
}

/// One QUIC connection: a handle on its endpoint's machine and tasks, which is
/// why it is a value and why it outlives no `Endpoint.deinit`.
pub const Connection = struct {
    core: *Core,

    pub const AcceptStreamError = ConnectionError || Io.Cancelable;
    /// `error.OutOfMemory` is the pool, which could not grow: the connection
    /// goes on as it was.
    pub const OpenStreamError = ConnectionError || Io.Cancelable || Allocator.Error;

    /// Wait for the next stream the peer opens, lowest ID first.
    ///
    /// Its buffers were ready before the peer could open it. Taking it lets
    /// the peer open one more, once the pool supplies the slot that stream
    /// will land in; a pool that cannot is not an error here, and the peer
    /// waits for credit until a stream closes (§4.6).
    ///
    /// A peer that opens more than this endpoint advertised has broken §4.6,
    /// and the connection ends, which this returns: `error.StreamLimit` when
    /// the table is full, and otherwise `error.FlowControl` once its bytes
    /// land in an entry with no buffers, because the machine does not count
    /// the peer's streams against its credit.
    pub fn acceptStream(self: Connection, io: Io) AcceptStreamError!Stream {
        return self.stream(try self.core.acceptStream(io));
    }

    /// Open a stream, waiting while the peer grants no credit for one (§4.6).
    /// `error.StreamLimit` when every slot is held, or kept for the streams
    /// the peer may open: close a stream first. `error.OutOfMemory` when the
    /// pool is empty and the allocator refuses another slot.
    pub fn openStream(self: Connection, io: Io, direction: Direction) OpenStreamError!Stream {
        return self.stream(try self.core.openStream(io, direction));
    }

    /// Send what the streams still owe, then CONNECTION_CLOSE with NO_ERROR
    /// (§10.2), and stop the connection's tasks.
    pub fn close(self: Connection, io: Io) void {
        self.core.close(io, 0);
    }

    /// As `close`, with an application error `code` (§20.2).
    pub fn closeWith(self: Connection, io: Io, code: u64) void {
        self.core.close(io, code);
    }

    fn stream(self: Connection, held: Core.Held) Stream {
        return .{
            .core = self.core,
            .index = held.index,
            .generation = held.generation,
            .id = held.id,
        };
    }
};

/// One QUIC stream: its slot and the generation that slot had when this handle
/// was made, so a handle kept past `close` is `error.StreamClosed` and never
/// someone else's stream.
pub const Stream = struct {
    core: *Core,
    index: u16,
    generation: u32,
    /// §2.1: the wire stream id. A protocol above QUIC keys its streams by this
    /// number, so it is part of the handle rather than hidden in the machine.
    id: u64,

    pub const ReadError = ConnectionError || error{
        /// The peer reset the stream (§3.2).
        StreamReset,
        /// This handle was closed.
        StreamClosed,
    } || Io.Cancelable;

    pub const WriteError = ConnectionError || error{
        /// The peer asked this endpoint to stop sending (§3.5).
        StreamReset,
        /// This handle was closed, or the send half shut down.
        StreamClosed,
    } || Io.Cancelable;

    pub const ShutdownError = ConnectionError || error{StreamClosed} || Io.Cancelable;

    /// Read what has arrived into `data`, in order, waiting while there is
    /// none. 0 is the end of the stream: the peer's FIN, or `shutdown(.recv)`.
    /// A stream that only sends is `error.WrongDirection`.
    pub fn read(self: Stream, io: Io, data: [][]u8) ReadError!usize {
        const core = self.core;
        try core.mutex.lock(io);
        defer core.mutex.unlock(io);
        while (true) {
            const entry = try core.held(self.index, self.generation);
            if (!entry.canRecv()) return error.WrongDirection;
            if (try readAvailable(&entry.recv, data)) |count| {
                // A read is what opens the window (§4.2), so the sender may now
                // owe the peer a MAX_STREAM_DATA.
                if (count > 0) core.wake.signal(io);
                return count;
            }
            try core.alive();
            try core.storage.slots[self.index].changed.wait(io, &core.mutex);
        }
    }

    /// Queue as much of `bytes` as the send buffer holds and wake the sender.
    /// Returns how many were queued; `error.NoSpace` once the buffer is spent,
    /// because it does not wrap (`SizingLimits.stream_ring`).
    pub fn write(self: Stream, io: Io, bytes: []const u8) WriteError!usize {
        const core = self.core;
        try core.mutex.lock(io);
        defer core.mutex.unlock(io);
        const entry = try core.held(self.index, self.generation);
        try core.alive();
        if (!entry.canSend()) return error.WrongDirection;
        const send = &entry.send;
        if (send.stop_sending_code != null) return error.StreamReset;
        if (send.reset_code != null or send.final_size != null) return error.StreamClosed;
        assert(send.written <= send.buffer.len);
        const room = send.buffer.len - @as(usize, @intCast(send.written));
        if (room == 0) return error.NoSpace;
        const count = @min(room, bytes.len);
        send.write(bytes[0..count]) catch unreachable;
        core.wake.signal(io);
        return count;
    }

    /// End one half of the stream, or both, the way QUIC can:
    ///
    /// - `.send`: FIN after the bytes already written; reads go on.
    /// - `.recv`: STOP_SENDING, and reads return 0 from here.
    /// - `.both`: RESET_STREAM, then STOP_SENDING.
    ///
    /// Both frames carry application error code 0. A half that is already
    /// over, or that a unidirectional stream never had, is left alone.
    pub fn shutdown(self: Stream, io: Io, how: ShutdownHow) ShutdownError!void {
        const core = self.core;
        try core.mutex.lock(io);
        defer core.mutex.unlock(io);
        _ = try core.held(self.index, self.generation);
        try core.alive();
        switch (how) {
            .send => core.finishSending(self.index),
            .recv => core.stopReceiving(self.index),
            .both => {
                core.resetSending(self.index);
                core.stopReceiving(self.index);
            },
        }
        core.wake.signal(io);
    }

    /// Close both directions and release the handle: a FIN after what was
    /// written, STOP_SENDING if the peer could still send. The slot is reused
    /// once both halves are over. A closed handle is a no-op here and
    /// `error.StreamClosed` everywhere else.
    pub fn close(self: Stream, io: Io) void {
        const core = self.core;
        core.mutex.lockUncancelable(io);
        defer core.mutex.unlock(io);
        _ = core.held(self.index, self.generation) catch return;
        if (core.phase != .closed) {
            core.finishSending(self.index);
            core.stopReceiving(self.index);
        }
        core.release(self.index);
        core.wake.signal(io);
    }

    /// A `std.Io.Reader` over `read`, as `Io.net.Stream.Reader` is over a
    /// socket: hand `&reader.interface` to anything that takes a reader. The
    /// peer's FIN is `error.EndOfStream`; a failed `read` is
    /// `error.ReadFailed`, and `err` holds why.
    pub const Reader = struct {
        io: Io,
        interface: Io.Reader,
        stream: Stream,
        err: ?Error,

        pub const Error = ReadError;

        /// The most slices one `read` fills: the caller's and the buffer.
        const max_vectors = 8;

        pub fn init(stream: Stream, io: Io, buffer: []u8) Reader {
            return .{
                .io = io,
                .interface = .{
                    .vtable = &.{
                        .stream = streamImpl,
                        .readVec = readVec,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
                .stream = stream,
                .err = null,
            };
        }

        fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            var data: [1][]u8 = .{dest};
            const n = try readVec(io_r, &data);
            io_w.advance(n);
            return n;
        }

        fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
            const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
            var vectors: [max_vectors][]u8 = undefined;
            const dest_n, const data_size = try io_r.writableVector(&vectors, data);
            const dest = vectors[0..dest_n];
            // `read` returns 0 for no room as well as for the FIN, so an empty
            // destination would read as the end of the stream.
            assert(dest[0].len > 0);
            const n = r.stream.read(r.io, dest) catch |err| {
                r.err = err;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            if (n > data_size) {
                r.interface.end += n - data_size;
                return data_size;
            }
            return n;
        }
    };

    /// A `std.Io.Writer` over `write`, as `Io.net.Stream.Writer` is over a
    /// socket. What it drains is queued for the connection's sender, which
    /// carries it in STREAM frames; a failed `write` is `error.WriteFailed`,
    /// and `err` holds why. The FIN is still `shutdown(.send)` or `close`.
    pub const Writer = struct {
        io: Io,
        interface: Io.Writer,
        stream: Stream,
        err: ?Error = null,

        pub const Error = WriteError;

        pub fn init(stream: Stream, io: Io, buffer: []u8) Writer {
            return .{
                .io = io,
                .stream = stream,
                .interface = .{
                    .vtable = &.{ .drain = drain },
                    .buffer = buffer,
                },
            };
        }

        /// One `write` per call, of the buffer first and then of the first
        /// slice of `data` with bytes in it: `write` takes one slice, and a
        /// short drain is the interface's to repeat.
        fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            assert(data.len > 0);
            const buffered = io_w.buffered();
            if (buffered.len > 0) return io_w.consume(try w.send(buffered));
            for (data[0 .. data.len - 1]) |bytes| {
                if (bytes.len > 0) return w.send(bytes);
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            // One copy of the pattern; the interface counts the rest.
            return w.send(pattern);
        }

        fn send(w: *Writer, bytes: []const u8) Io.Writer.Error!usize {
            assert(bytes.len > 0);
            const n = w.stream.write(w.io, bytes) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            assert(n > 0);
            return n;
        }
    };

    /// What a read can return now, or null when it has to wait.
    fn readAvailable(recv: *quic.ReceiveStream, data: [][]u8) error{StreamReset}!?usize {
        switch (recv.state) {
            .reset_recvd => {
                _ = recv.readReset() catch unreachable;
                return error.StreamReset;
            },
            .reset_read => return error.StreamReset,
            .recv, .size_known, .data_recvd, .data_read => {},
        }
        var count: usize = 0;
        var capacity: usize = 0;
        for (data) |buffer| {
            capacity += buffer.len;
            // Only a reset refuses a read, and that is handled above.
            const taken = recv.readInto(buffer) catch unreachable;
            count += taken;
            if (taken < buffer.len) break;
        }
        if (count > 0) return count;
        if (recv.state == .data_read) return 0;
        if (recv.stop_sending_code != null) return 0;
        if (capacity == 0) return 0;
        return null;
    }
};

// -- Tests -------------------------------------------------------------------
//
// What needs no handshake. The handshake, streams in both directions, a
// canceled read, a stale handle, `deinit` with the tasks running, and
// `Stream.Reader` and `Stream.Writer` are in examples/hq.zig, which has a real
// TLS driver.

test "SizingLimits, every dependent length follows from its numbers" {
    const S = Sizing(.{
        .streams = 3,
        .stream_ring = 100,
        .sent_packets = 5,
        .crypto = 7,
        .datagram = 1300,
        .tls = .{ .post_handshake = 9 },
        .peer_initial = 2,
    });
    var sizing: S = undefined;
    const slot: S.StreamSlot = undefined;
    try testing.expectEqual(@as(u64, 300), S.receive_limit);
    try testing.expectEqual(3, sizing.stream_events.len);
    try testing.expectEqual(100, slot.recv.len);
    try testing.expectEqual(100, slot.send.len);
    try testing.expectEqual(5, sizing.sent[2].len);
    try testing.expectEqual(5, sizing.lost.len);
    try testing.expectEqual(5, sizing.records.len);
    try testing.expectEqual(5, sizing.sent_streams.len);
    try testing.expectEqual(7, sizing.cryptoReceived().handshake.len);
    try testing.expectEqual(7, sizing.cryptoSent().handshake.len);
    // The application level receives one post-handshake message and sends
    // nothing (`SizingLimits.crypto`).
    try testing.expectEqual(9, sizing.cryptoReceived().app.len);
    try testing.expectEqual(0, sizing.cryptoSent().app.len);
    try testing.expectEqual(1300, sizing.datagram_out.len);
    try testing.expectEqual(6, sizing.control.len);

    // The rings are the pool's: a larger one changes the slot, not the sizing.
    try testing.expectEqual(@sizeOf(S), @sizeOf(Sizing(.{
        .streams = 3,
        .stream_ring = 100_000,
        .sent_packets = 5,
        .crypto = 7,
        .datagram = 1300,
        .tls = .{ .post_handshake = 9 },
    })));
    try testing.expectEqual(200, @sizeOf(S.StreamSlot));

    const advertised = S.advertised(.{ .max_idle_timeout = 30 });
    try testing.expectEqual(@as(?u64, 300), advertised.initial_max_data);
    try testing.expectEqual(@as(?u64, 100), advertised.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(?u64, 2), advertised.initial_max_streams_bidi);
    try testing.expectEqual(@as(?u64, 1300), advertised.max_udp_payload_size);
    try testing.expectEqual(@as(?u64, 30), advertised.max_idle_timeout);
}

/// The loopback fixtures, which tls ships and the build hands this module.
const test_certificate = @embedFile("tls_server_crt");
const test_key = @embedFile("tls_server_key");

/// File scope: an endpoint is tens of kilobytes and must not move.
var test_endpoint: Endpoint(Sizing(.{})) = undefined;

test "RFC 9000 §14.1, accept drops what cannot start a connection, and is cancelable" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var address: IpAddress = undefined;
    const socket = bound: {
        var port: u16 = 47501;
        while (port < 47551) : (port += 1) {
            address = .{ .ip4 = .loopback(port) };
            break :bound address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch continue;
        }
        return error.NoFreePort;
    };
    const local: IpAddress = .{ .ip4 = .loopback(0) };
    const sender = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(io);

    try test_endpoint.listen(testing.allocator, .{
        .io = io,
        .socket = socket,
        .certificate = test_certificate,
        .key = test_key,
    });
    defer test_endpoint.deinit(io);

    var accepting = try io.concurrent(Endpoint(Sizing(.{})).accept, .{ &test_endpoint, io });
    // A short datagram, then a full-size one that is not QUIC at all.
    const junk: [1200]u8 = @splat(0x40);
    try sender.send(io, &address, junk[0..20]);
    try sender.send(io, &address, &junk);
    try testing.expectError(error.Canceled, accepting.cancel(io));
    try testing.expectEqual(Core.Phase.listening, test_endpoint.core.phase);
}

/// A version 1 Initial from a client that named the server `dcid`, sealed under
/// the keys that name seeds (§5.2 of RFC 9001) and padded to 1200 bytes
/// (§14.1). Its payload is a PING and padding: enough to open, and no CRYPTO.
fn clientInitial(out: *[Conn.min_initial_datagram]u8, dcid: *const [8]u8) void {
    out[0..5].* = .{ 0xc3, 0, 0, 0, 1 };
    out[5] = dcid.len;
    out[6..14].* = dcid.*;
    out[14] = 8; // The client's own name, which the test never reads back.
    out[15..23].* = @splat(0xc1);
    out[23] = 0; // No token.
    const pn_offset = 26;
    const pn_len = 4;
    const payload_len = out.len - pn_offset - pn_len - quic.protection.tag_length;
    // The Length field is a two-byte varint counting what follows it.
    const length: u16 = out.len - pn_offset;
    out[24] = 0x40 | @as(u8, @intCast(length >> 8));
    out[25] = @truncate(length);
    out[pn_offset..][0..pn_len].* = @splat(0); // Packet number 0.
    var payload: [payload_len]u8 = @splat(0);
    payload[0] = 0x01; // PING; the rest is PADDING.
    const secrets = quic.protection.initialSecrets(dcid);
    const keys = quic.protection.deriveKeys(&secrets.client, .aes_128_gcm) catch unreachable;
    const sealed = quic.protection.sealPacket(&keys, 0, pn_offset, pn_len, &payload, out) catch unreachable;
    assert(sealed == out.len);
}

test "RFC 9000 §8.1, a first datagram that does not open leaves the endpoint as it was, and a genuine one then opens" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var address: IpAddress = undefined;
    const socket = bound: {
        var port: u16 = 47551;
        while (port < 47601) : (port += 1) {
            address = .{ .ip4 = .loopback(port) };
            break :bound address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch continue;
        }
        return error.NoFreePort;
    };
    const local: IpAddress = .{ .ip4 = .loopback(0) };
    const sender = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(io);

    try test_endpoint.listen(testing.allocator, .{
        .io = io,
        .socket = socket,
        .certificate = test_certificate,
        .key = test_key,
    });
    defer test_endpoint.deinit(io);
    const nowhere: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };

    var genuine: [Conn.min_initial_datagram]u8 = undefined;
    clientInitial(&genuine, &.{ 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1 });

    // The header reads true and the tag does not verify: one flipped bit.
    var bad_tag = genuine;
    bad_tag[bad_tag.len - 1] ^= 0x01;
    // The Length field claims 2800 bytes more than the datagram has.
    var too_long = genuine;
    too_long[24] = 0x40 | @as(u8, @intCast((genuine.len - 26 + 2800) >> 8));
    too_long[25] = @truncate(genuine.len - 26 + 2800);
    // Random ciphertext after a true header.
    var noise = genuine;
    io.random(noise[26..]);

    for ([_]*const [Conn.min_initial_datagram]u8{ &bad_tag, &too_long, &noise }) |datagram| {
        try sender.send(io, &address, datagram);
        try test_endpoint.receiveFirst(io);
        try testing.expectEqual(Core.Phase.listening, test_endpoint.core.phase);
        try testing.expect(test_endpoint.core.peer.eql(&nowhere));
    }

    // The next datagram, from anyone, is a first attempt: this one is.
    try sender.send(io, &address, &genuine);
    try test_endpoint.receiveFirst(io);
    try testing.expectEqual(Core.Phase.handshaking, test_endpoint.core.phase);
    try testing.expect(test_endpoint.core.peer.eql(&sender.address));
}

// -- The handshake's buffers -------------------------------------------------
//
// What `listen` and `connect` take from the allocator for TLS, and when they
// give it back.

/// tls's fixture certificate, in the DER bytes it decodes to.
const test_chain = 411;

/// A sizing whose chain limit is one byte short of the fixture's.
var test_short: Endpoint(Sizing(.{ .tls = .{ .chain = test_chain - 1 } })) = undefined;

test "RFC 8446 §4.4.2, a certificate longer than tls.chain fails listen with NoSpace, not a truncation" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any: IpAddress = .{ .ip4 = .loopback(0) };

    var counted: testing.FailingAllocator = .init(testing.allocator, .{});
    try testing.expectError(error.NoSpace, test_short.listen(counted.allocator(), .{
        .io = io,
        .socket = try any.bind(io, .{ .mode = .dgram }),
        .certificate = test_certificate,
        .key = test_key,
    }));
    // Decoding stopped at the limit: never more than it was asked for, and
    // nothing after it, no flight and no streams.
    try testing.expectEqual(1, counted.allocations);
    try testing.expectEqual(test_chain - 1, counted.allocated_bytes);
    test_short.deinit(io);
    try testing.expectEqual(counted.allocated_bytes, counted.freed_bytes);
}

test "the handshake's buffers come from the allocator at listen and connect, sized from the certificate, and go back" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any: IpAddress = .{ .ip4 = .loopback(0) };
    const S = Sizing(.{});

    var server_counted: testing.FailingAllocator = .init(testing.allocator, .{});
    const listening = try any.bind(io, .{ .mode = .dgram });
    try test_endpoint.listen(server_counted.allocator(), .{
        .io = io,
        .socket = listening,
        .certificate = test_certificate,
        .key = test_key,
    });
    // The chain is the certificate's DER exactly, and the flight follows from
    // it, not from the limit.
    const server_flight = driver.Flight.lengths(S.limits.tls, .server, test_chain);
    try testing.expectEqual(test_chain, test_endpoint.chain.len);
    try testing.expectEqual(server_flight.out, test_endpoint.flight.out.len);
    try testing.expectEqual(server_flight.peer_handshake, test_endpoint.flight.peer_handshake.len);
    try testing.expectEqual(server_flight.server_hello, test_endpoint.flight.server_hello.len);
    try testing.expect(server_flight.out < driver.Flight.lengths(S.limits.tls, .server, S.limits.tls.chain).out);
    const outstanding = server_counted.allocated_bytes - server_counted.freed_bytes;
    try testing.expect(outstanding >= test_chain + server_flight.total());
    test_endpoint.deinit(io);
    try testing.expectEqual(server_counted.allocated_bytes, server_counted.freed_bytes);
    try testing.expectEqual(server_counted.allocations, server_counted.deallocations);

    // A client that gets no answer: its handshake ends on the idle timeout,
    // or on the port refusing it, and its memory goes back all the same.
    var client_counted: testing.FailingAllocator = .init(testing.allocator, .{});
    const nobody = try any.bind(io, .{ .mode = .dgram });
    const nowhere = nobody.address;
    nobody.close(io);
    const client_flight = driver.Flight.lengths(S.limits.tls, .client, 0);
    if (test_endpoint.connect(client_counted.allocator(), .{
        .io = io,
        .socket = try any.bind(io, .{ .mode = .dgram }),
        .peer = nowhere,
        .trust = .insecure,
        .parameters = .{ .max_idle_timeout = 50 },
    })) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
    try testing.expectEqual(0, test_endpoint.chain.len);
    try testing.expectEqual(client_flight.out, test_endpoint.flight.out.len);
    try testing.expectEqual(0, test_endpoint.flight.server_hello.len);
    test_endpoint.deinit(io);
    try testing.expect(client_counted.allocated_bytes >= client_flight.total());
    try testing.expectEqual(client_counted.allocated_bytes, client_counted.freed_bytes);
    try testing.expectEqual(client_counted.allocations, client_counted.deallocations);
}

// -- The application level's CRYPTO buffers ----------------------------------
//
// Two machines over two `Sizing`s, wired as `Endpoint.machine` wires one, with
// the handshake between them carried in memory: no socket and no tasks, so a
// test can hand the client exactly the CRYPTO frames it means to.

const TestSizing = Sizing(.{});
var test_client_sizing: TestSizing = undefined;
var test_server_sizing: TestSizing = undefined;
/// Each driver with its flights inline, which is all an endpoint adds to the
/// sizing's `tls`: the machines here are wired by hand.
var test_client_tls: driver.Storage(TestSizing.limits.tls) = undefined;
var test_server_tls: driver.Storage(TestSizing.limits.tls) = undefined;
var test_client: Conn = undefined;
var test_server: Conn = undefined;

/// Build both machines and run their handshake to the end. `deinit`
/// `test_client_tls` and `test_server_tls` afterwards.
fn testHandshake() !void {
    const client = &test_client_sizing;
    const server = &test_server_sizing;
    client.prepare();
    server.prepare();
    test_client_tls.init();
    test_server_tls.init();
    const alpn: []const []const u8 = &.{"hq-interop"};
    const trust: Trust = .insecure;
    const credentials = try test_server_tls.credentials(test_certificate, test_key);
    const server_role: driver.Config = .{ .server = .{ .credentials = credentials, .alpn = alpn } };
    const server_tls = try test_server_tls.start(server_role, @splat(0x22));
    const client_role: driver.Config = .{ .client = .{ .policy = trust.policy(), .alpn = alpn } };
    const client_tls = try test_client_tls.start(client_role, @splat(0x11));

    client.original_id = @splat(0xc0);
    client.own_id = @splat(0xc1);
    var client_config = Conn.clientConfig(&client.original_id, &client.own_id, client.loss());
    client_config.connection_id_storage = &client.adopted_id;
    client_config.tls = client_tls;
    client_config.crypto = client.cryptoReceived();
    client_config.crypto_sent = client.cryptoSent();
    client_config.transport_parameters = try testParameters(client, .{
        .initial_source_connection_id = &client.own_id,
    }, .client);
    test_client = .init(client_config);
    const first = (try test_client.writeHandshake(&client.scratch, &client.datagram_out, 0)).?;

    server.own_id = @splat(0x5e);
    const opening = try Conn.Opening.fromDatagram(client.datagram_out[0..first], &server.connection_ids);
    var server_config = opening.serverConfig(&server.own_id, server.loss());
    server_config.tls = server_tls;
    server_config.crypto = server.cryptoReceived();
    server_config.crypto_sent = server.cryptoSent();
    server_config.transport_parameters = try testParameters(server, .{
        .original_destination_connection_id = opening.destination_connection_id,
        .initial_source_connection_id = &server.own_id,
    }, .server);
    test_server = .init(server_config);
    try testFeed(&test_server, server, client.datagram_out[0..first]);

    var rounds: u32 = 0;
    while (rounds < 8) : (rounds += 1) {
        const answered = try testCarry(&test_server, server, &test_client, client);
        const finished = try testCarry(&test_client, client, &test_server, server);
        if (!answered and !finished) break;
    }
    try testing.expect(test_client_tls.fixed.engine.done());
    try testing.expect(test_server_tls.fixed.engine.done());
}

fn testParameters(
    sizing: *TestSizing,
    parameters: TransportParameters,
    role: TransportParameters.Role,
) TransportParameters.Error![]const u8 {
    var writer: quic.Writer = .init(&sizing.parameter_bytes);
    try TransportParameters.encode(&writer, parameters, role);
    return writer.written();
}

/// Every handshake datagram `from` owes, fed to `to`. Whether there was one.
fn testCarry(from: *Conn, from_sizing: *TestSizing, to: *Conn, to_sizing: *TestSizing) !bool {
    var moved = false;
    while (try from.writeHandshake(&from_sizing.scratch, &from_sizing.datagram_out, 0)) |length| {
        try testFeed(to, to_sizing, from_sizing.datagram_out[0..length]);
        moved = true;
    }
    return moved;
}

fn testFeed(conn: *Conn, sizing: *TestSizing, datagram: []u8) Conn.Error!void {
    var events: Recovery.Events = .init(&sizing.acked, &sizing.lost);
    _ = try conn.feed(datagram, &sizing.plaintext, &sizing.frames, &sizing.stream_events, &events, 0);
}

/// One 1-RTT packet from the server carrying one CRYPTO frame, fed to the
/// client.
fn testServerCrypto(offset: u64, data: []const u8) Conn.Error!void {
    const server = &test_server_sizing;
    var writer: quic.Writer = .init(&server.scratch);
    try frame.write(&writer, .{ .crypto = .{ .offset = offset, .data = data } });
    const length = try test_server.writeFrames(.app, writer.written(), &server.datagram_out, .data(0));
    try testFeed(&test_client, &test_client_sizing, server.datagram_out[0..length]);
}

/// A NewSessionTicket (§4.6.1 of RFC 8446) exactly `len` bytes long: no nonce,
/// no extensions, and the ticket itself the rest.
fn testTicket(comptime len: u32) [len]u8 {
    const fixed = 4 + 4 + 4 + 1 + 2 + 2;
    comptime assert(len > fixed);
    var message: [len]u8 = @splat(0x7e);
    message[0] = 4; // new_session_ticket
    mem.writeInt(u24, message[1..4], len - 4, .big);
    message[4..12].* = @splat(0); // ticket_lifetime, ticket_age_add
    message[12] = 0; // ticket_nonce, empty
    mem.writeInt(u16, message[13..15], len - fixed, .big);
    message[len - 2 ..][0..2].* = .{ 0, 0 }; // extensions, empty
    return message;
}

test "RFC 8446 §4.6, a post-handshake message of tls.post_handshake bytes arrives, one byte more is NoSpace" {
    try testHandshake();
    defer test_client_tls.deinit();
    defer test_server_tls.deinit();
    const limit = TestSizing.limits.tls.post_handshake;
    const client_tls = &test_client_tls.fixed.engine.engine.client;

    // Exactly the limit, in one frame: the ring and the driver each hold it.
    try testServerCrypto(0, &testTicket(limit));
    try testing.expectEqual(limit - 17, client_tls.lastTicket().?.ticket.len);

    // QUIC forbids KeyUpdate (§6 of RFC 9001), but tls's client answers one at
    // the application level, which is the one CRYPTO send there it can make.
    // The buffer for it is empty, and the answer is refused before a byte of
    // it is framed.
    const key_update = [_]u8{ 24, 0, 0, 1, 1 };
    try testServerCrypto(limit, &key_update);
    const app_sent = test_client.app.?.next_packet_number;
    try testing.expectError(
        error.NoSpace,
        test_client.writeHandshake(&test_client_sizing.scratch, &test_client_sizing.datagram_out, 0),
    );
    try testing.expectEqual(app_sent, test_client.app.?.next_packet_number);
    try testing.expectEqual(0, test_client.replayCrypto(.app).len);

    // One byte over, in one frame: the ring refuses it, and takes none of it.
    const offset = limit + key_update.len;
    const over = testTicket(limit + 1);
    try testing.expectError(error.NoSpace, testServerCrypto(offset, &over));
    try testing.expectEqual(offset, test_client.crypto[@backingInt(Conn.SpaceId.app)].received());

    // The same message in two frames: each fits the ring, and the driver,
    // which reassembles whole messages, refuses the second.
    const half = over.len / 2;
    try testServerCrypto(offset, over[0..half]);
    try testing.expectError(error.NoSpace, testServerCrypto(offset + half, over[half..]));
}

test {
    _ = Core;
}
