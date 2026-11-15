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
//! Nothing allocates and nothing is sized by the caller except `SizingLimits`.
//! `Endpoint(Sizing(limits))` holds every buffer one connection needs, and is
//! built in place because the machine inside refuses to move.
//!
//! The TLS handshake is not this module's: an endpoint is handed a ready
//! `quic.handshake.Driver` (the certificate, the key, and ALPN are the
//! driver's), so a program that speaks no TLS never compiles any.
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

const quic = @import("quic");
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const StreamTable = quic.StreamTable;
const TransportParameters = quic.TransportParameters;
const frame = quic.frame;

const Core = @import("io/Core.zig");

const Io = std.Io;

pub const IpAddress = Io.net.IpAddress;
pub const ShutdownHow = Io.net.ShutdownHow;
pub const Direction = quic.stream_id.Direction;

/// Why a connection ended, which every operation on it returns from then on:
/// `error.ConnectionClosed` and `error.IdleTimeout`, the socket's errors, and
/// the machine's transport errors by name (`error.HandshakeFailed`,
/// `error.FlowControl`, `error.StreamLimit`, ...).
pub const ConnectionError = Core.Failure;

pub const AcceptError = ConnectionError || Io.ConcurrentError || TransportParameters.Error;
pub const ConnectError = ConnectionError || Io.ConcurrentError || TransportParameters.Error;

/// The four numbers a caller chooses. Every other length follows from them.
pub const SizingLimits = struct {
    /// Streams held at once, both directions and both initiators.
    streams: u16 = 4,
    /// Each stream's receive ring and send buffer, and so the per-stream window
    /// this endpoint advertises (§4.1). The send buffer does not wrap: a stream
    /// carries at most this many bytes out over its life.
    stream_ring: u32 = 4096,
    /// Sent packets tracked per packet number space for loss recovery.
    sent_packets: u16 = 32,
    /// CRYPTO reassembly and replay, per encryption level.
    crypto: u32 = 4096,
    /// One datagram, in and out, and the max_udp_payload_size advertised.
    datagram: u16 = 1500,
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

/// Every buffer one connection needs, sized from `limits`: the loss tables,
/// the CRYPTO buffers, the stream slots and rings, the sent-frame records, and
/// the datagram scratch.
pub fn Sizing(comptime limits_given: SizingLimits) type {
    comptime {
        assert(limits_given.streams > 0);
        assert(limits_given.stream_ring > 0);
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

        loss_state: Recovery = .{},
        spaces: [3]Recovery.Space = undefined,
        sent: [3][sent]Recovery.SentPacket = undefined,
        acked: [sent]Recovery.SentPacket = undefined,
        lost: [sent]Recovery.SentPacket = undefined,
        crypto_in: [3][limits_given.crypto]u8 = undefined,
        crypto_sent: [3][limits_given.crypto]u8 = undefined,
        connection_ids: [2 * max_connection_id]u8 = undefined,
        adopted_id: [max_connection_id]u8 = undefined,
        original_id: [own_id_len]u8 = undefined,
        own_id: [own_id_len]u8 = undefined,
        parameter_bytes: [parameter_capacity]u8 = undefined,
        table: [streams]StreamTable.Slot = undefined,
        streams: [streams]Conn.Stream = undefined,
        send_bytes: [streams][ring]u8 = undefined,
        recv_bytes: [streams][ring]u8 = undefined,
        slots: [streams]Core.Slot = undefined,
        /// One record per tracked 1-RTT packet, each with room for a frame per
        /// stream, which is the most `Conn.writeStreams` packs.
        records: [sent]Core.Record = undefined,
        entries: [sent * streams]Core.Entry = undefined,
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

        fn prepare(self: *Self) void {
            self.loss_state = .{};
            // `Conn.init` asserts no two buffers overlap, so each stream has
            // its own pair.
            for (&self.streams, &self.send_bytes, &self.recv_bytes) |*stream, *send, *recv| {
                stream.* = .{ .send_buffer = send, .recv_buffer = recv, .recv_limit_bytes = ring };
            }
        }

        fn loss(self: *Self) Conn.Loss {
            return .{
                .shared = &self.loss_state,
                .spaces = &self.spaces,
                .sent_initial = &self.sent[0],
                .sent_handshake = &self.sent[1],
                .sent_app = &self.sent[2],
            };
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
                .slots = &self.slots,
                .records = &self.records,
                .entries = &self.entries,
            };
        }

        /// The caller's transport parameters with every number this sizing
        /// decides written over: the windows, the datagram size, and, when the
        /// caller named neither stream count, every slot for the peer's
        /// bidirectional streams.
        fn advertised(given: TransportParameters) TransportParameters {
            var parameters = given;
            parameters.initial_max_data = receive_limit;
            parameters.initial_max_stream_data_bidi_local = ring;
            parameters.initial_max_stream_data_bidi_remote = ring;
            parameters.initial_max_stream_data_uni = ring;
            parameters.max_udp_payload_size = datagram;
            if (given.initial_max_streams_bidi == null and given.initial_max_streams_uni == null) {
                parameters.initial_max_streams_bidi = streams;
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

        pub const Listen = struct {
            io: Io,
            /// A bound UDP socket. The endpoint owns it: `deinit` closes it.
            socket: Io.net.Socket,
            /// The handshake, built by the caller with its certificate, key,
            /// and ALPN. One connection's worth.
            driver: quic.handshake.Driver,
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
            driver: quic.handshake.Driver,
            /// As in `Listen`.
            parameters: TransportParameters = .{},
        };

        /// Start listening on `config.socket`. Nothing is read until `accept`.
        pub fn listen(self: *Self, config: Listen) void {
            const nowhere: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
            self.prepare(config.io, config.socket, nowhere, config.driver, config.parameters);
        }

        /// Wait for a client's first Initial, build the connection from it,
        /// and return once its handshake is done (§7.2).
        ///
        /// A datagram that cannot start a connection is dropped and the wait
        /// goes on: one under 1200 bytes (§14.1), or one whose first packet is
        /// not a version 1 Initial with a destination connection ID. A
        /// handshake that fails after that returns its error, and the endpoint
        /// is spent: its driver was that handshake's. `deinit` it either way.
        pub fn accept(self: *Self, io: Io) AcceptError!Connection {
            assert(self.core.phase == .listening);
            while (self.core.phase == .listening) {
                const message = try self.core.socket.receive(io, &self.sizing.datagram_in);
                if (message.data.len < Conn.min_initial_datagram) continue;
                const opening = Conn.Opening.fromDatagram(message.data, &self.sizing.connection_ids) catch continue;
                self.core.peer = message.from;
                try self.begin(io, opening, message.data);
            }
            errdefer self.core.stop(io);
            try self.core.awaitEstablished(io);
            return .{ .core = &self.core };
        }

        /// Connect to `config.peer` and return once the handshake is done. The
        /// endpoint owns the socket from here, so `deinit` follows a failed
        /// `connect` too.
        pub fn connect(self: *Self, config: Connect) ConnectError!Connection {
            const io = config.io;
            self.prepare(io, config.socket, config.peer, config.driver, config.parameters);
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

        /// Cancel the connection's tasks, return only once neither runs, and
        /// close the socket. No CONNECTION_CLOSE: that is `Connection.close`.
        pub fn deinit(self: *Self, io: Io) void {
            self.core.stop(io);
            self.core.socket.close(io);
            self.* = undefined;
        }

        fn prepare(
            self: *Self,
            io: Io,
            socket: Io.net.Socket,
            peer: IpAddress,
            driver: quic.handshake.Driver,
            parameters: TransportParameters,
        ) void {
            self.sizing.prepare();
            self.driver = driver;
            self.parameters = S.advertised(parameters);
            // §4.6: credit the table cannot back turns a legal peer into a
            // connection error, which `Conn.init` refuses too.
            const bidi = self.parameters.initial_max_streams_bidi orelse 0;
            const uni = self.parameters.initial_max_streams_uni orelse 0;
            assert(bidi + uni <= S.limits.streams);
            self.core.init(.{
                .io = io,
                .socket = socket,
                .peer = peer,
                .storage = self.sizing.coreStorage(),
                .events = .init(&self.sizing.acked, &self.sizing.lost),
                .loss = self.sizing.loss(),
                .idle_timeout_ms = self.parameters.max_idle_timeout orelse 0,
            });
        }

        /// A server's machine, named by the client's first Initial (§7.2),
        /// with parameters that echo it (§7.3).
        fn begin(self: *Self, io: Io, opening: Conn.Opening, first: []u8) AcceptError!void {
            const sizing = &self.sizing;
            io.random(&sizing.own_id);
            var parameters = self.parameters;
            parameters.original_destination_connection_id = opening.destination_connection_id;
            parameters.initial_source_connection_id = &sizing.own_id;
            var config = self.machine(opening.serverConfig(&sizing.own_id, sizing.loss()));
            config.transport_parameters = try self.encode(parameters, .server);
            try self.core.begin(config, first);
        }

        /// Fill in what every machine this endpoint builds shares.
        fn machine(self: *Self, base: Conn.Config) Conn.Config {
            const sizing = &self.sizing;
            var config = base;
            config.tls = self.driver;
            config.crypto = .{
                .initial = &sizing.crypto_in[0],
                .handshake = &sizing.crypto_in[1],
                .app = &sizing.crypto_in[2],
            };
            config.crypto_sent = .{
                .initial = &sizing.crypto_sent[0],
                .handshake = &sizing.crypto_sent[1],
                .app = &sizing.crypto_sent[2],
            };
            config.stream_slots = &sizing.table;
            config.streams = &sizing.streams;
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
    pub const OpenStreamError = ConnectionError || Io.Cancelable;

    /// Wait for the next stream the peer opens, lowest ID first.
    ///
    /// A peer that opens more than this endpoint advertised has broken §4.6,
    /// and the connection ends with `error.StreamLimit`, which this returns.
    pub fn acceptStream(self: Connection, io: Io) AcceptStreamError!Stream {
        return self.stream(try self.core.acceptStream(io));
    }

    /// Open a stream, waiting while the peer grants no credit for one (§4.6).
    /// `error.StreamLimit` when every slot is held: close a stream first.
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
        return .{ .core = self.core, .index = held.index, .generation = held.generation };
    }
};

/// One QUIC stream: its slot and the generation that slot had when this handle
/// was made, so a handle kept past `close` is `error.StreamClosed` and never
/// someone else's stream.
pub const Stream = struct {
    core: *Core,
    index: u16,
    generation: u32,

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

test "SizingLimits, every dependent length follows from five numbers" {
    const S = Sizing(.{ .streams = 3, .stream_ring = 100, .sent_packets = 5, .crypto = 7, .datagram = 1300 });
    const sizing: S = undefined;
    try testing.expectEqual(@as(u64, 300), S.receive_limit);
    try testing.expectEqual(3, sizing.streams.len);
    try testing.expectEqual(100, sizing.recv_bytes[0].len);
    try testing.expectEqual(100, sizing.send_bytes[2].len);
    try testing.expectEqual(5, sizing.sent[2].len);
    try testing.expectEqual(5, sizing.lost.len);
    try testing.expectEqual(5, sizing.records.len);
    try testing.expectEqual(15, sizing.entries.len);
    try testing.expectEqual(7, sizing.crypto_sent[1].len);
    try testing.expectEqual(1300, sizing.datagram_out.len);
    try testing.expectEqual(6, sizing.control.len);

    const advertised = S.advertised(.{ .max_idle_timeout = 30 });
    try testing.expectEqual(@as(?u64, 300), advertised.initial_max_data);
    try testing.expectEqual(@as(?u64, 100), advertised.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(?u64, 3), advertised.initial_max_streams_bidi);
    try testing.expectEqual(@as(?u64, 1300), advertised.max_udp_payload_size);
    try testing.expectEqual(@as(?u64, 30), advertised.max_idle_timeout);
}

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

    var stub: quic.handshake.Stub = .{};
    test_endpoint.listen(.{ .io = io, .socket = socket, .driver = stub.driver() });
    defer test_endpoint.deinit(io);

    var accepting = try io.concurrent(Endpoint(Sizing(.{})).accept, .{ &test_endpoint, io });
    // A short datagram, then a full-size one that is not QUIC at all.
    const junk: [1200]u8 = @splat(0x40);
    try sender.send(io, &address, junk[0..20]);
    try sender.send(io, &address, &junk);
    try testing.expectError(error.Canceled, accepting.cancel(io));
    try testing.expectEqual(Core.Phase.listening, test_endpoint.core.phase);
}
