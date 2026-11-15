//! What a connection's two tasks and every handle on it share: the machine, the
//! socket, the mutex they all take, and the conditions they park on.
//!
//! Two tasks, not one, and neither spawned with `Io.async`:
//!
//! - `Io.async` may run its function inline, at the call site, when the `Io`
//!   has no unit of concurrency to spare (`Io.Threaded` does exactly this once
//!   its busy count reaches `async_limit`, and always when single-threaded). A
//!   task that only ends when canceled then never returns, and `accept` never
//!   returns either. `Io.concurrent` fails with `error.ConcurrencyUnavailable`
//!   instead of deadlocking, and that error reaches the caller.
//! - One task cannot wait on a socket and on an `Io.Condition` at once: the
//!   receive is an `Io.Operation` and the condition is a futex, and `Io.Batch`
//!   takes operations only. So the receiver blocks in `Socket.receive` and the
//!   sender parks on `wake` with the next timer as its deadline, and a
//!   `Stream.write` wakes the sender without touching the socket.
//!
//! Both tasks live in one `Io.Group`, and `stop` cancels and awaits the group,
//! so nothing outlives the storage it points into.
//!
//! Everything below runs with `mutex` held unless it says otherwise. The
//! receive and the condition waits are the only places a task lets go of it.

const std = @import("std");
const assert = std.debug.assert;

const quic = @import("quic");

const Io = std.Io;
const Conn = quic.Conn;
const Recovery = quic.Recovery;
const RecoveryDriver = quic.RecoveryDriver;
const frame = quic.frame;
const stream_id = quic.stream_id;
const error_code = quic.error_code;

const Core = @This();

/// Where a connection is in its life. `listening` is a server that has not
/// met its client, so there is no machine yet; `closed` holds `failure`.
pub const Phase = enum { listening, handshaking, established, closed };

/// Why a connection ended, which every waiter on it is told.
pub const Failure = error{
    /// The peer sent CONNECTION_CLOSE (§10.2.2), or `Connection.close` ran.
    ConnectionClosed,
    /// §10.1: nothing arrived for the idle timeout, so the connection is
    /// discarded without a word.
    IdleTimeout,
} || Conn.Error || Io.net.Socket.ReceiveError;

/// Who holds a stream slot. Exhaustive: a slot is never both pending and held.
pub const Handle = enum {
    /// No application handle: the slot is free, or is a stream nobody owns.
    none,
    /// The peer opened it and `acceptStream` has not handed it out.
    pending,
    /// A `Stream` names it, with the slot's current generation.
    held,
    /// The application closed it; the slot goes back once both halves end.
    released,
};

/// One stream slot's shell state, beside the machine's `Conn.Stream` at the
/// same index.
pub const Slot = struct {
    /// Bumped when a handle is released, so a stale `Stream` names nothing.
    generation: u32 = 0,
    /// Read waits on it; the receiver broadcasts it when the stream changes.
    changed: Io.Condition = .init,
    handle: Handle = .none,
    /// A RESET_STREAM the sender owes: `shutdown(.both)`, a peer's
    /// STOP_SENDING, or a lost one.
    owe_reset: bool = false,
    /// A STOP_SENDING the sender owes: `shutdown(.recv)`, or a lost one.
    owe_stop: bool = false,
};

/// One frame a 1-RTT packet carried that has to be sent again if the packet is
/// lost (§13.3). ACKs, PADDING, PING, and the flow control frames are absent:
/// the first three are never retransmitted and `Conn` recomputes the last.
pub const Entry = union(enum) {
    stream: Conn.Written,
    reset_stream: u64,
    stop_sending: u64,
    handshake_done,
};

/// The frames of one sent 1-RTT packet, by packet number. `len` zero is free.
pub const Record = struct {
    packet_number: u64 = 0,
    len: u16 = 0,
};

/// The buffers the core works in, all the caller's (`Sizing`'s).
pub const Storage = struct {
    /// The receiver's datagram, filled without the mutex held.
    datagram_in: []u8,
    /// Every packet sealed, by whichever task holds the mutex.
    datagram_out: []u8,
    plaintext: []u8,
    /// Frames composed before they are sealed. It also carries an Initial's
    /// padding, so it holds `initial_payload_floor` bytes at least.
    scratch: []u8,
    frames: []frame.Frame,
    stream_events: []Conn.StreamEvent,
    /// What `Conn.flowControlOwed` writes into.
    control: []frame.Frame,
    offers: []Conn.Offer,
    written: []Conn.Written,
    slots: []Slot,
    records: []Record,
    /// `records.len` runs of `entries.len / records.len` entries each.
    entries: []Entry,
};

/// §14.1: a datagram carrying an ack-eliciting Initial is at least 1200 bytes.
/// The smallest Initial header this shell writes is 34 bytes with the tag (an
/// empty destination ID and its own 8-byte source ID), so a payload this long
/// always reaches 1200, and the longest header (a 20-byte destination) leaves
/// the packet at 1220.
pub const initial_payload_floor = Conn.min_initial_datagram - 34;

/// The most a long header, a packet number, a tag, and a CRYPTO frame's own
/// fields can take, so a CRYPTO chunk this much under the datagram fits.
const crypto_overhead = 96;

io: Io,
socket: Io.net.Socket,
/// Where packets go. A server learns it from the first datagram; §9 says a
/// datagram from anywhere else is not followed, because this layer validates no
/// path, so it is dropped.
peer: Io.net.IpAddress,
storage: Storage,
phase: Phase = .listening,
/// Meaningful once `phase` is `closed`.
failure: Failure = error.ConnectionClosed,
/// Built in place by `begin`, because a `Conn` refuses to move once used.
conn: Conn = undefined,
mutex: Io.Mutex = .init,
/// Connection-wide: the handshake finished, a peer stream arrived, credit
/// grew, or the connection ended.
changed: Io.Condition = .init,
/// The sender's: there is something to send.
wake: Io.Condition = .init,
group: Io.Group = .init,
events: Recovery.Events,
recovery_spaces: [3]*Recovery.Space,
recovery: RecoveryDriver = undefined,
/// The zero of every `Conn.Duration` this core hands the machine.
origin: Io.Timestamp,
/// §10.1: when a packet last opened, which restarts the idle timer.
received_at: Conn.Duration = 0,
/// This endpoint's max_idle_timeout, in nanoseconds; zero is none.
idle_timeout: Conn.Duration,
/// How many streams this endpoint has opened, per direction.
opened: Conn.StreamLimits = .{},

pub const Options = struct {
    io: Io,
    socket: Io.net.Socket,
    peer: Io.net.IpAddress,
    storage: Storage,
    events: Recovery.Events,
    loss: Conn.Loss,
    idle_timeout_ms: u64,
};

/// Build the core in place: `recovery` points at `recovery_spaces`.
pub fn init(self: *Core, options: Options) void {
    const storage = options.storage;
    assert(storage.records.len > 0);
    assert(storage.entries.len % storage.records.len == 0);
    assert(storage.entries.len / storage.records.len >= storage.slots.len);
    assert(storage.scratch.len >= initial_payload_floor);
    assert(storage.datagram_out.len > crypto_overhead);
    for (storage.slots) |*slot| slot.* = .{};
    for (storage.records) |*record| record.* = .{};
    self.* = .{
        .io = options.io,
        .socket = options.socket,
        .peer = options.peer,
        .storage = storage,
        .events = options.events,
        .recovery_spaces = .{ &options.loss.spaces[0], &options.loss.spaces[1], &options.loss.spaces[2] },
        .origin = Io.Timestamp.now(options.io, .awake),
        .idle_timeout = options.idle_timeout_ms *| std.time.ns_per_ms,
    };
    self.recovery = .init(options.loss.shared, &self.recovery_spaces);
}

/// Build the machine, walk the datagram that started it (a server's first
/// Initial), and spawn the two tasks.
pub fn begin(self: *Core, config: Conn.Config, first: ?[]u8) Io.ConcurrentError!void {
    assert(self.phase == .listening);
    // In place: the machine is first used, and so pinned, after this.
    self.conn = .init(config);
    self.phase = .handshaking;
    self.received_at = self.clock();
    // No task runs yet, so nothing else can hold the mutex.
    if (first) |data| self.onDatagram(data);
    try self.group.concurrent(self.io, receiveTask, .{self});
    self.group.concurrent(self.io, sendTask, .{self}) catch |err| {
        self.group.cancel(self.io);
        return err;
    };
}

/// Wait until the handshake is done or the connection has failed.
pub fn awaitEstablished(self: *Core, io: Io) (Failure || Io.Cancelable)!void {
    try self.mutex.lock(io);
    defer self.mutex.unlock(io);
    while (self.phase == .handshaking) try self.changed.wait(io, &self.mutex);
    if (self.phase == .closed) return self.failure;
    assert(self.phase == .established);
}

/// Cancel both tasks and return once neither runs. Idempotent.
pub fn stop(self: *Core, io: Io) void {
    self.group.cancel(io);
}

/// Stop the tasks, send what the application already wrote, then
/// CONNECTION_CLOSE with an application `code` (§10.2.3).
///
/// Cleanup, like a `defer`: a canceled caller still sends the close, so the
/// whole of it runs with cancelation blocked.
pub fn close(self: *Core, io: Io, code: u64) void {
    const protection = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(protection);
    self.stop(io);
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    if (self.phase == .listening or self.phase == .closed) return;
    // Nothing is a cancelation point while protection is blocked.
    self.flush() catch unreachable;
    if (self.phase == .closed) return;
    self.sendClose(.{ .error_code = code, .application = true });
    self.end(error.ConnectionClosed);
}

/// The failure, once the connection has one.
pub fn alive(self: *const Core) Failure!void {
    if (self.phase == .closed) return self.failure;
}

/// The machine's stream behind a handle, or `error.StreamClosed` when the
/// handle is stale: its slot was released, and may be someone else's now.
pub fn held(self: *Core, index: u16, generation: u32) error{StreamClosed}!*Conn.Stream {
    const slot = &self.storage.slots[index];
    if (slot.generation != generation) return error.StreamClosed;
    // A release bumps the generation, so a handle that still matches is held.
    assert(slot.handle == .held);
    return &self.conn.streams[index];
}

/// A slot a handle now names, and the generation that names it.
pub const Held = struct { index: u16, generation: u32 };

fn hold(self: *Core, index: u16) Held {
    const slot = &self.storage.slots[index];
    assert(slot.handle == .none or slot.handle == .pending);
    slot.handle = .held;
    return .{ .index = index, .generation = slot.generation };
}

/// The next stream the peer opened, lowest ID first, waiting for one.
pub fn acceptStream(self: *Core, io: Io) (Failure || Io.Cancelable)!Held {
    try self.mutex.lock(io);
    defer self.mutex.unlock(io);
    while (true) {
        // A stream that arrived with the close is still the application's.
        if (try self.takePending()) |index| return self.hold(index);
        try self.alive();
        try self.changed.wait(io, &self.mutex);
    }
}

/// Open the next stream of `direction`, waiting for the peer's credit (§4.6).
/// A table with no free slot is `error.StreamLimit`: only a handle's close can
/// free one, so waiting would be waiting on the caller.
pub fn openStream(self: *Core, io: Io, direction: stream_id.Direction) (Failure || Io.Cancelable)!Held {
    try self.mutex.lock(io);
    defer self.mutex.unlock(io);
    const kind: stream_id.Kind = .{ .initiator = self.initiator(), .direction = direction };
    const count = switch (direction) {
        .bidi => &self.opened.bidi,
        .uni => &self.opened.uni,
    };
    while (true) {
        try self.alive();
        const id = kind.at(count.*) catch return error.StreamLimit;
        const entry = self.conn.openStream(id) catch |err| switch (err) {
            error.NoStreamCredit => {
                try self.changed.wait(io, &self.mutex);
                continue;
            },
            else => |e| return e,
        };
        count.* += 1;
        const index = self.indexOf(entry);
        assert(self.storage.slots[index].handle == .none);
        return self.hold(index);
    }
}

/// Give a slot back: the handle goes stale now, and the machine's slot frees
/// once both halves are terminal (`reclaim`).
pub fn release(self: *Core, index: u16) void {
    const slot = &self.storage.slots[index];
    assert(slot.handle == .held);
    slot.handle = .released;
    slot.generation +%= 1;
    self.reclaim(index);
}

/// §3.5: ask the peer to stop sending, if the receive half is still taking
/// bytes. Code 0, the application's to define.
pub fn stopReceiving(self: *Core, index: u16) void {
    const entry = &self.conn.streams[index];
    if (!entry.canRecv()) return;
    if (entry.recv.onStopSending(0) == null) return;
    self.storage.slots[index].owe_stop = true;
}

/// §3.1: abandon the send half with RESET_STREAM, code 0. A half that already
/// ended, or was already reset, owes nothing.
pub fn resetSending(self: *Core, index: u16) void {
    const entry = &self.conn.streams[index];
    if (!entry.canSend()) return;
    entry.send.reset(0) catch return;
    self.storage.slots[index].owe_reset = true;
}

/// §3.1: end the send half with a FIN. Idempotent, and a no-op on a half that
/// was reset or never existed.
pub fn finishSending(self: *Core, index: u16) void {
    const entry = &self.conn.streams[index];
    if (!entry.canSend()) return;
    if (entry.send.final_size != null or entry.send.reset_code != null) return;
    entry.send.finish() catch unreachable;
}

// -- The tasks -------------------------------------------------------------

/// Wait for datagrams from the peer and feed them to the machine.
fn receiveTask(self: *Core) Io.Cancelable!void {
    while (true) {
        // The only wait without the mutex: the sender works meanwhile.
        const message = self.socket.receive(self.io, self.storage.datagram_in) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |e| {
                try self.mutex.lock(self.io);
                defer self.mutex.unlock(self.io);
                return self.fail(e);
            },
        };
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (self.phase == .closed) return;
        // §9: a datagram from another address is the start of a migration this
        // layer cannot validate, so it is dropped rather than followed.
        if (!message.from.eql(&self.peer)) continue;
        self.onDatagram(message.data);
    }
}

/// Send what is owed, fire the timers, and park until either there is more or
/// the next timer is due.
fn sendTask(self: *Core) Io.Cancelable!void {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);
    while (true) {
        try self.flush();
        if (self.phase == .closed) return;
        try self.onTimers();
        if (self.phase == .closed) return;
        self.wake.waitTimeout(self.io, &self.mutex, self.nextTimeout()) catch |err| switch (err) {
            error.Timeout => {},
            error.Canceled => return error.Canceled,
        };
    }
}

// -- Receiving -------------------------------------------------------------

/// Walk one datagram, every packet in it (§12.2), then settle what changed.
fn onDatagram(self: *Core, data: []u8) void {
    const now = self.clock();
    var walk: Conn.Datagram = .init(data);
    while (true) {
        const opened = walk.next(
            &self.conn,
            self.storage.plaintext,
            self.storage.frames,
            self.storage.stream_events,
            &self.events,
            now,
        ) catch |err| return self.fail(err);
        const packet = opened orelse break;
        self.received_at = now;
        self.onPacket(packet, now) catch |err| return self.fail(err);
        if (self.phase == .closed) return;
    }
    self.settle();
}

/// Act on one opened packet: what its ACK cleared and lost, the streams it
/// changed, and the frames the machine handed back.
fn onPacket(self: *Core, opened: Conn.Opened, now: Conn.Duration) Failure!void {
    // The report describes this packet alone; the next `next` clears it.
    try self.onAcked(opened.space, self.events.ackedPackets());
    try self.onLost(opened.space, self.events.lostPackets(), now);
    for (opened.streams) |event| self.onStreamEvent(event);
    for (opened.frames) |value| switch (value) {
        // §10.2.2: the peer closed. The machine is draining and sends nothing.
        .connection_close => return self.fail(error.ConnectionClosed),
        // PING needs only the ACK the sender owes. The rest (NEW_TOKEN,
        // NEW_CONNECTION_ID, PATH_CHALLENGE, and the BLOCKED frames) have no
        // home in this shell yet and are dropped.
        else => {},
    };
}

/// The sent 1-RTT packets an ACK cleared: their stream bytes and resets are
/// acknowledged on the streams (§3.1). A handshake space keeps no records.
fn onAcked(self: *Core, id: Conn.SpaceId, packets: []const Recovery.SentPacket) Failure!void {
    if (id != .app) return;
    for (packets) |packet| {
        const index = self.findRecord(packet.packet_number) orelse continue;
        for (self.entriesOf(index)) |entry| switch (entry) {
            .stream => |written| {
                const stream = self.conn.stream(written.stream_id) orelse continue;
                if (stream.canSend()) try stream.send.onAck(written.offset, written.length);
            },
            .reset_stream => |id_reset| {
                const stream = self.conn.stream(id_reset) orelse continue;
                if (!stream.canSend() or stream.send.state != .reset_sent) continue;
                // Reset Sent is the one state the acknowledgment is legal in.
                stream.send.onResetAcked() catch unreachable;
            },
            .stop_sending, .handshake_done => {},
        };
        self.storage.records[index].len = 0;
    }
}

/// Packets declared lost (§6.1 of RFC 9002): a handshake space replays its
/// CRYPTO bytes, and a 1-RTT packet's frames go out again in a new one.
fn onLost(self: *Core, id: Conn.SpaceId, packets: []const Recovery.SentPacket, now: Conn.Duration) Failure!void {
    if (packets.len == 0) return;
    if (id != .app) return self.replayCrypto(id, now);
    for (packets) |packet| try self.resend(packet.packet_number, now);
}

fn onStreamEvent(self: *Core, event: Conn.StreamEvent) void {
    const entry = self.conn.stream(event.stream_id) orelse return;
    const index = self.indexOf(entry);
    // §3.5: the machine already reset the send half; the frame is ours to send.
    if (event.reset_owed != null) self.storage.slots[index].owe_reset = true;
    self.storage.slots[index].changed.broadcast(self.io);
}

/// After a datagram: find the streams the peer opened, free the ones that
/// ended, note the handshake, and wake everyone who might care.
fn settle(self: *Core) void {
    for (self.storage.slots, 0..) |*slot, index| {
        if (slot.handle != .none) continue;
        const entry = &self.conn.streams[index];
        if (!entry.isOpen()) continue;
        if (stream_id.isLocal(idOf(entry), self.initiator())) continue;
        slot.handle = .pending;
    }
    for (0..self.storage.slots.len) |index| self.reclaim(@intCast(index));
    if (self.phase == .handshaking and self.established()) self.phase = .established;
    self.changed.broadcast(self.io);
    self.wake.signal(self.io);
}

/// Whether the handshake is far enough along for the application.
///
/// A server is done when it is confirmed (§4.1.2 of RFC 9001). A client is
/// confirmed only by HANDSHAKE_DONE, half a round trip later, and needs only
/// the 1-RTT keys and the server's limits to open a stream; its Finished goes
/// out first because the sender drains handshake bytes before stream data.
fn established(self: *Core) bool {
    return switch (self.conn.role) {
        .server => self.conn.handshakeConfirmed(),
        .client => self.conn.app != null and self.conn.peer != null,
    };
}

/// Free a released slot once both halves are terminal (§3.1, §3.2). Bytes the
/// application will never read are drained here, and a peer's reset consumed,
/// because nobody else is left to do it.
fn reclaim(self: *Core, index: u16) void {
    const slot = &self.storage.slots[index];
    if (slot.handle != .released) return;
    const entry = &self.conn.streams[index];
    if (entry.canRecv()) drain(&entry.recv);
    self.conn.closeStream(idOf(entry)) catch return;
    slot.* = .{ .generation = slot.generation };
}

fn drain(recv: *quic.ReceiveStream) void {
    if (recv.state == .reset_recvd) {
        _ = recv.readReset() catch unreachable;
        return;
    }
    if (recv.state != .data_recvd) return;
    var sink: [256]u8 = undefined;
    while (recv.readable() > 0) _ = recv.readInto(&sink) catch unreachable;
    // An empty read settles a stream whose last byte was already read.
    _ = recv.readInto(sink[0..0]) catch unreachable;
}

/// The lowest-numbered stream waiting for `acceptStream`, now held. A
/// bidirectional one gets its send half here, so the handle can answer.
fn takePending(self: *Core) Failure!?u16 {
    var best: ?usize = null;
    for (self.storage.slots, 0..) |slot, index| {
        if (slot.handle != .pending) continue;
        if (best) |other| {
            if (idOf(&self.conn.streams[other]) < idOf(&self.conn.streams[index])) continue;
        }
        best = index;
    }
    const index = best orelse return null;
    const entry = &self.conn.streams[index];
    const id = idOf(entry);
    if (stream_id.direction(id) == .bidi and !entry.canSend()) _ = try self.conn.joinStream(id);
    return @intCast(index);
}

// -- Sending ---------------------------------------------------------------

/// Send everything owed, failing the connection on anything but cancelation.
fn flush(self: *Core) Io.Cancelable!void {
    self.flushOwed() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => |e| self.fail(e),
    };
}

/// Handshake bytes, HANDSHAKE_DONE, the stream control frames, window
/// updates, stream data, then ACKs.
fn flushOwed(self: *Core) Failure!void {
    const now = self.clock();
    while (try self.conn.writeHandshake(self.storage.scratch, self.storage.datagram_out, now)) |length| {
        try self.transmit(length);
    }
    try self.sendConfirmation(now);
    if (self.conn.app != null) {
        try self.sendControl(now);
        try self.sendFlowControl(now);
        try self.sendStreams(now);
    }
    var owed: [3]Conn.SpaceId = undefined;
    for (self.conn.acksOwed(&owed)) |id| {
        const length = try self.conn.writeAck(id, self.storage.datagram_out, now);
        if (length == 0) continue;
        try self.transmit(length);
    }
}

/// A server's HANDSHAKE_DONE, recorded so a lost one goes out again (§13.3),
/// which `Conn.writeConfirmation` cannot do on its own.
fn sendConfirmation(self: *Core, now: Conn.Duration) Failure!void {
    if (!self.appHasRoom()) return;
    const number = self.conn.app.?.next_packet_number;
    const length = (try self.conn.writeConfirmation(self.storage.datagram_out, now)) orelse return;
    self.claimRecord(number, 1)[0] = .handshake_done;
    try self.transmit(length);
}

/// The RESET_STREAM and STOP_SENDING frames owed, one per packet.
fn sendControl(self: *Core, now: Conn.Duration) Failure!void {
    for (self.storage.slots, self.conn.streams) |*slot, *entry| {
        if (!entry.isOpen()) continue;
        if (slot.owe_reset) {
            if (!self.appHasRoom()) return;
            slot.owe_reset = false;
            try self.sendOwed(.{ .reset_stream = idOf(entry) }, now);
        }
        if (slot.owe_stop) {
            if (!self.appHasRoom()) return;
            slot.owe_stop = false;
            try self.sendOwed(.{ .stop_sending = idOf(entry) }, now);
        }
    }
}

/// One owed frame in its own packet, unless the stream moved past needing it.
fn sendOwed(self: *Core, owed: Entry, now: Conn.Duration) Failure!void {
    var writer: quic.Writer = .init(self.storage.scratch);
    if (try self.rewrite(&writer, owed)) try self.sendApp(writer.written(), owed, now);
}

/// §4.2: the window updates the application's reads made due. They are not
/// recorded: `Conn` recomputes what is owed, so a lost one is owed again.
fn sendFlowControl(self: *Core, now: Conn.Duration) Failure!void {
    if (!self.appHasRoom()) return;
    const owed = self.conn.flowControlOwed(self.storage.control);
    if (owed.len == 0) return;
    var writer: quic.Writer = .init(self.storage.scratch);
    for (owed) |value| try frame.write(&writer, value);
    try self.sendApp(writer.written(), null, now);
    self.conn.onFlowControlSent(owed);
}

/// Every stream with bytes or a FIN to send, packed by the machine until
/// nothing is left that the peer's credit allows (§4.1).
fn sendStreams(self: *Core, now: Conn.Duration) Failure!void {
    const out = self.storage.datagram_out;
    while (self.appHasRoom()) {
        var count: usize = 0;
        for (self.conn.streams) |*entry| {
            if (!entry.canSend()) continue;
            if (entry.send.peekSegment(@intCast(out.len)) == null) continue;
            self.storage.offers[count] = .{ .stream_id = idOf(entry), .length = @intCast(out.len) };
            count += 1;
        }
        if (count == 0) return;
        const number = self.conn.app.?.next_packet_number;
        const packet = (try self.conn.writeStreams(.{
            .offers = self.storage.offers[0..count],
            .frames = self.storage.scratch,
            .out = out,
            .written = self.storage.written,
            .max_payload = @intCast(out.len),
            .now = now,
        })) orelse return;
        for (self.claimRecord(number, packet.frames.len), packet.frames) |*entry, written| {
            entry.* = .{ .stream = written };
        }
        try self.transmit(packet.length);
    }
}

/// Seal `payload` in a 1-RTT packet, record `entry` against its number, and
/// send it. The caller checked `appHasRoom`.
fn sendApp(self: *Core, payload: []const u8, entry: ?Entry, now: Conn.Duration) Failure!void {
    const number = self.conn.app.?.next_packet_number;
    const length = try self.conn.writeFrames(.app, payload, self.storage.datagram_out, .data(now));
    if (entry) |value| self.claimRecord(number, 1)[0] = value;
    try self.transmit(length);
}

/// Put one sealed packet on the wire.
///
/// A socket that refuses a datagram is not retried and not fatal: the packet is
/// already recorded in flight (§6 of RFC 9002), so loss recovery sends what it
/// carried again, and an endpoint that can never send times out idle.
fn transmit(self: *Core, length: u32) Io.Cancelable!void {
    self.socket.send(self.io, &self.peer, self.storage.datagram_out[0..length]) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {},
    };
}

// -- Timers and loss -------------------------------------------------------

/// §10.1's idle timer, then the loss and probe timers of RFC 9002 §6.
fn onTimers(self: *Core) Io.Cancelable!void {
    const now = self.clock();
    if (self.idleDeadline()) |deadline| {
        if (now >= deadline) return self.fail(error.IdleTimeout);
    }
    self.pollRecovery(now) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => |e| self.fail(e),
    };
}

fn pollRecovery(self: *Core, now: Conn.Duration) Failure!void {
    const side: Recovery.Side = switch (self.conn.role) {
        .client => .client,
        .server => .server,
    };
    const options = self.conn.recoveryOptions();
    const fired = (try self.recovery.poll(now, options, side, &self.events)) orelse return;
    // `recovery_spaces` is in `SpaceId` order, as `Conn.Loss.spaces` is.
    const id: Conn.SpaceId = @fromBackingInt(@intCast(fired.space));
    switch (fired.kind) {
        .loss => try self.onLost(id, self.events.lostPackets(), now),
        .probe => try self.probe(id, fired.probes, now),
    }
}

/// §6.2.4 of RFC 9002: one or two ack-eliciting packets. In a handshake space
/// the CRYPTO bytes the peer may be missing are the most useful thing to send;
/// otherwise a PING.
fn probe(self: *Core, id: Conn.SpaceId, count: u8, now: Conn.Duration) Failure!void {
    if (id != .app and self.conn.replayCrypto(id).len > 0) return self.replayCrypto(id, now);
    var sent: u8 = 0;
    while (sent < @max(count, 1)) : (sent += 1) {
        if (!self.spaceHasRoom(id)) return;
        var writer: quic.Writer = .init(self.storage.scratch);
        try frame.write(&writer, .ping);
        const length = try self.conn.writeFrames(id, self.padded(id, &writer), self.storage.datagram_out, .data(now));
        try self.transmit(length);
    }
}

/// §13.3: re-send a handshake space's CRYPTO bytes at their own offsets, in
/// chunks that fit a datagram. The peer drops what it already has (§19.6).
fn replayCrypto(self: *Core, id: Conn.SpaceId, now: Conn.Duration) Failure!void {
    const bytes = self.conn.replayCrypto(id);
    const chunk = self.storage.datagram_out.len - crypto_overhead;
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += chunk) {
        if (!self.spaceHasRoom(id)) return;
        var writer: quic.Writer = .init(self.storage.scratch);
        try frame.write(&writer, .{ .crypto = .{
            .offset = offset,
            .data = bytes[offset..][0..@min(chunk, bytes.len - offset)],
        } });
        const length = try self.conn.writeFrames(id, self.padded(id, &writer), self.storage.datagram_out, .data(now));
        try self.transmit(length);
    }
}

/// §14.1: an Initial payload grown with PADDING so its datagram reaches 1200.
fn padded(self: *Core, id: Conn.SpaceId, writer: *const quic.Writer) []const u8 {
    if (id != .initial or writer.pos >= initial_payload_floor) return writer.written();
    @memset(self.storage.scratch[writer.pos..initial_payload_floor], 0);
    return self.storage.scratch[0..initial_payload_floor];
}

/// Send a lost 1-RTT packet's frames again, together in one new packet, under
/// the same record. The frames still worth sending fit, because they fit the
/// packet that was lost.
fn resend(self: *Core, number: u64, now: Conn.Duration) Failure!void {
    const index = self.findRecord(number) orelse return;
    const entries = self.entriesOf(index);
    var writer: quic.Writer = .init(self.storage.scratch);
    var kept: u16 = 0;
    for (entries) |entry| {
        if (!try self.rewrite(&writer, entry)) continue;
        entries[kept] = entry;
        kept += 1;
    }
    self.storage.records[index].len = 0;
    if (kept == 0) return;
    // The lost packet left the sent table and its record is free again.
    assert(self.appHasRoom());
    const fresh = self.conn.app.?.next_packet_number;
    const length = try self.conn.writeFrames(.app, writer.written(), self.storage.datagram_out, .data(now));
    self.storage.records[index] = .{ .packet_number = fresh, .len = kept };
    try self.transmit(length);
}

/// Write `entry` again if it still means something, and say whether it did.
fn rewrite(self: *Core, writer: *quic.Writer, entry: Entry) Failure!bool {
    switch (entry) {
        .stream => |written| {
            const stream = self.conn.stream(written.stream_id) orelse return false;
            if (!stream.canSend() or stream.send.reset_code != null) return false;
            if (written.offset + written.length <= stream.send.acked and !written.fin) return false;
            try frame.write(writer, .{ .stream = .{
                .id = written.stream_id,
                .offset = written.offset,
                .data = try stream.send.data(written.offset, written.length),
                .fin = written.fin,
                .length_present = true,
            } });
            return true;
        },
        .reset_stream => |id| return writeReset(writer, self.conn.stream(id) orelse return false),
        .stop_sending => |id| return writeStop(writer, self.conn.stream(id) orelse return false),
        .handshake_done => {
            try frame.write(writer, .handshake_done);
            return true;
        },
    }
}

/// §19.4: RESET_STREAM, while the send half is in Reset Sent. The final size is
/// what was sent, which is the credit the stream used (§4.5).
fn writeReset(writer: *quic.Writer, entry: *Conn.Stream) Failure!bool {
    if (!entry.canSend() or entry.send.state != .reset_sent) return false;
    try frame.write(writer, .{ .reset_stream = .{
        .stream_id = entry.send.id,
        .error_code = entry.send.reset_code.?,
        .final_size = entry.send.sent,
    } });
    return true;
}

/// §19.5: STOP_SENDING, while the receive half could still be sent bytes.
fn writeStop(writer: *quic.Writer, entry: *Conn.Stream) Failure!bool {
    if (!entry.canRecv()) return false;
    const code = entry.recv.stop_sending_code orelse return false;
    switch (entry.recv.state) {
        .recv, .size_known => {},
        .data_recvd, .data_read, .reset_recvd, .reset_read => return false,
    }
    try frame.write(writer, .{ .stop_sending = .{ .stream_id = entry.recv.id, .error_code = code } });
    return true;
}

// -- Ending ----------------------------------------------------------------

/// End the connection over `err`, telling the peer why when there is a peer
/// left to tell.
fn fail(self: *Core, err: Failure) void {
    if (self.phase == .closed) return;
    switch (err) {
        // §10.2.2 and §10.1: a draining or idle connection sends nothing.
        error.ConnectionClosed, error.IdleTimeout => {},
        else => self.sendClose(.{ .error_code = self.transportCode(err) }),
    }
    self.end(err);
}

/// Seal and send one CONNECTION_CLOSE, best effort: the connection is over
/// whether or not it leaves.
fn sendClose(self: *Core, args: Conn.Close) void {
    const out = self.storage.datagram_out;
    const length = self.conn.close(args, self.storage.scratch, out, self.clock()) catch return;
    self.socket.send(self.io, &self.peer, out[0..length]) catch |err| switch (err) {
        // Not swallowed: the task's next cancelation point sees it again.
        error.Canceled => self.io.recancel(),
        else => {},
    };
}

/// Record the failure and wake every waiter, so each one returns it.
fn end(self: *Core, err: Failure) void {
    assert(self.phase != .closed);
    self.failure = err;
    self.phase = .closed;
    self.changed.broadcast(self.io);
    self.wake.signal(self.io);
    for (self.storage.slots) |*slot| slot.changed.broadcast(self.io);
}

/// §20.1: the transport error code a failure closes the connection with.
fn transportCode(self: *Core, err: Failure) u64 {
    const code: error_code.Transport = switch (err) {
        error.HandshakeFailed => return if (self.conn.tls) |tls| tls.errorCode() else 0x01,
        error.FlowControl => .flow_control_error,
        error.StreamLimit => .stream_limit_error,
        error.StreamState => .stream_state_error,
        error.FinalSize => .final_size_error,
        error.TransportParameter => .transport_parameter_error,
        error.ProtocolViolation, error.WrongFrameSpace, error.NonMinimalFrameType => .protocol_violation,
        error.UnknownFrameType,
        error.InvalidFrameType,
        error.InvalidAckRange,
        error.InvalidRetirePriorTo,
        error.EmptyToken,
        error.StreamCountTooLarge,
        => .frame_encoding_error,
        else => .internal_error,
    };
    return code.toInt();
}

// -- Bookkeeping -----------------------------------------------------------

/// Nanoseconds since `init`, the clock the machine is handed.
fn clock(self: *const Core) Conn.Duration {
    const elapsed = self.origin.durationTo(Io.Timestamp.now(self.io, .awake));
    return @intCast(@max(elapsed.nanoseconds, 0));
}

/// §10.1: the effective idle timeout is the smaller of the two endpoints'
/// nonzero ones, counted from the last packet that opened.
fn idleDeadline(self: *const Core) ?Conn.Duration {
    var timeout = self.idle_timeout;
    if (self.conn.peer) |peer| {
        if (peer.max_idle_timeout != 0) {
            timeout = if (timeout == 0) peer.max_idle_timeout else @min(timeout, peer.max_idle_timeout);
        }
    }
    if (timeout == 0) return null;
    return self.received_at +| timeout;
}

/// When the sender must wake on its own: the idle timer or the recovery
/// deadline, whichever is first.
fn nextTimeout(self: *Core) Io.Timeout {
    var at = self.idleDeadline();
    const due = self.recovery.deadline(self.conn.recoveryOptions());
    if (due.kind != .none) at = if (at) |idle| @min(idle, due.at) else due.at;
    const deadline = at orelse return .none;
    return .{ .deadline = .{
        .raw = self.origin.addDuration(.fromNanoseconds(@intCast(deadline))),
        .clock = .awake,
    } };
}

/// Room for one more tracked 1-RTT packet and its record.
fn appHasRoom(self: *Core) bool {
    return self.spaceHasRoom(.app);
}

/// Room for one more tracked packet in `id`'s space: keys, a sent-table slot,
/// and for 1-RTT a free record.
fn spaceHasRoom(self: *Core, id: Conn.SpaceId) bool {
    const space = self.conn.spaceFor(id) catch return false;
    if (!space.recovery.hasRoom()) return false;
    if (id != .app) return true;
    for (self.storage.records) |record| {
        if (record.len == 0) return true;
    }
    return false;
}

/// Claim a free record for packet `number` and return its `count` entries to
/// fill. Every tracked 1-RTT packet holds a sent-table slot, the table and the
/// records are the same length, and `appHasRoom` checked both.
fn claimRecord(self: *Core, number: u64, count: usize) []Entry {
    assert(count > 0);
    for (self.storage.records, 0..) |*slot, index| {
        if (slot.len != 0) continue;
        slot.* = .{ .packet_number = number, .len = @intCast(count) };
        return self.entriesOf(index);
    }
    unreachable;
}

fn findRecord(self: *const Core, number: u64) ?usize {
    for (self.storage.records, 0..) |slot, index| {
        if (slot.len != 0 and slot.packet_number == number) return index;
    }
    return null;
}

/// The entries a record holds, as many as it says.
fn entriesOf(self: *const Core, index: usize) []Entry {
    const per_record = self.storage.entries.len / self.storage.records.len;
    const record_len = self.storage.records[index].len;
    assert(record_len <= per_record);
    return self.storage.entries[index * per_record ..][0..record_len];
}

fn indexOf(self: *const Core, entry: *const Conn.Stream) u16 {
    const offset = @intFromPtr(entry) - @intFromPtr(self.conn.streams.ptr);
    const index = offset / @sizeOf(Conn.Stream);
    assert(index < self.conn.streams.len);
    return @intCast(index);
}

fn initiator(self: *const Core) stream_id.Initiator {
    return switch (self.conn.role) {
        .client => .client,
        .server => .server,
    };
}

/// The ID of an open stream, from whichever half it has.
fn idOf(entry: *const Conn.Stream) u64 {
    assert(entry.isOpen());
    return if (entry.canRecv()) entry.recv.id else entry.send.id;
}
