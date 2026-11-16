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

/// One frame this shell composed itself in a 1-RTT packet, which it has to send
/// again if the packet is lost (§13.3). Only RESET_STREAM and STOP_SENDING: the
/// machine records and resends the STREAM ranges, HANDSHAKE_DONE, and the flow
/// control frames it writes, ACKs are never retransmitted, and PING and PADDING
/// carry nothing to repair.
pub const Entry = union(enum) {
    reset_stream: u64,
    stop_sending: u64,
};

/// The owed frame one sent 1-RTT packet carried, by packet number. Each goes
/// in a packet of its own, so a record holds one; `entry` null is free.
pub const Record = struct {
    packet_number: u64 = 0,
    entry: ?Entry = null,
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

/// Fire the timers, send what is owed, and park until either there is more or
/// the next timer is due.
fn sendTask(self: *Core) Io.Cancelable!void {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);
    while (try self.turn()) |due| {
        self.wake.waitTimeout(self.io, &self.mutex, due) catch |err| switch (err) {
            error.Timeout => {},
            error.Canceled => return error.Canceled,
        };
    }
}

/// One pass of the sender: the timers that are due, then everything owed. Null
/// once the connection is closed, and otherwise when to wake next.
///
/// Timers first, because a timer makes work owed: a loss timer marks STREAM
/// ranges, a HANDSHAKE_DONE, and the MAX_* frames owed again (§13.3), and only
/// a flush sends them. The other way round, that work waits for an unrelated
/// wake, and with nothing else in flight there is no probe timer to give one
/// (RFC 9002 A.8): the connection sits until its idle timeout.
fn turn(self: *Core) Io.Cancelable!?Io.Timeout {
    try self.onTimers();
    if (self.phase == .closed) return null;
    try self.flush();
    if (self.phase == .closed) return null;
    return self.nextTimeout();
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

/// The sent 1-RTT packets an ACK cleared: a reset they carried is acknowledged
/// on its stream (§3.1). The machine already acknowledged the stream bytes, and
/// a handshake space keeps no records.
fn onAcked(self: *Core, id: Conn.SpaceId, packets: []const Recovery.SentPacket) Failure!void {
    if (id != .app) return;
    for (packets) |packet| {
        const index = self.findRecord(packet.packet_number) orelse continue;
        switch (self.storage.records[index].entry.?) {
            .reset_stream => |id_reset| reset: {
                const stream = self.conn.stream(id_reset) orelse break :reset;
                if (!stream.canSend() or stream.send.state != .reset_sent) break :reset;
                // Reset Sent is the one state the acknowledgment is legal in.
                stream.send.onResetAcked() catch unreachable;
            },
            .stop_sending => {},
        }
        self.storage.records[index] = .{};
    }
}

/// Packets declared lost (§6.1 of RFC 9002): a handshake space replays its
/// CRYPTO bytes, and a 1-RTT packet's owed frame goes out again in a new one.
/// The machine has already marked what it wrote as owed again.
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

/// A server's HANDSHAKE_DONE. The machine says it is owed again when the
/// packet carrying it is lost (§13.3).
fn sendConfirmation(self: *Core, now: Conn.Duration) Failure!void {
    if (!self.sentHasRoom(.app)) return;
    const length = (try self.conn.writeConfirmation(self.storage.datagram_out, now)) orelse return;
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

/// §4.2: the window updates the application's reads made due, and the ones
/// whose newest copy was lost (§13.3). The machine keeps both.
fn sendFlowControl(self: *Core, now: Conn.Duration) Failure!void {
    if (!self.sentHasRoom(.app)) return;
    const out = self.storage.datagram_out;
    const length = (try self.conn.writeFlowControl(self.storage.control, self.storage.scratch, out, now)) orelse return;
    try self.transmit(length);
}

/// Every stream with bytes or a FIN to send, lost ranges first, packed by the
/// machine until nothing is left that the peer's credit allows (§4.1, §13.3).
fn sendStreams(self: *Core, now: Conn.Duration) Failure!void {
    const out = self.storage.datagram_out;
    while (self.sentHasRoom(.app)) {
        var count: usize = 0;
        for (self.conn.streams) |*entry| {
            if (!entry.canSend()) continue;
            if (entry.send.peekSegment(@intCast(out.len)) == null) continue;
            self.storage.offers[count] = .{ .stream_id = idOf(entry), .length = @intCast(out.len) };
            count += 1;
        }
        if (count == 0) return;
        const packet = (try self.conn.writeStreams(.{
            .offers = self.storage.offers[0..count],
            .frames = self.storage.scratch,
            .out = out,
            .written = self.storage.written,
            .max_payload = @intCast(out.len),
            .now = now,
        })) orelse return;
        try self.transmit(packet.length);
    }
}

/// Seal `payload` in a 1-RTT packet, record `entry` against its number, and
/// send it. The caller checked `appHasRoom`.
fn sendApp(self: *Core, payload: []const u8, entry: Entry, now: Conn.Duration) Failure!void {
    const number = self.conn.app.?.next_packet_number;
    const length = try self.conn.writeFrames(.app, payload, self.storage.datagram_out, .data(now));
    self.claimRecord(number, entry);
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
        .loss => {
            // A timer's losses are the caller's to hand over: the machine saw
            // the ones an acknowledgment declared, not these (§13.3).
            self.conn.onPacketsLost(id, self.events.lostPackets());
            try self.onLost(id, self.events.lostPackets(), now);
        },
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
        if (!self.sentHasRoom(id)) return;
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
        if (!self.sentHasRoom(id)) return;
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

/// Send a lost 1-RTT packet's owed frame again, in one new packet, under the
/// same record, if it still means something.
fn resend(self: *Core, number: u64, now: Conn.Duration) Failure!void {
    const index = self.findRecord(number) orelse return;
    const entry = self.storage.records[index].entry.?;
    self.storage.records[index] = .{};
    var writer: quic.Writer = .init(self.storage.scratch);
    if (!try self.rewrite(&writer, entry)) return;
    // The lost packet left the sent table and its record is free again.
    assert(self.appHasRoom());
    const fresh = self.conn.app.?.next_packet_number;
    const length = try self.conn.writeFrames(.app, writer.written(), self.storage.datagram_out, .data(now));
    self.storage.records[index] = .{ .packet_number = fresh, .entry = entry };
    try self.transmit(length);
}

/// Write `entry` again if it still means something, and say whether it did.
fn rewrite(self: *Core, writer: *quic.Writer, entry: Entry) Failure!bool {
    switch (entry) {
        .reset_stream => |id| return writeReset(writer, self.conn.stream(id) orelse return false),
        .stop_sending => |id| return writeStop(writer, self.conn.stream(id) orelse return false),
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

/// Room for one more tracked 1-RTT packet carrying an owed frame: a sent-table
/// slot and a free record of this shell's.
fn appHasRoom(self: *Core) bool {
    if (!self.sentHasRoom(.app)) return false;
    for (self.storage.records) |record| {
        if (record.entry == null) return true;
    }
    return false;
}

/// Room for one more tracked packet in `id`'s space: keys and a sent-table
/// slot. What the machine writes it records itself, in a table as long.
fn sentHasRoom(self: *Core, id: Conn.SpaceId) bool {
    const space = self.conn.spaceFor(id) catch return false;
    return space.recovery.hasRoom();
}

/// Record `entry` against packet `number`. Every tracked 1-RTT packet holds a
/// sent-table slot, the table and the records are the same length, and
/// `appHasRoom` checked both.
fn claimRecord(self: *Core, number: u64, entry: Entry) void {
    for (self.storage.records) |*slot| {
        if (slot.entry != null) continue;
        slot.* = .{ .packet_number = number, .entry = entry };
        return;
    }
    unreachable;
}

fn findRecord(self: *const Core, number: u64) ?usize {
    for (self.storage.records, 0..) |slot, index| {
        if (slot.entry != null and slot.packet_number == number) return index;
    }
    return null;
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

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const TransportParameters = quic.TransportParameters;

/// A client core with 1-RTT keys from a stub driver, no tasks, and a socket
/// whose peer is `observer`, beside a server machine with the same keys that
/// the test feeds by hand. Built in place: the machines pin their addresses.
const LossFixture = struct {
    threaded: Io.Threaded = undefined,
    observer: Io.net.Socket = undefined,
    core: Core = undefined,
    server: Conn = undefined,
    client_stub: quic.handshake.Stub = undefined,
    server_stub: quic.handshake.Stub = undefined,
    client_loss: Recovery = .{},
    server_loss: Recovery = .{},
    spaces: [2][3]Recovery.Space = undefined,
    sent: [2][3][8]Recovery.SentPacket = undefined,
    sent_streams: [2][8]Conn.SentStreams = @splat(@splat(.{})),
    acked: [8]Recovery.SentPacket = undefined,
    lost: [8]Recovery.SentPacket = undefined,
    send_buffer: [64]u8 = undefined,
    recv_buffer: [64]u8 = undefined,
    stream_slots: [1]quic.StreamTable.Slot = undefined,
    streams: [1]Conn.Stream = undefined,
    datagram_in: [1500]u8 = undefined,
    datagram_out: [1500]u8 = undefined,
    plaintext: [1500]u8 = undefined,
    scratch: [1500]u8 = undefined,
    frames: [16]frame.Frame = undefined,
    stream_events: [1]Conn.StreamEvent = undefined,
    control: [4]frame.Frame = undefined,
    offers: [1]Conn.Offer = undefined,
    written: [Conn.stream_frames_per_packet]Conn.Written = undefined,
    slots: [1]Slot = undefined,
    records: [8]Record = undefined,
    parameter_bytes: [3][64]u8 = undefined,

    const client_id = [_]u8{0xc1};
    const server_id = [_]u8{0x5e};
    const secrets: [4][32]u8 = .{ @splat(0x11), @splat(0x22), @splat(0x33), @splat(0x44) };

    fn loss(self: *LossFixture, side: usize, shared: *Recovery) Conn.Loss {
        return .{
            .shared = shared,
            .spaces = &self.spaces[side],
            .sent_initial = &self.sent[side][0],
            .sent_handshake = &self.sent[side][1],
            .sent_app = &self.sent[side][2],
            .sent_streams = &self.sent_streams[side],
        };
    }

    fn storage(self: *LossFixture) Storage {
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
        };
    }

    fn encode(
        self: *LossFixture,
        index: usize,
        sender: TransportParameters.Role,
        parameters: TransportParameters,
    ) []const u8 {
        var writer: quic.Writer = .init(&self.parameter_bytes[index]);
        TransportParameters.encode(&writer, parameters, sender) catch unreachable;
        return writer.written();
    }

    fn init(self: *LossFixture) !void {
        self.threaded = .init(testing.allocator, .{});
        errdefer self.threaded.deinit();
        const io = self.threaded.io();
        const any: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        self.observer = try any.bind(io, .{ .mode = .dgram });
        errdefer self.observer.close(io);
        const socket = try any.bind(io, .{ .mode = .dgram });
        errdefer socket.close(io);

        // Each stub stands in for TLS: the same secrets on both ends, and the
        // other end's transport parameters. The server grants one stream.
        const client_parameters = self.encode(0, .client, .{ .initial_source_connection_id = &client_id });
        const both: quic.handshake.Secrets = .{ .client = &secrets[0], .server = &secrets[1] };
        const app: quic.handshake.Secrets = .{ .client = &secrets[2], .server = &secrets[3] };
        const server_parameters = self.encode(1, .server, .{
            .original_destination_connection_id = &server_id,
            .initial_source_connection_id = &server_id,
            .initial_max_data = 64,
            .initial_max_stream_data_bidi_remote = 64,
            .initial_max_streams_bidi = 1,
        });
        self.client_stub = .{ .handshake_secrets = both, .app_secrets = app, .peer_parameters = server_parameters };
        self.server_stub = .{ .handshake_secrets = both, .app_secrets = app, .peer_parameters = client_parameters };

        self.streams = .{.{ .send_buffer = &self.send_buffer, .recv_buffer = &self.recv_buffer }};
        self.core.init(.{
            .io = io,
            .socket = socket,
            .peer = self.observer.address,
            .storage = self.storage(),
            .events = .init(&self.acked, &self.lost),
            .loss = self.loss(0, &self.client_loss),
            .idle_timeout_ms = 0,
        });
        var config = Conn.clientConfig(&server_id, &client_id, self.loss(0, &self.client_loss));
        config.tls = self.client_stub.driver();
        config.transport_parameters = client_parameters;
        config.stream_slots = &self.stream_slots;
        config.streams = &self.streams;
        self.core.conn = .init(config);
        try self.core.conn.installSpaces();
        self.core.phase = .established;

        self.server = .init(.{
            .role = .server,
            .loss = self.loss(1, &self.server_loss),
            .original_destination_connection_id = &server_id,
            .destination_connection_id = &client_id,
            .source_connection_id = &server_id,
            .tls = self.server_stub.driver(),
            .transport_parameters = self.encode(2, .server, .{
                .original_destination_connection_id = &server_id,
                .initial_source_connection_id = &server_id,
            }),
        });
        try self.server.installSpaces();
    }

    fn deinit(self: *LossFixture) void {
        const io = self.threaded.io();
        self.core.socket.close(io);
        self.observer.close(io);
        self.threaded.deinit();
        self.* = undefined;
    }

    /// Hand the server a datagram, and the core what the server acknowledges.
    fn acknowledge(self: *LossFixture, datagram: []u8) !void {
        var plaintext: [1500]u8 = undefined;
        var frames: [4]frame.Frame = undefined;
        var events: [1]Conn.StreamEvent = undefined;
        var acked: [8]Recovery.SentPacket = undefined;
        var lost: [8]Recovery.SentPacket = undefined;
        var report: Recovery.Events = .init(&acked, &lost);
        _ = try self.server.feed(datagram, &plaintext, &frames, &events, &report, 0);
        var ack: [64]u8 = undefined;
        const length = try self.server.writeAck(.app, &ack, 0);
        self.core.onDatagram(ack[0..length]);
    }
};

/// File scope: the fixture holds two machines, which must not move.
var loss_fixture: LossFixture = .{};

test "RFC 9002 §6.1.2, a loss timer's STREAM data leaves in the same turn, with nothing else in flight" {
    const f = &loss_fixture;
    f.* = .{};
    try f.init();
    defer f.deinit();
    const io = f.threaded.io();

    // The stream's bytes leave in packet 0, and the network drops them.
    const entry = try f.core.conn.openStream(0);
    try entry.send.write("lost");
    _ = try f.core.turn();
    var dropped: [1500]u8 = undefined;
    _ = try f.observer.receiveTimeout(io, &dropped, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });

    // Packet 1, a PING, arrives and is acknowledged. Packet 0 is short of the
    // packet threshold, so only the loss timer declares it lost, once the time
    // threshold passes; and then nothing is left in flight to arm a probe.
    var ping: [64]u8 = undefined;
    const length = try f.core.conn.writeFrames(.app, &.{0x01}, &ping, .data(f.core.clock()));
    try f.acknowledge(ping[0..length]);
    const due = f.core.recovery.deadline(f.core.conn.recoveryOptions());
    try testing.expectEqual(Recovery.TimerKind.loss, due.kind);
    try io.sleep(.fromNanoseconds(@intCast(due.at -| f.core.clock() + 1)), .awake);

    // One turn of the sender fires the timer, and the bytes go again before it
    // parks: not at the next wake, which here would never come. They are no
    // longer owed, and one packet in flight carries them.
    _ = try f.core.turn();
    try testing.expectEqual(@as(usize, 0), entry.send.lost_len);
    var carrying: usize = 0;
    for (&f.sent_streams[0]) |*record| carrying += record.written().len;
    try testing.expectEqual(@as(usize, 1), carrying);
}
