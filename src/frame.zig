//! QUIC frames, RFC 9000 §19.
//!
//! A packet payload is a sequence of frames, each starting with a variable
//! length frame type. `read` takes one frame off a cursor and borrows every
//! byte it returns; `write` puts one back. The frame type must use the shortest
//! encoding (§12.4), so the reader rejects a padded one.
//!
//! Read and write share one union because the shapes agree: a STREAM frame's
//! data is a borrowed slice either way. The ACK ranges are the one place where
//! the wire is already the natural form, so they stay encoded bytes and
//! `Ack.ranges` walks them.

const std = @import("std");
const testing = std.testing;
const Cursor = @import("Cursor.zig");
const Writer = @import("Writer.zig");
const varint = @import("varint.zig");

const frame = @This();

pub const Error = error{
    /// The payload ended inside a frame.
    Truncated,
    /// §12.4: a frame of unknown type is a connection error.
    UnknownFrameType,
    /// §12.4: the frame type did not use the shortest encoding.
    NonMinimalFrameType,
    /// §19.3.1: an ACK range would place a packet number below zero.
    InvalidAckRange,
    /// §19.15: a connection ID shorter than 1 or longer than 20 bytes.
    InvalidConnectionId,
    /// §19.15: Retire Prior To greater than the sequence number.
    InvalidRetirePriorTo,
    /// §19.7: a NEW_TOKEN frame with no token.
    EmptyToken,
    /// The writer was handed a frame that cannot be put on the wire.
    InvalidFrameType,
    /// The caller's buffer has no room for the frame.
    NoSpace,
};

/// The half of a stream frame's flags that says which way the stream runs.
pub const Direction = enum {
    bidi,
    uni,
};

/// §19.3.2, the ECN counts of an ACK frame of type 0x03.
pub const Ecn = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// One Gap and ACK Range Length pair (§19.3.1).
pub const AckRange = struct {
    gap: u64,
    length: u64,
};

/// The ACK ranges of one ACK frame, walked in wire order.
pub const AckRanges = struct {
    cursor: Cursor,
    remaining: u64,

    /// The next pair, or null when `range_count` pairs have been read.
    pub fn next(self: *AckRanges) Error!?AckRange {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        const gap = try readVarint(&self.cursor);
        const length = try readVarint(&self.cursor);
        return .{ .gap = gap, .length = length };
    }
};

/// §19.3. `largest`, `delay`, and `first_range` are not truncated anywhere:
/// the wire carries the whole packet number.
pub const Ack = struct {
    largest: u64,
    /// Microseconds, before the `ack_delay_exponent` scaling of §18.2.
    delay: u64,
    /// How many packets below `largest` are acknowledged contiguously.
    first_range: u64,
    /// How many Gap and ACK Range Length pairs `bytes` holds.
    range_count: u64,
    /// Those pairs, already encoded. Reading borrows them from the payload;
    /// writing emits them as given.
    bytes: []const u8,
    /// The ECN counts, present only in a frame of type 0x03.
    ecn: ?Ecn,

    pub fn ranges(self: *const Ack) AckRanges {
        return .{ .cursor = .init(self.bytes), .remaining = self.range_count };
    }
};

/// §19.4.
pub const ResetStream = struct {
    stream_id: u64,
    error_code: u64,
    final_size: u64,
};

/// §19.5.
pub const StopSending = struct {
    stream_id: u64,
    error_code: u64,
};

/// §19.6.
pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

/// §19.8. The OFF, LEN, and FIN bits are the low three bits of the frame type.
pub const Stream = struct {
    id: u64,
    /// The offset of `data` in the stream. Zero when the frame omitted it,
    /// which means the same thing: the frame carries the start of the stream.
    offset: u64,
    data: []const u8,
    /// §19.8: the FIN bit, so this is the last byte of the stream.
    fin: bool,
    /// Whether the wire carried a Length field. When it did not, the frame ran
    /// to the end of the payload, so it must be the last frame in the packet.
    length_present: bool,
};

/// §19.11 and §19.14.
pub const MaxStreams = struct {
    direction: Direction,
    maximum: u64,
};

/// §19.15.
pub const NewConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    reset_token: [16]u8,
};

/// §19.19.
pub const ConnectionClose = struct {
    /// True for type 0x1d: the code is the application's, and the frame type
    /// field is absent.
    application: bool,
    error_code: u64,
    /// The frame type that caused the close, present only for type 0x1c.
    frame_type: ?u64,
    reason: []const u8,
};

/// One frame.
pub const Frame = union(enum) {
    /// §19.1. Runs of PADDING coalesce: this is how many bytes of it there
    /// were, and it is always at least one.
    padding: u32,
    ping,
    ack: Ack,
    reset_stream: ResetStream,
    stop_sending: StopSending,
    crypto: Crypto,
    new_token: []const u8,
    stream: Stream,
    max_data: u64,
    max_stream_data: struct { stream_id: u64, maximum: u64 },
    max_streams: MaxStreams,
    data_blocked: u64,
    stream_data_blocked: struct { stream_id: u64, maximum: u64 },
    streams_blocked: MaxStreams,
    new_connection_id: NewConnectionId,
    retire_connection_id: u64,
    path_challenge: [8]u8,
    path_response: [8]u8,
    connection_close: ConnectionClose,
    handshake_done,

    /// §19.1: a PADDING frame is one byte, and a run of them is one frame of
    /// that many bytes.
    pub fn isPadding(self: *const Frame) bool {
        return switch (self.*) {
            .padding => true,
            else => false,
        };
    }
};

/// Read one frame from the payload.
pub fn read(cursor: *Cursor) Error!Frame {
    const frame_type = try readFrameType(cursor);

    return switch (frame_type) {
        0x00 => .{ .padding = try readPadding(cursor) },
        0x01 => .ping,
        0x02, 0x03 => .{ .ack = try readAck(cursor, frame_type == 0x03) },
        0x04 => .{ .reset_stream = .{
            .stream_id = try readVarint(cursor),
            .error_code = try readVarint(cursor),
            .final_size = try readVarint(cursor),
        } },
        0x05 => .{ .stop_sending = .{
            .stream_id = try readVarint(cursor),
            .error_code = try readVarint(cursor),
        } },
        0x06 => .{ .crypto = try readCrypto(cursor) },
        0x07 => .{ .new_token = try readNewToken(cursor) },
        0x08...0x0f => .{ .stream = try readStream(cursor, @intCast(frame_type)) },
        0x10 => .{ .max_data = try readVarint(cursor) },
        0x11 => .{ .max_stream_data = .{
            .stream_id = try readVarint(cursor),
            .maximum = try readVarint(cursor),
        } },
        0x12, 0x13 => .{ .max_streams = .{
            .direction = if (frame_type == 0x12) .bidi else .uni,
            .maximum = try readVarint(cursor),
        } },
        0x14 => .{ .data_blocked = try readVarint(cursor) },
        0x15 => .{ .stream_data_blocked = .{
            .stream_id = try readVarint(cursor),
            .maximum = try readVarint(cursor),
        } },
        0x16, 0x17 => .{ .streams_blocked = .{
            .direction = if (frame_type == 0x16) .bidi else .uni,
            .maximum = try readVarint(cursor),
        } },
        0x18 => .{ .new_connection_id = try readNewConnectionId(cursor) },
        0x19 => .{ .retire_connection_id = try readVarint(cursor) },
        0x1a => .{ .path_challenge = try readPathData(cursor) },
        0x1b => .{ .path_response = try readPathData(cursor) },
        0x1c, 0x1d => .{ .connection_close = try readConnectionClose(cursor, frame_type == 0x1d) },
        0x1e => .handshake_done,
        else => error.UnknownFrameType,
    };
}

/// Write one frame.
pub fn write(writer: *Writer, value: Frame) Error!void {
    switch (value) {
        .padding => |count| {
            // A run of one is the minimum: a frame always has its type byte.
            if (count == 0) return error.InvalidFrameType;
            _ = try writer.reserve(count);
        },
        .ping => try writer.putByte(0x01),
        .ack => |ack| try writeAck(writer, ack),
        .reset_stream => |reset| {
            try writer.putByte(0x04);
            try writeVarint(writer, reset.stream_id);
            try writeVarint(writer, reset.error_code);
            try writeVarint(writer, reset.final_size);
        },
        .stop_sending => |stop| {
            try writer.putByte(0x05);
            try writeVarint(writer, stop.stream_id);
            try writeVarint(writer, stop.error_code);
        },
        .crypto => |crypto| {
            try writer.putByte(0x06);
            try writeVarint(writer, crypto.offset);
            try writeVarint(writer, crypto.data.len);
            try writer.put(crypto.data);
        },
        .new_token => |token| {
            if (token.len == 0) return error.EmptyToken;
            try writer.putByte(0x07);
            try writeVarint(writer, token.len);
            try writer.put(token);
        },
        .stream => |stream| try writeStream(writer, stream),
        .max_data => |maximum| {
            try writer.putByte(0x10);
            try writeVarint(writer, maximum);
        },
        .max_stream_data => |data| {
            try writer.putByte(0x11);
            try writeVarint(writer, data.stream_id);
            try writeVarint(writer, data.maximum);
        },
        .max_streams => |streams| {
            try writer.putByte(if (streams.direction == .bidi) 0x12 else 0x13);
            try writeVarint(writer, streams.maximum);
        },
        .data_blocked => |maximum| {
            try writer.putByte(0x14);
            try writeVarint(writer, maximum);
        },
        .stream_data_blocked => |data| {
            try writer.putByte(0x15);
            try writeVarint(writer, data.stream_id);
            try writeVarint(writer, data.maximum);
        },
        .streams_blocked => |streams| {
            try writer.putByte(if (streams.direction == .bidi) 0x16 else 0x17);
            try writeVarint(writer, streams.maximum);
        },
        .new_connection_id => |id| {
            if (id.connection_id.len < 1 or id.connection_id.len > 20) {
                return error.InvalidConnectionId;
            }
            if (id.retire_prior_to > id.sequence) return error.InvalidRetirePriorTo;
            try writer.putByte(0x18);
            try writeVarint(writer, id.sequence);
            try writeVarint(writer, id.retire_prior_to);
            try writer.putByte(@intCast(id.connection_id.len));
            try writer.put(id.connection_id);
            try writer.put(&id.reset_token);
        },
        .retire_connection_id => |sequence| {
            try writer.putByte(0x19);
            try writeVarint(writer, sequence);
        },
        .path_challenge => |data| {
            try writer.putByte(0x1a);
            try writer.put(&data);
        },
        .path_response => |data| {
            try writer.putByte(0x1b);
            try writer.put(&data);
        },
        .connection_close => |close| {
            try writer.putByte(if (close.application) 0x1d else 0x1c);
            try writeVarint(writer, close.error_code);
            if (!close.application) try writeVarint(writer, close.frame_type orelse 0);
            try writeVarint(writer, close.reason.len);
            try writer.put(close.reason);
        },
        .handshake_done => try writer.putByte(0x1e),
    }
}

fn readFrameType(cursor: *Cursor) Error!u64 {
    return varint.decodeMinimal(cursor) catch |err| switch (err) {
        error.Truncated => return error.Truncated,
        error.NonMinimal => return error.NonMinimalFrameType,
    };
}

/// §19.1: a PADDING frame is a single 0x00 byte. The type byte is already
/// consumed, so count the run that follows it.
fn readPadding(cursor: *Cursor) Error!u32 {
    var count: u32 = 1;
    while (cursor.peek()) |byte| {
        if (byte != 0x00) break;
        _ = cursor.next();
        count += 1;
    }
    return count;
}

fn readAck(cursor: *Cursor, ecn_present: bool) Error!Ack {
    const largest = try readVarint(cursor);
    const delay = try readVarint(cursor);
    const range_count = try readVarint(cursor);
    const first_range = try readVarint(cursor);

    // Walk the ranges once to find where they end, because the ECN counts
    // follow them.
    var ranges: AckRanges = .{ .cursor = cursor.*, .remaining = range_count };
    while (try ranges.next()) |_| {}
    const bytes = cursor.slice(cursor.pos, ranges.cursor.pos);
    cursor.pos = ranges.cursor.pos;

    const ack: Ack = .{
        .largest = largest,
        .delay = delay,
        .first_range = first_range,
        .range_count = range_count,
        .bytes = bytes,
        .ecn = if (ecn_present) .{
            .ect0 = try readVarint(cursor),
            .ect1 = try readVarint(cursor),
            .ce = try readVarint(cursor),
        } else null,
    };
    try validateAck(ack);
    return ack;
}

/// §19.3.1: a range whose arithmetic goes below zero is a FRAME_ENCODING_ERROR,
/// so it is refused here rather than left for a caller that may not walk them.
fn validateAck(ack: Ack) Error!void {
    if (ack.first_range > ack.largest) return error.InvalidAckRange;

    var smallest = ack.largest - ack.first_range;
    var ranges = ack.ranges();
    while (try ranges.next()) |range| {
        if (range.gap + 2 > smallest) return error.InvalidAckRange;
        const range_largest = smallest - range.gap - 2;
        if (range.length > range_largest) return error.InvalidAckRange;
        smallest = range_largest - range.length;
    }
}

fn writeAck(writer: *Writer, ack: Ack) Error!void {
    // The caller supplies the encoded pairs, so check that they are the count
    // they claim and that they do not run below zero.
    var ranges = ack.ranges();
    while (try ranges.next()) |_| {}
    if (ranges.cursor.pos != ack.bytes.len) return error.InvalidAckRange;
    try validateAck(ack);

    try writer.putByte(if (ack.ecn == null) 0x02 else 0x03);
    try writeVarint(writer, ack.largest);
    try writeVarint(writer, ack.delay);
    try writeVarint(writer, ack.range_count);
    try writeVarint(writer, ack.first_range);
    try writer.put(ack.bytes);
    if (ack.ecn) |ecn| {
        try writeVarint(writer, ecn.ect0);
        try writeVarint(writer, ecn.ect1);
        try writeVarint(writer, ecn.ce);
    }
}

fn readCrypto(cursor: *Cursor) Error!Crypto {
    const offset = try readVarint(cursor);
    const length = try readVarint(cursor);
    if (length > cursor.remaining()) return error.Truncated;
    return .{ .offset = offset, .data = cursor.take(@intCast(length)) orelse unreachable };
}

fn readNewToken(cursor: *Cursor) Error![]const u8 {
    const length = try readVarint(cursor);
    if (length > cursor.remaining()) return error.Truncated;
    const token = cursor.take(@intCast(length)) orelse unreachable;
    // §19.7: a client must treat an empty token as a FRAME_ENCODING_ERROR.
    if (token.len == 0) return error.EmptyToken;
    return token;
}

fn readStream(cursor: *Cursor, frame_type: u8) Error!Stream {
    const id = try readVarint(cursor);
    const offset = if (frame_type & 0x04 != 0) try readVarint(cursor) else 0;

    const length_present = frame_type & 0x02 != 0;
    const data = if (length_present) blk: {
        const length = try readVarint(cursor);
        if (length > cursor.remaining()) return error.Truncated;
        break :blk cursor.take(@intCast(length)) orelse unreachable;
    } else cursor.take(cursor.remaining()) orelse unreachable;

    return .{
        .id = id,
        .offset = offset,
        .data = data,
        .fin = frame_type & 0x01 != 0,
        .length_present = length_present,
    };
}

fn writeStream(writer: *Writer, stream: Stream) Error!void {
    // The OFF bit is set only when the offset is not zero, which is the
    // shortest encoding of the same frame.
    const offset_present = stream.offset != 0;
    var frame_type: u8 = 0x08;
    if (offset_present) frame_type |= 0x04;
    if (stream.length_present) frame_type |= 0x02;
    if (stream.fin) frame_type |= 0x01;

    try writer.putByte(frame_type);
    try writeVarint(writer, stream.id);
    if (offset_present) try writeVarint(writer, stream.offset);
    if (stream.length_present) try writeVarint(writer, stream.data.len);
    try writer.put(stream.data);
}

fn readNewConnectionId(cursor: *Cursor) Error!NewConnectionId {
    const sequence = try readVarint(cursor);
    const retire_prior_to = try readVarint(cursor);
    // §19.15: Retire Prior To greater than the sequence number is a
    // FRAME_ENCODING_ERROR.
    if (retire_prior_to > sequence) return error.InvalidRetirePriorTo;

    const length = cursor.next() orelse return error.Truncated;
    // §19.15: a connection ID shorter than 1 or longer than 20 bytes is a
    // FRAME_ENCODING_ERROR.
    if (length < 1 or length > 20) return error.InvalidConnectionId;

    const connection_id = cursor.take(length) orelse return error.Truncated;
    const token = cursor.take(16) orelse return error.Truncated;

    var reset_token: [16]u8 = undefined;
    @memcpy(&reset_token, token);

    return .{
        .sequence = sequence,
        .retire_prior_to = retire_prior_to,
        .connection_id = connection_id,
        .reset_token = reset_token,
    };
}

fn readPathData(cursor: *Cursor) Error![8]u8 {
    const bytes = cursor.take(8) orelse return error.Truncated;
    var data: [8]u8 = undefined;
    @memcpy(&data, bytes);
    return data;
}

fn readConnectionClose(cursor: *Cursor, application: bool) Error!ConnectionClose {
    const error_code = try readVarint(cursor);
    const frame_type = if (application) null else try readVarint(cursor);
    const length = try readVarint(cursor);
    if (length > cursor.remaining()) return error.Truncated;

    return .{
        .application = application,
        .error_code = error_code,
        .frame_type = frame_type,
        .reason = cursor.take(@intCast(length)) orelse unreachable,
    };
}

/// `varint.decode` and `varint.write` have wider error sets than this codec
/// needs. A frame type is never written in a wider form than it needs, and a
/// value read from the wire is never out of range.
fn readVarint(cursor: *Cursor) Error!u64 {
    return varint.decode(cursor) catch |err| switch (err) {
        error.Truncated => return error.Truncated,
        error.NonMinimal => unreachable,
    };
}

fn writeVarint(writer: *Writer, value: u64) Error!void {
    varint.write(writer, value) catch |err| switch (err) {
        error.NoSpace => return error.NoSpace,
        error.Overflow => unreachable,
    };
}

const expect = testing.expect;
const expectEqual = testing.expectEqual;

/// Write a frame, read it back, re-encode it, and require both byte strings to
/// match. Returns the frame as read.
fn roundTrip(value: Frame) !Frame {
    var buf: [512]u8 = undefined;
    var writer: Writer = .init(&buf);
    try write(&writer, value);
    const bytes = writer.written();

    var cursor: Cursor = .init(bytes);
    const back = try read(&cursor);
    try expectEqual(bytes.len, cursor.pos);

    var second: [512]u8 = undefined;
    var writer2: Writer = .init(&second);
    try write(&writer2, back);
    try testing.expectEqualSlices(u8, bytes, writer2.written());
    return back;
}

test "RFC 9000 §19, every one-field frame round trips" {
    inline for (.{
        Frame{ .ping = {} },
        Frame{ .max_data = 0 },
        Frame{ .max_data = 1 << 40 },
        Frame{ .data_blocked = 1234 },
        Frame{ .retire_connection_id = 7 },
        Frame{ .handshake_done = {} },
        Frame{ .path_challenge = .{ 1, 2, 3, 4, 5, 6, 7, 8 } },
        Frame{ .path_response = .{ 8, 7, 6, 5, 4, 3, 2, 1 } },
        Frame{ .padding = 1 },
        Frame{ .padding = 40 },
        Frame{ .new_token = "a token" },
        Frame{ .max_streams = .{ .direction = .bidi, .maximum = 10 } },
        Frame{ .max_streams = .{ .direction = .uni, .maximum = 11 } },
        Frame{ .streams_blocked = .{ .direction = .bidi, .maximum = 12 } },
        Frame{ .streams_blocked = .{ .direction = .uni, .maximum = 13 } },
        Frame{ .reset_stream = .{ .stream_id = 1, .error_code = 2, .final_size = 3 } },
        Frame{ .stop_sending = .{ .stream_id = 4, .error_code = 5 } },
        Frame{ .max_stream_data = .{ .stream_id = 6, .maximum = 7 } },
        Frame{ .stream_data_blocked = .{ .stream_id = 8, .maximum = 9 } },
        Frame{ .crypto = .{ .offset = 0, .data = "handshake" } },
        Frame{ .crypto = .{ .offset = 1 << 20, .data = "" } },
        Frame{ .stream = .{ .id = 0, .offset = 0, .data = "x", .fin = false, .length_present = true } },
        Frame{ .stream = .{ .id = 4, .offset = 100, .data = "y", .fin = true, .length_present = true } },
        Frame{ .stream = .{ .id = 4, .offset = 0, .data = "rest", .fin = false, .length_present = false } },
        Frame{ .new_connection_id = .{
            .sequence = 3,
            .retire_prior_to = 1,
            .connection_id = &.{ 1, 2, 3, 4 },
            .reset_token = @splat(0x5a),
        } },
        Frame{ .connection_close = .{
            .application = false,
            .error_code = 0x0a,
            .frame_type = 0x08,
            .reason = "bad frame",
        } },
        Frame{ .connection_close = .{
            .application = true,
            .error_code = 0x100,
            .frame_type = null,
            .reason = "",
        } },
    }) |value| {
        const back = try roundTrip(value);
        try expectEqual(@as(u8, @backingInt(std.meta.activeTag(value))), @backingInt(std.meta.activeTag(back)));
    }
}

test "RFC 9000 §19.1, a run of PADDING is one frame" {
    var cursor: Cursor = .init(&.{ 0x00, 0x00, 0x00, 0x01, 0x00 });
    const padding = try read(&cursor);
    try expectEqual(@as(u32, 3), padding.padding);
    try expectEqual(@as(u32, 3), cursor.pos);

    const ping = try read(&cursor);
    try expect(ping.isPadding() == false);
    try expectEqual(@as(u32, 4), cursor.pos);
}

test "RFC 9000 §19.2 and §12.4, the frame type must be one byte and known" {
    // PING encoded in two bytes is the §12.4 violation.
    var padded: Cursor = .init(&.{ 0x40, 0x01 });
    try testing.expectError(error.NonMinimalFrameType, read(&padded));
    try expectEqual(@as(u32, 0), padded.pos);

    var unknown: Cursor = .init(&.{0x1f});
    try testing.expectError(error.UnknownFrameType, read(&unknown));
}

test "RFC 9000 §19.3, an ACK with ranges and ECN counts" {
    var scratch: [16]u8 = undefined;
    var scratch_writer: Writer = .init(&scratch);
    try varint.write(&scratch_writer, 2); // gap
    try varint.write(&scratch_writer, 3); // ack range length

    const ack: Ack = .{
        .largest = 100,
        .delay = 5,
        .first_range = 1,
        .range_count = 1,
        .bytes = scratch_writer.written(),
        .ecn = .{ .ect0 = 10, .ect1 = 11, .ce = 12 },
    };

    var back = (try roundTrip(.{ .ack = ack })).ack;
    try expectEqual(@as(u64, 100), back.largest);
    try expectEqual(@as(u64, 5), back.delay);
    try expectEqual(@as(u64, 1), back.range_count);
    try expectEqual(@as(u64, 1), back.first_range);
    try expectEqual(@as(u64, 10), back.ecn.?.ect0);

    // §19.3.1: smallest = 100 - 1 = 99, then 99 - 2 - 2 = 95, then 95 - 3 = 92.
    var ranges = back.ranges();
    const range = (try ranges.next()).?;
    try expectEqual(@as(u64, 2), range.gap);
    try expectEqual(@as(u64, 3), range.length);
    try expect((try ranges.next()) == null);
}

test "RFC 9000 §19.3.1, an ACK range that goes below zero is an error" {
    // largest 1 and first range 1 leaves smallest 0, and a gap of 0 needs 0-2.
    const underflow: Ack = .{
        .largest = 1,
        .delay = 0,
        .first_range = 1,
        .range_count = 1,
        .bytes = &.{ 0x00, 0x00 },
        .ecn = null,
    };
    var buf: [64]u8 = undefined;
    var writer: Writer = .init(&buf);
    try testing.expectError(error.InvalidAckRange, write(&writer, .{ .ack = underflow }));

    // The same frame on the wire is refused at the parser.
    var wire: [8]u8 = undefined;
    var wire_writer: Writer = .init(&wire);
    try wire_writer.putByte(0x02);
    try varint.write(&wire_writer, 1); // largest
    try varint.write(&wire_writer, 0); // delay
    try varint.write(&wire_writer, 1); // range count
    try varint.write(&wire_writer, 1); // first range
    try wire_writer.put(&.{ 0x00, 0x00 }); // gap 0, length 0
    var cursor: Cursor = .init(wire_writer.written());
    try testing.expectError(error.InvalidAckRange, read(&cursor));

    // Bytes that end inside a pair are truncation, the same as on the wire.
    const cut_short: Ack = .{
        .largest = 100,
        .delay = 0,
        .first_range = 0,
        .range_count = 2,
        .bytes = &.{ 0x00, 0x00 },
        .ecn = null,
    };
    try testing.expectError(error.Truncated, write(&writer, .{ .ack = cut_short }));

    // A count that disagrees with the bytes is a frame the caller got wrong.
    const miscounted: Ack = .{
        .largest = 100,
        .delay = 0,
        .first_range = 0,
        .range_count = 1,
        .bytes = &.{ 0x00, 0x00, 0x00, 0x00 },
        .ecn = null,
    };
    try testing.expectError(error.InvalidAckRange, write(&writer, .{ .ack = miscounted }));
}

test "RFC 9000 §19.8, the OFF, LEN, and FIN bits" {
    // Type 0x0a: LEN set, OFF clear, FIN clear, with a Length field.
    var cursor: Cursor = .init(&.{ 0x0a, 0x04, 0x02, 0xaa, 0xbb, 0xff });
    const with_length = try read(&cursor);
    try expectEqual(@as(u64, 4), with_length.stream.id);
    try expectEqual(@as(u64, 0), with_length.stream.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, with_length.stream.data);
    try expect(with_length.stream.length_present);
    try expect(with_length.stream.fin == false);
    try expectEqual(@as(u32, 5), cursor.pos);

    // Type 0x0f: OFF, LEN, and FIN all set.
    var all: Cursor = .init(&.{ 0x0f, 0x01, 0x03, 0x01, 0x99 });
    const stream = try read(&all);
    try expectEqual(@as(u64, 1), stream.stream.id);
    try expectEqual(@as(u64, 3), stream.stream.offset);
    try testing.expectEqualSlices(u8, &.{0x99}, stream.stream.data);
    try expect(stream.stream.fin);

    // Type 0x08: no Length, so the data runs to the end of the payload.
    var tail: Cursor = .init(&.{ 0x08, 0x01, 0xde, 0xad, 0xbe, 0xef });
    const to_end = try read(&tail);
    try expect(to_end.stream.length_present == false);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, to_end.stream.data);
    try expect(tail.atEnd());

    // A Length past the end is truncation, not a short read.
    var short: Cursor = .init(&.{ 0x0a, 0x01, 0x05, 0x00 });
    try testing.expectError(error.Truncated, read(&short));
}

test "RFC 9000 §19.15, a connection ID of 1 to 20 bytes and a sane retire index" {
    var cursor: Cursor = .init(&.{ 0x18, 0x01, 0x00, 0x00 });
    try testing.expectError(error.InvalidConnectionId, read(&cursor));

    var long: [24]u8 = undefined;
    long[0] = 0x18;
    long[1] = 1; // sequence
    long[2] = 0; // retire prior to
    long[3] = 21; // over the limit
    @memset(long[4..24], 0xaa);
    var long_cursor: Cursor = .init(&long);
    try testing.expectError(error.InvalidConnectionId, read(&long_cursor));

    // Retire Prior To greater than the sequence number.
    const retire_bytes = [_]u8{ 0x18, 0x01, 0x02, 0x01, 0xaa } ++ @as([16]u8, @splat(0));
    var retire: Cursor = .init(&retire_bytes);
    try testing.expectError(error.InvalidRetirePriorTo, read(&retire));
}

test "RFC 9000 §19.7, an empty NEW_TOKEN is an error" {
    var cursor: Cursor = .init(&.{ 0x07, 0x00 });
    try testing.expectError(error.EmptyToken, read(&cursor));

    var buf: [8]u8 = undefined;
    var writer: Writer = .init(&buf);
    try testing.expectError(error.EmptyToken, write(&writer, .{ .new_token = "" }));
}

test "RFC 9000 §19.19, the two CONNECTION_CLOSE shapes" {
    var close: Cursor = .init(&.{ 0x1c, 0x07, 0x08, 0x02, 'h', 'i' });
    const quic_close = try read(&close);
    try expectEqual(@as(u64, 0x07), quic_close.connection_close.error_code);
    try expectEqual(@as(?u64, 0x08), quic_close.connection_close.frame_type);
    try testing.expectEqualStrings("hi", quic_close.connection_close.reason);

    var app: Cursor = .init(&.{ 0x1d, 0x0c, 0x00 });
    const app_close = try read(&app);
    try expect(app_close.connection_close.application);
    try expectEqual(@as(?u64, null), app_close.connection_close.frame_type);
    try expectEqual(@as(usize, 0), app_close.connection_close.reason.len);
}

test "every prefix of a payload is truncation, not a wrong answer" {
    var buf: [512]u8 = undefined;
    var writer: Writer = .init(&buf);
    try write(&writer, .{ .ping = {} });
    try write(&writer, .{ .max_data = 1 << 30 });
    try write(&writer, .{ .stream = .{ .id = 2, .offset = 9, .data = "abc", .fin = true, .length_present = true } });
    try write(&writer, .{ .connection_close = .{
        .application = false,
        .error_code = 1,
        .frame_type = 0,
        .reason = "x",
    } });

    const bytes = writer.written();
    var len: usize = 0;
    while (len < bytes.len) : (len += 1) {
        var cursor: Cursor = .init(bytes[0..len]);
        while (true) {
            _ = read(&cursor) catch |err| {
                try expectEqual(error.Truncated, err);
                break;
            };
            if (cursor.atEnd()) break;
        }
    }
}

test "fuzz the frame parser" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const input = buf[0..smith.slice(&buf)];

            var cursor: Cursor = .init(input);
            while (true) {
                const value = read(&cursor) catch |err| {
                    // The only acceptable reasons are a short buffer, a bad
                    // type, or a value the frame cannot carry.
                    try expect(switch (err) {
                        error.Truncated,
                        error.UnknownFrameType,
                        error.NonMinimalFrameType,
                        error.InvalidAckRange,
                        error.InvalidConnectionId,
                        error.InvalidRetirePriorTo,
                        error.EmptyToken,
                        => true,
                        else => false,
                    });
                    break;
                };
                // A parsed frame re-encodes into a buffer no larger than the
                // bytes it came from plus its type byte.
                try expect(encodedSize(value) >= cursor.pos);
                if (cursor.atEnd()) break;
            }
        }

        /// A cheap upper bound on the frame's wire size: every field is at most
        /// eight bytes, and the payload data is counted whole.
        fn encodedSize(value: Frame) usize {
            return switch (value) {
                .padding => |count| count,
                .ping, .handshake_done => 1,
                .ack => |ack| 40 + ack.bytes.len,
                .reset_stream, .stop_sending => 25,
                .crypto => |crypto| 17 + crypto.data.len,
                .new_token => |token| 9 + token.len,
                .stream => |stream| 25 + stream.data.len,
                .max_data, .data_blocked, .retire_connection_id => 9,
                .max_stream_data, .stream_data_blocked => 17,
                .max_streams, .streams_blocked => 9,
                .new_connection_id => 9 + 9 + 1 + 20 + 16,
                .path_challenge, .path_response => 9,
                .connection_close => |close| 17 + 9 + close.reason.len,
            };
        }
    }.run, .{ .corpus = &.{ "", "\x01", "\x00\x00\x0c\x01\x00" } });
}
