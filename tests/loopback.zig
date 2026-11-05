//! The pipe, end to end: a client Initial crosses to a server, the server
//! acknowledges it, and the client reads the acknowledgment.
//!
//! This is the smallest exchange that puts every piece side by side: the frame
//! codec writes the payload, the packet codec writes the header, protection
//! seals it and masks the header, the server unmasks and opens it, recovers the
//! packet number, records the range, and answers with an ACK frame the client
//! opens and records.
//!
//! What it does not prove, and must not be read as proving: nothing here is a
//! TLS handshake. The CRYPTO frame carries four arbitrary bytes because that is
//! the frame a handshake would ride in, not because those bytes mean anything.
//! The Initial keys come from the connection ID, so any observer could open
//! these packets; there is no authentication, no certificate, no handshake, no
//! retransmission, no loss detection, no congestion control, no version
//! negotiation, and no Retry. A real peer would also pad the datagram to 1200
//! bytes (§14.1), which the driver deliberately leaves to its caller.

const std = @import("std");
const testing = std.testing;
const quic = @import("quic");

/// The client's Destination Connection ID, which is what the Initial keys come
/// from (RFC 9001 §5.2). Both sides derive the same secrets from it.
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "RFC 9001 §5.2 with RFC 9000 §19.6 and §19.3, a loopback exchange" {
    var client: quic.InitialSpace = .init(.{
        .side = .client,
        .original_destination_connection_id = &original_dcid,
        .destination_connection_id = &original_dcid,
        .source_connection_id = &.{ 0xc1, 0xc2 },
    });
    var server: quic.InitialSpace = .init(.{
        .side = .server,
        .original_destination_connection_id = &original_dcid,
        .destination_connection_id = &.{ 0xc1, 0xc2 },
        .source_connection_id = &.{ 0x5e, 0x5e, 0x5e },
    });

    // The client's first packet: one CRYPTO frame holding four bytes that mean
    // nothing. This is not a handshake.
    const handshake_bytes = "none";
    var payload_buf: [128]u8 = undefined;
    var payload_writer: quic.Writer = .init(&payload_buf);
    try quic.frame.write(&payload_writer, .{
        .crypto = .{ .offset = 0, .data = handshake_bytes },
    });

    var datagram: [512]u8 = undefined;
    const packet_len = try client.seal(payload_writer.written(), &datagram);

    // The server opens it without knowing anything but the connection ID.
    var plaintext: [512]u8 = undefined;
    const opened = try server.open(datagram[0..packet_len], &plaintext);
    try testing.expectEqual(@as(u64, 0), opened.packet_number);
    try testing.expectEqual(@as(u32, packet_len), opened.header_len + opened.payload.len + 16);

    var cursor: quic.Cursor = .init(opened.payload);
    const first_frame = try quic.frame.read(&cursor);
    try testing.expectEqualStrings(handshake_bytes, first_frame.crypto.data);
    try testing.expectEqual(@as(u64, 0), first_frame.crypto.offset);
    try testing.expect(cursor.atEnd());

    // The server answers with one ACK frame and nothing else.
    var ack_scratch: [64]u8 = undefined;
    const ack_frame = (try server.ackFrame(&ack_scratch)).?;
    var reply_buf: [128]u8 = undefined;
    var reply_writer: quic.Writer = .init(&reply_buf);
    try quic.frame.write(&reply_writer, ack_frame);

    var reply_datagram: [512]u8 = undefined;
    const reply_len = try server.seal(reply_writer.written(), &reply_datagram);

    // The client opens the acknowledgment and records it.
    var client_plaintext: [512]u8 = undefined;
    const client_opened = try client.open(reply_datagram[0..reply_len], &client_plaintext);
    try testing.expectEqual(@as(u64, 0), client_opened.packet_number);

    var client_cursor: quic.Cursor = .init(client_opened.payload);
    const ack = (try quic.frame.read(&client_cursor)).ack;
    try testing.expectEqual(@as(u64, 0), ack.largest);
    try testing.expectEqual(@as(u64, 0), ack.first_range);
    try testing.expectEqual(@as(u64, 0), ack.range_count);
    try client.recordAck(&ack);
    try testing.expectEqual(@as(?u64, 0), client.largest_acked);

    // A second client packet continues the number, and the server's next ACK
    // covers both: one range, so the second ACK is still a single pair.
    const second_len = try client.seal(payload_writer.written(), &datagram);
    const second = try server.open(datagram[0..second_len], &plaintext);
    try testing.expectEqual(@as(u64, 1), second.packet_number);

    var second_scratch: [64]u8 = undefined;
    const second_ack = (try server.ackFrame(&second_scratch)).?.ack;
    try testing.expectEqual(@as(u64, 1), second_ack.largest);
    try testing.expectEqual(@as(u64, 1), second_ack.first_range);
    try testing.expectEqual(@as(u64, 0), second_ack.range_count);

    const second_reply_len = try server.seal(
        blk: {
            var wire: [64]u8 = undefined;
            var writer: quic.Writer = .init(&wire);
            try quic.frame.write(&writer, .{ .ack = second_ack });
            break :blk writer.written();
        },
        &reply_datagram,
    );
    const acked = try client.open(reply_datagram[0..second_reply_len], &client_plaintext);
    var second_cursor: quic.Cursor = .init(acked.payload);
    const ack2 = (try quic.frame.read(&second_cursor)).ack;
    try client.recordAck(&ack2);
    try testing.expectEqual(@as(?u64, 1), client.largest_acked);
}

test "RFC 9000 §12.2, two Initial packets share a datagram" {
    // A client sends two packets, the server opens them from one buffer in
    // order, and both numbers land in the ACK.
    var client: quic.InitialSpace = .init(.{
        .side = .client,
        .original_destination_connection_id = &original_dcid,
        .destination_connection_id = &original_dcid,
        .source_connection_id = &.{ 0x11 },
    });
    var server: quic.InitialSpace = .init(.{
        .side = .server,
        .original_destination_connection_id = &original_dcid,
        .destination_connection_id = &.{ 0x11 },
        .source_connection_id = &.{ 0x22 },
    });

    const payload = "payload with enough bytes to be sampled";
    var datagram: [512]u8 = undefined;
    var cursor: quic.Writer = .init(&datagram);

    var single: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;

    const first_len = try client.seal(payload, &single);
    try cursor.put(single[0..first_len]);
    const second_len = try client.seal(payload, &single);
    try cursor.put(single[0..second_len]);

    var offset: usize = 0;
    var expected: u64 = 0;
    while (offset < datagram.len and offset < cursor.pos) {
        const opened = try server.open(datagram[offset..cursor.pos], &plaintext);
        try testing.expectEqual(expected, opened.packet_number);
        offset += opened.packet_len;
        expected += 1;
    }
    try testing.expectEqual(@as(usize, 2), expected);
    try testing.expectEqual(@as(u4, 1), server.range_count);
    try testing.expectEqual(@as(u64, 1), server.ranges[0].largest);
}
