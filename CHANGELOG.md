# Changelog

All notable changes to quic are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `varint` decodes and writes the RFC 9000 §16 variable-length integer, in all
  four widths. `decodeMinimal` rejects a width wider than the value needs, which
  is what the frame type requires.
- `Cursor` and `Writer` read and write caller-owned bytes at a `u32`
  position.
- `packet` reads and writes every RFC 9000 §17 header: Initial, 0-RTT,
  Handshake, Retry, Version Negotiation, and the short header.
  `packet.parseInvariant` reads the connection IDs and the version from a long
  header without keys, which is what answering with version negotiation needs.
- `packet_number` picks the width of the truncated packet number and recovers
  it at the receiver (§17.1).
- `frame` reads and writes every RFC 9000 §19 frame. `Ack.ranges` walks the
  Gap and ACK Range Length pairs without copying them, a run of PADDING is one
  frame, and `frame.read` rejects a frame type that is not one byte (§12.4).
- `error_code` has the RFC 9000 §20.1 transport codes, the CRYPTO_ERROR block,
  and `error_code.forFrameError`, which names the code that closes a connection
  over a frame that will not decode.
- `TransportParameters` reads and writes every RFC 9000 §18.2 parameter,
  including `preferred_address`. It refuses a duplicate, an out-of-range value,
  and a server-only parameter sent by a client, and it ignores a parameter this
  version does not define.
