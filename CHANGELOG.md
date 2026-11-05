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
- `InitialSpace` is no longer exported from the package. It is an Initial-level
  prototype, and the per-space type that replaces it will own the state
  `Recovery` already has.
- `Recovery` splits into the connection-wide state (`rtt`, `pto_count`) and a
  `Space` per packet number space, over caller-owned sent-packet storage, so a
  full table is `error.NoSpace` and never a forgotten packet.
- `Recovery` does RFC 9002 §5 and §6 for one packet number space: RTT
  estimation with the A.7 update order, the packet and time thresholds, and the
  probe timeout with backoff and the client's two-probe rule. No congestion
  control (§7), no timers of its own, no I/O. `SentPacket` carries
  `sent_bytes` and the events carry byte totals, which is what a controller
  reads.
- `InitialSpace` is the Initial-level driver: it derives both Initial keys from
  the connection ID, seals and opens Initial packets, tracks the packet number
  in each direction, and turns what it received into an ACK frame. It is not a
  connection: no handshake, no retransmission, no loss recovery, no Retry.
- `protection.deriveKeys` takes the traffic secret as a slice and refuses one
  whose length does not match the suite, instead of assuming 32 bytes.
- `protection` seals and opens RFC 9001 §5 packets: Initial keys from the
  connection ID (§5.2), the AEAD nonce (§5.3), and AES or ChaCha20 header
  protection (§5.4). `protection.Suite` covers AES-128-GCM and
  ChaCha20-Poly1305; TLS_AES_256_GCM_SHA384 is not wired up yet.
- `hkdf.expandLabel` is the TLS 1.3 derivation with the `quic key`, `quic iv`,
  `quic hp`, and `quic ku` labels.
- `TransportParameters` reads and writes every RFC 9000 §18.2 parameter,
  including `preferred_address`. It refuses a duplicate, an out-of-range value,
  and a server-only parameter sent by a client, and it ignores a parameter this
  version does not define.
