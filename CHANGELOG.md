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
- `just interop` builds `tools/interop.zig` and runs it against `quiche-client`:
  a Retry it must echo back, and a version list it must not negotiate. It skips
  with the build command when quiche-client is absent, which is the only path
  that has run here.
- `StreamTable` is a fixed-capacity id-to-slot table over caller storage: it
  keeps slots sorted by stream ID for a binary lookup, refuses a stream past
  capacity with `error.TableFull`, and never evicts or owns a stream's buffers.
- `ReceiveStream.onData` reports backpressure instead of an error when the
  caller's ring is full, leaving the stream untouched. The reassembly table's
  own limit is `error.TooManyGaps`.
- `RecoveryDriver` is the timer side of RFC 9002: one deadline across every
  packet number space (a due loss time beats a probe), and the event to service
  when it passes. It holds no clock; the caller passes the time. Firing changes
  the state the deadline is computed from, so two calls at the same instant
  cannot both fire. `Recovery.Space.discard` implements the §6.4 cleanup that
  keeps the path's RTT.
- `connection_setup` is RFC 9000 §6: a server builds a Version Negotiation
  packet by echoing the connection IDs it saw, a client's handling of one can
  never return a different version (the §6.2 rule, expressed as the return
  type), and a Retry is built and validated with the RFC 9001 §5.8 integrity
  tag. `connection_setup.Client` is the client side of "one Retry, only before
  the first response".
- `SendStream` is the §3.1 sending state machine over caller storage: it hands
  out segments bounded by the peer's limit, emits the zero-length FIN at the
  final size, tracks out-of-order acknowledgments to a contiguous offset, and
  answers a STOP_SENDING with a reset when §3.5 requires one.
- `ReceiveStream` reassembles out-of-order data into a contiguous stream in a
  ring the caller owns, enforces the §4.1 stream limit as FLOW_CONTROL_ERROR,
  pins the §4.5 final size, and reports the MAX_STREAM_DATA it owes.
- `FlowControl` is the connection-level §4.1 counter for both directions, and
  `stream_id` is the §2.1 arithmetic for the four stream kinds.
- `Congestion` is the NewReno part of RFC 9002 §7 that is about correctness:
  bytes in flight, the §7.2 initial and minimum window, slow start, congestion
  avoidance with a carried residue, and one window reduction per recovery
  period. `onPacketsLost` returns the recovery period's start, so a test can
  assert one loss episode halves the window once instead of inferring it.
- `Recovery` splits into the connection-wide state (`rtt`, `pto_count`) and a
  `Space` per packet number space, over caller-owned sent-packet storage, so a
  full table is `error.NoSpace` and never a forgotten packet.
- `Recovery` does RFC 9002 §5 and §6 for one packet number space: RTT
  estimation with the A.7 update order, the packet and time thresholds, and the
  probe timeout with backoff and the client's two-probe rule. No congestion
  control (§7), no timers of its own, no I/O. `SentPacket` carries
  `sent_bytes`, and the events carry the records plus byte totals, which is what
  a controller reads.
- `Recovery` now decides persistent congestion (RFC 9002 §7.6.2) and reports it
  with the loss event, using the §7.6.1 duration that always includes
  `max_ack_delay`.
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
