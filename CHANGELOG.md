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
- `Conn` begins the connection machine: it derives the Initial keys, seals and
  opens Initial packets, tracks packet numbers both ways, records the ranges it
  received, and builds the ACK frame it owes. It has no handshake, streams,
  congestion, coalescing, or timers yet, and the A.2 client Initial is its
  golden test.
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
- `Conn` wires streams: a STREAM frame opens the stream if this is the first
  one (§2.1), its bytes go into the stream's `ReceiveStream` ring, and the
  connection-wide receive window counts the highest offset reached (§4.1). A
  table with no free slot is `error.StreamLimit`, which the caller closes the
  connection with (STREAM_LIMIT_ERROR, §4.6), not a dropped packet. `Conn.stream`
  hands the caller the stream halves, `Conn.writeStream` seals the next
  `SendStream` segment into a packet clamped by the peer's connection allowance,
  and `Conn.onMaxData` raises that allowance. `Conn.Config` gained `stream_slots`,
  `streams`, `receive_limit`, and `send_limit`; `Conn.Stream` is the caller's
  per-stream storage. `Conn.init` asserts that every receive ring holds the
  per-stream limit that stream advertises (§4.1), so a ring that is too small
  fails at setup instead of turning a peer's frame into `error.NoSpace`.
- `Conn` parses the frames of every packet it opens. CRYPTO frames are
  reassembled per level and handed to the TLS driver in order; PADDING is
  consumed; every other frame comes back to the caller as `Conn.Opened.frames`,
  borrowed from the payload and in wire order, because the machine has no home
  for it yet. A frame that will not parse is a connection error (§12.4) and not
  a dropped packet: only a packet that will not unprotect is dropped.
- `CryptoStream` reassembles one encryption level's CRYPTO stream (RFC 9000
  §19.6) over a ring the caller owns: bytes that arrive past a gap wait there,
  and every run that becomes contiguous comes back as one or two borrowed
  slices. A frame that would put the end of the stream further past what the
  ring holds is `error.NoSpace`, never a silent truncation.
- `handshake.Suite` names the five TLS 1.3 cipher suites, and
  `handshake.VTable.suite` is a required call: the machine derives keys for the
  suite the driver reports or refuses with `error.UnsupportedCipherSuite`. It
  never falls back to AES-128-GCM.
- `handshake` is the TLS seam: a vtable of eight calls that a driver implements
  and the machine calls — `feed` with CRYPTO payloads per level, `next` for the
  bytes to send back, `secrets` per level, our and the peer's transport
  parameters as opaque bytes, `confirmed`, `alpn`, and `errorCode` for the
  CRYPTO_ERROR range. No record layer, no clock, no allocator, and every slice
  borrowed. `handshake.Stub` is a scripted driver for a caller that has none.
- `Conn.writeHandshake` drives the TLS seam: it hands the driver this endpoint's
  transport parameters once, installs every space the driver reports secrets
  for, writes the driver's next message as a CRYPTO frame at the level it named,
  and discards the Handshake keys when the driver reports the handshake
  confirmed (RFC 9001 §4.9.2). `Conn.Config` takes the driver and the encoded
  parameters; without a driver the call writes nothing.
- `Conn.Datagram` walks one datagram packet by packet (RFC 9000 §12.2): long
  headers delimit themselves with their Length field, a short header runs to the
  end, a packet that will not open is counted in `dropped` and the walk
  continues (RFC 9001 §5.5), and bytes with no readable end stop the walk. It
  reuses one plaintext buffer, so the caller pulls each packet's frames in turn.
- `Conn.discard` drops a packet number space and its keys (RFC 9001 §4.9, RFC
  9000 §17.2.2.1): the key material is zeroed, the space becomes absent, and a
  packet that arrives for it afterwards is `error.NoKeys` for the datagram walk
  to drop. `Conn.Space.discard` is the same at the space level, for a caller
  that holds a copy.
- `Conn` carries the connection IDs, not each space: `Conn.Space` holds keys,
  counters, and received ranges only. A discarded space no longer takes the
  connection's identity with it, so a space can be created after another one is
  gone.

### Changed

- STREAM frames no longer appear in `Conn.Opened.frames`, because the machine
  has a home for them. A STREAM frame in an Initial or Handshake packet is
  `error.WrongFrameSpace` (§12.4).
- `Conn.feed` and `Conn.Datagram.next` take a caller array for the frames the
  machine did not act on, and `Conn.Opened` carries `space`, the parsed `frames`,
  and `payload` instead of the raw payload alone. `Conn.Config` gained `crypto`,
  the CRYPTO reassembly storage per level.
- `Conn` discards the Initial keys at the two moments RFC 9000 §17.2.2.1 names:
  a client's first Handshake packet sent, a server's first one processed. A
  late Initial packet after that is dropped by the datagram walk.
- `Conn.initial` is `?Conn.Space`, because RFC 9000 §17.2.2.1 discards the
  Initial keys once a Handshake packet goes each way. All three spaces now
  follow the same rule: absent means no keys.
- `Conn` holds the three packet number spaces of RFC 9000 §12.3 and picks one
  from the packet's form and type. `Conn.feed`, `Conn.writeFrames`,
  `Conn.writeAck`, and `Conn.ackOwed` take the space they act on, and a space
  without traffic keys is `error.NoKeys`. `Conn.feed` no longer returns
  `error.NotInitial`, and `Conn.writeAck` with nothing received is
  `error.NothingToAcknowledge`.

### Fixed

- `Conn.writeAck` sized its buffers for a single received range, so eight
  fragments could overflow the varint scratch into a panic. Both buffers now
  follow `Conn.range_capacity`.
