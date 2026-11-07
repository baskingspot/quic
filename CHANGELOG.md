# Changelog

All notable changes to quic are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `Conn.clientConfig` builds a client's configuration from the name it invents
  for the server, its own connection ID, and its loss state, mirroring
  `Opening.serverConfig`. The two numbers the Initial keys depend on cannot
  disagree when one call sets both.
- `Conn` asserts, in debug builds, that it is still at the address it was first
  used from. A caller builds a `RecoveryDriver` over `&conn.app.?.recovery`, so a
  connection that moves leaves the driver writing through pointers into nobody's
  storage. The assertion catches the move on the next call instead of days later.
- `Conn.acksOwed` reports every packet number space that owes an acknowledgment
  in one call, lowest first, as `Conn.flowControlOwed` does for the window
  frames. `ackOwed` and `writeAck` still take a space; the summary removes the
  loop where a caller either knew the three-space enum or forgot one.
- `Conn.installSpaces` installs the packet number spaces the TLS driver has
  reported secrets for, hands over the transport parameters once, and discards
  the Handshake keys on confirmation. It is separate from `writeHandshake`, which
  now calls it and then drains a message: a server with nothing to send installs
  its 1-RTT keys with `installSpaces` instead of calling a write function and
  getting null.
- `Conn.joinStream` takes up the sending half of a stream the peer opened. It is
  a different act from `Conn.openStream`, which now opens only the stream IDs
  this endpoint initiates and refuses the peer's with `error.WrongDirection`;
  joining answers on the peer's stream and a one-way one is refused the same
  way. A caller that sent on a peer's stream by calling `openStream(id, limit)`
  calls `joinStream(id)`.
- `Conn.Config.send_streams` carries the peer's three initial per-stream limits
  from its transport parameters (`initial_max_stream_data_bidi_remote`,
  `bidi_local`, and `uni`), so opening or joining a stream takes its limit from
  the machine instead of a number handed in again at each call.
- `Conn.writeStreams` reports `Packet.remaining`: the payload room the packet was
  given and did not use, when the offer list ran out before the room did. The
  congestion window is the caller's, so the machine cannot say how much of it is
  left; this says whether the last packet bought everything the application had,
  so a caller writing several packets can tell a full window from an idle stream.
- `Conn.Opening.fromDatagram` reads a client's first Initial, refuses anything
  that is not one, and copies its two connection IDs into the caller's storage.
  `Opening.serverConfig` turns that into a `Conn.Config` seeded from the
  datagram: the client's Destination Connection ID is the Initial key seed, its
  Source Connection ID is the reply's destination, and the server's own
  Connection ID is the caller's, because the machine holds no entropy. Filling
  those three by hand is how a server ends up with a handshake that never opens.
- `Conn.feed` and `Conn.Datagram.next` report the streams a packet changed, in a
  caller-owned list returned as `Opened.streams`: one record per stream with
  `readable` set when new bytes became contiguous and `finished` set when the
  FIN completed the stream. Both calls take the list next to the frames array,
  and a frame that changed nothing the application can see adds no record. An
  application no longer scans the stream table after every packet.
- `Conn.init` asserts that no two stream buffers share storage: not two slots
  over one ring, and not the send buffer that is also the receive ring of the
  same stream. A shared buffer is two byte budgets overwriting each other while
  neither half can detect it. A caller that aliased its storage was silently
  corrupting both streams and now gets a panic at construction.
- `examples/echo.zig` is a client and a server over `Conn` with a faked
  handshake, echoing one stream. `just example` builds and runs it. It is the
  first code in the tree that calls the machine the way an application does, and
  the gaps it found are recorded in `docs/slop/connection-machine.md`.
- `Conn.writeStreams` packs several streams into one packet from the caller's
  ordered offer list, up to the caller's payload budget, the peer's
  connection-wide allowance, and the output buffer, and describes what it wrote so
  a lost packet can be answered from the caller's own record of it.

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
- `Conn.flowControlOwed` reports the MAX_DATA and MAX_STREAM_DATA frames the
  application's reads have made due, and `Conn.onFlowControlSent` records the
  raises after the caller puts them on the wire. A frame that never left does
  not widen a window.
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
  per-stream storage. `Conn.init` asserts `streamsValid`, which checks that every
  receive ring holds the per-stream limit that stream advertises (§4.1) and that
  the table has one slot per stream, so a configuration that cannot hold its own
  windows fails at setup instead of turning a peer's frame into `error.NoSpace`
  or a runtime table overflow.
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
- `Conn.writeHandshake` drains the TLS seam's messages: each call installs what
  the driver reported (`Conn.installSpaces`) and writes its next message as a
  CRYPTO frame at the level it named, so a caller loops until it returns null.
  `Conn.Config` takes the driver and the encoded parameters; without a driver the
  call writes nothing.
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
- `Conn` drives loss recovery. `Conn.Config` takes `loss`, a `Conn.Loss` of the
  caller's `Recovery`, its three sent-packet tables, and `max_ack_delay`,
  `ack_delay_exponent`, and `peer_address_validated`. Each `Conn.Space` holds a
  `Recovery.Space` over the table for its packet number space, an incoming ACK
  is acted on instead of handed back (`onAckReceived`, so the RTT sample, the
  cleared packets, and the loss set land in the caller's `Recovery.Events`), and
  `Conn.onPeerAddressValidated` is the caller's half of the §6.2.1 rule.
- `Conn.Write` says what the caller knows about a packet the machine is sealing:
  its send time, whether it is ack-eliciting (§13.2.1), and whether it is in
  flight (§7.1 of RFC 9002). `Conn.writeFrames` records every such packet in the
  sent table, which is what an acknowledgment and the loss timer act on. An
  ACK-only packet (`Conn.Write.acknowledgment`) is neither, so it takes no room
  in the table.
- `Conn.close` seals a CONNECTION_CLOSE (§19.19) in the highest-numbered space
  that has keys, a transport code (§20.1) or the application's own, with the
  optional diagnostic reason, and puts the connection in the closing state.
  `Conn.State` is `open`, `closing`, or `draining` (§10.2.1 and §10.2.2): a
  closed connection answers `error.Closed` to `feed` and to every writer except
  `close` itself, `ackOwed` is false, and a peer's CONNECTION_CLOSE comes back in
  `Opened.frames` with the code it was given.
- `Conn` owns the client's handshake attempt (`connection_setup.Client`), so the
  §6.2 rule "discard a Version Negotiation after anything else arrived" is the
  machine's to enforce rather than the caller's to remember.
  `Conn.onVersionNegotiation` answers with `connection_setup.VersionNegotiation.Action`,
  which has no "change version" branch, and a server gets `error.WrongRole`
  because it has no attempt. A 1-RTT packet sent records §17.2.5.2's deadline for
  accepting a Retry.
- `Conn.Config.crypto_sent` is the caller's per-level buffer for the CRYPTO bytes
  this endpoint sends, and `Conn.replayCrypto(space)` returns them from offset
  zero (§13.3). A lost Initial or Handshake packet can now be re-sent, which it
  could not before: the machine handed the bytes to the TLS driver and kept only
  an offset. The capacity is the caller's, a message that does not fit is
  `error.NoSpace` before any of it is framed rather than a truncated flight
  (CRYPTO_BUFFER_EXCEEDED, §20.1), the replay is idempotent, and a discarded
  space replays nothing. `Conn.Space.crypto_sent_bytes` is gone: the buffer's
  length is the offset.
- `Conn.onRetry` completes the client's side of RFC 9000 §17.2.5: it discards a
  Retry that does not name this endpoint's connection ID, validates the integrity
  tag (§5.8 of RFC 9001), refuses a second one or one that arrives after the
  server has spoken, and on acceptance adopts the Retry's connection ID and token
  and rekeys the Initial space from the new Destination Connection ID (§5.2 of
  RFC 9001). Packet numbers continue rather than restarting (§17.2.5.3), the
  packets sent under the old keys are dropped rather than declared lost, and the
  handshake bytes stay in `replayCrypto(.initial)` so the ClientHello can go out
  again. `Conn.Config` gained `token`, which every Initial carries (§8.1.2), and
  `retry_storage`, where the adopted connection ID and token are copied so the
  machine never points into a datagram the caller will reuse.
- `Conn.closeStream` frees a stream's slot once both halves are finished and
  returns the credit the peer spent on it, which `Conn.flowControlOwed` now
  offers as a MAX_STREAMS frame (RFC 9000 §4.6, §19.11) and
  `Conn.onFlowControlSent` records. A stream this endpoint opened frees its slot
  and grants nothing, because no credit was spent on it. A stream that is not
  finished is `error.StreamState` rather than a freed slot, so a peer's next
  frame cannot reopen it over the same buffers. `Conn.Config` gained
  `max_streams_bidi` and `max_streams_uni`, the counts this endpoint advertised,
  and `init` asserts the table can hold them both.

### Changed

- `SendStream.write` returns `Error!void`: it appends every byte it is given or
  refuses the whole write with `error.NoSpace`, so a short write cannot exist and
  a caller has no count to check. `SendStream.end` is `SendStream.finish`, and it
  can no longer publish a truncated stream because nothing can be truncated. A
  caller that ignored the old return value was writing an empty stream and
  closing it.
- `Conn.writeStream` is removed, not deprecated: `Conn.writeStreams` replaces it
  and returns the `Conn.Packet` description a resend queue needs. A caller that
  wrote `writeStream(id, max_len, frames, out, now)` writes
  `writeStreams(.{ .offers = &.{ .{ .stream_id = id, .length = max_len } }, ... })`
  and gets the packet's number, length, and carried frames back instead of a
  bare byte count.
- `varint.decode` returns `varint.Error`, which is `error{Truncated}`. Its old
  set named `error.NonMinimal`, which it never returned; `decodeMinimal` keeps
  that and its own `DecodeError`. The three callers that carried an
  `unreachable` arm for it lost the arm.
- `InitialSpace` is deleted. It was the Initial-level prototype the machine
  replaced, unexported since then and unused, and it carried the second
  `largest_acked` this package spent a note arguing against. Its range-table
  tests moved to `Conn.Space.record`, its receive path fuzzing became a target
  over `Conn.Datagram`, and `AGENTS.md` says where the job lives now.
- `Conn.Space` carries the loss state of its packet number space, and
  `Conn.discard` empties it before the keys (RFC 9002 §6.4), so a timer a
  caller's `RecoveryDriver` already holds for that space has nothing to fire.
  `Recovery.Space.discard` marks the space discarded, which is what stops
  §6.2.2.1's anti-deadlock probe from re-arming itself forever.
- ACK frames no longer appear in `Conn.Opened.frames`: the machine acts on them.
  A caller that read them from there reads `Recovery.Events.ackedPackets()` and
  `lostPackets()` after `Conn.feed` instead, and an acknowledgment of a packet
  number this endpoint never sent is `error.InvalidAckRange` (§19.3.1 of RFC
  9000).
- `Conn.feed`, `Conn.Datagram.next`, `Conn.writeFrames`, `Conn.writeAck`,
  `Conn.writeStream`, and `Conn.writeHandshake` take `now`, because the machine
  holds no clock and every sent packet has a time (§5.1 of RFC 9002). `feed` and
  `Datagram.next` also take the caller's `Recovery.Events`, which describes the
  one call.
- `Recovery.Events` takes the caller's storage: `Recovery.Events.init(acked,
  lost)` replaces the fixed 64-record arrays, so a space is no longer limited to
  64 packets in flight. A report smaller than the sent table is
  `error.NoSpace` from `onAckReceived` or `onTimeout`, refused before anything
  moves. `Recovery.sent_packets_max` is gone.
- `FlowControl.nextLimit` raises the limit by the window the receiver keeps open,
  not by a fixed 16 KiB: `FlowControl` remembers its window, and a raise is due
  once half of it is consumed. A caller that read a few bytes no longer owes a
  frame for every read call.
- `varint.size` takes a `u62` instead of a `u64`, so the value it measures must
  have an encoding. A caller passing a `u64` adds `@intCast` after its own range
  check, and `varint.write` stays the one place that refuses `error.Overflow`.
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

- `just interop` never built anything runnable: `interop-bin` compiled the tool
  and installed nothing, so the recipe's `./zig-out/bin/interop` was always
  missing. Both developer binaries are installed by their steps now.
- A single ACK frame that covered more than 64 packets wrote past the fixed
  64-record `Recovery.Events` array, against a caller-owned sent table of any
  length. That was an assertion failure in a safe build and an out-of-bounds
  write in `ReleaseFast`, latent until an acknowledgment covered 65 packets. A
  style pass found it, which is the argument for doing one. The report now takes
  the caller's arrays (`Recovery.Events.init`), and a report shorter than the
  sent table is `error.NoSpace` before anything moves.
- `transport.encode` panicked on a parameter value above 2^62 - 1, which has no
  varint encoding, and wrote a connection ID longer than 20 bytes that its own
  decoder refuses. Both are `error.InvalidValue` now.
- `Conn` records a packet's number and range only after its frames parse, so a
  packet with a frame that will not parse is never acknowledged. State that was
  half-updated on an error path was the audit's first finding: `CryptoStream`
  now books the run before it copies the bytes, so `error.TooManyGaps` leaves the
  ring as it found it.
- `Conn.writeAck` sized its buffers for a single received range, so eight
  fragments could overflow the varint scratch into a panic. Both buffers now
  follow `Conn.range_capacity`.
