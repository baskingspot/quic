# The connection machine: contract, spaces, line

Design note. No code yet. The model is `h1.ServerConn` in http: the caller owns
the wire, the buffers, and the clock; the machine owns protocol state and turns
bytes into events.

## The contract

A caller provides, once, at `init`:

- storage: the send datagram, the receive datagram, one `StreamTable` and its
  slots, and the send buffers and receive rings for each stream. No allocator
  enters the API, so capacity is the caller's number and every "no room" is a
  named error rather than a reallocation.
- identity: role, local connection IDs, the peer's initial connection ID, and
  the initial limits from its own transport parameters.
- its own `Recovery` and `Congestion`, and the `RecoveryDriver` over them.

Per call it provides `now` and, for input, exactly one datagram. It receives:

- `events`: packets parsed, CRYPTO bytes per encryption level, stream bytes,
  acknowledgments requested, packets declared lost, a discarded space, a close
  with its code, and a timestamp-free deadline from `RecoveryDriver`.
- `out`: datagrams to send, one at a time, built by `write(out)`. Each emitted
  packet is described by the frames it carries: a stream ID and byte range, a
  CRYPTO range at a level, an ACK, a reset. That description is what makes the
  retransmission boundary below real rather than nominal.

Everything is borrowed or caller-owned. `feed` never keeps a pointer into the
datagram it was handed; a stream's bytes are copied into that stream's ring at
`onData`, which is where the only unavoidable copy lives.

## The three spaces

| space | keys from | created | discarded |
| --- | --- | --- | --- |
| Initial | `protection.initialSecrets(dcid)` — us, not tls | `init` | the client's first Handshake packet sent, or the server's first received (RFC 9000 §17.2.2.1) |
| Handshake | the TLS driver's handshake secrets | when the driver reports them | when the handshake is confirmed (RFC 9001 §4.9.2) |
| 1-RTT | the driver's application secrets | same | on close |

Each space has its own `Recovery.Space` over caller slots, and a discard is
`Space.discard()` plus zeroing the key bytes: the RTT estimate and congestion
window survive, because they belong to the path, not the space (RFC 9002 A.2).

Key update (RFC 9001 §6) is deliberately out of the first build. The "quic ku"
derivation is already tested, so the hook is a driver method, not new arithmetic.

### What I need from tls, precisely

The handshake driver is a sans-I/O message machine with encryption levels, no
record layer:

1. `feed(level, bytes) -> Error!void` — CRYPTO frame payloads, in order, per
   level. The machine does reassembly of CRYPTO offsets; the driver sees a
   contiguous stream.
2. `next() -> ?Message { level, bytes }` — handshake bytes to put in CRYPTO
   frames at that level, drained until null.
3. `secrets(level) -> ?Secrets { client, server }` — 32-byte traffic secrets
   (48 for SHA-384 suites, which `protection.deriveKeys` already refuses by
   length). The driver says when they become available.
4. A way to set our `quic_transport_parameters` extension (0x0039) before the
   first flight and to return the peer's bytes when they arrive. QUIC encodes
   them; tls carries them opaquely.
5. `confirmed() -> bool` — the moment §4.9.2 lets us discard Handshake keys and
   the moment §6.2.1 lets us arm 1-RTT PTO.
6. `alpn() -> ?[]const u8`, and alerts surfaced as the CRYPTO_ERROR range so
   §20.1 mapping needs no table in the machine.
7. The same ownership rules: no I/O, no clock, caller buffers, explicit errors.

This list is now a type: `src/handshake.zig` holds the vtable, and a driver
implements it without importing the connection machine. Two things the list
left open have an answer there. Alerts do not need a separate call: while the
driver has failed, `errorCode` is `0x100 + alert`, so the machine closes with a
number and keeps no table. And a vtable is what a repository boundary needs:
`baskingspot/tls` implements the table, and `handshake.Stub` stands in for it in
this package's tests.

What the machine does with it so far is one direction and the two key-discard
moments: `Conn.writeHandshake` installs the spaces the driver reports, writes
its next message as a CRYPTO frame, hands over the transport parameters once,
and discards the Handshake keys when the driver reports confirmation. The other
direction waits for CRYPTO reassembly (below).

## The constraints already written down

`connection-constraints.md` holds two, both of which the machine satisfies by
construction:

- **Coalescing.** `feed` takes a datagram and walks it: parse the invariant
  header, choose the space from the version and packet type, unprotect, and on
  failure drop that packet and continue (RFC 9001 §5.5). A short header ends the
  walk because it has no Length field. `Long.packet_len` is where the next one
  starts.
- **Key discard.** `Space.discard()` exists now; the machine calls it at the two
  moments in the table above, and a packet arriving for a discarded space is
  dropped, not an error.

The third item in that note, the duplicated `largest_acked`, disappears: the
machine owns the only `Recovery.Space` per space, and `InitialSpace` is deleted
in the same change that lands the machine.

## The line

The machine owns: packet format and protection per space, packet number
assignment, ACK generation and ranges, the stream table and both stream halves,
stream and connection flow control counters, close, version negotiation and
Retry on the server side, the client's `connection_setup.Client`, and key
discard.

It refuses to own, because a caller does it better or because it needs a
resource a library must not hold:

- the socket, the clock value, and the send loop;
- the congestion controller — `Congestion` exists, the machine calls it and reads
  `canSend`, and implements no policy of its own;
- retransmission policy, over facts it hands over in full. A loss event names
  the frames that were in the lost packets, not a bare packet number: the caller
  cannot resend a STREAM range it is never told about, and if the machine kept
  the packet-to-frames mapping to itself every caller would maintain a parallel
  copy of it. Acknowledgements come back the same way, as the frames that are
  now known received. The caller owns a resend queue of frames it already has a
  description of; the machine keeps no mapping beyond the sent-packet records
  `Recovery.Space` already holds, and those exist for loss detection, not for
  the caller to query.
- pacing, ECN, PMTUD, stream scheduling, and any server policy with a clock in
  it (token minting, anti-amplification, idle timeout).

To be a QUIC endpoint a caller writes: a UDP socket, a monotonic clock, a
resend queue, a TLS driver satisfying the seam above, a `Congestion`, and its
application protocol. Those seven exist in `http` already or are the reason
`http.h3` will be a separate module.

## Size, in slices

The number Matt asked for, as increments that each end green. Line counts are
for `src/` plus their tests, which in this repo has run about 1:2.

| slice | what it is | size |
| --- | --- | --- |
| 1 | `Conn` skeleton: config, storage, `feed` that only parses and drops, the event union, a close path | ~250 |
| 2 | the three spaces: keys, packet numbers, protection in and out, ACK generation from `Recovery.Space` | ~400 |
| 3 | coalescing and the datagram walk, undecryptable packets dropped per §5.5 | ~150 |
| 4 | stream wiring: `StreamTable`, STREAM frames into `ReceiveStream`, segments out of `SendStream`, flow control counters | ~500 |
| 5 | connection close, `connection_setup` wired for the server side, client Retry/VN state | ~250 |
| 6 | key discard at the two moments, 1-RTT PTO arming, the `RecoveryDriver` loop in one place | ~200 |

About 1,750 lines with tests, or five to six working sessions. Slices 1 through
3 need no tls at all: a machine that parses, protects, and acknowledges can be
tested against itself and against `quiche-server --dump-packets`. Slice 4 needs
only stream state, which exists. Slices 5 and 6 are where the tls seam becomes
load-bearing, so the seam list above is the critical path and the only part that
can block everything after slice 4.

What is not in the number: `http.h3`, QPACK, stream scheduling, pacing, ECN,
PMTUD, key update, and the 0-RTT path. Each is its own note.

## Where to resume

State as of the three spaces, the datagram walk, key discard, the TLS seam,
frame parsing, streams, and the receive-side flow control generator: 199
tests.

### The TigerStyle pass

Landed after the note was written, in four commits. It changed no bytes on the
wire, and the round-trip and RFC vector tests that were already there stayed
byte-identical.

- `frame.write` is a switch over the §19 families, each one calling a helper
  that takes `(writer, payload)` and switches its own arms: `writeMarker`
  (§19.1, §19.2, §19.20), `writeStreamControl` (§19.4, §19.5),
  `writeStreamData` (§19.6, §19.7), `writeFlowControl` (§19.9 to §19.14),
  `writeConnectionId` (§19.15, §19.16), `writePath` (§19.17, §19.18), and
  `writeConnectionClose` (§19.19). `writeAck` and `writeStream` were already
  there. A frame that reaches a helper without a matching arm hits its
  `else => unreachable`, so the two lists are asserted against each other at
  runtime by the tests rather than by the compiler.
- `transport.decode` already refused a declared length past the end of the
  slice before it took anything, and had since the file was written; the guard
  is now pinned by a test with a length in the eight-byte form above `u32`,
  which is the case a `usize` or `u32` position would have hidden.
- `transport.encode` had no check on what a caller handed it, and its
  `writeVarint` called `error.Overflow` impossible: a parameter value above
  2^62 - 1 panicked, and a connection ID over 20 bytes was written even though
  this same decoder refuses those bytes. Both are `error.InvalidValue` now.
- `varint.size` is on the `u62` half of the range, so it needs no assertion and
  `varint.write` is the only place that refuses a value with no encoding.
- `Recovery` had a real overrun, not a style problem: `Events` was 64 records,
  the caller's sent table is any size, and one ACK covering more than 64 of them
  tripped the report's assertion, which in a release build is an out-of-bounds
  write. The report now takes the caller's storage (`Events.init(acked, lost)`),
  a report smaller than the table is `error.NoSpace` refused before anything
  moves, and `Space.sentValid` is asserted wherever the count moves. The
  index-versus-count hazard is the removal loop: `remove` moves the tail down,
  so the loop must not advance afterwards.
- Receive-side flow control exists: `Conn.flowControlOwed` reports the MAX_DATA
  and MAX_STREAM_DATA frames the application's reads have made due, and
  `Conn.onFlowControlSent` records the raises only once the caller puts them on
  the wire. `FlowControl` keeps its window and raises when half of it is
  consumed; `ReceiveStream.nextMaxStreamData` raises when the credit left is
  under half a ring. Deciding is separate from raising on purpose: a frame that
  never left must not widen a window.

What exists in `src/Conn.zig`:

- `Conn.init` derives the Initial keys from the connection ID, by role, and
  holds the connection IDs itself: a space is keys, counters, and received
  ranges, and a discarded space does not take the connection's identity away.
- `Conn.SpaceId` is `initial`, `handshake`, or `app`; `Conn.spaceFor` returns
  the space or `error.NoKeys`, and every space is optional. `Conn.discard`
  zeroes a space's keys and removes it (RFC 9001 §4.9), and the two moments of
  RFC 9000 §17.2.2.1 are wired: a client drops Initial keys when its first
  Handshake packet goes out, a server when its first one arrives.
- `Conn.feed` takes one packet and picks its space from the form and type
  (§12.3). `Conn.Datagram` walks a whole datagram: long headers delimit
  themselves, a short header ends it, a packet that will not unprotect or whose
  space is gone is counted in `dropped` and skipped (RFC 9001 §5.5), and bytes
  with no readable end stop stop the walk without an error.
- Every packet that opens has its payload parsed. CRYPTO frames go through
  `CryptoStream` — one ring per level, in the caller's storage — and then to the
  driver in order, whatever order the frames arrived in (§19.6). PADDING is
  consumed. Everything else is returned to the caller as `Conn.Opened.frames`,
  borrowed and in wire order, which is the list of what the machine has no home
  for yet. A frame that will not parse is a connection error (§12.4); only a
  packet that will not unprotect is dropped.
- `Conn.writeFrames`, `Conn.writeAck`, and `Conn.ackOwed` take the space they act
  on; `writeFrames` writes a short header for `app` and a long one otherwise.
- `Conn.writeHandshake` drives the `handshake` seam: transport parameters once,
  spaces installed from the secrets and the cipher suite the driver reports
  (`error.UnsupportedCipherSuite` rather than a substitution), one CRYPTO frame
  per call at the level the driver named, and the Handshake keys gone once
  `confirmed` says so (§4.9.2).

`src/handshake.zig` is the seam: the vtable, `Driver` with the context bound,
and `Stub` for a caller that has no TLS.

- Streams are wired: `Conn.stream_slots` and `Conn.streams` are the caller's
  storage and their length is the stream limit; a STREAM frame opens the stream
  it names (§2.1) and its bytes land in that stream's `ReceiveStream`; the
  connection-wide `FlowControl` counts the highest offset per stream (§4.1), and
  both limits are connection errors when a peer passes them. `Conn.writeStream`
  seals one `SendStream` segment per call, clamped by `FlowControl.Sender`.

What is still unwired, in the order I would take it:

1. `Recovery` has no caller in `Conn`, so nothing is acknowledged in the loss
   sense, nothing is ever declared lost, no PTO is armed, and ACK frames still
   come back in `Opened.frames` as caller events. The shape to build, because it
   is the one that does not create a self-reference:

   - `Conn.Config` gains `recovery: *Recovery` and three caller-owned sent
     tables (`sent_initial`, `sent_handshake`, `sent_app`). The `Recovery` must
     live outside `Conn`: `Recovery.Space` holds `*Recovery`, and `Conn` is
     returned by value from `init`, so a `Recovery` field inside `Conn` would
     leave every space pointing at the old address the moment `init`'s result is
     copied.
   - `Conn.Space` holds `?Recovery.Space`, created from `Config` on first use and
     taken away by `Conn.discard`, which also calls `Space.discard()` (§6.4:
     loss state goes with the keys).
   - `Conn` has no clock today, so every write and every feed grows a `now:
     Duration`. `writeFrames` also has to record the packet: whether it is
     ack-eliciting and in flight is a property of the frames the caller put
     inside, which the machine never parses, so the caller says it. An options
     struct keeps the two bools from being swapped.
   - `feed` gains enough information to route an ACK: `.ack` frames go to
     `space.recovery.onAckReceived(ack, now, options, events)` and stop coming
     back in `Opened.frames`. `events` is caller storage, passed in the same way
     `frames` is. `Options` (`max_ack_delay`, `peer_address_validated`,
     `handshake_confirmed`) comes from `Config` plus the handshake seam's
     `confirmed`.
   - The caller reads `nextTimer`/`onTimeout` through `RecoveryDriver`, which
     already exists and is tested; `Conn` should not grow a timer loop of its
     own.

2. `connection_setup` on the server side, Retry and version negotiation state on
   the client side, and the connection close path every error above is waiting
   for.
3. MAX_STREAMS when a stream slot frees. The receive-side MAX_DATA and
   MAX_STREAM_DATA generation landed; this is the one limit still never raised.
4. The stream scheduler that decides which `SendStream` gets the next packet.
5. `varint.decode`'s error set includes `NonMinimal`, which it never returns, so
   both callers carry an `unreachable` arm for it. Narrowing the set to
   `error{Truncated}` deletes those arms.

Two things the next agent should not re-derive:

- `error.NoKeys` is the only way the machine says a space is not there. It used
  to be a null optional next to a keys field; it is not any more, and a readiness
  flag would be the same mistake a third time.
- `protection.openPacket` mutates the packet in place, so the datagram the
  caller hands to `Datagram` is a receive buffer, not read-only bytes: header
  protection is an XOR. Feeding the same buffer twice does not work, which is
  why a test that wants to walk and then feed builds the packet twice.
- `Conn.dropped` counts packets the datagram could not process, and a frame that
  will not parse is not one of them: the packet decrypted, so the peer said
  something invalid and the connection closes (§12.4).
