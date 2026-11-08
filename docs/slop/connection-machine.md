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
frame parsing, streams, the receive-side flow control generator, loss recovery,
the close path, the client's handshake attempt, CRYPTO retention, the client's
Retry, MAX_STREAMS, and the end of `InitialSpace`: 222 tests.

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
  consumed, STREAM frames go to their stream, and ACK frames go to loss
  recovery. Everything else is returned to the caller as `Conn.Opened.frames`,
  borrowed and in wire order, which is the list of what the machine has no home
  for yet. A frame that will not parse is a connection error (§12.4); only a
  packet that will not unprotect is dropped.
- `Conn.writeFrames`, `Conn.writeAck`, and `Conn.ackOwed` take the space they act
  on; `writeFrames` writes a short header for `app` and a long one otherwise.
  Every writer takes `now`, and `writeFrames` takes a `Conn.Write` that says what
  the machine cannot see: the send time, and whether the packet is ack-eliciting
  and in flight.
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

### Loss recovery is wired, and it is the caller's

The trap above is closed by the type. `Conn.Config.loss` is a `Conn.Loss`: the
caller's `*Recovery` plus one sent-packet table per space. `Conn` keeps only
handles built from it, so a `Conn` value copies correctly, and a test asserts the
pointers still name the caller's storage after a copy.

`Conn.Space.recovery` is a `Recovery.Space`, not the `?Recovery.Space` this note
first asked for. All three tables are required — `lossTablesValid` asserts it in
`init` — so every space always has one; the optional would have existed only to
express "no table", which is now a configuration error. `Conn.discard` empties
the loss space in place instead of taking it away, which is what keeps the
address a caller's `RecoveryDriver` already holds usable.

Two things `Recovery.Space` grew, both because the wiring found a hole:

- `discarded`. §6.2.2.1 arms an anti-deadlock probe when nothing is in flight and
  the peer's address is unvalidated, and that branch is unconditional: without a
  flag, a discarded space answers `nextTimer` with a probe at every call, forever.
  §6.4 says a discarded space contributes no timer, so it says so itself rather
  than asking the driver to remember.
- `hasRoom`, so a writer can refuse a full table before it seals anything.

Acknowledgments are the machine's now. `feed` and `Datagram.next` take the
caller's `Recovery.Events` and `now`; `.ack` goes to `onAckReceived` and no longer
appears in `Opened.frames`. The report describes one packet, so a call with no ACK
leaves it empty, and `finish` clears it for that reason. An ACK naming a packet
number this endpoint never used is `error.InvalidAckRange` (§19.3.1), refused
before the estimator moves. The delay field is scaled by `Config.ack_delay_exponent`
(§18.2) on the way in, because `Recovery` wants nanoseconds and saturates rather
than wrapping on a hostile 2^62.

Writers date what they send. `Conn.Write` carries the send time and the two
properties the machine cannot see for itself: ack-eliciting (§13.2.1) and in
flight (§7.1 of RFC 9002). A packet that is neither — an ACK on its own, a
CONNECTION_CLOSE — is not recorded, so an idle connection does not fill the sent
table with packets that will be reported lost and resent for nothing.

`Conn.close` and `Conn.State` landed with it. Every error the machine now returns
(`error.FlowControl`, `error.StreamLimit`, `error.InvalidAckRange`) is one the
caller closes the connection over, and `error_code.forFrameError` names the code,
so the machine being able to seal a CONNECTION_CLOSE was the missing half.

### CRYPTO retransmission, which is what Retry was really waiting on

The wall was never the Retry packet. Continuing after one means sending the same
ClientHello again, and nothing in the machine could do that: the bytes went to
the TLS driver, the machine kept `crypto_sent_bytes`, and the caller's resend
queue holds frame descriptions — for a CRYPTO frame, a range with no bytes behind
it. The same gap blocked §13.3 for a plain lost Initial or Handshake packet, so
the fix is not a Retry special case.

Approved shape, landed: `Config.crypto_sent` is the caller's buffer per level,
the machine copies every CRYPTO payload it seals into it after the packet leaves,
and `Conn.replayCrypto(space)` hands back what has been sent there from offset
zero.

- **Bounded.** A message that does not fit is `error.NoSpace` before any of it is
  framed. That failure is fatal by design: there is no retry to make, because
  `tls.next` has already handed the message over. §20.1 gives the caller
  CRYPTO_BUFFER_EXCEEDED, which is the same answer a receiver gives a peer whose
  handshake outgrows its buffer.
- **Idempotent by space.** The answer is "what has been sent in this space",
  which only grows, so calling twice returns the same bytes and a caller need not
  remember whether it replayed. `Conn.discard` forgets the level's bytes with the
  keys, so a discarded space returns nothing instead of a flight nobody can read.
- **Why the whole flight and not the unacknowledged part.** An ACK names packet
  numbers, and turning those back into CRYPTO ranges needs the packet-to-frame
  table this design refuses to keep. Re-sending a prefix is legal and cheap for a
  handshake (§19.6 makes the peer drop what it already has by offset).

### The client's Retry, landed

`Conn.onRetry(retry, raw)` is the whole of it, and the order inside it is the
design:

1. A server has no attempt, so it is `error.WrongRole`.
2. A Retry that does not name this endpoint's own Source Connection ID is
   `.ignored` before the tag is even checked (§17.2.5.2), because it costs
   nothing and settles the question.
3. The caller's `retry_storage` has to hold the connection ID plus the token, or
   the call is `error.NoSpace` — before any state moves, so a Retry cannot be
   half-accepted.
4. `connection_setup.Client.onRetry` decides `.ignored` against `.accepted` with
   the tag, the one-Retry rule, and the "after the server spoke" rule.
5. On acceptance the connection ID and token are copied out of the datagram and
   adopted, and `rekeyInitial` builds a live Initial space over the new
   Destination Connection ID (§5.2 of RFC 9001), keeping the packet number
   (§17.2.5.3) and leaving `crypto_sent[initial]` alone.

Things that were easy to get wrong and are now pinned by tests:

- **The datagram does not outlive the call.** `retry.source_connection_id` and
  `retry.token` point into the caller's receive buffer, which the caller reuses
  for the next packet. Both are copied into `Config.retry_storage`, and a test
  overwrites the Retry's bytes before the client sends again.
- **The rekey must not go through `discard`.** That calls `clear`, which forgets
  the level's CRYPTO bytes — and the ClientHello to re-send is exactly there.
- **The packet number is carried across.** A test has the client send at 0, take
  a Retry, re-send its flight, and the server reads packet number 1.
- **The new keys are the ones the server can read.** The same test builds the
  server from the Retry's Source Connection ID, which is where its Initial keys
  come from, and the retried packet opens.

### What is still unwired

Nothing from the old list: MAX_STREAMS landed with `Conn.closeStream`,
`InitialSpace` is deleted (its range tests moved to `Conn.Space.record` and its
fuzz target became one over `Conn.Datagram`), and `varint.decode`'s error set is
`error{Truncated}`.

### Packing, which is not scheduling

**The machine does not schedule.** Which stream deserves the next byte is a policy
over application intent, and it belongs to the caller, like congestion control and
the resend queue. What the machine owes is the ability to *pack*: `Conn.writeStreams`
takes the caller's ordered list of offers and fills one packet.

Three decisions, all of them the caller's half of the contract:

- **Partial, never refused.** A packet that fits three of five offers and then
  refuses wastes the window the congestion controller just granted. The machine
  writes what fits and reports `Consumed{ taken, partial }`: offers it is finished
  with, and bytes of the next one that went in. The caller re-offers from there. A
  stream with nothing sendable is finished with too, so an idle stream cannot
  stall the list behind it.
- **`null` is a different answer.** Nothing fit at all — the window had no room, or
  no offer had bytes. That is not the same as a packet that used part of the
  budget, and the two must not be confused by a caller deciding whether it is
  application-limited.
- **The description names the packet number.** `Packet{ length, number, frames,
  consumed }`, where each `Written` is `{ stream_id, offset, length, fin }`. The
  machine is the only party that knows which number the caller's ranges went out
  under, and the resend queue needs exactly that pairing to answer "which frames
  were in packet 5" — the same question losses answer for everything else.

The offsets in the description are the stream's, not the caller's offer, so a
caller advancing its own bookkeeping uses what went, not what it offered. And
`SendStream` grew `peekSegment`: a packer has to size a frame before committing to
it, because taking a segment it then cannot write loses the bytes — `nextSegment`
moves the cursor and there is no way back.

`Conn.writeStream` is gone rather than kept beside it. A one-stream caller writes
one `Offer`; a second path that returns no description is how a resend queue ends
up missing exactly the packets that were declared lost.

### Three things the next agent should not re-derive

- `error.NoKeys` is the only way the machine says a space is not there. It used
  to be a null optional next to a keys field; it is not any more, and a readiness
  flag would be the same mistake a third time.
- `protection.openPacket` mutates the packet in place, so the datagram the caller
  hands to `Datagram` is a receive buffer, not read-only bytes: header protection
  is an XOR. Feeding the same buffer twice does not work, which is why a test that
  wants to walk and then feed builds the packet twice — and why a test that feeds
  a packet after a close needs a packet built before the close.
- `Conn.dropped` counts packets the datagram could not process, and a frame that
  will not parse is not one of them: the packet decrypted, so the peer said
  something invalid and the connection closes (§12.4).

## What the echo example found

`examples/echo.zig` is the first caller that is not a test. Writing it produced
this list, in the order the friction bit. None of them are bugs; all of them are
places the machine knows something the caller has to reconstruct.

1. **A twenty-line struct before the first packet.** `Config` needs a `*Recovery`,
   three sent tables, one ring and one send buffer per stream, CRYPTO storage in
   both directions, and four buffers per `feed`. There is no default
   configuration and no type that says "build me one". The rule that a `Conn`
   must not move — every space holds pointers into the caller's state — is a
   comment, not a constraint the compiler sees.
2. **`writeHandshake` is the only way to install 1-RTT keys.** A server with
   nothing to say calls a function named "write handshake" and gets null, which
   is how its application space appears. Installing what the driver reported is
   not the same act as writing a packet, and the API says it is.
3. **No stream-readiness event.** The machine consumes a STREAM frame and tells
   nobody which stream moved, so an application scans `stream_table.iterator()`
   after every packet. Both halves of this example are that scan. The machine
   knew the stream ID at `onStreamFrame` and reports nothing.
4. **A peer-opened bidirectional stream needs `openStream`** to become writable,
   which reads like creating a stream rather than joining one, and wants the
   peer's per-stream limit again — a number that arrived in the handshake and
   that the machine never learned.
5. **`SendStream.write` takes less than it is given and says so only in its
   return value.** With no send buffer configured, 21 bytes became an empty FIN:
   the peer sees a closed stream with no data. The example now checks the count,
   because nothing in the machine will.
6. **Nothing checks that two stream slots have distinct buffers.**
   `streamsValid` checks lengths, not identity; the loss path grew a
   `tablesOverlap` assert for exactly this, and the stream side has nothing.
7. **The machine's packet description earned its keep in the first draft.** The
   example dropped `Packet.length` and had no way to delimit the packet for the
   socket: the send buffer is the caller's, so nothing else knows.
8. **Recovery's timer and congestion are not connected to the machine.** The
   caller builds `[]const *Recovery.Space` from `&conn.app.?.recovery`, which
   pins the connection's address forever, and reconstructs `Recovery.Options`
   because `Conn.recoveryOptions` is private. `Congestion` is not wired at all:
   `writeStreams` takes `max_payload` and nothing tells the caller what the
   controller allows.
9. **Acknowledgments are pull-only.** `ackOwed`/`writeAck` must be consulted per
   space per datagram or the peer never learns anything; the example skips it and
   the closing print shows the bill. `flowControlOwed` reports what is due in one
   list; acknowledgments have no equivalent summary.
10. **A server cannot be constructed from a datagram.** This example hardcodes
    both connection IDs. A real server parses the invariant header, chooses its
    own connection ID, and builds a `Conn` whose Initial keys come from the
    client's — a helper would remove the chance of pairing the wrong one.

Not friction, and worth saying: `writeStreams`, `feed`'s event report, and
`replayCrypto` were used exactly as designed, and the echo needed no reach into
machine internals.

## The queue, in Matt's order, and where the next session starts

Nothing in this list is built. It is ordered, with the reasoning, so the next
session starts with an edit and not a decision.

1. **`SendStream.write` must not be able to take part of what it is given (item
   5).** Today it returns the count and taking less is not an error; with no send
   buffer configured, a 21-byte write became a zero-length FIN and the peer saw a
   closed stream with no data, silently. The fix is the type, not a comment:
   `write(bytes) Error!void` takes all of it or `error.NoSpace`, so a short write
   does not exist; and `end()` becomes `finish()`, which can no longer publish a
   truncated stream because no write can be truncated. The example checks the
   count today, which is the workaround this item deletes. Call sites: every
   `SendStream` test, the three `openStream`/`write`/`end` sequences in
   `Conn.zig`'s tests, and `examples/echo.zig`.
2. **Distinct stream buffers must be asserted, not documented (item 6).**
   `streamsValid` checks lengths and not identity; two slots can point at one
   ring, and one stream silently overwrites another — the same bug class as
   shared CRYPTO flights. Add `buffersOverlap` and assert it in `init`, the way
   `tablesOverlap` already guards the sent tables. The example already hit this
   by writing `\@splat` over its stream slots and aliasing all four rings; it is
   one keystroke away.
3. **Report which streams received data (item 3).** `finish` consumes STREAM
   frames and reports nothing, so a caller scans `stream_table.iterator()` after
   every packet. Add to `Opened` a caller-storage list of `{ stream_id, newly
   readable, newly finished }`, filled at `onStreamFrame`, the same shape as the
   loss report: the machine states the fact and the caller decides.
4. **Build a server from a datagram (item 9).** A checked constructor:
   `Conn.Opening.fromDatagram(bytes)` reading the invariant header, plus a
   `Conn.Config` path that takes the client's connection ID as both the
   destination and the source of the Initial keys, and a generated server
   connection ID. This is also where connection ID derivation lives, which is a
   decision about the server's identity, not plumbing.
5. **`writeStreams` should report the window left (item 7).** Returning the
   remaining bytes in `Packet` keeps the policy with the caller and makes the
   coupling visible at the call site; the alternative, refusing past
   `Congestion.canSend`, puts policy inside the machine.
6. **`openStream` needs a second name (item 4).** Joining a peer-initiated stream
   and opening one of your own are different acts, and the join needs the peer's
   per-stream limit, which the machine should carry from the handshake rather than
   be handed again.
7. **`writeHandshake` is named for its side effect (item 2).** Installing the
   spaces a driver reported is not writing a packet; it will probably split in
   two.
8. **Acknowledgments need a summary (item 8).** `flowControlOwed` reports what is
   due in one list; `ackOwed`/`writeAck` make the caller ask per space.
9. **The twenty lines of caller state (item 1).** A default configuration and a
   debug assertion that a `Conn` is where it was initialised, since every space
   holds pointers into the caller's state.

Also worth recording: `zig build interop-bin` never installed its artifact, so
`just interop` could never have run. A test that cannot start is worse than no
test, and it survived because quiche is not installed anywhere this repo has run.

## The queue, landed

All nine, one commit each, `just ci` green between them. The order was the point:
the type fix went first so nothing built on a `write` that could truncate.

| # | what | commit |
| --- | --- | --- |
| 1 | `SendStream.write` takes all of it or `error.NoSpace`; `end` is `finish` | e1c9ce4 |
| 2 | `Conn.init` refuses two stream buffers over any shared byte | eef66d5 |
| 3 | `Opened.streams` says which streams a packet made readable or finished | b046237 |
| 4 | `Conn.Opening.fromDatagram` and `Opening.serverConfig` | 7b58f7a |
| 5 | `Packet.remaining` reports the granted budget this packet did not use | 31e2bc4 |
| 6 | `openStream` opens, `joinStream` joins, limits live in `Config.send_streams` | ba53751 |
| 7 | `installSpaces` installs keys; `writeHandshake` writes a message | 9d91a81 |
| 8 | `acksOwed` is the acknowledgment summary | 278001b |
| 9 | `Conn.clientConfig` and the move assertion | 179977c |

Three of them were not shaped the way this note guessed:

- **`Opening` copies, it does not borrow.** `protection.openPacket` rewrites a
  receive buffer in place, so a pointer into the datagram is dead before the
  server can send anything. `fromDatagram(bytes, storage)` copies both connection
  IDs into the caller's storage and refuses with `error.NoSpace` before writing a
  byte, which is the lesson `onRetry` already taught.
- **`Packet.remaining` is zero when the packet stopped on an offer.** §19.8 frames
  reserve their widest header before the data is measured, so a packet that
  refuses an offer has up to 25 bytes in hand that no next frame could use.
  Reporting those as room would tell a caller to write a packet that cannot carry
  anything; the field is the leftover only when the offer list ran out first.
- **`Conn.clientConfig` and `Opening.serverConfig` replace the identity lines, not
  the arrays.** A caller still declares its Recovery, its three sent tables, its
  stream rings, and its CRYPTO buffers. What is left of friction item 1 is the
  storage bundle, not the configuration.

The example exercises the new surface: server built from the client's datagram,
streams found from `Opened.streams`, the answer on a joined stream, the server's
keys from `installSpaces`, and both configs from a constructor.

### RESET_STREAM and STOP_SENDING, landed after the queue

One commit, `Conn`'s frame dispatch: a reset ends the receive half
(`ReceiveStream.onReset`, §19.4 and §4.5) and a stop resets the sending half
(`SendStream.onStopSending`, §3.5), with `StreamEvent` gaining `reset` and
`reset_owed`. Three shapes the RFC named and the tests pin: a RESET_STREAM for a
send-only stream, a STOP_SENDING for a receive-only stream, and a STOP_SENDING
for a locally initiated stream that was never opened are all STREAM_STATE_ERROR.
A STOP_SENDING for a peer bidi stream that no frame has reached yet opens it,
sending half included, because §3.2 says the frame does that and it may arrive
before the STREAM frame does.

The §19.8 checks came one commit later, with the memory they needed. A slot can
be freed by `closeStream`, so "not in the table" is ambiguous between
never-created and created-and-forgotten, and §3.3 says a delayed frame is legal.
`Conn` records the highest ordinal it has opened per direction
(`opened_local`): an id below it was created and a frame for it is ignored, an
id at or above it was never created and the frame is STREAM_STATE_ERROR. That is
the only state `closeStream` leaves behind, and it answers the same question for
a delayed STOP_SENDING.

### The recovery handles, landed after that

`Conn.Loss` gained `spaces: *[3]Recovery.Space`, the caller's storage for the
three spaces, and `Conn.Space.recovery` became a pointer into it. A
`RecoveryDriver` is now built over `&loss.spaces` and outlives a connection that
moves, because nothing it holds lives inside the `Conn`; the move assertion stays
for everything else. `Conn.recoveryOptions` is public, so the caller no longer
reconstructs the options the driver takes on every call.

`placeRecovery` is the only place that knows where the state lives, and three
calls reach it: `init` places all three spaces, because a driver over the array
must never read a slot that was never written; `installSpace` replaces the
Handshake or 1-RTT state in place when its keys arrive; and `rekeyInitial`
replaces the Initial one for a Retry, which is what a Retry wanted anyway —
fresh loss state, same address. CI caught the first version of this, where
`init` placed only Initial and the driver read two undefined spaces: the local
stack was zero and the runner's was not, which is the whole argument for
initializing rather than asserting.

### What is not wired, in the order the RFC makes it matter

1. **Connection ID changes are not adopted.** The echo keeps the client's and the
   server's IDs the same length, because a short header's destination length comes
   from the connection and nothing copies a peer's Source Connection ID into the
   destination when the two differ. NEW_CONNECTION_ID is not wired either.
2. **0-RTT**, which the constraints note already records as dropped, not buffered.

The queue in this note is empty; the next session starts at item 1 above, or at
whatever Matt puts ahead of it.
