# What the connection machine has to satisfy

Two constraints that are not bugs today because no connection machine exists.
`InitialSpace` is a prototype and both fall outside it. They become bugs the
moment a real connection is built on top of the codecs, so they are written down
here with the section that imposes each one.

A third, smaller constraint already lives in `src/InitialSpace.zig`'s module doc:
`largest_acked` is tracked twice, there and in `Recovery.Space`, and the
per-space type that replaces the prototype has to have one source of truth.

## 1. Coalescing: one datagram is not one packet

RFC 9000 §12.2. A datagram may carry several QUIC packets end to end. Long
header packets delimit themselves with the Length field; a short header has no
Length, so it runs to the end of the datagram and must be the last one.

The case that forces the design is the server's first flight: an Initial and a
Handshake packet coalesced into one datagram, because the server does not yet
know whether the client can read either. The client has to process both, and
they have different keys and different packet number spaces. A receiver that
assumes one packet per datagram silently drops the server's handshake data.

Three more things §12.2 and its neighbours require:

- **A packet that cannot be processed is dropped, not fatal.** §12.2: an endpoint
  that receives a packet it cannot process discards it. RFC 9001 §5.5 adds that
  a packet that will not unprotect is discarded rather than treated as a
  connection error, specifically so an attacker cannot kill a connection with a
  corrupted datagram. The loop that walks a datagram must continue after a
  failed unprotect.
- **0-RTT can arrive before the packet it depends on** (§17.2.3). A server may
  hold a 0-RTT packet whose Initial is not there yet; it either buffers it or
  discards it, and either way the rest of the datagram is processed normally.
- **The short header needs the connection's connection ID length** (§17.3.1:
  the length is not on the wire), so the datagram walker cannot be a pure
  function of bytes. It needs the connection.

What the codecs already give a walker: `packet.parseLong` returns `body_offset`,
`length`, and `rest`; `InitialSpace.open` returns `packet_len`. Nothing walks a
datagram for you, and it should not: the walk belongs where the keys and the
packet number spaces are.

Test to write when it lands: a server flight of Initial plus Handshake in one
buffer, fully processed by the client; and a datagram whose first packet is
corrupt, where the second is still processed.

## 2. Key discard: keys do not last forever

RFC 9001 §4.9 and RFC 9000 §17.2.2.1.

- **Initial keys go** when the first Handshake packet is sent (client) or
  received (server). §17.2.2.1 is explicit that no further Initial packets need
  to be exchanged after that, though ones in flight may still arrive.
- **Handshake keys go** when the handshake is confirmed (§4.9.2 of RFC 9001).
- **Loss state for the space goes with them.** RFC 9002 §6.4: when keys are
  discarded, all packets sent with them MUST be discarded and removed from the
  count of bytes in flight, and the loss detection timers MUST be reset, because
  a timer may be set for a space that no longer exists.

What that costs a connection that gets it wrong: a discarded space keeps its
sent packets, so bytes in flight never fall, the congestion window never opens
again, and every PTO fires for a space that cannot answer. The failure looks
like a stall with no error anywhere.

What exists today: nothing. `InitialSpace` has no discard path; `Recovery.Space`
can only empty its sent table through acknowledgment or loss; `protection.Keys`
is a plain struct a caller can hold forever. The pieces a `discard()` needs are
all present, they just have no method.

What the machine must have:

- a `discard()` per space that empties the sent table, clears `loss_time`, and
  makes the space contribute nothing to the next PTO;
- zeroing of the key material, so a discarded key is not still reachable;
- a policy for a packet that arrives for a discarded space: dropped, not an
  error (§17.2.2.1: a late Initial is expected, not a violation);
- and the RTT estimator left alone. It belongs to the connection, not the space
  (RFC 9002 A.2), so discarding the Initial space must not reset `smoothed_rtt`.

Test to write when it lands: after `discard()`, bytes in flight are zero, the
next timer is `none`, and an incoming packet for that space is dropped without
touching the RTT estimate.
