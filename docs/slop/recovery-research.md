# Recovery research: what real NewReno stacks do

Question from the lead: before writing congestion control, read how the live
implementations actually do it, and separate what is *correct* from what is
*being a full transport*. Nothing here is code we can use: I read for shape and
every number below is re-derived from the RFCs. No source was copied.

Sources read, shallow clones at these commits:

| Repo | Commit | License |
| --- | --- | --- |
| cloudflare/quiche | `d7387df` | BSD-2-Clause |
| quinn-rs/quinn | `aa61ce9` | MIT / Apache-2.0 |
| ngtcp2/ngtcp2 | `e82176c` | MIT |
| private-octopus/picoquic | `3e2e3d3` | BSD-style |

RFCs fetched into `docs/research/rfcs/`: 9002 (loss recovery), 9406
(HyStart++), 3168 (ECN).

## The short version

NewReno is three functions in all four stacks. RFC 9002 §7 is close to
complete, and what the working stacks add on top is not a different algorithm:
it is *gating* (app-limited, MTU probes, spurious losses) and *accounting
precision* (residues, batches, floors). The two things that most often go wrong
when reading a spec and writing code are the ones the RFC leaves open: where the
recovery period starts, and whether persistent congestion exists at all.

The finding worth acting on: **two of the four do not implement persistent
congestion.** quiche has no trace of §7.6 (only a BBR2 "persistent RTT jump",
which is a different idea), and picoquic mentions it once, in a comment inside
its Prague congestion controller. quinn and ngtcp2 implement it, and disagree
about where it may fire.

## 1. What a real implementation adds that the RFC does not say

**The unit of a congestion event is the ACK batch, not the packet.** quinn's
trait has `on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)`
next to the per-packet `on_ack` (`quinn-proto/src/congestion.rs:3-56`), ngtcp2
passes a whole `ngtcp2_cc_ack` struct into `congestion_event`
(`lib/ngtcp2_cc.c:167`), and quiche drains a `Vec<Acked>` in one call
(`quiche/src/recovery/congestion/reno.rs:70-73`). The reason is the recovery
period: you can only decide "was this loss already accounted for" once you know
the largest sent-time in the batch. A per-packet API forces the caller to
re-derive that, and gets it wrong under reordering.

**App-limited gating.** None of the RFC mentions it. quiche: `if r.app_limited
{ return; }` before growing the window (`reno.rs:80`). quinn: an `app_limited`
argument on `on_ack` (`congestion/new_reno.rs:56-61`). ngtcp2: `pkt->is_app_limited`
short-circuits the increase (`lib/ngtcp2_cc.c:137`). picoquic puts the comment in
the code: `/* Only increase CWIN if the path is CWIN limited. */`
(`picoquic/newreno.c:102`). This exists because growing cwnd on acknowledgments
for data the application was not trying to send is how a stack ends up
hammering the network after an idle period.

**Residue arithmetic.** The RFC says the window grows by one datagram per window
of bytes acked. Doing that with integers loses a fraction every time. ngtcp2
keeps the remainder: `m = mtu * pktlen + pending_add; pending_add = m % cwnd;
cwnd += m / cwnd` (`lib/ngtcp2_cc.c:151-154`). picoquic keeps `residual_ack` the
same way (`picoquic/newreno.c:110-113`). quiche instead tracks `bytes_acked_ca`
and resets it to `cwnd * factor` on a congestion event (`reno.rs:126-127`),
which is a different, cheaper approximation.

**Spurious loss undo.** picoquic restores the window when a repeat turns out to
be spurious and the loss was detected less than an RTT ago: `cwnd = 2 *
ssthresh` and back to congestion avoidance (`picoquic/newreno.c:126-160`).
quinn exposes the hook (`on_spurious_congestion_event`,
`congestion.rs:38`); ngtcp2 has no such path. This is RACK/TLP territory and
strictly optional for us.

**MTU probes are not congestion events.** quinn excludes a lost in-flight MTU
probe from `lost_packets` (`quinn-proto/src/connection/mod.rs:1804-1806`), and
ngtcp2 skips the congestion event entirely when only PMTUD packets were lost
(`lib/ngtcp2_rtb.c:1163-1166`). We have no MTU discovery, so this does not
apply yet, but it shows the shape: the CC is told about losses by something that
already knows which losses matter.

**The floor.** Every one of them clamps to two datagrams: quiche
`MINIMUM_WINDOW_PACKETS = 2` (`recovery/mod.rs:91`), quinn `2 * current_mtu`
(`congestion/new_reno.rs:38-40`), ngtcp2 `2 * max_tx_udp_payload_size`
(`lib/ngtcp2_cc.c:172-173`), picoquic `PICOQUIC_CWIN_MINIMUM`. RFC 9002 §7.2
says "at least two packets"; the implementations make it two *datagrams* so a
larger PMTU does not shrink the floor.

**Recovery is keyed on the sent time of the largest lost packet**, not on the
time the ACK arrived: quiche `in_congestion_recovery(packet.time_sent)`
(`recovery/congestion/mod.rs:176-183`), quinn `sent <= recovery_start_time`
(`congestion/new_reno.rs:93`), ngtcp2 `sent_time <= congestion_recovery_start_ts`
(`lib/ngtcp2_cc.c:137`). The RFC says the same in §7.3.2; the point is that all
three read the *packet's* timestamp, which is the thing a caller can get wrong
by passing `now`.

**picoquic uses a sequence number instead of a timestamp**: `recovery_sequence =
picoquic_cc_get_sequence_number(...)` and it enters recovery when
`recovery_sequence <= lost_packet_number` (`picoquic/newreno.c:69,126`). That
avoids a clock comparison entirely and is worth knowing about, because a
time-based recovery period is the one part of NewReno that needs a monotonic
clock and we are refusing to keep one.

## 2. Where they diverge

**Slow start exit.** All four leave slow start when `cwnd >= ssthresh`, and none
of them leaves it on ECN-CE by default: ECN is a separate notification that
enters recovery without changing the phase. The divergence is what else they
bolt on. quiche runs HyStart++ (RFC 9406) and exits to congestion avoidance when
CSS ends (`reno.rs:95-104`, `congestion/hystart.rs`). quinn adds the acked bytes
and checks the crossing, then seeds `bytes_acked` with the overshoot so the
first congestion-avoidance round is not lost (`new_reno.rs:63-77`). picoquic
keeps an explicit `alg_state` enum rather than inferring the phase from the
window. Ours should infer from `cwnd < ssthresh`: one field fewer, and the RFC's
§7.1/§7.2 make the phase a pure function of the two numbers.

**The recovery period.** As above: time in three, sequence number in one. quiche
also resets `bytes_acked_ca` to half the window on a congestion event, which
makes its congestion avoidance slightly more aggressive after a loss than the
RFC's description; quinn does not.

**Persistent congestion (§7.6).** This is where they disagree most.

- quinn computes it in the *connection*, not the controller
  (`connection/mod.rs:1780-1824`): `congestion_period = pto(Data) *
  persistent_congestion_threshold`, threshold 3 by default
  (`config/transport.rs:262-264`). It requires the run of lost packets to start
  after the first RTT sample (`first_packet_after_rtt_sample`), it resets the
  run whenever an intervening packet was acked, and it uses the **Data-space**
  PTO even when detecting loss in Initial or Handshake, with the comment "PTO
  computation must always include max ACK delay, i.e. operate as if in Data
  space (see RFC9002 §7.6.1)". Then it hands a boolean to the controller, which
  drops the window to the floor.
- ngtcp2 evaluates it only in the **application** space, only for packets sent
  after the handshake is confirmed (`lib/ngtcp2_rtb.c:1195-1204`), and on
  detection it additionally **resets min_rtt, smoothed_rtt and rttvar** to their
  initial values (`:1210-1215`). The comment gives the reasoning: during the
  handshake there is little data and people work hard not to trip it.
- quiche and picoquic: absent. A forced conclusion is that §7.6 is believed
  optional in the field, or expensive to get right; either way, if we implement
  it we own a behavior their stacks do not have, which is fine only if the tests
  are as good as the rest of the repo's.

**Pacing (§7.7).** Universal, four different mechanisms, all needing a clock:
ngtcp2 computes a pacing *rate* with gain 2.0 in slow start and 1.25 in
congestion avoidance, `pacing_interval = smoothed_rtt * 100 / gain / cwnd`
(`lib/ngtcp2_cc.c:60-82`), and leaves the sending to the application. quiche has
a token-bucket `Pacer` with burst and lumpy tokens
(`recovery/gcongestion/pacer.rs:62-80`). quinn has `connection/pacing.rs`.
picoquic uses a leaky bucket measured in nanoseconds per packet
(`picoquic/pacing.c:27-60`). Every one of them answers "may I send now?" from
inside a send loop. That is the seam we do not have.

## 3. What is the minimal correct thing for us

Split the list by *why* each feature exists.

Correctness, which we should own:

1. Bytes-in-flight accounting, with `in_flight` decided by the caller, because
   an ACK-only packet is not a congestion signal. The RFC's §7.1 initial window
   (10 datagrams, or 14720 bytes, whichever is smaller) is the start.
2. The recovery period, keyed on the sent time of the largest lost packet, so
   one loss episode halves the window once. Our `Recovery` already hands the
   caller the lost packets; what it does not hand over is that packet's send
   time, and it should.
3. The floor at two datagrams, and `cwnd = max(cwnd * 0.5, 2 * mds)`.
4. Slow start (one datagram per datagram acked) and congestion avoidance with a
   residue, because the residue is four lines and removes a known bias.
5. Persistent congestion, because without it a blackout leaves the window at the
   floor forever. The RFC's §7.6.2 period is `(smoothed_rtt + max(4*rttvar,
   kGranularity) + max_ack_delay) * 3`; it must be computed from the PTO of the
   space we have, and the run must start after the first RTT sample.

Being a full transport, which we should not own:

- app-limited detection (we have no application, and the caller knows better),
- pacing (needs a send loop and a "when may I send" answer),
- HyStart++, spurious-loss undo, BBR/BBR2, PRR, MTU-probe special cases,
- ECN validation.

The API shape that follows is small: `Congestion` with `onPacketSent(bytes)`,
`onPacketsAcked(bytes, sent_time)`, `onPacketsLost(lost_bytes,
largest_lost_sent_time, now)`, `onPersistentCongestion()`, `window()`, and a
`bytes_in_flight` the caller owns and we only read. The only durations it takes
are the ones `Recovery` already has, so no new clock. If a caller wants a pacing
rate, `3 * cwnd / (2 * smoothed_rtt)` is arithmetic they can do with our numbers;
we do not need to own it.

One open question for the lead: persistent congestion needs the *send time* of
the largest lost packet and the PTO, both of which live in `Recovery`. Two
options: `Recovery` computes `is_persistent_congestion` and returns it with the
loss event (quinn's shape), or `Congestion` takes the raw fields and decides.
quinn's split is better because the RTT estimator and the sent packets are
already there.

## Scope options

Three sizes. The middle one is what I would build.

| | Contains | Excludes | Size |
| --- | --- | --- | --- |
| **Minimum** | bytes in flight, recovery period on sent time, `cwnd = max(cwnd/2, 2*mds)`, slow start, congestion avoidance with a residue | persistent congestion, pacing, app-limited | ~120 lines, ~8 tests |
| **Recommended** | the above, plus persistent congestion decided in `Recovery` and handed to the controller as a boolean (§7.6), with the run starting after the first RTT sample and the connection's PTO used as the period | pacing, app-limited, ECN | ~180 lines, ~14 tests |
| **Full** | the above, plus a `pacingRate()` the caller may use (3/2 in slow start, 5/4 in avoidance, `rate = gain * cwnd / smoothed_rtt`), an `app_limited` flag the caller sets, and an `onEcnCe()` hook | a send loop, a clock, ECN validation, BBR, PRR | ~260 lines, ~20 tests |

What no option includes, because we own no socket and no clock: a send loop, a
pacer's timers, ECN validation state, or HyStart++. The Full option computes a
rate; it does not act on one.

Two decisions the lead should make explicitly:

1. **Persistent congestion or not.** Two of the four stacks surveyed skip it.
   Including it means a blackout recovers to the initial window instead of
   staying at the floor forever; excluding it is defensible and halves the
   surface. I recommend including it, in `Recovery`, because the sent times and
   the PTO are already there.
2. **Where `bytes_in_flight` lives.** A controller that owns a counter and a
   `Recovery.Space` that owns sent packets can disagree. Either the controller
   is handed the number by whoever owns the packets, or it keeps its own and we
   accept two counters. I recommend the first: the connection passes
   `bytes_in_flight` into `onPacketSent`/`onAck`/`onLoss`, exactly as quiche's
   `CongestionControlOps` does.

## 4. ECN

Who actually implements it:

- ngtcp2: the most complete. A four-state validation machine (TESTING, UNKNOWN,
  FAILED, CAPABLE; `lib/ngtcp2_conn.h:299-302`), a three-PTO testing window, and
  lost-marked-packet counts feeding failure detection (`lib/ngtcp2_rtb.c:1140-1175`).
- quinn: passes `is_ecn` into `on_congestion_event` (`congestion.rs:43`) and
  tracks receiving state in the connection; the validation lives outside the
  controller.
- picoquic: has a Prague congestion controller whose entire premise is ECN
  (`picoquic/prague.c:70` and the rest of that file).
- quiche: parses ECN counts in frames; the Reno path I read has no ECN branch at
  all.

Is it worth it before v0.1: no. It cannot be exercised without a socket that
sets the IP ECN field, a peer that echoes counts, and a path that does not
bleach them. None of that is testable in a library with no I/O, and the payoff
is a congestion response that is better on paths that support it. It is a
deployment feature. If it lands later, the shape to copy is ngtcp2's: a state
machine outside the congestion controller, feeding it a fifth "this loss was
ECN-marked" bit.

## What I did not read

BBR and BBR2 (`quiche/src/recovery/gcongestion/bbr*`, `ngtcp2/lib/ngtcp2_bbr.c`),
CUBIC, PRR and HyStart++ internals beyond their entry points, and multipath. If
any of those is on the table, this note is not the survey of them.
