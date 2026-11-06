# External interop: what is available, what it proves

Every test in this repo is us agreeing with ourselves. The RFC vectors from
9001 Appendix A are the exception, and they only cover protection. A symmetric
bug in our header parser, our frame writer, or our Retry tag would pass every
test we have. This note surveys what could give us a second opinion, in order of
what it costs us to reach.

Verified by reading source at the commits already cloned for the recovery
research: quiche `d7387df`, ngtcp2 `e82176c`. Anything marked *unverified* is
from the ecosystem, not read here.

## The four candidates

**quiche's examples** (`quiche/apps/src/bin/`): `quiche-client` and
`quiche-server`, Rust, one binary each. The server takes `--listen`,
`--cert`, `--key`, and `--no-retry`; it also takes `--dump-packets <dir>`,
which writes every packet it receives to a file whether or not it decrypts.
The client takes `--no-verify`, so a self-signed certificate is enough.
Building them is `cargo build --bin quiche-client --bin quiche-server` with
boringssl vendored through the `boring-sys` crate, which is the slow part
(minutes, and it wants cmake and a C compiler).

**ngtcp2's examples** (`ngtcp2/examples/`): `client.cc` and `server.cc`, about
95 KB of C++ each, plus `hq_*` and `http3_*`. They link a TLS backend
(gnutls, quictls, boringssl, or picotls) and nghttp3 for the HTTP/3 modes.
There is no mode that skips the handshake, so they hit the same wall as quiche
without offering anything quiche does not.

**quic-go's interop image** (*unverified*): a Docker image that speaks the
quic-interop-runner protocol. It is an endpoint for the runner, not a standalone
peer.

**quic-interop-runner**: the real thing, and the furthest away. It drives
Docker images through a test-case matrix (`handshake`, `retry`, `versionnegotiation`,
`transfer`, ...). An endpoint has to implement the runner's control interface and
speak QUIC with TLS. That is a connection machine plus a handshake, which is
exactly what we do not have.

## What each would prove

| Option | What it proves | What it needs from us |
| --- | --- | --- |
| quiche-server, receiving our Initial | that a foreign stack parses our long header, removes header protection, decrypts the payload, and reads our frames; a reply of any kind is the signal | a way to send one datagram (a tool binary), no TLS |
| quiche-client, answered with our VN or Retry | that a foreign stack accepts our Retry integrity tag and our version list, and re-sends with our token and connection ID | a tool binary that listens, no TLS |
| quiche-server, full exchange | that our frames, ack ranges, and stream data are accepted end to end | a TLS ClientHello and a connection machine |
| quic-interop-runner | everything above, as a scoreboard | a full endpoint plus TLS |

The first two are worth staring at. Neither needs a handshake, because both
happen before the crypto matters: a Retry is answered by the client's *second*
Initial, and that second Initial is all we need to see.

## What the server does with a packet that has no CRYPTO frame

A server that decrypts our Initial and finds no CRYPTO frame sends a
CONNECTION_CLOSE with PROTOCOL_VIOLATION, or drops the packet. Either outcome is
usable: a close is *encrypted with the Initial keys*, which we can derive, so a
close we can read proves our protection and our frame decoding against a
foreign implementation. Silence proves nothing, which is why
`quiche-server --dump-packets` matters: it writes the packet it received even
when it cannot process it, so "did it parse our header at all" becomes a file
size instead of a guess.

## Recommendation

Build one small tool, `tools/interop.zig`, run by `just interop`, that does two
things against `quiche-client` (both need the client binary and nothing else):

1. **Retry.** Listen on UDP, receive the client's first Initial, parse it with
   `packet.parseInvariant`, mint a Retry with `connection_setup.Retry.write`
   using the client's DCID as the original ID, and send it. The client validates
   the tag; if we are right it re-sends an Initial whose DCID is our Retry SCID
   and whose token is ours. Assert that, and the Retry tag has a second opinion.
2. **Version negotiation.** Answer a fresh Initial with a version list that
   excludes 1. `quiche-client` supports only 1, so §6.2 makes it abandon; the
   signal is that it does not send a second Initial with a different version.

Then, if we want the server direction, point `quiche-server` at a hand-built
Initial and check `--dump-packets` for a file: that only proves the header
parsed, and it is worth the twenty lines.

This is I/O, so it is a tool and not library code; the library stays sans-I/O.
The recipe must degrade to a skip with a loud line when `quiche-client` is not
installed, rather than fail CI on a machine that lacks it. The interop *runner*
is shelved until a connection machine exists, and the full quiche exchange is
blocked on the TLS ClientHello, which is the gate Matt is holding.

What none of this covers: a bug that only appears with a real handshake, stream
state, or loss recovery between real endpoints. Those need the machine.
