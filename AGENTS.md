# AGENTS.md

Working notes for AI coding agents in baskingspot/quic.

## What this is

QUIC in Zig: sans-I/O packet and frame codecs, transport parameters, and the loss recovery a connection needs. It is incubating: unstable, with no promises about its API.

## Environment

Zig 0.17 only. The flake is the tool contract, from `baskingspot/nix`: `nix develop` provides Zig, `ziglint`, and the base tools, and nothing comes from the system PATH. The justfile is the command interface: `just test`, `just lint`, `just fuzz`, `just ci`. Run `just fmt` before you commit.

## Design

- Sans-I/O, no allocator. Nothing here opens a socket, holds a clock, or
  allocates. A decoder takes bytes and returns borrowed slices or fills
  caller-owned storage; an encoder fills a caller-owned buffer. An allocator
  never appears in the API, so a caller sees every byte it pays for.
- Two byte walkers and only two. `src/Cursor.zig` reads, `src/Writer.zig`
  writes, both over caller storage with a `u32` position. Every codec uses
  them. Do not add a third or a local position type.
- The writer hands back offsets. A packet header's Length field sits before
  the payload it counts, so a header writer returns the offset of that field
  and the caller patches it with `Writer.patch` once the payload exists.
- Packet protection is RFC 9001 and it lives in `protection.zig`, behind
  `protection.sealPacket` and `protection.openPacket`. The header codecs and
  the frame codec still read and write plaintext; a caller protects a packet
  after building it and unprotects one before parsing its frames.
- No hand-rolled cipher, MAC, or constant-time comparison, ever. The AEADs,
  AES-ECB, ChaCha20, and HKDF are `std.crypto`. A suite std does not provide is
  a missing feature, not an invitation: TLS_AES_256_GCM_SHA384 is absent
  because it needs SHA-384, and it says so in the doc comment.
- Initial keys come from the connection ID, not from TLS (RFC 9001 §5.2), so
  Initial protection is testable against Appendix A with no handshake. The TLS
  handshake itself, and the traffic secrets it produces, are a separate gate.
- `Recovery.zig` is RFC 9002 §5 and §6 for one space and stops at the edge of
  §7: it hands back the packets a timeout says to probe and never decides how
  many bytes may be in flight. The caller owns the clock and calls it with
  `Duration` values, so there is no timer, thread, or I/O in it.
- `InitialSpace.zig` is the driver, not a connection: keys, packet numbers,
  and the received ranges an ACK frame needs, for the Initial level only. When
  a change would need a timer, a retransmission, a stream, or a handshake, it
  belongs in a later module and not there.
- The TLS handshake is not in this repo. HTTP/3 and QPACK are not either.
  This is RFC 9000: packets, frames, transport parameters, and the loss
  recovery loop.
- Error sets are explicit and per codec. A decoder distinguishes `Truncated`
  (the buffer ended inside a field) from a protocol violation (`NonMinimal`,
  `InvalidAckRange`), because the caller's response differs: one waits for
  more bytes, the other closes the connection.
- A parse leaves the cursor where it found it on every error. Partial reads
  that move the position are how a caller ends up retrying from the middle of
  a varint.
- Tests cite the RFC section they pin, in the comment above the test. A
  codec with a loop gets a `std.testing.fuzz` target with a corpus. Rejecting
  hostile input is the job, not a hardening pass: a 62-bit length field, a
  zero-length connection ID, or an ACK range that underflows is an error path
  with a test.
- RFC text lives in `docs/research/rfcs/`. When the code and the RFC seem to
  disagree, read the RFC again before changing the code.

## Fuzzing

`just fuzz 5M` runs every `std.testing.fuzz` target under the build runner's
fuzz mode with an iteration budget. The budget is required: without one the
runner opens a web UI and waits.

Two traps on Zig 0.17.0, both hit while wiring this up:

- Do not call `Run.addPassthruArgs` on the test step. It forwards `--fuzz=`
  to the test runner, which rejects it with `panic: reached unreachable code`
  and no stack trace. `b.args` is gone in 0.17, so the fuzz step simply does
  not forward arguments.
- Do not set `.fuzz = true` on the module. That path segfaults in the runner
  (`fuzzer_new_input` reads uninitialized state) even on a trivial project.
  `zig build test --fuzz=N` sets what the runner needs.
- `zig build test --fuzz=N` exits 0 when a fuzz target fails. The `just fuzz`
  recipe reads the "exited with code" line out of the output and fails on it,
  because otherwise a crash reads as a pass in CI.

## Rules

- Commit messages are one line, `area: summary`, and every commit is signed. Do not rewrite pushed history.
- Gate commands on their exit codes, and claim only what you ran.
- Format with `zig fmt` and lint with `ziglint`. `just fmt` and `just lint` run both.
- This repo's GitHub settings come from `baskingspot/.github`, with `just settings`. Do not change them by hand.
- To graduate the project, follow the `baskingspot-new-repo` skill: logos, a real README, and the audit passing.

## Changelog

`CHANGELOG.md` is one file, Keep a Changelog format, newest first. Add a bullet
under `## [Unreleased]` in the same change that alters something a user can
notice: the public API, expected behavior, performance a benchmark row would
show, a supported backend, or the build requirements. Docs, CI, and internal
refactors do not need one unless they change how someone uses the package.

Write from the user's side: what changed, and what they must do about it. Name
the symbol, flag, or error. One line, under Added, Changed, Fixed, or Removed.

To release, dispatch the repo's `release.yml` with the version. The workflow
moves the Unreleased section into a dated heading, sets `.version` in
`build.zig.zon`, commits, tags, and opens the GitHub release. Do not tag by hand.
