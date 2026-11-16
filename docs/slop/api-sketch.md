# The `quic-io` API, mirrored on `std.Io.net`

Status: agreed 2026-11-14 with Matt. This is the contract the code moves to.
Where this file and the code disagree, the code is wrong until this file is
changed on purpose.

## The rule

`quic-io` is `std.Io.net` with QUIC underneath. A program that reads a TCP
stream and a program that reads a QUIC stream must be the same code with a
different type. `Io` owns concurrency in both cases, so the library never
exposes a loop, a pump, or a "blocking" call: a sequential-looking method that
takes `io` is correct under every `Io` implementation.

Mirror, method for method:

| `std.Io.net` | `quic-io` | Notes |
|---|---|---|
| `IpAddress` | `IpAddress` | unchanged, it is the same type |
| `Server` | `Endpoint` | `accept(io)`, `deinit(io)` |
| `Server.accept(io) -> Stream` | `Endpoint.accept(io) -> Connection` | what you accept is what you then work on |
| `Stream` | `Stream` | one QUIC stream |
| `Stream.read(io, data: [][]u8) -> usize` | same | vectored, 0 means FIN for that direction |
| `Stream.shutdown(io, how)` | same | `ShutdownHow = enum { recv, send, both }` |
| `Stream.close(io) -> void` | same | both directions of this stream |
| `Stream.Reader.init(stream, io, buffer)` | same | returns `std.Io.Reader` |
| `Stream.Writer.init(stream, io, buffer)` | same | returns `std.Io.Writer` |
| — | `Connection.acceptStream(io) -> Stream` | a peer-opened stream |
| — | `Connection.openStream(io, dir) -> Stream` | `dir = enum { bidi, uni }` |
| — | `Connection.close(io)` | CONNECTION_CLOSE, NO_ERROR |

`shutdown` is where QUIC says something TCP cannot:

| `how` | QUIC |
|---|---|
| `.send` | FIN: the write half is closed, reads continue |
| `.recv` | STOP_SENDING: stop asking the peer for more |
| `.both` | RESET_STREAM, then STOP_SENDING |

## What the types hold

`Endpoint(Sizing)` and `Connection` own every buffer; nothing allocates and
nothing is sized by the caller except the four numbers in `Sizing`.

```zig
pub fn Sizing(comptime limits: SizingLimits) type;   // computes every dependent length

const SizingLimits = struct {
    streams: u16 = 4,          // concurrent streams, both directions
    stream_ring: u32 = 4096,   // receive ring and send buffer, per stream
    sent_packets: u16 = 32,    // loss recovery table per space
    crypto: u32 = 4096,        // CRYPTO reassembly and replay, per level
    datagram: u16 = 1500,      // one datagram in and out
};
```

A `Stream` is a small handle: a pointer to its slot in the sizing storage plus a
generation, so a stale handle cannot name a recycled stream. Streams are bounded
by `streams` and that is the point: `Sizing(.{ .streams = 256, ... })` is how a
program asks for 256, and it costs exactly what it says.

Measured after pooling streams (Zig 0.17.1, aarch64, default limits):

| | before | after | crypto by level | TLS flights allocated |
|---|---|---|---|---|
| `@sizeOf(Sizing(.{}))` | 104,648 | 68,936 | 61,256 | 44,192 |
| CRYPTO in `Sizing` (in: 4,096 + 4,096 + 512; sent: 4,096 + 4,096 + 0) | 24,576 | 24,576 | 16,896 | 16,896 |
| TLS in `Sizing` (`Storage(.{})`, then `Fixed(.{})`) | 22,720 | 22,720 | 22,720 | 5,656 |
| stream table, per `streams`, allocated in `listen`/`connect` | (in `Sizing`) | 736 | 736 | 736 |
| one live stream's slot (`StreamSlot`, 2 x `stream_ring`) | (in `Sizing`) | 8,192 | 8,192 | 8,192 |
| TLS allocated by `listen` (411-byte fixture chain: chain 411, out 1,622, peer Initial 3,201, peer Handshake 5,307, ServerHello 187) | (in `Sizing`) | (in `Sizing`) | (in `Sizing`) | 10,728 |
| TLS allocated by `connect` (out 3,201, peer Initial 3,201, peer Handshake 5,307) | (in `Sizing`) | (in `Sizing`) | (in `Sizing`) | 11,709 |
| `listen`/`connect` allocation, `preheat = 0`, `peer_initial = 1` | 0 | 15,304 | 15,304 | 26,032 / 27,016 |
| total up front, defaults (server / client) | 104,648 | 84,240 | 76,560 | 70,224 / 71,208 |
| `fixed_buffer_bytes`, then `listenBytes(411)` / `connect_bytes`, `preheat = 2` (the hq examples) | n/a | 27,568 (27,544 used) | 27,568 (27,544 used) | 38,272 / 39,256, exact |
| `allocation_bytes`, `preheat = 2`, chain at its 4,096 limit | n/a | n/a | n/a | 45,648 |

The pool's `ArenaAllocator` takes 12,360 bytes for its first 8,192-byte slot
and 16,384 for each slot after it when it grows in place, as on a
`FixedBufferAllocator`.

## Concurrency

`Connection` spawns **two** tasks with `Io.concurrent` when it is accepted or
connected, both in one `Io.Group`, both cancelled and awaited by `deinit`. They
take turns under one connection `Io.Mutex`:

- the receiver blocks in `socket.receive`, walks the datagram into the machine,
  and signals the per-stream conditions;
- the sender parks in `Condition.waitTimeout` until the earliest of the PTO/loss
  deadline and the idle timeout, then flushes what the machine owes.

Each stream has its own `Io.Condition`; `Stream.read` waits on it, cancelable
like every other `Io` wait. `Stream.write` signals the sender's condition rather
than touching the socket.

Two facts about `std.Io` forced this shape, and both are easy to walk into:

- **`Io.async` may run the function inline.** `Threaded.zig` calls the function
  at the call site when the busy count is at its limit or the future cannot be
  allocated, and returns a null future. A task that only ends when cancelled
  would therefore never return from `accept`. `Io.concurrent` instead fails with
  `error.ConcurrencyUnavailable`, which is a caller's error and not a deadlock.
- **One task cannot wait on a socket and a condition at once.**
  `Condition.wait` is a futex wait and `Socket.receive` is an `Operation`;
  `Io.Batch` takes operations and has no futex member. So "the writer signals
  the demux task" only works if the task is parked on a condition, which is why
  receiving and sending are separate tasks.

Consequences a caller sees:

- Stream operations carry `Io.Cancelable` in their error sets, exactly as
  `std.Io.net` operations do.
- `Connection.deinit` cancels the task and does not return with it running.
- Nothing in the API is `pub fn step`, `pub fn run`, or `pub fn flush`. If a
  caller needs to drive the machine by hand, it uses `quic.Conn` directly; that
  is what the sans-I/O layer is for.

## Where QUIC cannot mirror a socket, and what to do instead

1. **A handshake can fail after `accept` is called.** `Io.net.Server.accept`
   fails only on the socket; `Endpoint.accept` also reports transport failures,
   so its error set carries `Error.HandshakeFailed` and the transport errors by
   name.
2. **Streams have a transport limit, not a backlog.** `acceptStream` returns
   `error.StreamLimit` when the peer opens more than our parameters allow; the
   limit is a number we advertised, not a queue length.
3. **One connection, many streams.** A `Connection` is a multiplexer, which is
   why it exists as a type at all; a socket has exactly one stream.
4. **Close codes travel.** `Connection.close(io)` sends NO_ERROR; a program that
   wants another code calls `Connection.closeWith(io, code)`.

## Staging

1. Done (`c2d3cf5`): `Sizing`, `Endpoint`, `Connection`, `Stream` with the
   signatures above, two tasks as described, both hq examples migrated.
   `just interop-hq`, `just interop-go`, and `just interop-go-xnet` green.
2. `Reader`/`Writer` adapters over `std.Io.Reader`/`std.Io.Writer`.
3. Delete what the shell no longer needs from `src/io.zig` (the current
   eight-buffer `Config`, the manual `flush`/`receive` pair).
