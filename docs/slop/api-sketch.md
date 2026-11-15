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

## Concurrency

`Connection` spawns one task with `Io.async` when it is accepted or connected.
That task owns the socket: it reads datagrams, feeds the machine, arms the PTO
and idle timers with `Io.sleep`, and parks on an `Io.Condition` when there is
nothing to do. Each stream has its own `Io.Condition`; `Stream.read` waits on
it, cancelable like every other `Io` wait, and `Stream.write` signals the task
rather than touching the socket.

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

1. `Sizing` + `Endpoint` + `Connection` + `Stream` with the signatures above,
   `Endpoint.accept`/`Connection.openStream`/`acceptStream`/`Stream.read`/
   `write`/`shutdown`/`close`, driving the existing machine. Migrate
   `examples/hq_server.zig` and `examples/hq_client.zig`. `just interop-hq`,
   `just interop-go`, and `just interop-go-xnet` must stay green.
2. `Reader`/`Writer` adapters over `std.Io.Reader`/`std.Io.Writer`.
3. Delete what the shell no longer needs from `src/io.zig` (the current
   eight-buffer `Config`, the manual `flush`/`receive` pair).
