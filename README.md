# quic

QUIC in Zig: packet and frame codecs, a sans-I/O connection machine, and loss recovery, with a std.Io driver on top.

This project is incubating. It is unstable, its API will change, and it is not ready to depend on.

The package is three modules. `quic` holds the machine: packets, frames, streams, flow control, transport parameters, congestion, and recovery, with no socket, clock, or allocator in the core. `quic-tls` drives the handshake over [baskingspot/tls](https://github.com/baskingspot/tls) and produces the traffic secrets. `quic-io` puts `std.Io.net` in front of it: an `Endpoint` that listens or connects, a multiplexed `Connection`, and a `Stream`.

This is RFC 9000 and the RFC 9001 packet protection around it. HTTP/3 and QPACK are not here.

The driver is the newest layer. What it does not do yet is listed in [`src/io.zig`](src/io.zig): congestion control in the driver, Retry and version negotiation, connection migration, and more than one connection per endpoint.

## Work on it

`nix develop` provides the toolchain, and `just ci` runs what CI runs.

## License

MIT. See `LICENSE`.
