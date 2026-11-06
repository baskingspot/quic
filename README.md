# quic

QUIC in Zig: sans-I/O packet and frame codecs, transport parameters, and the loss recovery a connection needs.

This project is incubating. It is unstable, its API will change, and it is not ready to depend on.

## Work on it

Run `git config core.hooksPath .githooks` once, so the pre-commit hook runs `just lint`.

`nix develop` provides the toolchain, and `just ci` runs what CI runs.

## License

MIT. See `LICENSE`.
