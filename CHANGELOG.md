# Changelog

All notable changes to quic are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `varint` decodes and writes the RFC 9000 §16 variable-length integer, in all
  four widths. `decodeMinimal` rejects a width wider than the value needs, which
  is what the frame type requires.
- `Cursor` and `Writer` read and write caller-owned bytes at a `u32`
  position.
