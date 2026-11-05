# quic: QUIC in Zig: sans-I/O packet and frame codecs, transport parameters, and the loss recovery a connection needs. `just --list` shows the recipes.
# AGENTS.md holds the working conventions.

[private]
default:
    @just --list

[doc("Unit tests")]
[group("test")]
test:
    zig build test --summary all

[doc("Fuzz the codecs with an iteration budget, for example `just fuzz 50M`. A budget is required: without one the build runner opens a web UI and waits")]
[group("test")]
fuzz LIMIT="10M":
    #!/usr/bin/env bash
    # Zig 0.17.0's build runner exits 0 when a fuzz target fails, so the
    # failure has to be read out of the output. Without this, a crash in CI
    # would look like a pass.
    set -uo pipefail
    output=$(zig build test -Doptimize=ReleaseSafe --fuzz={{ LIMIT }} 2>&1)
    status=$?
    printf '%s\n' "$output"
    if [ "$status" -ne 0 ] || printf '%s' "$output" | grep -q "exited with code"; then
        echo "fuzz: a target found a failure" >&2
        exit 1
    fi

[doc("Lint Zig, Nix, Markdown, the workflows, and this justfile: ziglint, zig fmt, nix fmt, oxfmt, actionlint, zizmor, and just --fmt")]
[group("lint")]
lint:
    ziglint
    zig fmt --check src build.zig
    nix fmt -- --ci
    oxfmt --check README.md AGENTS.md .github
    actionlint
    zizmor .
    just --fmt --check

[doc("Format everything lint checks")]
[group("lint")]
fmt:
    zig fmt src build.zig
    nix fmt
    oxfmt README.md AGENTS.md .github
    just --fmt

[doc("Everything CI runs")]
[group("ci")]
ci: test lint
