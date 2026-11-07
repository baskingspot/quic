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

[doc("Answer a foreign client's first Initial with a Retry, then with version negotiation, and assert on the bytes it sends back. Needs quiche-client on PATH; skips with the exact command when it is absent")]
[group("test")]
interop:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v quiche-client >/dev/null 2>&1; then
        echo "interop: SKIP no quiche-client, so no foreign peer was reached."
        echo "interop: it is not in nixpkgs. Build it from a checkout:"
        echo "  git clone --depth 1 https://github.com/cloudflare/quiche"
        echo "  cd quiche && cargo build --release --bin quiche-client"
        echo 'interop: then: PATH="$PWD/target/release:$PATH" just interop'
        exit 0
    fi
    zig build interop-bin
    for mode in retry vn; do
        port=$(( 40000 + RANDOM % 20000 ))
        ./zig-out/bin/interop "$mode" "$port" &
        pid=$!
        sleep 0.3
        timeout 10 quiche-client --no-verify --idle-timeout 3000 "https://127.0.0.1:$port/" >/dev/null 2>&1 || true
        wait "$pid" || exit 1
    done

[doc("Lint Zig, Nix, Markdown, the workflows, and this justfile: ziglint, zig fmt, nix fmt, oxfmt, actionlint, zizmor, and just --fmt")]
[group("lint")]
lint:
    ziglint
    zig fmt --check src tools build.zig
    # The validator validates itself first: the fixtures are what tell the next
    # person who edits it that a rule they changed stopped working.
    zig run tools/changelog.zig -- --self-test
    zig run tools/changelog.zig
    nix fmt -- --ci
    oxfmt --check README.md AGENTS.md .github
    actionlint
    zizmor .
    just --fmt --check

[doc("Format everything lint checks")]
[group("lint")]
fmt:
    zig fmt src tools build.zig
    nix fmt
    oxfmt README.md AGENTS.md .github
    just --fmt

[doc("Everything CI runs")]
[group("ci")]
ci: test lint
