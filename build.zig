const std = @import("std");

/// The crypto backend `baskingspot/tls` builds with. The names match its own
/// `-Dcrypto` option. Setting this value passes `crypto` to tls and makes the
/// tls dependency a separate package from a consumer's own tls dependency; a
/// consumer that also depends on tls must pass the same backend.
const CryptoBackend = enum { auto, native, openssl, @"aws-lc", boringssl };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The exported modules. A consumer of `quic` gets the codecs; a consumer
    // that builds TLS also gets the driver and the I/O shell. Everything else
    // below is a developer step.
    const mod = b.addModule("quic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The TLS driver over baskingspot/tls is built by default: QUIC requires
    // TLS 1.3, so a package that cannot connect is not much of a package.
    // `-Dno-tls` is the escape hatch for a codec-only build, which fetches no
    // tls and needs no crypto library at all.
    //
    // Unset uses the pinned native-default tls commit, so quic and a consumer
    // that also depends on tls resolve one shared package. Setting a backend
    // passes `crypto` to tls and deliberately forks the package; a consumer
    // that also depends on tls must pin the same commit and pass the same
    // value or the build has two tls packages. On the native backend a server
    // needs ECDSA P-256 or P-384 credentials; native has no RSA signing.
    // Ed25519 is a chain-signature scheme in tls, not a CertificateVerify
    // scheme, so it cannot sign the server's handshake.
    const no_tls = b.option(
        bool,
        "no-tls",
        "Build the codecs only, with no quic-tls driver and no baskingspot/tls build",
    ) orelse false;
    const crypto_backend = b.option(
        CryptoBackend,
        "crypto",
        "TLS crypto backend: unset uses the pinned native default; auto, native, " ++
            "openssl, aws-lc, or boringssl forks the tls package",
    );
    const tls_dep: ?*std.Build.Dependency = if (no_tls)
        null
    else if (crypto_backend) |backend|
        b.dependency("tls", .{
            .target = target,
            .optimize = optimize,
            .crypto = backend,
        })
    else
        b.dependency("tls", .{ .target = target, .optimize = optimize });

    // The driver imports tls; `quic` never does. Both modules are registered
    // before the consumer return so a package like http can reach `quic-io`.
    // The test artifacts, fixtures, and examples that need tls's files stay
    // below the return.
    const modules: ?struct {
        driver: *std.Build.Module,
        io: *std.Build.Module,
    } = if (tls_dep) |dependency| blk: {
        const driver = b.addModule("quic-tls", .{
            .root_source_file = b.path("src/tls.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "tls", .module = dependency.module("tls") },
            },
        });
        const io = b.addModule("quic-io", .{
            .root_source_file = b.path("src/io.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "quic-tls", .module = driver },
            },
        });
        break :blk .{ .driver = driver, .io = io };
    } else null;

    if (b.pkg_hash.len != 0) return;

    const test_step = b.step("test", "Run the unit tests");

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    test_step.dependOn(&run_mod_tests.step);

    // The RFC 9001 Appendix A vectors live outside `src/`, so the package a
    // consumer fetches does not carry them.
    const vector_mod = b.createModule(.{
        .root_source_file = b.path("tests/rfc9001.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = mod }},
    });
    const vector_tests = b.addTest(.{ .root_module = vector_mod });
    const run_vector_tests = b.addRunArtifact(vector_tests);
    test_step.dependOn(&run_vector_tests.step);

    // The seam tests below check what the seam asks of a TLS driver against the
    // package that has to provide it. They exist to fail when baskingspot/tls
    // closes a gap: each one pins a place the two packages do not meet today,
    // so the day it meets them the work resumes instead of being forgotten.
    if (tls_dep) |dependency| {
        const driver_mod = modules.?.driver;
        // The driver's tests need a certificate and key, which are tls's
        // fixtures and not copies this repository could let go stale.
        const driver_test_mod = b.createModule(.{
            .root_source_file = b.path("src/tls.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "tls", .module = dependency.module("tls") },
            },
        });
        driver_test_mod.addAnonymousImport("tls_server_crt", .{
            .root_source_file = dependency.path("tests/fixtures/server.crt"),
        });
        driver_test_mod.addAnonymousImport("tls_server_key", .{
            .root_source_file = dependency.path("tests/fixtures/server.key"),
        });
        const driver_tests = b.addTest(.{ .root_module = driver_test_mod });
        test_step.dependOn(&b.addRunArtifact(driver_tests).step);

        // The I/O shell over `std.Io`: a socket, a receive that waits, and a
        // flush that sends what the machine owes, with the handshake built
        // inside it. Separate from `quic` so a caller that never opens a socket
        // never compiles std.Io, and the machine stays free of crypto: the
        // dependencies run tls, then quic and quic-tls, then quic-io.
        const io_mod = modules.?.io;
        // Its tests listen with tls's fixture certificate, as the driver's do.
        const io_test_mod = b.createModule(.{
            .root_source_file = b.path("src/io.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "quic-tls", .module = driver_mod },
            },
        });
        io_test_mod.addAnonymousImport("tls_server_crt", .{
            .root_source_file = dependency.path("tests/fixtures/server.crt"),
        });
        io_test_mod.addAnonymousImport("tls_server_key", .{
            .root_source_file = dependency.path("tests/fixtures/server.key"),
        });
        const io_tests = b.addTest(.{ .root_module = io_test_mod });
        test_step.dependOn(&b.addRunArtifact(io_tests).step);

        const seam_mod = b.createModule(.{
            .root_source_file = b.path("tests/tls_seam.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "tls", .module = dependency.module("tls") },
            },
        });
        const seam_tests = b.addTest(.{ .root_module = seam_mod });
        const run_seam_tests = b.addRunArtifact(seam_tests);
        test_step.dependOn(&run_seam_tests.step);

        // The proof: two machines, two real drivers, certificates from tls's
        // own fixtures, and one stream each way. The fixture files are the
        // dependency's, so they are anonymous imports rather than paths this
        // repository could copy and let go stale.
        const loopback_mod = b.createModule(.{
            .root_source_file = b.path("tests/tls_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "quic-tls", .module = driver_mod },
                .{ .name = "tls", .module = dependency.module("tls") },
            },
        });
        loopback_mod.addAnonymousImport("tls_server_crt", .{
            .root_source_file = dependency.path("tests/fixtures/server.crt"),
        });
        loopback_mod.addAnonymousImport("tls_server_key", .{
            .root_source_file = dependency.path("tests/fixtures/server.key"),
        });
        const loopback_tests = b.addTest(.{ .root_module = loopback_mod });
        test_step.dependOn(&b.addRunArtifact(loopback_tests).step);

        // The hq-interop pair: a real handshake over loopback UDP carrying one
        // GET and its response. Both share `examples/hq.zig`, which is a file
        // beside them rather than a module, so each executable owns its copy.
        const install_hq_step = b.step("hq-bin", "Build the hq-interop server and client examples");
        for ([_][]const u8{ "hq_server", "hq_client" }) |name| {
            const hq_mod = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "quic", .module = mod },
                    .{ .name = "quic-io", .module = io_mod },
                },
            });
            const hq_exe = b.addExecutable(.{ .name = name, .root_module = hq_mod });
            install_hq_step.dependOn(&b.addInstallArtifact(hq_exe, .{}).step);
        }

        // The pair's shared file also holds the test that runs a server against
        // a client, both built from it: its own module, because a test needs the
        // fixture certificate and the executables do not.
        const hq_test_mod = b.createModule(.{
            .root_source_file = b.path("examples/hq.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "quic-io", .module = io_mod },
            },
        });
        hq_test_mod.addAnonymousImport("tls_server_crt", .{
            .root_source_file = dependency.path("tests/fixtures/server.crt"),
        });
        hq_test_mod.addAnonymousImport("tls_server_key", .{
            .root_source_file = dependency.path("tests/fixtures/server.key"),
        });
        const hq_tests = b.addTest(.{ .root_module = hq_test_mod });
        test_step.dependOn(&b.addRunArtifact(hq_tests).step);

        // The hello world: `quic-io` over loopback, a server and a client in
        // one process, with this repository's fixture certificate embedded.
        const echo_mod = b.createModule(.{
            .root_source_file = b.path("examples/echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "quic-io", .module = io_mod },
            },
        });
        echo_mod.addAnonymousImport("server_crt", .{ .root_source_file = b.path("tests/fixtures/server.crt") });
        echo_mod.addAnonymousImport("server_key", .{ .root_source_file = b.path("tests/fixtures/server.key") });
        const echo = b.addExecutable(.{ .name = "echo", .root_module = echo_mod });
        const install_echo = b.addInstallArtifact(echo, .{});
        b.step("example-bin", "Build the echo example").dependOn(&install_echo.step);
    }

    // The machine example: `quic.Conn` driven directly over a `quic.Storage`,
    // with a stub handshake and no socket shell, so it needs no TLS. It is an
    // executable rather than a test because its value is in being read.
    const machine_mod = b.createModule(.{
        .root_source_file = b.path("examples/machine.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = mod }},
    });
    const machine = b.addExecutable(.{ .name = "machine", .root_module = machine_mod });
    // Installed rather than merely built: `just machine` runs it from
    // zig-out/bin, and a step that only compiles leaves nothing to run.
    const install_machine = b.addInstallArtifact(machine, .{});
    b.step("machine-bin", "Build the bare-machine example").dependOn(&install_machine.step);

    // The external interop tool: a real UDP socket against a foreign client.
    // Developer-only, like the fuzz step; `just interop` runs it.
    const interop_mod = b.createModule(.{
        .root_source_file = b.path("tools/interop.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = mod }},
    });
    const interop = b.addExecutable(.{ .name = "interop", .root_module = interop_mod });
    const install_interop = b.addInstallArtifact(interop, .{});
    b.step("interop-bin", "Build the external interop tool").dependOn(&install_interop.step);

    // Fuzzing is driven by the build runner: `zig build test --fuzz=10M`. The
    // `fuzz` module option segfaults in the test runner on Zig 0.17.0, so the
    // module here stays plain and the flag does the work.
}
