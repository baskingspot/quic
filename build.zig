const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The one exported module. Everything below is a developer step, so a
    // consumer's fetch graph stops here.
    const mod = b.addModule("quic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The TLS driver over baskingspot/tls lives behind an option, the way tls
    // gates its own xev integration: a consumer that never asks for the driver
    // never fetches the dependency. `just test` passes -Dtls, so the driver
    // tests run in CI without making TLS part of every quic build.
    const expose_tls = b.option(
        bool,
        "tls",
        "Expose the quic-tls driver and fetch the baskingspot/tls dependency",
    ) orelse false;
    const tls_dep: ?*std.Build.Dependency = if (expose_tls)
        b.lazyDependency("tls", .{ .target = target, .optimize = optimize })
    else
        null;

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

    // What the seam asks of a TLS driver, checked against the package that has
    // to provide it. These tests exist to fail when baskingspot/tls closes a
    // gap: each one pins a place the two packages do not meet today, so the
    // day it meets them the work resumes instead of being forgotten.
    // The driver itself, and a second module because it imports tls: a
    // consumer that fetches `quic` must not fetch tls, so `quic-tls` exists
    // only behind `-Dtls`.
    if (tls_dep) |dependency| {
        const driver_mod = b.addModule("quic-tls", .{
            .root_source_file = b.path("src/tls.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = mod },
                .{ .name = "tls", .module = dependency.module("tls") },
            },
        });
        const driver_tests = b.addTest(.{ .root_module = driver_mod });
        test_step.dependOn(&b.addRunArtifact(driver_tests).step);

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
    }

    // The I/O shell over `std.Io`: a socket, a receive that waits, and a flush
    // that sends what the machine owes. Separate from `quic` so a caller that
    // never opens a socket never compiles std.Io.
    const io_mod = b.addModule("quic-io", .{
        .root_source_file = b.path("src/io.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = mod }},
    });
    const io_tests = b.addTest(.{ .root_module = io_mod });
    test_step.dependOn(&b.addRunArtifact(io_tests).step);

    // The echo example: the machine called the way an application would. It is
    // an executable rather than a test because its value is in being read.
    const echo_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = mod }},
    });
    const echo = b.addExecutable(.{ .name = "echo", .root_module = echo_mod });
    // Installed rather than merely built: `just example` runs it from
    // zig-out/bin, and a step that only compiles leaves nothing to run.
    const install_echo = b.addInstallArtifact(echo, .{});
    b.step("example-bin", "Build the echo example").dependOn(&install_echo.step);

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
