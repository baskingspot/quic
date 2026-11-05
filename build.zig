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

    // The pipe test: one client and one server exchanging Initial packets over
    // a buffer. Also outside the package.
    const loopback_mod = b.createModule(.{
        .root_source_file = b.path("tests/loopback.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = mod }},
    });
    const loopback_tests = b.addTest(.{ .root_module = loopback_mod });
    test_step.dependOn(&b.addRunArtifact(loopback_tests).step);

    // Fuzzing is driven by the build runner: `zig build test --fuzz=10M`. The
    // `fuzz` module option segfaults in the test runner on Zig 0.17.0, so the
    // module here stays plain and the flag does the work.
}
