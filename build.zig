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

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    b.step("test", "Run the unit tests").dependOn(&run_mod_tests.step);

    // Fuzzing is driven by the build runner: `zig build test --fuzz=10M`. The
    // `fuzz` module option segfaults in the test runner on Zig 0.17.0, so the
    // module here stays plain and the flag does the work.
}
