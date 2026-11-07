//! Check the structure of `CHANGELOG.md`: a semantic check, not a formatter.
//!
//! The failure this exists for is the one a formatter cannot see. Markdown does
//! not care whether `### Changed` starts a line, so a scripted edit that glued
//! the heading onto the end of the previous bullet produced a file that was
//! valid Markdown, looked fine in a rendered page, and silently moved a whole
//! section's entries under the section before it. The diff showed only the
//! bullet that was added, and the tests passed, because the library had not
//! changed at all.
//!
//! So this reads the file as text and counts four shapes as failures:
//!
//! - a known section heading that does not own its line,
//! - a `###` heading with no blank line before it,
//! - a `###` heading this file does not use,
//! - the same section twice in one release.
//!
//! `just lint` runs `--self-test` first, over the fixtures below, and then the
//! real file. A validator that is itself unvalidated is not a gate: the fixtures
//! are what tell the next person who edits this that a rule they changed stopped
//! working, and the known-good fixture is what keeps the tool from becoming a
//! rule that rejects everything.
//!
//! The headings are Keep a Changelog's, and the release headings are what the
//! release workflow moves bullets out of.

const std = @import("std");
const Io = std.Io;

/// Keep a Changelog's six sections, and the only `###` headings this file may
/// have inside a release.
const sections = [_][]const u8{
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
};

/// Room for the messages one check can produce. A file with more problems than
/// this still fails; only the tail of the report is cut.
const log_capacity = 4096;

const Report = struct {
    failures: u32,
    /// The messages, borrowed from the caller's buffer.
    log: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len > 1 and std.mem.eql(u8, args[1], "--self-test")) return selfTest();

    const text = Io.Dir.cwd().readFileAlloc(init.io, "CHANGELOG.md", arena, .limited(1 << 20)) catch |err| {
        std.debug.print("changelog: cannot read CHANGELOG.md: {t}\n", .{err});
        std.process.exit(1);
    };

    var log_buffer: [log_capacity]u8 = undefined;
    const report = check(text, &log_buffer);
    if (report.failures == 0) return;

    std.debug.print("{s}", .{report.log});
    std.debug.print("changelog: {d} structure failure(s)\n", .{report.failures});
    std.process.exit(1);
}

/// Count the structural failures in `text`, writing the messages into `log`.
fn check(text: []const u8, log: []u8) Report {
    var failures: u32 = 0;
    var used: usize = 0;
    var seen: [sections.len]bool = @splat(false);
    var release: u32 = 1;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var previous: []const u8 = "";
    var number: u32 = 0;
    while (lines.next()) |line| {
        number += 1;
        const trimmed = std.mem.trimEnd(u8, line, " \r");

        // A new release starts a new set of sections.
        if (std.mem.startsWith(u8, trimmed, "## ")) {
            seen = @splat(false);
            release += 1;
        }

        // A known heading has to be the whole line. This is the glued case, and
        // it is checked before the heading check below so the message says what
        // happened rather than "unknown section".
        for (sections) |section| {
            var buffer: [32]u8 = undefined;
            const heading = std.mem.print(&buffer, "### {s}", .{section}) catch unreachable;
            if (std.mem.find(u8, trimmed, heading) == null) continue;
            if (std.mem.eql(u8, trimmed, heading)) break;
            failures += 1;
            used += append(log[used..], "changelog: {d}: '{s}' does not own its line\n", .{ number, heading });
            break;
        }

        if (std.mem.startsWith(u8, trimmed, "### ")) {
            const name = trimmed[4..];
            const known = for (sections, 0..) |section, index| {
                if (std.mem.eql(u8, name, section)) break index;
            } else null;
            if (known) |index| {
                if (seen[index]) {
                    failures += 1;
                    used += append(log[used..], "changelog: {d}: '{s}' appears twice in release {d}\n", .{
                        number,
                        name,
                        release,
                    });
                }
                seen[index] = true;
            } else {
                failures += 1;
                used += append(log[used..], "changelog: {d}: '### {s}' is not one of the six sections\n", .{
                    number,
                    name,
                });
                used += append(log[used..], "changelog: the six are\n", .{});
                used += append(log[used..], "changelog: Added, Changed, Deprecated, Removed, Fixed, Security\n", .{});
            }

            // A heading starts a block, so the line above it is blank.
            if (previous.len != 0) {
                failures += 1;
                used += append(log[used..], "changelog: {d}: '### {s}' needs a blank line before it\n", .{
                    number,
                    name,
                });
            }
        }

        previous = trimmed;
    }

    return .{ .failures = failures, .log = log[0..used] };
}

/// Format one message into `log`, or drop it when the report is full. A cut
/// report still fails; the count is what the exit code depends on.
fn append(log: []u8, comptime format: []const u8, args: anytype) usize {
    const written = std.mem.print(log, format, args) catch return 0;
    return written.len;
}

/// Run the fixtures and fail when a rule stops rejecting, or a good file starts
/// being rejected.
///
/// Each case names the exact number of failures it must produce, not "more than
/// none": a rule that starts reporting twice per problem is a broken rule, and a
/// count is what makes that visible.
fn selfTest() void {
    const Case = struct { name: []const u8, text: []const u8, failures: u32 };
    const cases = [_]Case{
        // The known-good file. Two releases, each with a section of the same
        // name, because the duplicate rule is per release and must reset.
        .{ .name = "a correct changelog", .text = good, .failures = 0 },
        .{ .name = "a heading that does not own its line", .text = glued, .failures = 1 },
        .{ .name = "a heading with no blank line above it", .text = tight, .failures = 1 },
        .{ .name = "a section this file does not use", .text = unknown, .failures = 1 },
        .{ .name = "one section twice in a release", .text = duplicate, .failures = 1 },
    };

    var failed: u32 = 0;
    for (cases) |case| {
        var log_buffer: [log_capacity]u8 = undefined;
        const report = check(case.text, &log_buffer);
        if (report.failures == case.failures) continue;
        std.debug.print(
            "changelog --self-test: '{s}' produced {d} failure(s), expected {d}\n",
            .{ case.name, report.failures, case.failures },
        );
        std.debug.print("{s}", .{report.log});
        failed += 1;
    }

    if (failed != 0) {
        std.debug.print("changelog --self-test: {d} case(s) wrong\n", .{failed});
        std.process.exit(1);
    }
}

const good =
    \\# Changelog
    \\
    \\## [Unreleased]
    \\
    \\### Added
    \\
    \\- something new.
    \\
    \\## [0.1.0] - 2026-11-01
    \\
    \\### Added
    \\
    \\- the first release.
    \\
    \\### Fixed
    \\
    \\- a bug.
    \\
;

const glued =
    \\## [Unreleased]
    \\
    \\### Added
    \\
    \\- one
    \\both.### Changed
    \\- two
    \\
;

const tight =
    \\## [Unreleased]
    \\
    \\### Added
    \\
    \\- one
    \\### Changed
    \\
    \\- two
    \\
;

const unknown =
    \\## [Unreleased]
    \\
    \\### Notes
    \\
    \\- one
    \\
;

const duplicate =
    \\## [Unreleased]
    \\
    \\### Added
    \\
    \\- one
    \\
    \\### Added
    \\
    \\- two
    \\
;
