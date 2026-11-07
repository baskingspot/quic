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
//! So this reads the file as text and refuses three shapes:
//!
//! - a known section heading that does not own its line,
//! - a `###` heading with no blank line before it,
//! - the same section twice in one release, or a section this file does not use.
//!
//! Run by `just lint`, so no push and no CI run can carry the mistake.
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

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const text = Io.Dir.cwd().readFileAlloc(init.io, "CHANGELOG.md", arena, .limited(1 << 20)) catch |err| {
        std.debug.print("changelog: cannot read CHANGELOG.md: {t}\n", .{err});
        std.process.exit(1);
    };

    var failures: u32 = 0;
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
            std.debug.print(
                "changelog: {d}: '{s}' does not own its line, so it is not a heading\n",
                .{ number, heading },
            );
            failures += 1;
            break;
        }

        if (std.mem.startsWith(u8, trimmed, "### ")) {
            const name = trimmed[4..];
            const known = for (sections, 0..) |section, index| {
                if (std.mem.eql(u8, name, section)) break index;
            } else null;
            if (known) |index| {
                if (seen[index]) {
                    std.debug.print(
                        "changelog: {d}: '{s}' appears twice in release {d}\n",
                        .{ number, name, release },
                    );
                    failures += 1;
                }
                seen[index] = true;
            } else {
                std.debug.print(
                    "changelog: {d}: '### {s}' is not one of the six sections\n" ++
                        "changelog: the six are Added, Changed, Deprecated, Removed, Fixed, Security\n",
                    .{ number, name },
                );
                failures += 1;
            }

            // §style: a heading starts a block, so the line above it is blank.
            if (previous.len != 0) {
                std.debug.print("changelog: {d}: '### {s}' needs a blank line before it\n", .{ number, name });
                failures += 1;
            }
        }

        previous = trimmed;
    }

    if (failures != 0) {
        std.debug.print("changelog: {d} structure failure(s)\n", .{failures});
        std.process.exit(1);
    }
}
