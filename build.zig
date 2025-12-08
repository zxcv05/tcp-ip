const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("tcpip", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "tcpip",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const test_artifact = b.addTest(.{ .root_module = lib_mod });
    const test_step = b.step("test", "test lib");
    test_step.dependOn(&test_artifact.step);

    const exe = b.addExecutable(.{
        .name = "tcpip",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);
}
