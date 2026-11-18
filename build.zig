const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 库模块：其它 Zig 项目可通过 `b.dependency("pek_zpermissions", .{}).module("pek_zpermissions")` 引用
    _ = b.addModule("pek_zpermissions", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // CLI：三语言 JWT 互通对拍工具（gen / verify / inspect / selfcheck）
    const exe = b.addExecutable(.{
        .name = "zperm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "运行单元测试（含 C# / Rust 互操作黄金样本）");
    test_step.dependOn(&run_tests.step);
}
