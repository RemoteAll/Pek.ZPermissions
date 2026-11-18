const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 依赖：SQLite/ORM（Pek.ZCode）与 Redis 客户端（Pek.ZRedis），二者共用 zzig
    const zcode_dep = b.dependency("zcode", .{ .target = target, .optimize = optimize });
    const zredis_dep = b.dependency("pek_zredis", .{ .target = target, .optimize = optimize });
    const zzig_dep = b.dependency("zzig", .{ .target = target, .optimize = optimize });

    const imports = [_]std.Build.Module.Import{
        .{ .name = "zcode", .module = zcode_dep.module("zcode") },
        .{ .name = "pek_zredis", .module = zredis_dep.module("pek_zredis") },
        .{ .name = "zzig", .module = zzig_dep.module("zzig") },
    };

    // 库模块：其它 Zig 项目可通过 `b.dependency("pek_zpermissions", .{}).module("pek_zpermissions")` 引用
    _ = b.addModule("pek_zpermissions", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &imports,
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &imports,
        }),
    });

    // CLI：三语言 JWT 互通对拍工具（gen / verify / inspect / selfcheck）
    const exe = b.addExecutable(.{
        .name = "zperm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &imports,
        }),
    });
    b.installArtifact(exe);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "运行单元测试（含 C# / Rust 互操作黄金样本）");
    test_step.dependOn(&run_tests.step);
}
