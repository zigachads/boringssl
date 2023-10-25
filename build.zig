const std = @import("std");
const crypto = @import("crypto.zig");
const ssl = @import("ssl.zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const source = b.dependency("boringssl_source", .{});

    const crypto_library = try crypto.build(b, target, optimize, source);
    b.installArtifact(crypto_library);

    const ssl_library = try ssl.build(b, target, optimize, source);
    ssl_library.linkLibrary(crypto_library);
    b.installArtifact(ssl_library);
}
