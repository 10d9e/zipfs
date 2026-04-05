//! On-disk layout: `<root>/blocks/<cid-string>` (one file per block).

const std = @import("std");
const Blockstore = @import("blockstore.zig").Blockstore;

pub fn exportStore(store: *const Blockstore, root: []const u8) !void {
    const bpath = try std.fs.path.join(std.heap.page_allocator, &.{ root, "blocks" });
    defer std.heap.page_allocator.free(bpath);
    try std.fs.cwd().makePath(bpath);
    var d = try std.fs.cwd().openDir(bpath, .{});
    defer d.close();
    try store.exportFlatDir(d);
}

pub fn importStore(store: *Blockstore, allocator: std.mem.Allocator, root: []const u8) !void {
    const bpath = try std.fs.path.join(std.heap.page_allocator, &.{ root, "blocks" });
    defer std.heap.page_allocator.free(bpath);
    var d = std.fs.cwd().openDir(bpath, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer d.close();
    try store.importFlatDir(allocator, d);
}

pub fn repoRootFromEnv(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "IPFS_PATH")) |p| return p else |_| {}
    return try allocator.dupe(u8, ".zig-ipfs");
}
