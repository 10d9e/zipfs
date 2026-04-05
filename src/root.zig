//! Zig IPFS: content-addressed blocks, CID v0/v1, UnixFS files (local blockstore).

const std = @import("std");

pub const varint = @import("varint.zig");
pub const multihash = @import("multihash.zig");
pub const multibase = @import("multibase.zig");
pub const cid = @import("cid.zig");
pub const unixfs = @import("unixfs.zig");
pub const dag_pb = @import("dag_pb.zig");
pub const blockstore = @import("blockstore.zig");
pub const importer = @import("importer.zig");
pub const resolver = @import("resolver.zig");
pub const repo = @import("repo.zig");

pub const Cid = cid.Cid;
pub const Blockstore = blockstore.Blockstore;

pub const Node = struct {
    store: Blockstore = .{},

    pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        self.store.deinit(allocator);
    }

    pub fn addFile(self: *Node, allocator: std.mem.Allocator, data: []const u8) !Cid {
        return importer.addFile(allocator, &self.store, data);
    }

    pub fn catFile(self: *const Node, allocator: std.mem.Allocator, cid_str: []const u8) ![]u8 {
        return resolver.catFile(allocator, &self.store, cid_str);
    }

    pub fn blockPut(self: *Node, allocator: std.mem.Allocator, data: []const u8) !Cid {
        const id = try cid.hashRawBlock(allocator, data);
        errdefer id.deinit(allocator);
        try self.store.put(allocator, id, data);
        return id;
    }

    pub fn blockGet(self: *const Node, allocator: std.mem.Allocator, cid_str: []const u8) ![]u8 {
        const b = self.store.get(cid_str) orelse return error.NotFound;
        return try allocator.dupe(u8, b);
    }
};

test "cid roundtrip v1" {
    const gpa = std.testing.allocator;
    const digest = multihash.digestSha256("hello");
    const c = try Cid.rawSha256(gpa, &digest);
    defer c.deinit(gpa);
    const s = try c.toString(gpa);
    defer gpa.free(s);
    const c2 = try Cid.parse(gpa, s);
    defer c2.deinit(gpa);
    try std.testing.expectEqual(c.version, c2.version);
    try std.testing.expectEqual(c.codec, c2.codec);
    try std.testing.expectEqualSlices(u8, c.hash, c2.hash);
}

test "add cat small file" {
    const gpa = std.testing.allocator;
    var node: Node = .{};
    defer node.deinit(gpa);
    const payload = "hello ipfs from zig";
    const root = try node.addFile(gpa, payload);
    defer root.deinit(gpa);
    const key = try root.toString(gpa);
    defer gpa.free(key);
    const out = try node.catFile(gpa, key);
    defer gpa.free(out);
    try std.testing.expectEqualStrings(payload, out);
}

test "add cat chunked file" {
    const gpa = std.testing.allocator;
    var node: Node = .{};
    defer node.deinit(gpa);
    var payload = std.ArrayList(u8).empty;
    defer payload.deinit(gpa);
    try payload.appendNTimes(gpa, 'x', importer.chunk_size + 1234);
    const root = try node.addFile(gpa, payload.items);
    defer root.deinit(gpa);
    const key = try root.toString(gpa);
    defer gpa.free(key);
    const out = try node.catFile(gpa, key);
    defer gpa.free(out);
    try std.testing.expectEqualSlices(u8, payload.items, out);
}