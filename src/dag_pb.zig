//! dag-pb `PBNode` encoding (links + optional Data).

const std = @import("std");
const varint = @import("varint.zig");

pub const Link = struct {
    /// Full binary CID (v1 bytes or v0 multihash for compatibility).
    hash: []const u8,
    name: []const u8 = "",
    tsize: u64,

    pub fn encode(self: Link, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        // field 1 Hash
        try buf.append(allocator, 0x0a);
        try varint.encodeU64(&buf, allocator, self.hash.len);
        try buf.appendSlice(allocator, self.hash);
        if (self.name.len > 0) {
            try buf.append(allocator, 0x12);
            try varint.encodeU64(&buf, allocator, self.name.len);
            try buf.appendSlice(allocator, self.name);
        }
        try buf.append(allocator, 0x18);
        try varint.encodeU64(&buf, allocator, self.tsize);
        return try buf.toOwnedSlice(allocator);
    }
};

pub fn encodeNode(allocator: std.mem.Allocator, data: ?[]const u8, links: []const Link) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    if (data) |d| {
        try buf.append(allocator, 0x0a); // field 1 Data
        try varint.encodeU64(&buf, allocator, d.len);
        try buf.appendSlice(allocator, d);
    }
    for (links) |lnk| {
        const enc = try lnk.encode(allocator);
        defer allocator.free(enc);
        try buf.append(allocator, 0x12); // field 2 Links
        try varint.encodeU64(&buf, allocator, enc.len);
        try buf.appendSlice(allocator, enc);
    }
    return try buf.toOwnedSlice(allocator);
}
