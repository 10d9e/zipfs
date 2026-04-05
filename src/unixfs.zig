//! Minimal UnixFS `Data` protobuf (proto2) encoding for File / Raw.

const std = @import("std");
const varint = @import("varint.zig");

pub const DataType = enum(u32) {
    raw = 0,
    directory = 1,
    file = 2,
    metadata = 3,
    symlink = 4,
    hamt_shard = 5,
};

/// Encode `Data` message: Type (varint), optional Data bytes, optional filesize.
pub fn encodeData(allocator: std.mem.Allocator, typ: DataType, data: ?[]const u8, filesize: ?u64) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    // field 1, wire 0 (varint)
    try buf.append(allocator, 0x08);
    try varint.encodeU64(&buf, allocator, @intFromEnum(typ));
    if (data) |d| {
        try buf.append(allocator, 0x12); // field 2, wire 2
        try varint.encodeU64(&buf, allocator, d.len);
        try buf.appendSlice(allocator, d);
    }
    if (filesize) |fs| {
        try buf.append(allocator, 0x18); // field 3, wire 0
        try varint.encodeU64(&buf, allocator, fs);
    }
    return try buf.toOwnedSlice(allocator);
}
