//! Multihash: `<code><digest length><digest>` with protobuf varints.

const std = @import("std");
const varint = @import("varint.zig");

/// https://github.com/multiformats/multicodec/blob/master/table.csv — sha2-256
pub const code_sha2_256: u64 = 0x12;

pub fn digestSha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

/// Allocates multihash bytes: code varint + len varint + digest.
pub fn wrapSha256(allocator: std.mem.Allocator, digest: *const [32]u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try varint.encodeU64(&buf, allocator, code_sha2_256);
    try varint.encodeU64(&buf, allocator, digest.len);
    try buf.appendSlice(allocator, digest);
    return try buf.toOwnedSlice(allocator);
}

pub fn decode(slice: []const u8) error{ Truncated, UnsupportedCode, UnsupportedDigestLen }!struct {
    code: u64,
    digest: []const u8,
} {
    var off: usize = 0;
    const code = try varint.decodeU64(slice, &off);
    const dlen = try varint.decodeU64(slice, &off);
    if (dlen > 128) return error.UnsupportedDigestLen;
    const dlen_usize: usize = @intCast(dlen);
    if (off + dlen_usize > slice.len) return error.Truncated;
    return .{ .code = code, .digest = slice[off .. off + dlen_usize] };
}
