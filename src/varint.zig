//! Protobuf-style unsigned varints (multicodec, multihash length, etc.).

const std = @import("std");

pub fn encodeU64(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try buf.append(gpa, @truncate((v & 0x7f) | 0x80));
        v >>= 7;
    }
    try buf.append(gpa, @truncate(v));
}

pub fn decodeU64(slice: []const u8, offset: *usize) error{Truncated}!u64 {
    if (offset.* >= slice.len) return error.Truncated;
    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const b = slice[offset.*];
        offset.* += 1;
        result |= @as(u64, b & 0x7f) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 63) return error.Truncated;
        if (offset.* >= slice.len) return error.Truncated;
    }
    return result;
}

pub fn u64EncodedLen(value: u64) usize {
    var v = value;
    var n: usize = 1;
    while (v >= 0x80) : (v >>= 7) n += 1;
    return n;
}
