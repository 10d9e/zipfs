//! Content identifiers (CID v0 base58, v1 base32 multibase `b`).

const std = @import("std");
const multihash = @import("multihash.zig");
const multibase = @import("multibase.zig");
const varint = @import("varint.zig");

/// dag-pb
pub const codec_dag_pb: u64 = 0x70;
/// raw
pub const codec_raw: u64 = 0x55;

pub const Cid = struct {
    version: u8,
    codec: u64,
    hash: []const u8, // owned by caller / arena; multihash bytes

    pub fn deinit(self: Cid, allocator: std.mem.Allocator) void {
        allocator.free(self.hash);
    }

    pub fn clone(self: Cid, allocator: std.mem.Allocator) !Cid {
        const h = try allocator.dupe(u8, self.hash);
        return .{ .version = self.version, .codec = self.codec, .hash = h };
    }

    /// Binary CID: v0 = multihash only; v1 = 0x01 + codec varint + multihash.
    pub fn toBytes(self: Cid, allocator: std.mem.Allocator) ![]u8 {
        if (self.version == 0) {
            return try allocator.dupe(u8, self.hash);
        }
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        try buf.append(allocator, 1);
        try varint.encodeU64(&buf, allocator, self.codec);
        try buf.appendSlice(allocator, self.hash);
        return try buf.toOwnedSlice(allocator);
    }

    pub fn toString(self: Cid, allocator: std.mem.Allocator) ![]u8 {
        if (self.version == 0) {
            return multibase.encodeBase58Btc(allocator, self.hash);
        }
        const inner = try self.toBytes(allocator);
        defer allocator.free(inner);
        const b32 = try multibase.encodeBase32Lower(allocator, inner);
        defer allocator.free(b32);
        const out = try allocator.alloc(u8, 1 + b32.len);
        out[0] = 'b';
        @memcpy(out[1..], b32);
        return out;
    }

    pub fn parse(allocator: std.mem.Allocator, s: []const u8) !Cid {
        if (s.len >= 2 and s[0] == 'Q' and s[1] == 'm') {
            const decoded = try multibase.decodeBase58Btc(allocator, s);
            defer allocator.free(decoded);
            const mh = try multihash.decode(decoded);
            if (mh.code != multihash.code_sha2_256 or mh.digest.len != 32) {
                return error.InvalidCidV0;
            }
            return .{ .version = 0, .codec = codec_dag_pb, .hash = try allocator.dupe(u8, decoded) };
        }
        if (s.len >= 2 and s[0] == 'b') {
            const inner = try multibase.decodeBase32LowerAlloc(allocator, s[1..]);
            defer allocator.free(inner);
            return try fromBytes(allocator, inner);
        }
        return error.UnsupportedCidString;
    }

    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) !Cid {
        if (bytes.len >= 1 and bytes[0] != 1) {
            const mh = try multihash.decode(bytes);
            if (mh.code != multihash.code_sha2_256 or mh.digest.len != 32)
                return error.InvalidCidV0;
            return .{ .version = 0, .codec = codec_dag_pb, .hash = try allocator.dupe(u8, bytes) };
        }
        if (bytes.len < 3) return error.InvalidCidV1;
        var off: usize = 1;
        const codec = try varint.decodeU64(bytes, &off);
        const rest = bytes[off..];
        _ = try multihash.decode(rest);
        return .{ .version = 1, .codec = codec, .hash = try allocator.dupe(u8, rest) };
    }

    pub fn rawSha256(allocator: std.mem.Allocator, digest: *const [32]u8) !Cid {
        const mh = try multihash.wrapSha256(allocator, digest);
        return .{ .version = 1, .codec = codec_raw, .hash = mh };
    }

    pub fn dagPbSha256(allocator: std.mem.Allocator, digest: *const [32]u8) !Cid {
        const mh = try multihash.wrapSha256(allocator, digest);
        return .{ .version = 1, .codec = codec_dag_pb, .hash = mh };
    }

};

pub fn hashRawBlock(allocator: std.mem.Allocator, data: []const u8) !Cid {
    const d = multihash.digestSha256(data);
    return try Cid.rawSha256(allocator, &d);
}

pub fn hashDagPbBlock(allocator: std.mem.Allocator, data: []const u8) !Cid {
    const d = multihash.digestSha256(data);
    return try Cid.dagPbSha256(allocator, &d);
}
