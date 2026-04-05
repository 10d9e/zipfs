//! Multibase: base58-btc (CID v0), base32 lower (multibase `b` for CID v1).

const std = @import("std");

const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encodeBase58Btc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var z: usize = 0;
    for (input) |b| {
        if (b == 0) z += 1 else break;
    }
    const body = input[z..];
    if (body.len == 0) {
        const r = try allocator.alloc(u8, z);
        @memset(r, '1');
        return r;
    }
    var work = try allocator.dupe(u8, body);
    defer allocator.free(work);

    var rev: std.ArrayList(u8) = .empty;
    defer rev.deinit(allocator);

    var wlen = work.len;
    while (true) {
        var rem: u64 = 0;
        for (0..wlen) |i| {
            rem = rem * 256 + work[i];
            work[i] = @truncate(rem / 58);
            rem = rem % 58;
        }
        try rev.append(allocator, base58_alphabet[@intCast(rem)]);

        var nz: usize = 0;
        while (nz < wlen and work[nz] == 0) nz += 1;
        if (nz == wlen) break;
        if (nz > 0) {
            std.mem.copyForwards(u8, work[0 .. wlen - nz], work[nz..wlen]);
            wlen -= nz;
        }
    }

    const total = z + rev.items.len;
    const out = try allocator.alloc(u8, total);
    @memset(out[0..z], '1');
    var i: usize = 0;
    while (i < rev.items.len) : (i += 1) {
        out[z + i] = rev.items[rev.items.len - 1 - i];
    }
    return out;
}

pub fn decodeBase58Btc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var num: [128]u8 = [_]u8{0} ** 128;
    var num_len: usize = 1;

    for (s) |ch| {
        const digit = decode58Digit(ch) orelse return error.InvalidChar;
        var carry: u16 = digit;
        var i: usize = 0;
        while (i < num_len) : (i += 1) {
            carry += @as(u16, num[i]) * 58;
            num[i] = @truncate(carry);
            carry >>= 8;
        }
        if (carry != 0) {
            if (num_len >= num.len) return error.Overflow;
            num[num_len] = @truncate(carry);
            num_len += 1;
        }
    }

    var leading: usize = 0;
    for (s) |ch| {
        if (ch == '1') leading += 1 else break;
    }

    while (num_len > 0 and num[num_len - 1] == 0) num_len -= 1;
    const body_len = num_len;
    const total = leading + body_len;
    const out = try allocator.alloc(u8, total);
    @memset(out[0..leading], 0);
    var j: usize = 0;
    while (j < body_len) : (j += 1) {
        out[leading + body_len - 1 - j] = num[j];
    }
    return out;
}

fn decode58Digit(c: u8) ?u8 {
    return switch (c) {
        '1'...'9' => c - '1',
        'A'...'H' => c - 'A' + 9,
        'J'...'N' => c - 'J' + 17,
        'P'...'Z' => c - 'P' + 22,
        'a'...'k' => c - 'a' + 33,
        'm'...'z' => c - 'm' + 44,
        '0', 'I', 'O', 'l' => null,
        else => null,
    };
}

/// RFC 4648 lowercase base32, no padding (multibase `b`).
pub fn encodeBase32Lower(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    if (input.len == 0) return allocator.dupe(u8, "");
    const out_len = (input.len * 8 + 4) / 5;
    const out = try allocator.alloc(u8, out_len);
    var bit_buf: u64 = 0;
    var bits: u6 = 0;
    var o: usize = 0;
    for (input) |b| {
        bit_buf = (bit_buf << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const idx = @as(u5, @truncate((bit_buf >> bits) & 0x1f));
            out[o] = alphabet[idx];
            o += 1;
        }
    }
    if (bits > 0) {
        const idx = @as(u5, @truncate((bit_buf << (5 - bits)) & 0x1f));
        out[o] = alphabet[idx];
        o += 1;
    }
    std.debug.assert(o == out_len);
    return out;
}

pub fn decodeBase32LowerAlloc(allocator: std.mem.Allocator, input: []const u8) error{ InvalidChar, OutOfMemory }![]u8 {
    var bit_buf: u64 = 0;
    var bits: u6 = 0;
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (input) |c| {
        const v: u5 = decode32Digit(c) orelse return error.InvalidChar;
        bit_buf = (bit_buf << 5) | v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            const byte = @as(u8, @truncate((bit_buf >> bits) & 0xff));
            try buf.append(allocator, byte);
        }
    }
    return try buf.toOwnedSlice(allocator);
}

fn decode32Digit(c: u8) ?u5 {
    return switch (c) {
        'a'...'z' => @intCast(c - 'a'),
        '2'...'7' => @intCast(26 + (c - '2')),
        else => null,
    };
}
