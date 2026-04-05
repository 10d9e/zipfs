//! Read UnixFS file bytes from the local blockstore (dag-pb + raw leaves).

const std = @import("std");
const cid_mod = @import("cid.zig");
const Blockstore = @import("blockstore.zig").Blockstore;

const Cid = cid_mod.Cid;
const codec_raw = cid_mod.codec_raw;
const codec_dag_pb = cid_mod.codec_dag_pb;

fn readVarint(slice: []const u8, i: *usize) error{Truncated}!u64 {
    if (i.* >= slice.len) return error.Truncated;
    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const b = slice[i.*];
        i.* += 1;
        result |= @as(u64, b & 0x7f) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 63 or i.* >= slice.len) return error.Truncated;
    }
    return result;
}

fn readBytes(slice: []const u8, i: *usize) error{Truncated}![]const u8 {
    const len = try readVarint(slice, i);
    const n: usize = @intCast(len);
    if (i.* + n > slice.len) return error.Truncated;
    const r = slice[i.* .. i.* + n];
    i.* += n;
    return r;
}

const ParsedLink = struct {
    hash: []const u8,
    tsize: u64,
};

fn parseLink(msg: []const u8) error{Truncated}!ParsedLink {
    var i: usize = 0;
    var hash: ?[]const u8 = null;
    var tsize: u64 = 0;
    while (i < msg.len) {
        const tag = try readVarint(msg, &i);
        const field = tag >> 3;
        const wire = tag & 7;
        switch (field) {
            1 => {
                if (wire != 2) return error.Truncated;
                hash = try readBytes(msg, &i);
            },
            3 => {
                if (wire != 0) return error.Truncated;
                tsize = try readVarint(msg, &i);
            },
            else => {
                switch (wire) {
                    0 => _ = try readVarint(msg, &i),
                    2 => {
                        const skip_len = try readVarint(msg, &i);
                        const sn: usize = @intCast(skip_len);
                        if (i + sn > msg.len) return error.Truncated;
                        i += sn;
                    },
                    else => return error.Truncated,
                }
            },
        }
    }
    return .{ .hash = hash orelse return error.Truncated, .tsize = tsize };
}

const ParsedUnixFs = struct {
    typ: u64,
    data: []const u8,
};

fn parseUnixFs(msg: []const u8) error{Truncated}!ParsedUnixFs {
    var i: usize = 0;
    var typ: u64 = 0;
    var data: []const u8 = &.{};
    while (i < msg.len) {
        const tag = try readVarint(msg, &i);
        const field = tag >> 3;
        const wire = tag & 7;
        switch (field) {
            1 => {
                if (wire != 0) return error.Truncated;
                typ = try readVarint(msg, &i);
            },
            2 => {
                if (wire != 2) return error.Truncated;
                data = try readBytes(msg, &i);
            },
            else => {
                switch (wire) {
                    0 => _ = try readVarint(msg, &i),
                    2 => {
                        const skip_len = try readVarint(msg, &i);
                        const sn: usize = @intCast(skip_len);
                        if (i + sn > msg.len) return error.Truncated;
                        i += sn;
                    },
                    else => return error.Truncated,
                }
            },
        }
    }
    return .{ .typ = typ, .data = data };
}

/// UnixFS file type enum value (proto).
const unixfs_file: u64 = 2;

fn parseDagPbNode(allocator: std.mem.Allocator, block: []const u8) error{ Truncated, OutOfMemory }!struct {
    ufs_msg: ?[]const u8,
    links: []ParsedLink,
} {
    var ufs_msg: ?[]const u8 = null;
    var links = std.ArrayList(ParsedLink).empty;
    errdefer links.deinit(allocator);

    var i: usize = 0;
    while (i < block.len) {
        const tag = try readVarint(block, &i);
        const field = tag >> 3;
        const wire = tag & 7;
        switch (field) {
            1 => {
                if (wire != 2) return error.Truncated;
                ufs_msg = try readBytes(block, &i);
            },
            2 => {
                if (wire != 2) return error.Truncated;
                const enc = try readBytes(block, &i);
                const lnk = try parseLink(enc);
                try links.append(allocator, lnk);
            },
            else => {
                switch (wire) {
                    0 => _ = try readVarint(block, &i),
                    2 => {
                        const skip_len = try readVarint(block, &i);
                        const sn: usize = @intCast(skip_len);
                        if (i + sn > block.len) return error.Truncated;
                        i += sn;
                    },
                    else => return error.Truncated,
                }
            },
        }
    }
    return .{ .ufs_msg = ufs_msg, .links = try links.toOwnedSlice(allocator) };
}

fn catInto(allocator: std.mem.Allocator, store: *const Blockstore, key_utf8: []const u8, out: *std.ArrayList(u8)) error{ OutOfMemory, NotFound, BadBlock }!void {
    const block = store.get(key_utf8) orelse return error.NotFound;

    var root = Cid.parse(allocator, key_utf8) catch return error.BadBlock;
    defer root.deinit(allocator);

    if (root.codec == codec_raw) {
        try out.appendSlice(allocator, block);
        return;
    }
    if (root.codec != codec_dag_pb) return error.BadBlock;

    const parsed = parseDagPbNode(allocator, block) catch return error.BadBlock;
    defer allocator.free(parsed.links);

    const um = parsed.ufs_msg orelse return error.BadBlock;
    const ufs = parseUnixFs(um) catch return error.BadBlock;

    if (ufs.typ != unixfs_file) return error.BadBlock;

    if (ufs.data.len > 0) {
        try out.appendSlice(allocator, ufs.data);
        return;
    }

    for (parsed.links) |lnk| {
        const child = Cid.fromBytes(allocator, lnk.hash) catch return error.BadBlock;
        defer child.deinit(allocator);
        const ck = child.toString(allocator) catch return error.BadBlock;
        defer allocator.free(ck);
        try catInto(allocator, store, ck, out);
    }
}

/// Returns owned slice of file payload.
pub fn catFile(allocator: std.mem.Allocator, store: *const Blockstore, root_key_utf8: []const u8) error{ OutOfMemory, NotFound, BadBlock }![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try catInto(allocator, store, root_key_utf8, &buf);
    return try buf.toOwnedSlice(allocator);
}
