const std = @import("std");
const zig_ipfs = @import("zig_ipfs");

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();

    _ = args.skip();

    var stderr_buf: [512]u8 = undefined;
    var stderr_filew = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_filew.interface;
    defer stderr.flush() catch {};

    const repo_root = try zig_ipfs.repo.repoRootFromEnv(gpa);
    defer gpa.free(repo_root);

    const cmd = args.next() orelse {
        try stderr.writeAll(
            \\zig-ipfs — local IPFS-style content addressing (CID, UnixFS, blockstore)
            \\
            \\Blocks are stored under $IPFS_PATH/blocks (default: ./.zig-ipfs/blocks).
            \\
            \\Usage:
            \\  zig-ipfs add <path>           Add file, print root CID (v1 base32)
            \\  zig-ipfs cat <cid>            Print file bytes from the repo
            \\  zig-ipfs block put <path>     Store raw block, print CID (codec raw)
            \\  zig-ipfs block get <cid>      Write raw block bytes to stdout
            \\  zig-ipfs id                   Show implementation id
            \\
        );
        return;
    };

    if (std.mem.eql(u8, cmd, "id")) {
        try std.fs.File.stdout().writeAll("AgentVersion: zig-ipfs/0.1.0\nProtocolVersion: experimental-local-only\n");
        return;
    }

    if (std.mem.eql(u8, cmd, "add")) {
        const path = args.next() orelse {
            try stderr.writeAll("add: missing path\n");
            return error.BadArgs;
        };
        const data = try std.fs.cwd().readFileAlloc(gpa, path, std.math.maxInt(usize));
        defer gpa.free(data);
        var node: zig_ipfs.Node = .{};
        defer node.deinit(gpa);
        const root = try node.addFile(gpa, data);
        defer root.deinit(gpa);
        try zig_ipfs.repo.exportStore(&node.store, repo_root);
        const s = try root.toString(gpa);
        defer gpa.free(s);
        try std.fs.File.stdout().writeAll(s);
        try std.fs.File.stdout().writeAll("\n");
        return;
    }

    if (std.mem.eql(u8, cmd, "cat")) {
        const cid_str = args.next() orelse {
            try stderr.writeAll("cat: missing cid\n");
            return error.BadArgs;
        };
        var node: zig_ipfs.Node = .{};
        defer node.deinit(gpa);
        try zig_ipfs.repo.importStore(&node.store, gpa, repo_root);
        const out = try node.catFile(gpa, cid_str);
        defer gpa.free(out);
        try std.fs.File.stdout().writeAll(out);
        return;
    }

    if (std.mem.eql(u8, cmd, "block")) {
        const sub = args.next() orelse {
            try stderr.writeAll("block: missing subcommand (put|get)\n");
            return error.BadArgs;
        };
        if (std.mem.eql(u8, sub, "put")) {
            const path = args.next() orelse {
                try stderr.writeAll("block put: missing path\n");
                return error.BadArgs;
            };
            const data = try std.fs.cwd().readFileAlloc(gpa, path, std.math.maxInt(usize));
            defer gpa.free(data);
            var node: zig_ipfs.Node = .{};
            defer node.deinit(gpa);
            const id = try node.blockPut(gpa, data);
            defer id.deinit(gpa);
            try zig_ipfs.repo.exportStore(&node.store, repo_root);
            const s = try id.toString(gpa);
            defer gpa.free(s);
            try std.fs.File.stdout().writeAll(s);
            try std.fs.File.stdout().writeAll("\n");
            return;
        }
        if (std.mem.eql(u8, sub, "get")) {
            const cid_str = args.next() orelse {
                try stderr.writeAll("block get: missing cid\n");
                return error.BadArgs;
            };
            var node: zig_ipfs.Node = .{};
            defer node.deinit(gpa);
            try zig_ipfs.repo.importStore(&node.store, gpa, repo_root);
            const raw = try node.blockGet(gpa, cid_str);
            defer gpa.free(raw);
            try std.fs.File.stdout().writeAll(raw);
            return;
        }
        try stderr.print("block: unknown subcommand {s}\n", .{sub});
        return error.BadArgs;
    }

    try stderr.print("unknown command: {s}\n", .{cmd});
    return error.BadArgs;
}

pub const std_options: std.Options = .{
    .log_level = .warn,
};
