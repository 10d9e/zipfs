//! Discover providers via DHT (bootstrap + iterative walk) and fetch raw blocks with bitswap.

const std = @import("std");
const blockstore = @import("../blockstore.zig");
const cid_mod = @import("../cid.zig");
const dht = @import("../dht.zig");
const multiaddr = @import("multiaddr.zig");
const libp2p_dial = @import("libp2p_dial.zig");
const dht_walk = @import("dht_walk.zig");
const bootstrap_resolve = @import("bootstrap_resolve.zig");
const resolver = @import("../resolver.zig");

pub const FetchError = error{NoBlockFromNetwork};

pub const FetchDagError = FetchError || error{ DagTooLarge, TruncatedLocalUnixFsRoot, IncompleteLocalUnixFsDag };

/// Limits for `fetchUnixfsDagIntoStore` (prevents runaway queues on hostile DAGs).
pub const FetchDagOpts = struct {
    max_blocks: u32 = 100_000,
    /// After a walk, if nothing was fetched, compare root UnixFS `filesize` (when present) to `catFile`
    /// length to catch a local root that satisfies `store.has` but is not the full DAG.
    verify_declared_unixfs_filesize: bool = true,
    /// When true with verification, a mismatch (or `catFile` failure) removes the root once and
    /// re-runs the walk. The nested call sets this false so a second failure becomes `IncompleteLocalUnixFsDag`.
    repair_root_on_size_mismatch: bool = true,
};

/// BFS over linked `dag-pb` blocks (and `raw` leaves): fetch each missing CID via bitswap + DHT,
/// same as Kubo-style multi-block retrieval. Returns the number of blocks newly fetched.
pub fn fetchUnixfsDagIntoStore(
    allocator: std.mem.Allocator,
    store: *blockstore.Blockstore,
    root_cid_str: []const u8,
    bootstrap_peers: []const []const u8,
    ed25519_secret64: [64]u8,
    direct_bitswap_peers: []const []const u8,
    opts: FetchDagOpts,
) !usize {
    var done: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var it = done.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        done.deinit(allocator);
    }

    var queue: std.ArrayList([]u8) = .empty;
    defer {
        queue.deinit(allocator);
    }

    try queue.append(allocator, try allocator.dupe(u8, root_cid_str));

    var fetched: usize = 0;
    var head: usize = 0;
    var processed: u32 = 0;

    defer {
        for (queue.items[head..]) |s| allocator.free(s);
    }

    while (head < queue.items.len) {
        const qwork = queue.items[head];
        head += 1;

        if (done.contains(qwork)) {
            allocator.free(qwork);
            continue;
        }
        // Dup before put: map keys must not point into queue.items — ArrayList growth reallocates
        // and would invalidate pointers stored in done (skipping most children on large DAGs).
        const owned = try allocator.dupe(u8, qwork);
        allocator.free(qwork);
        try done.put(allocator, owned, {});

        processed += 1;
        if (processed > opts.max_blocks) return error.DagTooLarge;

        if (!store.has(owned)) {
            const new_block = try fetchBlockIntoStore(allocator, store, owned, bootstrap_peers, ed25519_secret64, direct_bitswap_peers);
            if (new_block) fetched += 1;
        }

        if (!store.has(owned)) return error.NoBlockFromNetwork;

        var c_parse = try cid_mod.Cid.parse(allocator, owned);
        defer c_parse.deinit(allocator);
        if (c_parse.codec != cid_mod.codec_dag_pb) {
            // `raw` and unknown codecs: leaf (no link walk).
            continue;
        }

        // Replace stub/truncated chunked-file roots: local blob present but no dag-pb Links while
        // UnixFS `filesize` > 0 — otherwise BFS sees zero children and reports "complete".
        {
            const probe = store.get(allocator, owned) orelse return error.NoBlockFromNetwork;
            defer allocator.free(probe);
            if (try resolver.dagPbChunkedUnixFsRootMissingLinks(allocator, probe)) {
                _ = store.remove(allocator, owned);
                const repaired = try fetchBlockIntoStore(allocator, store, owned, bootstrap_peers, ed25519_secret64, direct_bitswap_peers);
                if (repaired) fetched += 1;
                if (!store.has(owned)) return error.NoBlockFromNetwork;
                const probe2 = store.get(allocator, owned) orelse return error.NoBlockFromNetwork;
                defer allocator.free(probe2);
                if (try resolver.dagPbChunkedUnixFsRootMissingLinks(allocator, probe2))
                    return error.TruncatedLocalUnixFsRoot;
            }
        }

        const children = try resolver.dagChildKeys(allocator, store, owned);
        defer {
            for (children) |c| allocator.free(c);
            allocator.free(children);
        }

        for (children) |child| {
            if (done.contains(child)) continue;
            try queue.append(allocator, try allocator.dupe(u8, child));
        }
    }

    if (fetched == 0 and opts.verify_declared_unixfs_filesize) {
        const root_block = store.get(allocator, root_cid_str) orelse return fetched;
        defer allocator.free(root_block);
        var root_c = try cid_mod.Cid.parse(allocator, root_cid_str);
        defer root_c.deinit(allocator);
        if (root_c.codec == cid_mod.codec_dag_pb) {
            const meta = try resolver.dagPbUnixFsFileMeta(allocator, root_block);
            if (meta.is_unixfs_file) if (resolver.unixFsDeclaredPayloadLen(meta)) |expected| {
                const actual = resolver.unixFsFilePayloadByteCount(allocator, store, root_cid_str) catch |e| switch (e) {
                    error.NotFound, error.BadBlock => {
                        if (!opts.repair_root_on_size_mismatch) return error.IncompleteLocalUnixFsDag;
                        _ = store.remove(allocator, root_cid_str);
                        const got_root = try fetchBlockIntoStore(allocator, store, root_cid_str, bootstrap_peers, ed25519_secret64, direct_bitswap_peers);
                        const sub = try fetchUnixfsDagIntoStore(allocator, store, root_cid_str, bootstrap_peers, ed25519_secret64, direct_bitswap_peers, .{
                            .max_blocks = opts.max_blocks,
                            .verify_declared_unixfs_filesize = true,
                            .repair_root_on_size_mismatch = false,
                        });
                        return (if (got_root) @as(usize, 1) else @as(usize, 0)) + sub;
                    },
                    else => |e2| return e2,
                };
                if (actual != expected) {
                    if (!opts.repair_root_on_size_mismatch) return error.IncompleteLocalUnixFsDag;
                    _ = store.remove(allocator, root_cid_str);
                    const got_root = try fetchBlockIntoStore(allocator, store, root_cid_str, bootstrap_peers, ed25519_secret64, direct_bitswap_peers);
                    const sub = try fetchUnixfsDagIntoStore(allocator, store, root_cid_str, bootstrap_peers, ed25519_secret64, direct_bitswap_peers, .{
                        .max_blocks = opts.max_blocks,
                        .verify_declared_unixfs_filesize = true,
                        .repair_root_on_size_mismatch = false,
                    });
                    return (if (got_root) @as(usize, 1) else @as(usize, 0)) + sub;
                }
            };
        }
    }

    return fetched;
}

/// Try DHT walk + bitswap until the block is in `store`. Returns true if a block was fetched.
/// `direct_bitswap_peers`: multiaddr strings (`/ip4/.../tcp/...` or `/dns4/.../tcp/...`) to try with bitswap
/// before the DHT (needed on private networks where public DHT does not return RFC1918 provider addrs).
pub fn fetchBlockIntoStore(
    allocator: std.mem.Allocator,
    store: *blockstore.Blockstore,
    cid_str: []const u8,
    bootstrap_peers: []const []const u8,
    ed25519_secret64: [64]u8,
    direct_bitswap_peers: []const []const u8,
) !bool {
    if (store.has(cid_str)) return false;

    var c = try cid_mod.Cid.parse(allocator, cid_str);
    defer c.deinit(allocator);

    for (direct_bitswap_peers) |addr_str| {
        const t = multiaddr.parseStringTcp(allocator, addr_str) catch continue;
        defer t.deinit(allocator);
        const blk = libp2p_dial.dialBitswapWant(allocator, t.host, t.port, cid_str, ed25519_secret64) catch continue;
        defer if (blk) |b| allocator.free(b);
        if (blk) |b| {
            try store.put(allocator, c, b);
            return true;
        }
    }

    const routing_key = try dht.providerKeyForMultihash(allocator, c.hash);
    defer allocator.free(routing_key);

    var providers: std.ArrayList(dht.Peer) = .empty;
    defer {
        for (providers.items) |p| dht.peerFree(allocator, p);
        providers.deinit(allocator);
    }

    const resolved = try bootstrap_resolve.resolveBootstrapPeers(allocator, bootstrap_peers);
    defer bootstrap_resolve.freeResolved(allocator, resolved);
    try dht_walk.walkGetProviders(allocator, routing_key, resolved, ed25519_secret64, .{}, &providers);

    for (providers.items) |prov| {
        for (prov.addrs) |ab| {
            const pt = multiaddr.tcpTargetFromAddrBytes(allocator, ab) catch |err| switch (err) {
                error.BadMultiaddr, error.Truncated => continue,
                else => |e| return e,
            };
            defer pt.deinit(allocator);

            const blk = libp2p_dial.dialBitswapWant(allocator, pt.host, pt.port, cid_str, ed25519_secret64) catch continue;
            defer if (blk) |b| allocator.free(b);
            if (blk) |b| {
                try store.put(allocator, c, b);
                return true;
            }
        }
    }
    return error.NoBlockFromNetwork;
}
