//! Replication verification and audit: periodically probes peers to verify they
//! actually have the blocks they claim to have, removing stale confirmations and
//! triggering re-replication for missing blocks.

const std = @import("std");
const cluster_mod = @import("cluster.zig");
const cluster_push = @import("net/cluster_push.zig");
const repl_queue = @import("repl_queue.zig");

pub const AuditStats = struct {
    replicas_checked: u64 = 0,
    peers_checked: u64 = 0,
    blocks_confirmed: u64 = 0,
    blocks_missing: u64 = 0,
    blocks_repaired: u64 = 0,
    peer_unreachable: u64 = 0,
    last_audit_ns: i128 = 0,
    last_duration_ms: u64 = 0,
    running: bool = false,
    mu: std.Thread.Mutex = .{},

    pub fn snapshot(self: *AuditStats) AuditSnapshot {
        self.mu.lock();
        defer self.mu.unlock();
        return .{
            .replicas_checked = self.replicas_checked,
            .peers_checked = self.peers_checked,
            .blocks_confirmed = self.blocks_confirmed,
            .blocks_missing = self.blocks_missing,
            .blocks_repaired = self.blocks_repaired,
            .peer_unreachable = self.peer_unreachable,
            .last_audit_ns = self.last_audit_ns,
            .last_duration_ms = self.last_duration_ms,
            .running = self.running,
        };
    }
};

pub const AuditSnapshot = struct {
    replicas_checked: u64,
    peers_checked: u64,
    blocks_confirmed: u64,
    blocks_missing: u64,
    blocks_repaired: u64,
    peer_unreachable: u64,
    last_audit_ns: i128,
    last_duration_ms: u64,
    running: bool,
};

pub const AuditCtx = struct {
    repo_root: []const u8,
    interval_ns: u64 = 3600 * std.time.ns_per_s, // default 1 hour
    sample_rate: f32 = 0.2, // audit 20% of peers per cycle
    batch_size: u32 = 100, // audit 100 replicas per batch
    stats: AuditStats = .{},
    /// Shared mutex guarding ClusterState load/save.
    state_mu: *std.Thread.Mutex,
    /// Ed25519 secret for cluster authentication.
    ed25519_secret64: [64]u8,
    /// Cluster shared secret for authentication.
    cluster_secret: ?[]const u8 = null,
    /// Optional replication queue for direct re-enqueue (daemon mode).
    /// If null, falls back to file inbox notification.
    queue: ?*repl_queue.ReplQueue = null,
    /// Cluster mode for re-enqueued items.
    cluster_mode: cluster_mod.ClusterMode = .replicate,
    /// Replication factor for re-enqueued items.
    replication_factor: u8 = 2,
};

/// Background loop: run auditOnce periodically.
pub fn auditLoop(ctx: *AuditCtx) void {
    while (true) {
        auditOnce(ctx);
        std.Thread.sleep(ctx.interval_ns);
    }
}

/// Run a single audit pass over a batch of replicas.
pub fn auditOnce(ctx: *AuditCtx) void {
    const allocator = std.heap.page_allocator;
    const start_ns = std.time.nanoTimestamp();

    {
        ctx.stats.mu.lock();
        defer ctx.stats.mu.unlock();
        ctx.stats.running = true;
        ctx.stats.replicas_checked = 0;
        ctx.stats.peers_checked = 0;
        ctx.stats.blocks_confirmed = 0;
        ctx.stats.blocks_missing = 0;
        ctx.stats.blocks_repaired = 0;
        ctx.stats.peer_unreachable = 0;
    }

    // Load ClusterState under lock
    var state = blk: {
        ctx.state_mu.lock();
        defer ctx.state_mu.unlock();
        break :blk cluster_mod.ClusterState.load(allocator, ctx.repo_root) catch {
            finishAudit(ctx, start_ns);
            return;
        };
    };
    defer state.deinit();

    // Collect replica CIDs (up to batch_size)
    var cids_to_audit = std.ArrayList([]const u8).empty;
    defer {
        for (cids_to_audit.items) |c| allocator.free(c);
        cids_to_audit.deinit(allocator);
    }

    var replica_iter = state.replicas.iterator();
    var collected: u32 = 0;
    while (replica_iter.next()) |entry| : (collected += 1) {
        if (collected >= ctx.batch_size) break;
        const rec = entry.value_ptr.*;
        if (rec.confirmed_peers.len == 0) continue; // nothing to audit

        const cid_copy = allocator.dupe(u8, rec.cid) catch continue;
        cids_to_audit.append(allocator, cid_copy) catch {
            allocator.free(cid_copy);
            continue;
        };
    }

    // Audit each replica
    for (cids_to_audit.items) |cid| {
        auditReplica(ctx, &state, cid);
        // Yield between audits to avoid starving normal operations
        std.Thread.yield() catch {};
    }

    // Save updated state with removed peers (merge pattern)
    state.mergeSave(ctx.repo_root, ctx.state_mu);

    finishAudit(ctx, start_ns);
}

fn finishAudit(ctx: *AuditCtx, start_ns: i128) void {
    const end_ns = std.time.nanoTimestamp();
    const dur_ms: u64 = @intCast(@max(0, @divFloor(end_ns - start_ns, std.time.ns_per_ms)));
    ctx.stats.mu.lock();
    defer ctx.stats.mu.unlock();
    ctx.stats.running = false;
    ctx.stats.last_audit_ns = end_ns;
    ctx.stats.last_duration_ms = dur_ms;
}

/// Audit a single replica: sample N% of confirmed_peers and verify they have the block.
fn auditReplica(ctx: *AuditCtx, state: *cluster_mod.ClusterState, cid: []const u8) void {
    const allocator = std.heap.page_allocator;

    const rec = state.replicas.getPtr(cid) orelse return;
    if (rec.confirmed_peers.len == 0) return;

    {
        ctx.stats.mu.lock();
        defer ctx.stats.mu.unlock();
        ctx.stats.replicas_checked += 1;
    }

    // Sample peers (at least 1, at most all)
    const sample_count = @max(1, @as(usize, @intFromFloat(@as(f32, @floatFromInt(rec.confirmed_peers.len)) * ctx.sample_rate)));
    const to_check = @min(sample_count, rec.confirmed_peers.len);

    // Shuffle indices for random sampling
    var indices = std.ArrayList(usize).empty;
    defer indices.deinit(allocator);
    var i: usize = 0;
    while (i < rec.confirmed_peers.len) : (i += 1) {
        indices.append(allocator, i) catch continue;
    }
    // Simple Fisher-Yates shuffle
    if (indices.items.len > 1) {
        var rng = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
        const random = rng.random();
        var n = indices.items.len;
        while (n > 1) {
            n -= 1;
            const k = random.uintLessThan(usize, n + 1);
            const tmp = indices.items[n];
            indices.items[n] = indices.items[k];
            indices.items[k] = tmp;
        }
    }

    var peers_to_remove = std.ArrayList([]const u8).empty;
    defer {
        for (peers_to_remove.items) |p| allocator.free(p);
        peers_to_remove.deinit(allocator);
    }

    var checked: usize = 0;
    for (indices.items) |idx| {
        if (checked >= to_check) break;
        checked += 1;

        const peer_addr = rec.confirmed_peers[idx];

        // Parse host:port from multiaddr
        const hp = cluster_push.parseHostPort(allocator, peer_addr) catch {
            // Malformed address — skip (don't remove, might be config issue)
            continue;
        };
        defer allocator.free(hp.host);

        {
            ctx.stats.mu.lock();
            defer ctx.stats.mu.unlock();
            ctx.stats.peers_checked += 1;
        }

        // Verify peer has the block
        const result = verifyReplica(allocator, hp.host, hp.port, cid, ctx.cluster_secret, ctx.ed25519_secret64);

        if (result) |has_block| {
            if (has_block) {
                // Peer confirmed — good!
                ctx.stats.mu.lock();
                defer ctx.stats.mu.unlock();
                ctx.stats.blocks_confirmed += 1;
            } else {
                // Peer does NOT have the block — remove from confirmed_peers
                std.log.warn("audit: peer {s} missing block {s}, removing from confirmed_peers", .{ peer_addr, cid });
                const peer_copy = allocator.dupe(u8, peer_addr) catch continue;
                peers_to_remove.append(allocator, peer_copy) catch {
                    allocator.free(peer_copy);
                    continue;
                };
                ctx.stats.mu.lock();
                defer ctx.stats.mu.unlock();
                ctx.stats.blocks_missing += 1;
            }
        } else |err| {
            // Peer unreachable or error — log but don't remove (temporary network issue)
            std.log.warn("audit: peer {s} unreachable for {s}: {}", .{ peer_addr, cid, err });
            ctx.stats.mu.lock();
            defer ctx.stats.mu.unlock();
            ctx.stats.peer_unreachable += 1;
        }
    }

    // Remove missing peers from confirmed_peers
    if (peers_to_remove.items.len > 0) {
        removePeersFromReplica(allocator, rec, peers_to_remove.items);

        // Re-enqueue for replication if now under-replicated
        if (rec.confirmed_peers.len < rec.target_n) {
            std.log.info("audit: re-enqueuing {s} (confirmed {d}/{d})", .{ cid, rec.confirmed_peers.len, rec.target_n });
            enqueueRepair(ctx, cid);
            ctx.stats.mu.lock();
            defer ctx.stats.mu.unlock();
            ctx.stats.blocks_repaired += 1;
        }
    }
}

/// Verify that a peer has a specific block by sending a HAVE_CHECK message.
fn verifyReplica(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    cid: []const u8,
    cluster_secret: ?[]const u8,
    ed25519_secret64: [64]u8,
) !bool {
    // Build CID list (single CID)
    var cid_list: [1][]const u8 = .{cid};

    // Dial peer and send HAVE_CHECK
    const have_cids = cluster_push.dialClusterHaveCheck(
        allocator,
        host,
        port,
        &cid_list,
        cluster_secret,
        ed25519_secret64,
    ) catch |err| {
        return err; // Network or protocol error
    };
    defer {
        for (have_cids) |c| allocator.free(c);
        allocator.free(have_cids);
    }

    // Check if peer responded with our CID
    for (have_cids) |have_cid| {
        if (std.mem.eql(u8, have_cid, cid)) return true;
    }

    return false; // Peer does not have the block
}

/// Remove a list of peer addresses from a replica's confirmed_peers.
fn removePeersFromReplica(allocator: std.mem.Allocator, rec: *cluster_mod.ReplicaRecord, to_remove: []const []const u8) void {
    if (to_remove.len == 0) return;

    // Build new confirmed_peers list excluding to_remove
    var new_list = std.ArrayList([]const u8).empty;
    defer {
        // On failure, free any partial allocations
        for (new_list.items) |p| allocator.free(p);
        new_list.deinit(allocator);
    }

    for (rec.confirmed_peers) |peer| {
        var should_remove = false;
        for (to_remove) |rm| {
            if (std.mem.eql(u8, peer, rm)) {
                should_remove = true;
                break;
            }
        }
        if (!should_remove) {
            const peer_copy = allocator.dupe(u8, peer) catch continue;
            new_list.append(allocator, peer_copy) catch {
                allocator.free(peer_copy);
                continue;
            };
        }
    }

    // Replace old list with new list
    for (rec.confirmed_peers) |p| allocator.free(p);
    allocator.free(rec.confirmed_peers);
    rec.confirmed_peers = new_list.toOwnedSlice(allocator) catch {
        // OOM — keep old list (better than losing all confirmations)
        return;
    };
    // Prevent accidental double-free
    new_list = std.ArrayList([]const u8).empty;
}

/// Re-enqueue a CID for replication (direct queue or file inbox fallback).
fn enqueueRepair(ctx: *AuditCtx, cid: []const u8) void {
    const allocator = std.heap.page_allocator;

    // Try direct queue injection first (daemon mode)
    if (ctx.queue) |q| {
        const cid_copy = allocator.dupe(u8, cid) catch {
            // OOM — fall back to file inbox
            enqueueRepairViaInbox(ctx, cid);
            return;
        };
        const item = repl_queue.ReplItem{
            .cid = cid_copy,
            .priority = .heal, // high priority for audit-triggered repairs
            .mode = ctx.cluster_mode,
            .enqueued_ns = std.time.nanoTimestamp(),
            .target_peer = null,
            .shard_index = null,
            .replication_factor = ctx.replication_factor,
        };
        q.push(item);
    } else {
        // No queue — use file inbox
        enqueueRepairViaInbox(ctx, cid);
    }
}

/// Enqueue repair via file inbox (fallback for CLI mode or queue failure).
fn enqueueRepairViaInbox(ctx: *AuditCtx, cid: []const u8) void {
    const allocator = std.heap.page_allocator;
    const pin = @import("pin.zig");
    pin.notifyInbox(allocator, ctx.repo_root, cid) catch |e| {
        std.log.err("audit: failed to enqueue repair for {s}: {}", .{ cid, e });
    };
}

test "repl_audit: stats initialize with zero counters" {
    var stats = AuditStats{};
    try std.testing.expectEqual(@as(u64, 0), stats.replicas_checked);
    try std.testing.expectEqual(@as(u64, 0), stats.peers_checked);
    try std.testing.expectEqual(@as(u64, 0), stats.blocks_confirmed);
    try std.testing.expectEqual(@as(u64, 0), stats.blocks_missing);
    try std.testing.expectEqual(@as(u64, 0), stats.blocks_repaired);
    try std.testing.expectEqual(@as(u64, 0), stats.peer_unreachable);
    try std.testing.expectEqual(@as(i128, 0), stats.last_audit_ns);
    try std.testing.expectEqual(@as(u64, 0), stats.last_duration_ms);
    try std.testing.expectEqual(false, stats.running);

    // snapshot() reflects the zero state
    const snap = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 0), snap.blocks_confirmed);
    try std.testing.expectEqual(false, snap.running);
}

test "repl_audit: audit context fields are set correctly" {
    var mu = std.Thread.Mutex{};
    var secret: [64]u8 = undefined;
    @memset(&secret, 0x42);

    const ctx = AuditCtx{
        .repo_root = "/tmp/test-repo",
        .interval_ns = 60 * std.time.ns_per_s,
        .sample_rate = 0.25,
        .batch_size = 50,
        .state_mu = &mu,
        .ed25519_secret64 = secret,
        .cluster_secret = "my-cluster-secret",
    };

    try std.testing.expectEqualStrings("/tmp/test-repo", ctx.repo_root);
    try std.testing.expectEqual(@as(u64, 60_000_000_000), ctx.interval_ns);
    try std.testing.expectEqual(@as(f32, 0.25), ctx.sample_rate);
    try std.testing.expectEqual(@as(u32, 50), ctx.batch_size);
    try std.testing.expectEqualStrings("my-cluster-secret", ctx.cluster_secret.?);
    try std.testing.expect(ctx.queue == null);
    try std.testing.expectEqual(@as(u8, 2), ctx.replication_factor);
    try std.testing.expect(ctx.state_mu == &mu);
}

test "repl_audit: stats increment correctly" {
    var stats = AuditStats{};

    // Simulate the increment pattern used in auditReplica
    stats.replicas_checked += 1;
    stats.peers_checked += 2;
    stats.blocks_confirmed += 2;
    stats.blocks_missing += 1;
    stats.blocks_repaired += 1;
    stats.peer_unreachable += 1;
    stats.last_audit_ns = 1_000_000_000;
    stats.last_duration_ms = 500;
    stats.running = true;

    try std.testing.expectEqual(@as(u64, 1), stats.replicas_checked);
    try std.testing.expectEqual(@as(u64, 2), stats.peers_checked);
    try std.testing.expectEqual(@as(u64, 2), stats.blocks_confirmed);
    try std.testing.expectEqual(@as(u64, 1), stats.blocks_missing);
    try std.testing.expectEqual(@as(u64, 1), stats.blocks_repaired);
    try std.testing.expectEqual(@as(u64, 1), stats.peer_unreachable);
    try std.testing.expectEqual(@as(i128, 1_000_000_000), stats.last_audit_ns);
    try std.testing.expectEqual(@as(u64, 500), stats.last_duration_ms);
    try std.testing.expectEqual(true, stats.running);

    // snapshot() captures the current values
    const snap = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 1), snap.blocks_missing);
    try std.testing.expectEqual(@as(u64, 500), snap.last_duration_ms);
    try std.testing.expectEqual(true, snap.running);
}
