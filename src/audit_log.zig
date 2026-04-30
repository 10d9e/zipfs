//! Tamper-evident audit logging for compliance and forensics.
//! Append-only log with cryptographic hash chain linking entries.

const std = @import("std");

pub const Operation = enum {
    Add,
    Pin,
    Unpin,
    Delete,
    Replicate,
    GC,

    pub fn toString(self: Operation) []const u8 {
        return switch (self) {
            .Add => "Add",
            .Pin => "Pin",
            .Unpin => "Unpin",
            .Delete => "Delete",
            .Replicate => "Replicate",
            .GC => "GC",
        };
    }
};

pub const LogEntry = struct {
    timestamp_ns: i128,
    operation: Operation,
    cid: []const u8,
    peer_id: ?[]const u8 = null,
    metadata: ?[]const u8 = null,
    previous_hash: ?[64]u8 = null, // SHA-256 hex (32 bytes = 64 hex chars)
    entry_hash: [64]u8 = undefined,

    /// Compute the entry hash from previous hash + current data.
    /// Hash is computed over: timestamp_ns || operation || cid || peer_id || metadata || previous_hash
    pub fn computeHash(self: *LogEntry) void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Hash timestamp (i128 as bytes)
        var ts_buf: [16]u8 = undefined;
        std.mem.writeInt(i128, &ts_buf, self.timestamp_ns, .big);
        hasher.update(&ts_buf);

        // Hash operation
        hasher.update(self.operation.toString());

        // Hash CID
        hasher.update(self.cid);

        // Hash optional peer_id
        if (self.peer_id) |pid| {
            hasher.update(pid);
        } else {
            hasher.update("null");
        }

        // Hash optional metadata
        if (self.metadata) |meta| {
            hasher.update(meta);
        } else {
            hasher.update("null");
        }

        // Hash previous hash (links to prior entry)
        if (self.previous_hash) |prev| {
            hasher.update(&prev);
        } else {
            hasher.update("null");
        }

        // Finalize and convert to hex
        var digest: [32]u8 = undefined;
        hasher.final(&digest);

        @memcpy(&self.entry_hash, &std.fmt.bytesToHex(digest, .lower));
    }
};

/// Queue item for async log writes.
const QueueItem = struct {
    timestamp_ns: i128,
    operation: Operation,
    cid: []u8, // owned
    peer_id: ?[]u8 = null, // owned
    metadata: ?[]u8 = null, // owned
};

/// Audit log writer with async queue and daily rotation.
pub const AuditLog = struct {
    repo_root: []const u8,
    allocator: std.mem.Allocator,
    enabled: bool = false,
    max_size_bytes: u64 = 100 * 1024 * 1024, // 100 MB
    retention_days: u32 = 90,

    // Thread-safe queue
    queue: std.ArrayList(QueueItem),
    queue_mu: std.Thread.Mutex,
    queue_cond: std.Thread.Condition = .{},
    queue_max: usize = 10000,
    queue_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Last hash (for chain linking)
    last_hash: ?[64]u8 = null,
    last_hash_mu: std.Thread.Mutex,

    // Writer thread handle
    writer_thread: ?std.Thread = null,
    shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(allocator: std.mem.Allocator, repo_root: []const u8, enabled: bool, max_size_mb: u64, retention_days: u32) !AuditLog {
        var log = AuditLog{
            .repo_root = repo_root,
            .allocator = allocator,
            .enabled = enabled,
            .max_size_bytes = max_size_mb * 1024 * 1024,
            .retention_days = retention_days,
            .queue = std.ArrayList(QueueItem).empty,
            .queue_mu = .{},
            .last_hash_mu = .{},
        };

        if (!enabled) return log;

        // Load last hash from most recent log file
        log.loadLastHash() catch |e| { std.log.err("audit_log: failed to load last hash: {any}", .{e}); };

        return log;
    }

    pub fn deinit(self: *AuditLog) void {
        if (!self.enabled) return;

        // Signal shutdown
        self.shutdown.store(true, .seq_cst);

        // Wake up writer thread
        self.queue_cond.signal();

        // Wait for writer thread to finish
        if (self.writer_thread) |thread| {
            thread.join();
        }

        // Free queued items
        self.queue_mu.lock();
        defer self.queue_mu.unlock();
        for (self.queue.items) |item| {
            self.allocator.free(item.cid);
            if (item.peer_id) |pid| self.allocator.free(pid);
            if (item.metadata) |meta| self.allocator.free(meta);
        }
        self.queue.deinit(self.allocator);
    }

    /// Start the background writer thread.
    pub fn startWriter(self: *AuditLog) !void {
        if (!self.enabled) return;
        if (self.writer_thread != null) return; // Already started

        self.writer_thread = try std.Thread.spawn(.{}, writerLoop, .{self});
    }

    /// Append an entry to the audit log (async, non-blocking).
    pub fn append(self: *AuditLog, operation: Operation, cid: []const u8, peer_id: ?[]const u8, metadata: ?[]const u8) void {
        if (!self.enabled) return;

        const timestamp_ns = std.time.nanoTimestamp();

        // Dupe all strings for ownership
        const cid_dup = self.allocator.dupe(u8, cid) catch {
            // OOM — drop entry and increment counter
            _ = self.queue_dropped.fetchAdd(1, .seq_cst);
            return;
        };
        errdefer self.allocator.free(cid_dup);

        const peer_dup = if (peer_id) |pid| self.allocator.dupe(u8, pid) catch {
            _ = self.queue_dropped.fetchAdd(1, .seq_cst);
            return;
        } else null;
        errdefer if (peer_dup) |pd| self.allocator.free(pd);

        const meta_dup = if (metadata) |meta| self.allocator.dupe(u8, meta) catch {
            _ = self.queue_dropped.fetchAdd(1, .seq_cst);
            return;
        } else null;

        // Enqueue
        self.queue_mu.lock();
        defer self.queue_mu.unlock();

        // Check queue limit
        if (self.queue.items.len >= self.queue_max) {
            // Queue full — drop entry
            self.allocator.free(cid_dup);
            if (peer_dup) |pd| self.allocator.free(pd);
            if (meta_dup) |md| self.allocator.free(md);
            _ = self.queue_dropped.fetchAdd(1, .seq_cst);
            std.log.err("audit_log: queue full, dropped entry for {s}", .{cid});
            return;
        }

        self.queue.append(self.allocator, .{
            .timestamp_ns = timestamp_ns,
            .operation = operation,
            .cid = cid_dup,
            .peer_id = peer_dup,
            .metadata = meta_dup,
        }) catch {
            // Append failed — clean up
            self.allocator.free(cid_dup);
            if (peer_dup) |pd| self.allocator.free(pd);
            if (meta_dup) |md| self.allocator.free(md);
            _ = self.queue_dropped.fetchAdd(1, .seq_cst);
            return;
        };

        // Wake up writer
        self.queue_cond.signal();
    }

    /// Background writer loop (runs in separate thread).
    fn writerLoop(self: *AuditLog) void {
        while (!self.shutdown.load(.seq_cst)) {
            // Wait for queue items
            self.queue_mu.lock();
            while (self.queue.items.len == 0 and !self.shutdown.load(.seq_cst)) {
                self.queue_cond.wait(&self.queue_mu);
            }

            if (self.shutdown.load(.seq_cst) and self.queue.items.len == 0) {
                self.queue_mu.unlock();
                break;
            }

            // Pop batch (up to 100 items)
            const batch_size = @min(self.queue.items.len, 100);
            var batch = std.ArrayList(QueueItem).empty;
            batch.appendSlice(self.allocator, self.queue.items[0..batch_size]) catch {
                self.queue_mu.unlock();
                continue;
            };

            // Remove from queue
            std.mem.copyForwards(QueueItem, self.queue.items, self.queue.items[batch_size..]);
            self.queue.shrinkRetainingCapacity(self.queue.items.len - batch_size);
            self.queue_mu.unlock();

            // Write batch to disk
            for (batch.items) |item| {
                self.writeEntry(item) catch |err| {
                    std.log.err("audit_log: write failed: {}", .{err});
                };

                // Free item strings
                self.allocator.free(item.cid);
                if (item.peer_id) |pid| self.allocator.free(pid);
                if (item.metadata) |meta| self.allocator.free(meta);
            }
            batch.deinit(self.allocator);

            // Rotate log if needed
            self.rotateIfNeeded() catch |err| {
                std.log.err("audit_log: rotation failed: {}", .{err});
            };

            // Clean up old logs
            self.cleanupOldLogs() catch |err| {
                std.log.err("audit_log: cleanup failed: {}", .{err});
            };
        }
    }

    /// Write a single entry to the current log file.
    fn writeEntry(self: *AuditLog, item: QueueItem) !void {
        // Get current log file path
        const log_path = try self.getCurrentLogPath();
        defer self.allocator.free(log_path);

        // Ensure audit_log directory exists
        const audit_dir = try std.fs.path.join(self.allocator, &.{ self.repo_root, "audit_log" });
        defer self.allocator.free(audit_dir);
        std.fs.cwd().makePath(audit_dir) catch |e| { std.log.err("audit_log: failed to create audit dir {s}: {any}", .{audit_dir, e}); return; };

        // Create entry with hash chain
        var entry = LogEntry{
            .timestamp_ns = item.timestamp_ns,
            .operation = item.operation,
            .cid = item.cid,
            .peer_id = item.peer_id,
            .metadata = item.metadata,
            .previous_hash = null,
        };

        // Get previous hash
        {
            self.last_hash_mu.lock();
            defer self.last_hash_mu.unlock();
            if (self.last_hash) |prev| {
                entry.previous_hash = prev;
            }
        }

        // Compute entry hash
        entry.computeHash();

        // Update last hash
        {
            self.last_hash_mu.lock();
            defer self.last_hash_mu.unlock();
            self.last_hash = entry.entry_hash;
        }

        // Serialize to NDJSON
        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "{\"timestamp_ns\":");
        try buf.writer(self.allocator).print("{d}", .{entry.timestamp_ns});
        try buf.appendSlice(self.allocator, ",\"operation\":\"");
        try buf.appendSlice(self.allocator, entry.operation.toString());
        try buf.appendSlice(self.allocator, "\",\"cid\":\"");
        try jsonEscapeWrite(buf.writer(self.allocator), entry.cid);
        try buf.appendSlice(self.allocator, "\"");

        if (entry.peer_id) |pid| {
            try buf.appendSlice(self.allocator, ",\"peer_id\":\"");
            try jsonEscapeWrite(buf.writer(self.allocator), pid);
            try buf.appendSlice(self.allocator, "\"");
        } else {
            try buf.appendSlice(self.allocator, ",\"peer_id\":null");
        }

        if (entry.metadata) |meta| {
            try buf.appendSlice(self.allocator, ",\"metadata\":");
            try buf.appendSlice(self.allocator, meta); // Already JSON
        } else {
            try buf.appendSlice(self.allocator, ",\"metadata\":null");
        }

        if (entry.previous_hash) |prev| {
            try buf.appendSlice(self.allocator, ",\"previous_hash\":\"");
            try buf.appendSlice(self.allocator, &prev);
            try buf.appendSlice(self.allocator, "\"");
        } else {
            try buf.appendSlice(self.allocator, ",\"previous_hash\":null");
        }

        try buf.appendSlice(self.allocator, ",\"entry_hash\":\"");
        try buf.appendSlice(self.allocator, &entry.entry_hash);
        try buf.appendSlice(self.allocator, "\"}\n");

        // Append to log file
        const file = std.fs.cwd().openFile(log_path, .{ .mode = .write_only }) catch |err| switch (err) {
            error.FileNotFound => try std.fs.cwd().createFile(log_path, .{ .truncate = false }),
            else => return err,
        };
        defer file.close();

        try file.seekFromEnd(0);
        try file.writeAll(buf.items);
        try file.sync();
    }

    /// Get the path to the current log file (YYYY-MM-DD.jsonl).
    pub fn getCurrentLogPath(self: *AuditLog) ![]u8 {
        const now_s: i64 = @intCast(@divFloor(std.time.timestamp(), 1));
        const epoch_day = std.time.epoch.EpochDay{ .day = @intCast(@divFloor(now_s, 86400)) };
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        const filename = try std.fmt.allocPrint(self.allocator, "{d:0>4}-{d:0>2}-{d:0>2}.jsonl", .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
        });
        defer self.allocator.free(filename);

        return try std.fs.path.join(self.allocator, &.{ self.repo_root, "audit_log", filename });
    }

    /// Rotate log file if it exceeds max size.
    fn rotateIfNeeded(self: *AuditLog) !void {
        const log_path = try self.getCurrentLogPath();
        defer self.allocator.free(log_path);

        const file = std.fs.cwd().openFile(log_path, .{}) catch return;
        defer file.close();

        const stat = try file.stat();
        if (stat.size > self.max_size_bytes) {
            // Rotation: rename current file with timestamp suffix
            const ts = std.time.timestamp();
            const rotated_path = try std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ log_path, ts });
            defer self.allocator.free(rotated_path);

            std.fs.cwd().rename(log_path, rotated_path) catch |err| {
                std.log.err("audit_log: rotation failed: {}", .{err});
            };

            // Reset hash chain for new file
            self.last_hash_mu.lock();
            defer self.last_hash_mu.unlock();
            self.last_hash = null;
        }
    }

    /// Delete log files older than retention_days.
    fn cleanupOldLogs(self: *AuditLog) !void {
        const audit_dir_path = try std.fs.path.join(self.allocator, &.{ self.repo_root, "audit_log" });
        defer self.allocator.free(audit_dir_path);

        var audit_dir = std.fs.cwd().openDir(audit_dir_path, .{ .iterate = true }) catch return;
        defer audit_dir.close();

        const now_s = std.time.timestamp();
        const cutoff_s = now_s - (@as(i64, self.retention_days) * 86400);

        var iter = audit_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;

            // Get file mtime
            const file = audit_dir.openFile(entry.name, .{}) catch continue;
            defer file.close();
            const stat = file.stat() catch continue;

            const mtime_s: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
            if (mtime_s < cutoff_s) {
                audit_dir.deleteFile(entry.name) catch |err| {
                    std.log.err("audit_log: failed to delete old log {s}: {}", .{ entry.name, err });
                };
            }
        }
    }

    /// Load the last hash from the most recent log file.
    fn loadLastHash(self: *AuditLog) !void {
        const log_path = try self.getCurrentLogPath();
        defer self.allocator.free(log_path);

        const data = std.fs.cwd().readFileAlloc(self.allocator, log_path, 1 << 30) catch return;
        defer self.allocator.free(data);

        // Find last line
        var last_line: ?[]const u8 = null;
        var line_it = std.mem.splitScalar(u8, data, '\n');
        while (line_it.next()) |line| {
            if (line.len > 0) last_line = line;
        }

        if (last_line) |line| {
            // Parse JSON to extract entry_hash
            const Json = struct {
                entry_hash: ?[]const u8 = null,
            };
            var parsed = std.json.parseFromSlice(Json, self.allocator, line, .{}) catch return;
            defer parsed.deinit();

            if (parsed.value.entry_hash) |hash| {
                if (hash.len == 64) {
                    var h: [64]u8 = undefined;
                    @memcpy(&h, hash[0..64]);
                    self.last_hash_mu.lock();
                    defer self.last_hash_mu.unlock();
                    self.last_hash = h;
                }
            }
        }
    }

    /// Verify the integrity of a log file's hash chain.
    pub fn verify(self: *AuditLog, log_file: []const u8) !VerifyResult {
        const data = try std.fs.cwd().readFileAlloc(self.allocator, log_file, 1 << 30);
        defer self.allocator.free(data);

        var result = VerifyResult{
            .total_entries = 0,
            .valid_entries = 0,
            .broken_chains = 0,
            .hash_mismatches = 0,
        };

        var prev_hash: ?[64]u8 = null;
        var line_it = std.mem.splitScalar(u8, data, '\n');

        while (line_it.next()) |line| {
            if (line.len == 0) continue;
            result.total_entries += 1;

            // Parse entry
            const Json = struct {
                timestamp_ns: i128,
                operation: []const u8,
                cid: []const u8,
                peer_id: ?[]const u8 = null,
                metadata: ?[]const u8 = null,
                previous_hash: ?[]const u8 = null,
                entry_hash: []const u8,
            };

            var parsed = std.json.parseFromSlice(Json, self.allocator, line, .{}) catch {
                result.hash_mismatches += 1;
                continue;
            };
            defer parsed.deinit();

            // Verify previous hash matches chain
            if (prev_hash) |expected| {
                if (parsed.value.previous_hash) |actual| {
                    if (!std.mem.eql(u8, &expected, actual)) {
                        result.broken_chains += 1;
                        continue;
                    }
                } else {
                    result.broken_chains += 1;
                    continue;
                }
            } else {
                if (parsed.value.previous_hash != null) {
                    result.broken_chains += 1;
                    continue;
                }
            }

            // Recompute entry hash
            const op = parseOperation(parsed.value.operation) orelse {
                result.hash_mismatches += 1;
                continue;
            };

            var entry = LogEntry{
                .timestamp_ns = parsed.value.timestamp_ns,
                .operation = op,
                .cid = parsed.value.cid,
                .peer_id = parsed.value.peer_id,
                .metadata = parsed.value.metadata,
                .previous_hash = if (parsed.value.previous_hash) |ph| blk: {
                    if (ph.len == 64) {
                        var h: [64]u8 = undefined;
                        @memcpy(&h, ph[0..64]);
                        break :blk h;
                    }
                    break :blk null;
                } else null,
            };
            entry.computeHash();

            // Verify hash
            if (!std.mem.eql(u8, &entry.entry_hash, parsed.value.entry_hash)) {
                result.hash_mismatches += 1;
                continue;
            }

            // Valid entry
            result.valid_entries += 1;

            // Update prev_hash for next iteration
            if (parsed.value.entry_hash.len == 64) {
                var h: [64]u8 = undefined;
                @memcpy(&h, parsed.value.entry_hash[0..64]);
                prev_hash = h;
            }
        }

        return result;
    }
};

pub const VerifyResult = struct {
    total_entries: usize,
    valid_entries: usize,
    broken_chains: usize,
    hash_mismatches: usize,

    pub fn isValid(self: VerifyResult) bool {
        return self.broken_chains == 0 and self.hash_mismatches == 0;
    }
};

/// Escape JSON string content (without quotes).
fn jsonEscapeWrite(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

fn parseOperation(s: []const u8) ?Operation {
    if (std.mem.eql(u8, s, "Add")) return .Add;
    if (std.mem.eql(u8, s, "Pin")) return .Pin;
    if (std.mem.eql(u8, s, "Unpin")) return .Unpin;
    if (std.mem.eql(u8, s, "Delete")) return .Delete;
    if (std.mem.eql(u8, s, "Replicate")) return .Replicate;
    if (std.mem.eql(u8, s, "GC")) return .GC;
    return null;
}

test "audit_log: entry hash computation is deterministic and unique" {
    var entry = LogEntry{
        .timestamp_ns = 1_000_000,
        .operation = .Add,
        .cid = "QmTest",
        .peer_id = null,
        .metadata = null,
        .previous_hash = null,
    };
    entry.computeHash();

    // SHA-256 hex digest is 64 characters
    try std.testing.expectEqual(@as(usize, 64), entry.entry_hash.len);

    // Same inputs must produce identical hash
    var dup = LogEntry{
        .timestamp_ns = 1_000_000,
        .operation = .Add,
        .cid = "QmTest",
        .peer_id = null,
        .metadata = null,
        .previous_hash = null,
    };
    dup.computeHash();
    try std.testing.expectEqualSlices(u8, &entry.entry_hash, &dup.entry_hash);

    // Different CID must produce different hash
    var other = LogEntry{
        .timestamp_ns = 1_000_000,
        .operation = .Add,
        .cid = "QmOther",
        .peer_id = null,
        .metadata = null,
        .previous_hash = null,
    };
    other.computeHash();
    try std.testing.expect(!std.mem.eql(u8, &entry.entry_hash, &other.entry_hash));
}

test "audit_log: hash chain links consecutive entries" {
    var first = LogEntry{
        .timestamp_ns = 100,
        .operation = .Pin,
        .cid = "QmFirst",
        .peer_id = null,
        .metadata = null,
        .previous_hash = null,
    };
    first.computeHash();

    // Second entry's previous_hash points to first entry's hash
    var second = LogEntry{
        .timestamp_ns = 200,
        .operation = .Pin,
        .cid = "QmSecond",
        .peer_id = null,
        .metadata = null,
        .previous_hash = first.entry_hash,
    };
    second.computeHash();

    try std.testing.expect(first.previous_hash == null);
    try std.testing.expect(second.previous_hash != null);
    try std.testing.expectEqualSlices(u8, &first.entry_hash, &second.previous_hash.?);

    // Third entry links to second, forming a chain
    var third = LogEntry{
        .timestamp_ns = 300,
        .operation = .Pin,
        .cid = "QmThird",
        .peer_id = null,
        .metadata = null,
        .previous_hash = second.entry_hash,
    };
    third.computeHash();
    try std.testing.expectEqualSlices(u8, &second.entry_hash, &third.previous_hash.?);
    // Each link in the chain has a unique hash
    try std.testing.expect(!std.mem.eql(u8, &first.entry_hash, &third.entry_hash));
}

test "audit_log: tamper detection detects corrupted hash" {
    var entry = LogEntry{
        .timestamp_ns = 42,
        .operation = .Delete,
        .cid = "QmTarget",
        .peer_id = null,
        .metadata = null,
        .previous_hash = null,
    };
    entry.computeHash();

    // Re-compute and verify match (no tampering)
    {
        var verify = LogEntry{
            .timestamp_ns = 42,
            .operation = .Delete,
            .cid = "QmTarget",
            .peer_id = null,
            .metadata = null,
            .previous_hash = null,
        };
        verify.computeHash();
        try std.testing.expectEqualSlices(u8, &entry.entry_hash, &verify.entry_hash);
    }

    // Simulate tampering: flip a bit in stored hash
    var corrupted = entry.entry_hash;
    corrupted[31] ^= 0xFF;

    {
        var verify = LogEntry{
            .timestamp_ns = 42,
            .operation = .Delete,
            .cid = "QmTarget",
            .peer_id = null,
            .metadata = null,
            .previous_hash = null,
        };
        verify.computeHash();
        try std.testing.expect(!std.mem.eql(u8, &corrupted, &verify.entry_hash));
    }

    // Tamper with entry data (different CID)
    {
        var verify = LogEntry{
            .timestamp_ns = 42,
            .operation = .Delete,
            .cid = "QmTampered",
            .peer_id = null,
            .metadata = null,
            .previous_hash = null,
        };
        verify.computeHash();
        try std.testing.expect(!std.mem.eql(u8, &entry.entry_hash, &verify.entry_hash));
    }
}

test "audit_log: entry NDJSON roundtrip" {
    const ally = std.testing.allocator;

    var entry = LogEntry{
        .timestamp_ns = 999_999,
        .operation = .Replicate,
        .cid = "QmRoundtrip",
        .peer_id = "peer123",
        .metadata = "{\"origin\":\"test\"}",
        .previous_hash = null,
    };
    entry.computeHash();

    // Build NDJSON line matching writeEntry format
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ally);

    try buf.appendSlice(ally, "{\"timestamp_ns\":");
    try buf.writer(ally).print("{d}", .{entry.timestamp_ns});
    try buf.appendSlice(ally, ",\"operation\":\"");
    try buf.appendSlice(ally, entry.operation.toString());
    try buf.appendSlice(ally, "\",\"cid\":\"");
    try buf.appendSlice(ally, entry.cid);
    try buf.appendSlice(ally, "\"");
    try buf.appendSlice(ally, ",\"peer_id\":\"");
    try buf.appendSlice(ally, entry.peer_id.?);
    try buf.appendSlice(ally, "\"");
    try buf.appendSlice(ally, ",\"metadata\":");
    try buf.appendSlice(ally, entry.metadata.?);
    try buf.appendSlice(ally, ",\"previous_hash\":null");
    try buf.appendSlice(ally, ",\"entry_hash\":\"");
    try buf.appendSlice(ally, &entry.entry_hash);
    try buf.appendSlice(ally, "\"}\n");

    // Parse back with std.json
    const Json = struct {
        timestamp_ns: i128,
        operation: []const u8,
        cid: []const u8,
        peer_id: ?[]const u8 = null,
        metadata: ?[]const u8 = null,
        previous_hash: ?[]const u8 = null,
        entry_hash: []const u8,
    };

    var parsed = try std.json.parseFromSlice(Json, ally, buf.items, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(entry.timestamp_ns, parsed.value.timestamp_ns);
    try std.testing.expectEqualStrings(entry.operation.toString(), parsed.value.operation);
    try std.testing.expectEqualStrings(entry.cid, parsed.value.cid);
    try std.testing.expectEqualStrings(entry.peer_id.?, parsed.value.peer_id.?);
    try std.testing.expectEqualStrings(entry.metadata.?, parsed.value.metadata.?);
    try std.testing.expect(parsed.value.previous_hash == null);
    try std.testing.expectEqualSlices(u8, entry.entry_hash[0..], parsed.value.entry_hash);
}

test "audit_log: operation enum roundtrip" {
    const ops = [_]Operation{ .Add, .Pin, .Unpin, .Delete, .Replicate, .GC };
    for (ops) |op| {
        const s = op.toString();
        const parsed = parseOperation(s);
        try std.testing.expect(parsed != null);
        try std.testing.expectEqual(op, parsed.?);
    }
    try std.testing.expect(parseOperation("Bogus") == null);
    try std.testing.expect(parseOperation("") == null);
}
