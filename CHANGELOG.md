# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `net fetch` and `cat --net` recursively fetch linked `dag-pb` blocks (multi-block UnixFS), Kubo-style; use `net fetch --single-block <cid>` for the previous single-block fetch.
- CLI `zipfs add` / `add -r` append the new root CID to `repl_inbox` when `cluster_mode` and `cluster_peers` are set (same idea as HTTP `/api/v0/add`), so the running daemon can push the **full DAG** to cluster peers. Previously only local blocks were written and other nodes had nothing to replicate unless you used `pin add`, the gateway, or `cluster replicate`.

### Fixed

- Recursive DAG fetch: `done` map keys no longer alias the BFS queue buffer (queue growth could realloc and corrupt keys), which caused most child CIDs to be skipped after a couple of blocks on large files.
- Chunked UnixFS roots that were **truncated or stubbed** on disk (UnixFS `filesize` > 0 but no `dag-pb` links) no longer make `net fetch` / `cat --net` stop immediately with “DAG already complete”; the bad block is dropped and refetched. If the replacement is still invalid, `TruncatedLocalUnixFsRoot` is returned.
- When a walk fetches **zero** blocks, `net fetch` / `cat --net` now checks **declared UnixFS size vs. reachable payload bytes** (cheap tree walk, no full `cat` buffer): **`filesize` (field 3) or, if absent, the sum of `blocksizes` (field 4)** as Kubo often encodes. A mismatch means the root CID is present in the blockstore but the DAG is incomplete: the root is removed and refetched once, then the walk runs again. If it still fails, `IncompleteLocalUnixFsDag` is returned.

## [0.1.0] - 2026-04-04

### Added

- Local IPFS-style repo: sharded blockstore, `IPFS_PATH` / default `.zig-ipfs`, `config.json`.
- UnixFS import (`add`, `add -r`), `cat`, `ls`, `block put|get`, DAG CAR import/export.
- Pins (`pin add|rm|ls`), `repo gc`.
- Read-only HTTP gateway and `daemon` mode with libp2p swarm (Noise, yamux, multistream, Identify, bitswap 1.2.0, Kademlia DHT).
- Network: `net fetch`, `net provide`, `cat --net`, DHT walks (GET_PROVIDERS, FIND_NODE, ADD_PROVIDER with dialable multiaddrs), `/dnsaddr` bootstrap resolution, periodic reprovide for recursive pins.
- Kubo-oriented wire formats where implemented (provider keyspace, bitswap want-have / presences).

### Notes

- Not a full Kubo replacement; validate for your use case before relying on it in production.
