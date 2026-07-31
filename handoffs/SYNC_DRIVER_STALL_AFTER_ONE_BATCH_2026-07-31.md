---
created: 2026-07-31
branch: docs/escalation-sync-driver-stall-91k
author: Claude (Opus 4.8), directed by @SaulBuilds (citrate-core / desktop side)
status: P1 escalation to DGX/chain — a cold-syncing node's ACTIVE sync driver stops
  after a single batch and goes idle (0% CPU) while tens of thousands of blocks
  behind. It only advances by ~28-32 blocks per process restart. NOT the 54,600
  pruning wedge (that is fixed) — a second, independent onboarding blocker. No
  citrate-core app change can touch it; it is the node's sync-source / drain loop.
relates:
  - handoffs/FRESH_NODE_SYNC_WEDGE_54600_2026-07-30.md (the pruning wedge — SEPARATE, fixed)
  - PR #135 (86453cc) fix(sync): judge sync completion against our own applied height
  - PR #136 (8b07043) fix(sync): a peer at our own height is not a sync source, and
    the penalty box must not veto the last one that is
  - PR #86 (e75e037) fix(sync): periodic forward-drain (app.drive_drain 1s loop)
---

# P1 — the active sync driver stops after one batch (cold-sync strands ~36k short)

> ## ROOT CAUSE FOUND AND FIXED — 2026-07-31, DGX/chain side
> **It was not the sync driver.** The driver was fine; there was nobody left to
> answer it. `core/network/src/sync.rs::handle_blocks` computed a **progress
> percentage for a log line** with an unguarded `last_height - current`. Release
> builds set `overflow-checks = true`, so when a peer answered with a batch below
> our applied tip — a response to an anchor we had walked past, a sibling group on
> a shorter branch, or simply `drive_drain` advancing while the batch was in
> flight — it did not wrap, it **panicked**. The panic landed on the tokio task
> that owns the node's ENTIRE inbound message loop: serving `GetBlocks`/
> `GetHeaders`, admitting synced blocks, ingesting gossip, advancing the applied
> tip. All of it, gone, permanently, on one arithmetic op.
>
> Confirmed on the live fleet, not inferred:
> ```
> rpc-1 (THE SEQUENCER), journalctl -u citrate-node:
>   Jul 30 04:31:20  INFO citrate::producer: Produced block #10226 ... height 90467
>   Jul 30 04:31:20  thread 'tokio-rt-worker' panicked at core/network/src/sync.rs:551:14:
>   Jul 30 04:31:20  attempt to subtract with overflow
>   NRestarts=0   ActiveEnterTimestamp=Wed 2026-07-29 22:50:20 UTC
>   GetBlocks served in the last 2 min: 0
> ```
> A tokio task panic is caught by the runtime and surfaces only via a JoinHandle
> nobody held, so **the process stayed up and looked healthy from every angle an
> operator checks**: systemd `active (running)`, `NRestarts=0`, peers connected,
> JSON-RPC answering, the producer still minting blocks, `eth_syncing` reporting a
> correct gap. The sequencer went on to produce ~39,000 more blocks that **no node
> on the network could fetch**.
>
> Fleet state at diagnosis (2026-07-31 02:10 UTC):
>
> | node  | P2P message loop | GetBlocks served / 2 min |
> |-------|------------------|--------------------------|
> | rpc-1 | DEAD (panic 07-30 04:31:20, right after height 90,467) | 0 |
> | boot1 | DEAD             | 0 |
> | boot2 | **alive**        | 106 |
> | boot3 | restarting (5 restarts, OOM) | 0 |
>
> That table *is* the report above. boot2 is the only fleet node still able to ask
> anyone for anything, which is why it is the only peer in the stalled node's
> inbound log; it asks forever because everyone who holds the blocks is deaf. The
> desktop node froze at **91,187** — a few hundred blocks past the sequencer's
> **90,467** — because that is exactly as far as the bootnodes could carry it
> before the last serving source ran out. "Restart → +1 batch → idle" was the
> node running until its *own* copy of the same panic fired.
>
> Reproduced from scratch on the DGX (fresh node, chain `main`, no
> `CITRATE_DAG_PRUNE_RETAIN`): panicked at `sync.rs:551` after ~8,000 blocks; from
> that instant zero `Received GetBlocks`, zero imports, 0% CPU, process alive.
> A node pinned to the sequencer alone syncs **0 blocks** and reports
> `currentBlock: 0x0, highestBlock: 0x1f999` — it knows the tip (handshake, a
> different task) and cannot obtain one block of it.
>
> ### Fixed in this change
> 1. **`sync.rs` — the panic.** Every term in the progress calculation saturates.
>    The identical guard already existed in `handle_headers`, added when this very
>    panic was seen there; it was never mirrored into `handle_blocks`.
> 2. **`main.rs` — the silence.** A watchdog holds the message loop's JoinHandle
>    and exits non-zero if it ever ends, so this failure class can never again run
>    for 30 hours looking healthy.
> 3. **`discovery.rs` — the second, independent defect** found while reproducing:
>    a node that dropped the sequencer after repeated sync timeouts never dialed it
>    again, despite logging "will re-handshake". `find_peers` gated re-dials on a
>    `connected_peers` set that production never cleans, with a `peer_count < 3`
>    escape — and three discovery-only bootnodes hold the count at exactly 3.
>    Connectivity is now judged from the peer manager. Verified live: the dropped
>    sequencer is now re-dialed within ~5s.
>
> **The fleet must be redeployed on the fixed binary.** No client-side fix can
> sync from a sequencer whose serve loop is dead.
>
> Everything below is the original report, kept as written.

## Context (what is already resolved)
The 54,600 pruning wedge is FIXED: unset `CITRATE_DAG_PRUNE_RETAIN` (citrate-core
did this in app-PR #116). A fresh desktop node then cold-synced cleanly from
genesis, CROSSED 54,600, and climbed **36k blocks past it to height 91,187**. So
pruning-off works and this is a *different* bug that only shows up much later.

## The symptom (live, 2026-07-31, chain 40204)
- Desktop node (built from chain `main` @ `8bf275a`, follower, **no pruning**,
  correct env `CITRATE_BLOCK_V2=1` / `VALIDATOR_ACTIVATION_HEIGHT=2000` /
  `VALIDATOR_REGISTRY=0x61d44d8a…95a6`) applied head is stuck at **91,187**.
- **Network tip is 127,648** — the node is **36,461 blocks behind** and knows it
  (`eth_syncing` reports `currentBlock=91187, highestBlock=127648`).
- The node process is **0.0% CPU, RSS flat ~894 MB, uptime stable (not
  restarting), zero crash records.** It is genuinely IDLE, not slow.
- **Restarting the node advances it by exactly one batch (~28-32 blocks), then it
  idles again.** Toggle → +28 → idle. Repeat.

## The tell — the node's own log while idle (verbatim)
```
INFO citrate: Received GetHeaders request from peer noise_4ed2…(boot2) starting Hash([98,85,170,114,…]) count 64
INFO citrate: Received GetBlocks request from peer noise_4ed2…(boot2) for 32 blocks starting from Hash([98,85,170,114,…])
INFO citrate: Sending 0 blocks to peer noise_4ed2…(boot2)
… repeats every ~2s, forever.
```
**Every line is INBOUND** — the node is only *serving* (and serving 0). There is
**not a single outbound sync request from this node** in the idle state: no
"Downloaded N headers", no "Validated and imported", nothing. The node has
**stopped asking anyone for the blocks it is missing.** A good source exists and
is reachable: `rpc.citrate.ai` is a bootstrap peer and is AT the tip (127,648).

## Diagnosis (best read, for you to confirm)
The **active sync driver deactivates after one batch.** On (re)start the node
selects a sync source, pulls/applies one batch (~28-32), then loses/vetoes that
source and falls back to passive serve-only — it never re-selects a source or
re-issues `GetHeaders`/`GetBlocks` for its own head. Only a full restart resets
it, for exactly one more batch. This is squarely in the territory #135
("judge sync completion against our own applied height") and #136 ("the penalty
box must not veto the last sync source") were meant to cover — both are merged,
so either a residual case survives near the tip, or completion is being declared
after a single batch and the drain/forward-sync isn't re-arming.

## Where to look
- The sync-source selection + penalty-box path (#136, `8b07043`) — is the last
  usable source being vetoed after one batch, leaving no source → idle?
- The sync-completion judgment (#135, `86453cc`) — is the node concluding "caught
  up / nothing to request" while `applied (91187) << advertised tip (127648)`?
- The forward-drain / EXECUTE-ON-RECEIVE step-3 loop (#86, `e75e037`,
  `node/src/main.rs` `app.drive_drain()`): with no inbound blocks being requested,
  it has nothing to drain — confirm the driver is supposed to keep *requesting*,
  not just draining what gossip delivers.
- Why "Sending 0 blocks" to boot2 for `Hash([98,85,170,114,…])` — is a peer
  requesting a head this node advertised but cannot serve (advertised-vs-served
  mismatch), and does that interaction mark the peer unusable as a source?

## Repro
1. Fresh node, chain `main`, **no** `CITRATE_DAG_PRUNE_RETAIN`, join 40204.
2. Let it cold-sync. It crosses 54,600 fine and climbs.
3. Somewhere in the tens-of-thousands it stops advancing at a batch boundary,
   0% CPU, log shows inbound-only. Restart → +1 batch → idle. (Observed at 91,187;
   the exact height is wherever a batch ends when the source is lost.)

## Impact
Same class as the pruning wedge: **blocks any node from finishing a cold-sync to
the tip** — new members, new fleet nodes, explorers, indexers. The pruning fix got
onboarding off the 54,600 wall; this is the next wall before the tip.

## What is NOT the cause (already ruled out)
- Not pruning (it's off; the node is 36k past 54,600).
- Not a deep merge-parent — the next block (91,188) has `mergeParentHashes: []`.
- Not mining/self-fork (follower; citrate-core app-PR #115 gates `--mine` on synced).
- Not an unreachable source (`rpc.citrate.ai` at the tip, reachable).
- Not a crash-loop (uptime stable, 0 crash records) — it's a live idle.
