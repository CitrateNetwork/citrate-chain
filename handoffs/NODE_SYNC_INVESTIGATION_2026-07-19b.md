---
title: "Node sync investigation — target-overwrite FIXED; forward-drain APPLY bug remains (still blocks onboarding)"
created: 2026-07-19
branch: main
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: open
priority: P0
component: node / core/network sync / canonical_apply (forward drain)
follows: handoffs/NODE_FRESH_SYNC_WEDGE_2026-07-19.md
---

# Node sync — what was fixed, what remains

## Done this session
- **Fleet redeployed** with `main@ac23fe0` on all 4 nodes (rpc-1 + boot1/2/3). Chain
  HEALTHY: rpc-1 producing, head ~75,084 and advancing, chainId 40204, all services
  active with 0 restarts, no fork. Consumers unaffected. Old binaries backed up as
  `/home/citrate/bin/citrate-node.bak-jul18` on every node.
- **Fixed the sync-target overwrite** (PR #84, merged): `SyncManager::start_sync`
  overwrote `target_height` with the last peer's advertised head; a low-advertising peer
  (boots advertise height 0) collapsed the target. Now `target = max(target, peer)`.
  Correct + regression-tested — but NOT sufficient on its own (see below).

## What still blocks onboarding (deeper bug)
A fresh node — and every boot — wedges. Verified live on all 3 boots after redeploy:
each sits at its persisted applied tip (boot3 **124**, boot2 **9208**, boot1 **17,556**)
and loops every 2 s:
```
Downloaded 64 headers (height 117-180), progress: 100.0%
Starting block download from height 124 to 0          # target resolves to 0
Validated and imported 8/8 blocks (height 117-124)     # SAME window, every tick
Synchronization complete at height 124
```

Two distinct problems visible here:

1. **Forward-drain APPLY failure (root blocker).** The 8-block window downloads and is
   *stored* (`eth_blockNumber` reports the window top, e.g. 124) but the **applied tip
   does not advance** — the sync anchor (`get_applied_tip`) stays below (e.g. 116), so
   the drive loop re-requests the *same* window forever. Blocks are validated in
   `SyncManager::handle_blocks` (hash/sig/tx_root) and put in storage, but the
   `canonical_apply` forward-drain never commits them onto the applied tip. Suspected:
   the downloaded block won't apply onto the local applied-tip state (state-root/parent
   divergence at the wedge point), or `drain_forward` requires a precondition not met on
   the fresh-join path. **This is the applied-tip-vs-stored-height split again, on the
   APPLY side rather than the request side.** Look at `node/src/canonical_apply.rs`
   `drain_forward` / `drain_validated_blocks` and why stored-but-unapplied blocks never
   commit.

2. **Target still resolves to 0 on followers.** Even with rpc-1 running V2 (execute-on-
   receive) and its producer calling `record_produced` (which `put_applied_tip`s), the
   boots compute `target=0` — i.e. they never see a peer advertise a head > their own.
   Open question: **does rpc-1 actually advertise its real head (~75k) in the P2P
   Hello?** `advertised_head` is refreshed every 1 s from `get_applied_tip()`
   (`node/src/main.rs:1524`). If the producer's applied tip is itself not advancing to
   the produced height, rpc-1 advertises a stale/low head and no follower ever raises
   its target. This needs a DIRECT observation (log the head a follower receives in the
   Hello from rpc-1, or expose applied-tip via RPC). It may be the same root as (1):
   if apply doesn't advance the applied tip, neither the producer nor followers advertise
   correctly.

## Why I stopped here (not more live hot-patching)
This is a genuine consensus/apply bug, not a config nudge. Diagnosing why a downloaded
block won't commit onto the applied tip needs a **controlled two-node reproduction**
(the existing multinode fleet harness / two-node divergence harness is the right home),
not iterative restarts of the live producer. Per the reroll retrospective's own lesson:
name it precisely, keep the live chain healthy, and fix it against a falsifiable harness.

## Acceptance criteria (unchanged from the core-team handoff)
A fresh node built from current `main`, started against live 40204, advances
`eth_blockNumber` from 0 to within a few blocks of head unattended, then tracks the tip.
Add a regression test in the multinode harness: a genesis-only node reaches head in
bounded time.

## Secondary (real, smaller)
- `--network testnet` resolved **0 bootnodes** on a fresh run — had to pass
  `--bootstrap-nodes` explicitly (the bootnodes ARE in `node/config/testnet-beta.toml`).
  The citrate-core bundled node uses `--network testnet`; confirm its first-run config
  write actually loads `testnet-beta.toml`'s `bootstrap_nodes`, or it will start with 0
  peers. (Fleet bootnodes: boot1/2/3.citrate.ai:30303 + `rpc.citrate.ai:30303`, noise
  IDs in that toml.)
