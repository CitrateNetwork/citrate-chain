---
created: 2026-07-31
branch: docs/escalation-sync-anchors-frozen-peer-149k
author: Claude (Opus 4.8), directed by @SaulBuilds (citrate-core / desktop side)
status: P1 escalation to DGX/chain — residual after #147. A cold-syncing node
  reaches the BOOTNODES' height (149,388) then re-imports that one block forever,
  never pulling the remaining blocks from the sequencer (rpc-1, ~7k ahead). Either
  sync-source selection never switches to the highest-head peer, or the bootnodes
  themselves are frozen at 149,388 (FLEET HEALTH — verify boot1/2/3 first).
relates:
  - handoffs/SYNC_DRIVER_STALL_AFTER_ONE_BATCH_2026-07-31.md (#146 → fixed by #147)
  - PR #147 (a53d635) fix/sync-driver-stall-one-batch (progress-% panic + re-dial latch)
---

# P1 — after #147, cold-sync stalls at the bootnodes' height and re-imports the anchor

## What #147 fixed (context)
#147 fixed the progress-% underflow panic that killed the inbound loop AND the
re-dial latch. Result: the desktop node went from stalling every ~28 blocks to
climbing **continuously from 91,187 to 149,388** — a big win. Then it hit THIS.

## The symptom (live 2026-07-31, verbatim from the node's own log)
```
INFO citrate_network::sync: Validated and imported 1/1 blocks (height 149388-149388), progress: 0.0%
INFO citrate_network::sync: Validated and imported 1/1 blocks (height 149388-149388), progress: 0.0%
… every 2s, forever.
```
The node re-imports **its own current tip (149,388)** — a single block it already
has — over and over, and never fetches **149,389**. Confirmed:
- Applied head frozen at **149,388**; sequencer (`rpc.citrate.ai`) at **156,445**
  and advancing → **7,057 behind**.
- `eth_syncing` on the node = `{currentBlock: 149388, highestBlock: 156445}` — it
  **KNOWS the target is 156,445** (it has heard the sequencer's head).
- `eth_getBlockByHash(<149389 hash>)` on the node = **not present** → 149,389 was
  never downloaded. So this is a REQUEST/source problem, not apply/drain.
- 149,389 is a **plain block** (parentHash = 149,388 which the node HAS,
  `mergeParentHashes: []`) — nothing about the block is hard to apply.
- 0.0% CPU, 4 peers, stable uptime, zero crash records — a live idle, not a crash.
- **A restart does NOT clear it** (unlike the pre-#147 91k stall, where a restart
  bought one batch). It resumes at 149,388 and immediately re-enters the loop.

## Diagnosis
The node is syncing FROM a peer that is itself at 149,388 — it asks "give me
blocks from 149,388", gets back only block 149,388, re-imports it (no-op), and
makes no progress. **149,388 is the bootnodes' height.** The node never switches
its sync source to the peer with the highest advertised head (the sequencer,
`rpc.citrate.ai` @ 156,445), even though it has that peer in its bootstrap set
(`noise_6ee5…@rpc.citrate.ai:30303`) and reports its height as the target.

Two candidate causes — please check in this order:

1. **FLEET HEALTH FIRST: are boot1/boot2/boot3 frozen at 149,388?** If the three
   bootnodes are followers that hit this same class of stall, the whole fleet's
   non-sequencer nodes are stuck at 149,388 and only rpc-1 advances. A new node
   then syncs to the bootnodes' frozen height and stops. Check the bootnodes'
   applied heights directly. If they're frozen, that is the headline problem.

2. **Sync-source selection never promotes to the highest-head peer.** The driver
   anchors on whatever peer it's pulling from (a 149,388 bootnode) and re-requests
   from it every 2s instead of switching to the sequencer whose head (156,445) it
   already knows. Post-#147 the re-dial latch is gone, but selecting/So — WHO the
   node pulls from — still lands on the frozen peer. Likely near the same
   `start_sync` / target-vs-source path (`core/network/src/sync.rs`) — the target
   is raised to 156,445 but the actual `GetBlocks` anchor stays at the frozen
   peer's tip.

## Repro
Fresh node, chain main (post-#147), no pruning, join 40204, cold-sync. It climbs
continuously (that's #147 working), then stalls at the bootnodes' height and
re-imports that one block every 2s, `eth_syncing` target correctly showing the
sequencer's higher head. Restart does not help.

## Ruled out
Not pruning (off; 95k past 54,600) · not the #147 panic (it climbed 58k first) ·
not a deep merge-parent (149,389 has none, parent present) · not apply/drain
(149,389 never downloaded) · not an unreachable sequencer (rpc.citrate.ai answers
+ advertises 156,445) · not a crash-loop (live idle).

## Impact
Same onboarding-blocker class as before: a fresh node cannot reach the tip — it
tops out at the bootnodes' height. If the bootnodes are also frozen (cause #1),
the fleet is only as live as rpc-1.

## Desktop side (for reference — nothing here fixes it)
citrate-core is current: #113 llama-grace, #115 follower-until-synced, #116
stop-pruning; app rebuilt with the #147 node binary bundled; node data preserved
(valid to 149,388). It will finish the moment a node can pull 149,389+ from the
sequencer.
