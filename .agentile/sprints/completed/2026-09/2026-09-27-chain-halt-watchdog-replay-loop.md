---
created: 2026-09-27T18:00:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: completed
issue: citrate-security#126
---

# Incident retro — chain halt 2026-09-27 (watchdog replay-loop)

Fleet-wide halt, root-caused and recovered live. This is the operational record; the durable
state-loss root cause + crash-consistency fix are tracked as rescore #15/#32 and this issue.

## Source of truth (link, don't copy — Rule 9)
- citrate-security **#126** (state-durability root cause).
- Height watchdog fix: `citrate-height-watchdog.sh` (sync-aware) → citrate-chain **PR #243**.
- Related durability memory: committed-state-lags-tip; execute-on-receive replay.

## Timeline
1. An unclean restart lost in-memory state; the node fell back to a ~epoch-14 snapshot and began a
   **full re-execution** from there.
2. During replay the canonical head is frozen (it advances only as replay commits), which looks
   identical to a **wedge** to a naive height watchdog.
3. The height watchdog restarted the producer **mid-replay** → replay restarts from the snapshot →
   the head never advances → **restart loop**. The chain was not corrupt; it was being kicked every
   time it tried to heal.

## Fix
- Made the watchdog **sync-aware**: track `eth_syncing.currentBlock` and treat *replay progress* as
  liveness, only restarting on a genuine stall (no `currentBlock` movement), not on a frozen tip
  during replay (PR #243). Paused the watchdog during recovery; re-enabled after.
- Recovered the chain by bridging the public RPC to the **Mac producer** (which held full state)
  while `rpc-1` re-executed to catch up. The R2 redeploy was **not** lost.

## Lessons
- **Liveness signals must distinguish "frozen tip" from "no progress."** A watchdog that only watches
  the tip will fight its own recovery. Progress = the replay cursor moving, not the head moving.
- **A snapshot-fallback + a naive restarter is a loop generator.** Any auto-restart must be gated on a
  signal that keeps advancing during recovery.
- **Keep one known-good producer isolated** (the Mac node over the tunnel) so recovery has a source of
  truth to bridge to — and do NOT stop it until the replaying fleet's tip hash matches (still the
  standing rule for the RPC flip-back, rescore #17).

## Open
- Durable root cause of the state loss on unclean restart (rescore #15, #126) + a **kill-9-during-commit
  crash-consistency test** (rescore #32) so this class can't recur silently.
- Written postmortem with required frontmatter (rescore #43).
