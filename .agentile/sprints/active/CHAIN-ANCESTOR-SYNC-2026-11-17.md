---
name: CHAIN-ANCESTOR-SYNC
description: Header-first ancestor sync so a node on a lighter branch re-converges on the heavier one; verified-or-corroborated height evidence
created: 2026-11-17T23:30:00Z
branch: fix/ancestor-sync-reconverge
author: Larry Klosowski
status: active
---

# CHAIN-ANCESTOR-SYNC: re-converge after a partition

Incident: `citrate-labs/handoffs/FLEET_SPLIT_2026-11-17.md` (r1007, six partitions
since 2026-11-15 00:28Z, common ancestry to 105,012, finality stuck at 105,000).
Design: `.agentile/adrs/ADR-2026-11-17-ancestor-sync.md`.

Owner decisions (2026-11-17): build the ancestor-based sync fix; the canonical
branch for the later recovery is HEAVY (boot-1, boot-2, prod-5). The recovery
itself is a separate owner-run ops step. This sprint does not touch the fleet.

Relation to #482 (`hardening/pipeline-far-behind-v2`, 508407f1 / 18483dc5): that
change keeps the #477 pipeline from suppressing the tick's request when no peer
may be asked. This sprint is built alongside it, off `origin/main` f4a0e600; the
two touch `main.rs`, `sync_peer.rs` and `split_heal_tests.rs` in different places.

## WP-1 Red: the split and the poisoning reproduce

- [x] `node/src/split_heal_tests.rs::two_groups_forked_past_the_walk_reconverge_on_the_heavier_branch`:
  3v4 producers fork above a finalized checkpoint (registered through
  `CanonicalApplicator::register_certified`), 1,100 slots apart with the light
  group sealing every other slot (both branches 550 above the fork, past the
  512-height walk; heavy tip 550 above light, as r1007's HEAVY was +363), one
  transaction per side, reconnect; every node must select the heavy branch
  and every producer seal again within 60 slots;
  no floor below the checkpoint; a checkpoint above the fork registers on every
  node; both transactions executed on the converged chain or back in a pool.
- [x] `node/src/split_heal_tests.rs::a_lone_peers_far_ahead_gossip_moves_neither_the_target_nor_its_head`:
  one peer gossips signed blocks a million heights ahead on an unknown parent;
  `max_seen` and that peer's `head_height` must not move.
- Fixture: the harness applicator now gets the node's mempool, as `start_node`
  wires it (`with_mempool`).

## WP-2 Protocol 1.3 and the server

- [x] `GetAncestor` / `Ancestor` appended to `NetworkMessage`; `ProtocolVersion::ANCESTOR_SYNC`
  (1.3) is `CURRENT`; `Peer::send` withholds both from peers below 1.3;
  `GetAncestor` routed to the serving plane, `Ancestor` to the reserved lane.
- [x] `block_serve::serve_ancestor` (canonical index, 64-hash locator, 128
  headers, 60 KiB).
- Tests: `core/network/tests/ancestor_sync_wire.rs` (gating for 1.0 / 1.2 /
  unknown / 1.3, version compatibility, bincode tags unchanged, round trip, a
  full reply fits one Noise message); `block_serve::tests::serve_ancestor_*` (5).
- `core/network/tests/checkpoint_sync_wire.rs::version_bump_is_backward_compatible`:
  the pin `CURRENT == CHECKPOINT_CERT_SYNC` became "CURRENT is at or above 1.2"
  (the version moved to 1.3; assertion edit in its own commit).

## WP-3 The driver

- [x] `node/src/ancestor_sync.rs`: locator, header verification, episode
  driver (locate, headers, work gate, bodies), reorg floor, cooldowns; wired in
  `main.rs` (tick, `Ancestor` arm, `Blocks` arm) and mirrored in the harness
  (`main_loop_mirrors_the_harness` pins the calls).
- Tests (`ancestor_sync::tests`, 20): locator shape and bounds (3), header faults,
  heavier branch fetched past 512, lighter branch never fetched, a tip claim
  alone fetches nothing, fork beyond the undo window refused (the r1007 shape),
  fork below the finalized checkpoint refused, extends left to ordinary sync,
  forged common block, forged header work, stalled bodies, timeout, mixed
  versions, evidence required, peer left, bounded cooldown table, body window,
  cursor catches up with a split answer.
- Harness: `a_mixed_version_fleet_reconverges_through_its_upgraded_peers` (the
  same split with two heavy producers on 1.2; the harness asserts no 1.2 node
  is ever sent a 1.3 message).

## WP-4 Evidence poisoning

- [x] `sync_peer::DeferredHeights` (two distinct peers corroborate a deferred
  height; one peer counts when it is the only one connected) and
  `sync_peer::gossip_raises_head` / `raise_gossip_head`; `main.rs` no longer
  calls `observe_gossiped_head` on the raw block.
- Tests: `sync_peer::deferred_height_evidence` (6, incl. a tripwire on main.rs).

## Verification (cnv-build-2, Ubuntu 24.04, rustc 1.96.0; no cargo on the Mac)

| What | Result |
|---|---|
| Red, f4a0e600 + red tests | `a_lone_peers...` FAILED ("one peer's unverified claim of 1000011 moved the network height to 1000014 (verified 11)"). `two_groups...` (60-slot bound) FAILED: p0 and p2 stuck at 577 with 4,244 / 4,016 orphans, rejoin idle. The scenario is not deterministic on f4a0e600 (HashMap order): a second run with a 240-slot bound converged at slot 32, and an earlier 640-slot variant converged too. |
| Green, the fix | `two_groups...` converged at slot 19 (and passed in two suite runs); `a_mixed_version...` ok; `a_lone_peers...` ok. |
| `cargo test --workspace` baseline (f4a0e600) | 6,186 tests: 6,141 passed, 22 ignored, 23 failed, all `Too many open files` (run without `ulimit -n`); f4a0e600's node binary re-run with `ulimit -n 65536`: only the new red test fails. |
| `cargo test --workspace` fix | 6,225 tests: 6,203 passed, 0 failed, 22 ignored (+39; one more, the split-answer cursor test, added after). |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean. `--all-features` fails in `core/execution/src/zkp/halo2` (unused imports, unknown cfg), in files this change does not touch (not checked on main). |
| `cargo fmt --all -- --check` | clean (Mac). |
| Rule 6 benchmark | see `benchmarks/2026-11-18-ancestor-sync-devnet.md`. |

## Daily updates

- 2026-11-17: design settled (ADR). Code written; red tests built against
  f4a0e600.
- 2026-11-18: red confirmed, green, workspace suite and clippy clean on
  cnv-build-2; benchmark run; PR opened (owner merge).

## Notes / follow-ups

- The deep-split harness run is slow in debug (about 80 minutes; 1,100 slots
  of seven producers) and its outcome on f4a0e600 depends on HashMap order.
  On the red runs a stuck light node held 4,000+ orphans, and every new
  `Blocks` answer re-admits the whole orphan buffer (signature checks): the
  cost that made the slow runs slow. Bounding that rescan is a follow-up.
- `--all-features` clippy fails in `core/execution` zkp code this change does not touch.

- Today's r1007 fork (~121k deep) is below every node's reorg floor (undo
  window 10,000, DAG retain 10,000). This fix does not re-converge it; the
  losing nodes log `SYNCANCESTOR ... below our reorg floor` and need the
  owner-run re-seed from HEAVY. The fix keeps a future split inside the window
  from persisting.
