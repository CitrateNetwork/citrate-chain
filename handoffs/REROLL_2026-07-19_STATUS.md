---
title: "Re-roll 2026-07-19 — DONE (fleet healthy); cross-arch bug DISPROVEN; real blocker = fresh-sync wedge #85"
created: 2026-07-19
updated: 2026-07-19
branch: main
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: re-roll complete; NO reroll needed; cross-arch determinism DISPROVEN; open blocker = arch-independent fresh-node forward-sync wedge (#85)
chain: 40204, genesis 0x481a59bc, rpc.citrate.ai
---

> **SUPERSEDED 2026-07-20** — the "cross-arch" framing here was a misdiagnosis. The
> real root cause was state-root NON-DETERMINISM (non-idempotent `calculate_state_root`),
> fixed in PR #88 and re-rolled. See `REROLL_2026-07-20_DETERMINISM_FIX.md` for the final story.

# Re-roll status

## The original problem — FIXED
The live chain was un-syncable because it was produced by the 2026-07-17 reroll
binary whose tx execution (the ValidatorRegistry deploy) diverged from current `main`.
Root-caused, then re-rolled with current `main` so every node runs identical code.
Three sync bugs fixed + merged along the way: target-max (#84), periodic forward-drain
`drive_drain` (#86), and the diagnosis is in NODE_SYNC_INVESTIGATION_2026-07-19b.

## Re-roll — DONE
- **Atomic reset** (stop-all → wipe-all → producer isolated → verify fresh → join followers),
  after a first non-atomic attempt let rpc-1 re-adopt the old chain. Noise keys preserved.
- **All contracts deployed (except Boeing) + verified live: 54/54.** 28 core + 16 features
  + 7 AA (live addresses: EntryPoint 0xC698feAf, factory 0x5a45B6F8, paymaster 0xF14F56e8)
  + co-op 0x6fe6fd2a + ValidatorRegistry 0x3Bf6C5bb + membership.
- **4 validators registered + active** (`activeCount()==4`), before S(2)=1800.
- **Fleet converged and stays in lockstep through every deploy** — including the
  ValidatorRegistry deploy that broke the old chain. Determinism holds across the x86_64 fleet.
- Script fixes needed along the way (uncommitted, in working tree): `derive-operator-keys.sh`
  (bare `python3` → `uv run python3`), `post-reroll-redeploy.sh` (WS-3: EntryPoint now
  deployed by DeployAndPinAA, so unset `CITRATE_AA_ENTRY_POINT` is valid — softened two
  stale prechecks).

## ~~NEW BUG: cross-arch state-root divergence~~ — DISPROVEN (2026-07-19, investigated)
The earlier hypothesis (a genuine cross-arch EVM determinism bug: aarch64 computes a
different state root for the EntryPoint deploy at block 235) was a **MISDIAGNOSIS**. Ruled
out by controlled experiment. What was really happening:

**1. The original observation was confounded by a stale binary.** The aarch64 node that
"wedged at 235 with root `5fb263db` vs fleet `d9238df1`" was built at 14:20 — it LACKS
`#86 drive_drain` (`e75e037`, committed 14:38), the periodic forward-drain sync fix the
fleet binary (14:51) has. The only delta between the two binaries is that ONE sync commit;
the EVM execution path is byte-identical. So the aarch64 node was building on the wrong
ancestor via the sync wedge, not executing to a different root.

**2. Controlled solo reproduction shows NO arch divergence.** Two fresh isolated producers
(aarch64 DGX + x86_64 boot1, the exact fleet binary), same coinbase/genesis/env:
   - Pre-EntryPoint empty blocks 0–15: **state roots MATCH byte-for-byte** across arch.
   - Deployed identical EntryPoint init-code on both → same tx hash, same address, same
     `gasUsed 0x2a5849`, identical EntryPoint + SenderCreator code/nonce/balance.
   - Post-deploy state roots at every common height (162,163,170,175,176): **MATCH.**
   The state-root code (`core/storage/src/state_manager.rs::calculate_state_root`) is
   structurally arch-portable: sort-by-address + explicit `to_le_bytes`/`to_little_endian`
   + Sha3. No HashMap-order / float / native-endian hazard.

**3. The REAL blocker is the fresh-node forward-sync wedge (#85, STILL OPEN) — and it is
ARCH-INDEPENDENT.** A fresh node built from current `main` (with #84+#86) wedges at
**height 1**, not 235, and NOT with a state-root mismatch — with
`Rejected inconsistent synced block …: Missing parent at admission`. A fresh **x86_64**
follower wedges IDENTICALLY. Root cause in `node/src/main.rs:~2029`: `drain_validated_blocks()`
yields synced blocks, each admitted via `validate_block_consistency` which requires the
parent already in the DAG; if a child drains before its parent (out-of-order batch) it is
**rejected and DROPPED — never re-queued or backfilled**. Node gets block 1, then blocks
7,8,9… whose parents 2–6 never arrived in order, rejects them, and wedges. This is what
actually blocks citrate-core's bundled node — on Mac AND Linux equally.

**Reroll implication: NONE.** Chain state is correct and arch-portable. No reroll needed.
The fix is a node-sync change (parent-before-child ordering / re-queue / backfill in the
`Blocks` handler), not a chain re-roll.

## Remaining (owner / follow-up)
1. **Fresh-node forward-sync wedge (#85)** — the real blocker for node onboarding (all arches).
   Fix the `Blocks` handler in `node/src/main.rs` to topologically order drained blocks and/or
   re-queue "missing parent" rejects for retry after their parents admit (or request the
   missing parents). No reroll; ordinary node fix + fleet binary redeploy.
2. **SBT address drift:** CitrateMemberSBT deployed at `0x149E85A3C845d10556537DcF824D148aCB904578`
   (not the pre-reroll `0x7be005aa`); its constructor args differ. Book updated; re-pin
   core-membership + any SBT consumer to the new address.
3. Commit the two script fixes; regenerate/verify the federation address pins; fund operational
   roles (regenesis §7); rotate `DEPLOYER_PRIVATE_KEY` (it was echoed by a `bash -x` trace this
   session — do NOT reuse it for anything sensitive).
4. Boeing/BFR still deliberately excluded.
