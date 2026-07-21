---
created: 2026-07-21T05:00:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude (Opus 4.8, 1M)
status: PHASES 0–2 CODE-COMPLETE (spec+ADR+red-test+fix landed, all green) — awaiting owner gates G0/G1/G2; Phase 3 (durable reroll) pending owner go
progress:
  - "WP-0.1 RewardApplyPurity.tla + .cfg + _buggy.cfg — TLC-clean (committed-only: no error; buggy: RewardRootAgreement violated). DONE, G0 pending."
  - "WP-0.2 ADR-2026-07-21-reapply-reward-purity.md — decision + red-team, mechanism PINNED. DONE, G0 pending."
  - "WP-1.1 red test srp_s2_producer_receiver_reward_parity_on_restart_empty_block (node/src/producer.rs) drives the REAL produce_block — FAILED on main (StateRootMismatch 0x6f1d8584 vs 0xdf1c59d0), pins the enhanced-path mechanism. DONE, G1 pending."
  - "WP-2.1 fix: removed the node-local enhanced reward path; producer settles ONLY via settle_block_rewards_guarded (committed state). Red test GREEN; 121 node-bin + 8 rprime-parity + 46 rollback/reorg/batch tests all green; tripwire scripts/ci/srp_s2_reward_purity_tripwire.sh added. DONE, G2 pending."
  - "WP-3.1 durable reroll — NOT executed (live production ceremony; owner go required)."
program: SRP (State-Root Purity) — Sprint S2: the re-apply / reward-settlement path
code: SRP-S2
depends-on: SRP-S1 (forward root purity — DONE + rerolled); this covers the path S1 did NOT
blocks: a durable reroll; reliable citrate-core sync across app restart; TOB handoff
adr: ../adrs/ADR-2026-07-21-reapply-reward-purity.md (to write, Phase 0)
spec: ../../specs/tla/consensus/RewardApplyPurity.tla (to write, Phase 0)
---

> **This is a consensus-safety sprint (SRP class), not a feature.** SRP-S1 made the FORWARD
> state root a pure function of committed state (proven, rerolled). SRP-S2 covers the path S1
> left open: **the reward-settled root on the RE-APPLY / RESTART / REORG path.** Lead with spec,
> walk the full Agentile loop, do not band-aid.

## The incident that exposed it (2026-07-21, ground truth)

During the v2 fleet hot-swap, restarting the **miner** (rpc-1) mid-operation poisoned block
**2209** and split the fleet:

- Block 2209 is **empty** (gasUsed 0), **single-parent** (mergeParentHashes []), post-activation.
- Its canonical stateRoot is `0x237bf250…` — **identical to block 2208's** (i.e. on the canonical
  chain, applying 2209 produced **NO net state change**).
- A cleanly-synced node (boots, honest 0→2208, agreeing with rpc-1 on 2208's root) **re-executes
  2209 and computes `0x52e54249…`** — a state CHANGE — then hard-rejects the block
  (`state root mismatch (claimed 237bf250, computed 52e54249)`), freezing its applied tip at 2208
  while its DAG head advances. Result: **executed state diverges** (boot coinbase `0x5e6f1b…` vs
  rpc-1 `0x63c5336c…`), a split-brain.
- rpc-1's boot rehydration **succeeded** ("epoch-2 snapshot S=1800, 4 validators reloaded"), so a
  raw `None`-policy skip is NOT the cause. `settle_block_rewards` early-returns on `share.is_zero()`
  (empty block → no `creditReward`), and `calculate_reward` is a pure fn of the block — yet the
  producer's applied 2209 recorded NO change while a clean receiver computes one. **The producer's
  reward-settlement effect for 2209 is not reproducible by a clean re-apply.**

## Root cause — CLASS (established) + exact mechanism (Phase-1-to-pin)

**Class:** the reward/§R' settlement produces a state-root effect on the **producer** path that a
node re-applying the *same block* against honestly-synced state **cannot reproduce**, when the
producer restarted mid-operation. This is the SRP impurity — a root that is a function of
node-local/transient producer state rather than of committed state — but on the **re-apply/reward
path**, which SRP-S1 (forward root over committed accounts+storage) did not cover.

**Candidate mechanisms to disambiguate in Phase 1** (the red test pins exactly one):
1. **Producer enhanced-vs-basic path timing.** `use_enhanced = economics_manager.is_some() &&
   !emit_v2_headers` (producer.rs:899). If `emit_v2_headers` is briefly false around a restart, the
   producer credits a node-local *enhanced* reward (reputation f64 / dynamic pricing — producer.rs:
   900-935) that no receiver (basic path) reproduces.
2. **Basic-reward credit asymmetry.** Producer's `basic_credits` (producer.rs:955) vs receiver's
   `canonical_apply::reward_credits` diverging for a specific block (e.g. one credits the 10-SALT
   basic reward, the other early-returns) — the empirical "producer no-change, receiver change" at
   2209 fits a producer that skipped the basic credit the receiver applies.
3. **Reward-policy / proposer-selector reconstruction.** `hydrate_on_boot` restores the policy cell
   + selector; if the restored `staker_of` / `priority_fee_share_bps` / proposer selection differs
   by even one entry from a from-genesis node, `creditReward` targets/《amounts》diverge.

**Do NOT assume; the Phase-1 reproduction decides.** All three are the same fix shape: the
reward-settled root must be derived purely from committed state on every role.

## Phases (each = full Agentile loop; each gate = owner sign-off)

### Phase 0 — Spec + ADR (gate G0)
| WP | Title | Acceptance |
|---|---|---|
| **WP-0.1** | `RewardApplyPurity.tla` — formalize: the reward-settled state root is a pure function of committed state, identical across roles {producer, receiver, cold-sync, **restart-resume**, **reorg-reapply**}. Model a producer that restarts mid-epoch and a receiver replaying its block. | TLC clean; the invariant FAILS for a model that lets the producer's reward use transient state, PASSES for the committed-only model. |
| **WP-0.2** | `ADR-2026-07-21-reapply-reward-purity.md` — decision: single reward-settlement derivation from committed state on ALL roles; producer MUST hard-fail (not silently diverge) if its reward inputs aren't the committed-state ones; kill the enhanced path under v2 unconditionally. Red-team it. | ADR accepted + red-teamed; every WP cites its section. Blocks all others. |

### Phase 1 — Reproduce + pin (gate G1)
| WP | Title | Acceptance |
|---|---|---|
| **WP-1.1** | **Deterministic local red test**: 1 producer past activation; **restart the producer** mid-epoch; produce an empty post-activation block; a fresh node re-applies from genesis and asserts per-block root + balance equality. | Test FAILS on `main` (reproduces `237bf250 ≠ 52e54249` on the restart-produced block) — this is the pass/fail oracle + pins which of the 3 mechanisms. |

### Phase 2 — Fix (gate G2)
| WP | Title | Acceptance |
|---|---|---|
| **WP-2.1** | Make the reward-settled root pure on the re-apply path per the pinned mechanism (e.g. force basic path under v2 always; derive reward inputs only from committed state; producer hard-fails on any transient input). | WP-1.1 GREEN; all SRP-S1 + reorg/snapshot/persist tests stay green; a producer restart followed by empty + fee-bearing post-activation blocks re-applies byte-identically from genesis. |

### Phase 3 — Durable reroll (gate G3)
| WP | Title | Acceptance |
|---|---|---|
| **WP-3.1** | One clean reroll on the fixed binary (no mid-flight restarts); then **prove restart-resilience**: sync a fresh node to head, **restart it**, confirm it resumes without divergence; repeat for the miner. | Fresh + restarted nodes match the fleet on root + balances across activation; **citrate-core Linux + Mac cold-sync AND restart** hold. |

## Definition of done
- `RewardApplyPurity.tla` green; ADR accepted + red-teamed.
- The reward-settled root is proven pure across producer / receiver / cold-sync / **restart** / **reorg**.
- A node (incl. the miner) can be restarted mid-operation without poisoning a block.
- Durable reroll executed; citrate-core syncs **and survives app close/reopen** on Linux + Mac.

## Live-chain status (as of 2026-07-21, needs this fix before recovery)
Chain 40204 is split-brain: rpc-1 solo-advancing on the poisoned chain (block 2209+), 3 boots
wedged at applied-2208. RPC is up (rpc-1) but no fresh node can sync past 2209. **Recovery =
this fix, then a clean reroll (Phase 3).** Do NOT reroll on the current binary (would re-expose
the restart-wedge). Pre-swap fleet binary backed up on each node as `citrate-node.pre-v2`; wedged
boot state archived as `.citrate.wedged-*`.
