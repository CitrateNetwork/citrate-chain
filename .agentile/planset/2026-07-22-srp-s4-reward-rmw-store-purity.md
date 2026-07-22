---
title: SRP-S4 — reward read-modify-write / store purity (the block-5,406 cold-sync wedge)
created: 2026-07-22
branch: srp/s4-reward-rmw-store-purity
author: Claude (DGX / chain-ops session)
status: OPEN — Phase 0/1 (spec + reproduce + pin); fix + reroll gated on the pin
supersedes: none
related: .agentile/planset/2026-07-21-srp-s3-restart-produce-purity.md, ../../citrate-core/docs/DGX_NODE_SYNC_WEDGE_RESPONSE_2026-07-22.md
---

# SRP-S4 — reward RMW / store purity

## TL;DR

After SRP-S1/S2/S3 (all merged to `main` `f9c1551`, all their red tests green), a
**from-genesis cold-sync still wedges** — now at **block 5,406** — with
`state root mismatch (claimed 2d9381d2, computed 55286580)`. This is a **residual
state-root-purity bug**, NOT app config and NOT a missing binary. The live chain
survives only because the producer (`rpc-1`) runs continuously; **no fresh node can
join past 5,406**, and a clean reroll on the current binary would re-expose it.

## Proof it is real + not previously-fixed facets (DGX, 2026-07-22)

Reproduced on **3 independent nodes / 2 binaries**, all computing the identical wrong
root `55286580` at 5,406 while the producer committed `2d9381d2`:
- a fresh `f9c1551` build + full fleet env (`CITRATE_BLOCK_V2=1`,
  `CITRATE_VALIDATOR_ACTIVATION_HEIGHT=2000`, `CITRATE_VALIDATOR_REGISTRY=0x915DdE02…`);
- **`boot1` running the actual fleet binary `2a6d4cb`** with the identical fleet env
  (its RPC "head" 14,668 is downloaded-ahead blocks; its **applied tip is stuck at
  5,405**, 60k reject events).

Ruled out with evidence: **(a)** not the app env (full env still wedges); **(b)** not
an unpushed fleet commit (the fleet binary wedges identically); **(c)** not cross-arch
(refuted in the SRP-S1 docs by a two-arch experiment); **(d)** not restart-poison —
`rpc-1` ran continuously (`NRestarts=0` since 19:03), block 5,406 was produced at 21:59
with no restart near it.

## Root-cause fingerprint (what SRP-S1/S2/S3 did NOT close)

- **5,405 roots MATCH** (`0x668264ec`) → the divergence is entirely in the **5,406
  transition**. 5,406 is an **empty block** (0 txs), so the only state write is the
  BASIC block reward: `settle_block_rewards` step (1) credits `basic_credits`
  (`treasury 0x11…11` +1 SALT, `header.coinbase` +9 SALT) via `set_balance`
  (`executor.rs:1350`). §R' is a **no-op on empty blocks** — the priority pool is 0,
  so `share.is_zero()` early-returns before any state write (`executor.rs:1410`).
- **The trigger is post-activation.** The SRP-S1 §R'-off cold-sync gate
  (`scripts/ci/srp_coldsync_gate.sh`) passes to ~280 blocks; the live wedge is at
  activation(2000)+3406. The only thing that runs post-activation but not before is the
  **registry-snapshot materialization** in `registry_sync` at S(E) boundaries
  (S(3)=2800, S(4)=3800, S(5)=4800; `EPOCH=1000`, `SNAPSHOT_LAG=200`). That path does
  `view_call`s against the registry, which **read-through-hydrate** accounts into the
  resident map.
- **The mechanism = store ↔ resident-map desync propagated by the reward RMW.**
  `Executor::get_balance` (`executor.rs:806`) returns the RESIDENT value if the account
  is resident, else **reads the durable STORE and hydrates it** (`:811-813`). SRP-S1
  made `calculate_state_root` fold the *resident map*, but the *store* can still hold a
  divergent balance for the same account (the live "2557 class": identical `stateRoot`,
  divergent `eth_getBalance`). When the reward does
  `set_balance(x, get_balance(x) + r)` and `get_balance` read-throughs a **divergent
  store value**, that value is written into the resident map and **folded into the next
  root** → the first block whose fold surfaces the desync (5,406) forks. The producer
  (continuous, account always resident) never read-throughs; a cold-sync (fresh resident
  map, or one evicted/re-hydrated at an S(E) boundary) does.

> One-line statement of the bug: **the block-reward read-modify-write is not a pure
> function of committed state — via `get_balance`'s store read-through it can fold a
> durable-store value that diverges from what `calculate_state_root` committed.**

## The acceptance oracle that matters (unchanged from S1–S3)

A from-genesis cold-sync must match the producer on the state ROOT **and per-account
balance and per-storage-slot** at every height — not just the root. SRP-S4 additionally
asserts: **`get_balance(x)` equals the value `calculate_state_root` folds for `x`**, for
every account, resident or not (no store/resident divergence can enter the reward).

## Phases (each = full loop; each gate = owner sign-off)

### Phase 0 — Spec + ADR (G0)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-0.1** | `specs/tla/consensus/RewardRmwPurity.tla` (+ `.cfg` + `_buggy.cfg`) — model an account with a committed (root-folded) value and a possibly-divergent store value; the reward RMW must read the committed value; `RootAgreement` holds across producer/coldsync. | TLC clean on the fix config; the buggy config (RMW reads store) VIOLATES `RootAgreement`. |
| **WP-0.2** | `.agentile/adrs/ADR-2026-07-22-reward-rmw-store-purity.md` — decision (below) + red-team. | ADR accepted + red-teamed (≥2 adversarial passes; carry findings). |

### Phase 1 — Reproduce + PIN the origin (G1)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-1.1** | Executor-level red test `srp_s4_reward_rmw_reads_committed_not_divergent_store` (this branch, `core/execution/tests/srp_s4_reward_rmw_purity.rs`) — a committed account (root folds A) whose durable STORE holds a divergent B; the reward RMW + `calculate_state_root` MUST fold A+r, not B+r. | FAILS on `main` (store B leaks into the root), GREEN after the fix. **Scaffold written; confirm it goes RED on `main`.** |
| **WP-1.2** | **Pin the ORIGIN of the store↔resident desync** with the local §R' harness (`scripts/ci/srp_s4_coldsync_harness.sh`, already built — producer + cold-sync, §R' active) run past the S(E) boundary that first desyncs, then `state-digest` diff of the two data dirs to NAME the exact account/slot. NOTE the two harness blockers to clear first: the local `--network testnet` genesis under-funds the deployer for the 32k bond (deploy a low-`minStake` registry + recompute its CREATE2 address + set the env to it), and the CREATE2 registry deploy currently fails (gasUsed 700 — debug the forge init-code/broadcast). | `state-digest` names the diverging account (expected: `registry 0x915DdE02` storage, or `treasury`/`coinbase` balance); WP-1.1 reproduces that exact case. |

### Phase 2 — Fix (G2)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-2.1** | Decision (see ADR): make the reward RMW + every root-feeding read a pure function of committed state. Two candidate strategies — (A) `get_balance`/read-through **reconciles to the committed representation** the root folds (never surfaces a divergent store value into a root-feeding read), and/or (B) **eliminate the desync at its origin** (the `registry_sync` `view_call` read-through and `persist_state_changes` keep store == resident-map for every folded account). Prefer the strategy the ADR red-team shows is complete. | WP-1.1 RED→GREEN; SRP-S1/S2/S3 red tests + tripwires still pass; `citrate-execution` + `node` suites green (test ratchet ≥ current); a new `scripts/ci/srp_s4_reward_rmw_tripwire.sh`. |

### Phase 3 — Clean reroll + durable proof (G3)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-3.1** | ONE clean reroll on the SRP-S4 binary (both arches; address-neutral if the genesis root is unchanged, else re-pin the book). Then prove the oracle DEEP: a fresh external cold-sync crosses the old wedge height and **tracks the tip past 5,406-equivalent** with 0 mismatches AND per-account/per-slot equality; repeat with the `citrate-core` bundled node (Linux + Mac) + close/reopen. | New chain live on all 4; activeCount 4; deep cold-sync 0 mismatches; citrate-core cold-syncs to tip. Then update `citrate-core/docs/DGX_NODE_SYNC_WEDGE_RESPONSE_2026-07-22.md` with the SRP-S4 resolution + new genesis. |

## Decision (for the ADR, to be red-teamed)

The state root's authoritative representation is the **committed store** (what a
from-genesis replay reconstructs), and `calculate_state_root` already folds the resident
map rebuilt from it. Therefore **no root-feeding read may return a value that differs
from the committed store**, and **the block-reward RMW must read exactly that committed
value**. The fix closes the last read-through seam (`get_balance`/`view_call`
hydration) so producer, receiver, cold-sync, restart, and reorg all settle the reward
from byte-identical committed state — extending SRP-S1's pure-root guarantee from the
root COMPUTATION to every state READ that feeds it.

## Interim unblock (no reroll) — for citrate-core

Ship the app a **state snapshot** (a synced data dir at/near tip) that `NodeManager`
loads and follows live from, bypassing cold-sync entirely. A node that never replays
past the wedge never hits it. Track as an app-side item; it does not fix the chain.

## Definition of done

WP-1.1 RED→GREEN, origin pinned (WP-1.2), fix merged with tripwire + specs, one clean
reroll, and a DEEP from-genesis cold-sync (both arches, incl. citrate-core) proven to
track the tip with per-account/per-slot equality. Then SRP-S1..S4 collectively close the
"consensus root not a pure function of committed state" class end to end.

## Live-chain status

Chain 40204 (SRP-S3c reroll) is **cold-sync-broken past 5,406** and must NOT be
quick-rerolled on the current binary (re-exposes the wedge). Producer + boots stay up on
continuous uptime. `PR #94` (block-v2 default-on) and any reroll wait on SRP-S4.
