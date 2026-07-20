---
title: "State-root determinism fix + chain-40204 reroll — root cause, fix, execution"
created: 2026-07-20
branch: main
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: DONE — reroll executed + validated live; determinism bug fixed (PR #88) + sync fix (PR #87); key rotation + ecosystem reconnect deferred to next reroll
chain: 40204, genesis 0x481a59bc, rpc.citrate.ai
---

# TL;DR

Chain 40204 was split-brain: rpc-1 advanced on one branch while the 3 boots wedged at
height 1999, each rejecting block 235 with **`claimed d9238df1 vs computed 5fb263db`**. The
root cause was **NOT** architecture and **NOT** the sync path — it was genuine **state-root
non-determinism** in the consensus root function. Fixed (PR #88), hardened, mutation-tested,
then re-rolled with the deterministic binary. The reroll is live and clean: **0 state-root
mismatches through 3300+ blocks, past activation 2000, `activeCount()=4`.**

# The two wrong turns (so the next person doesn't repeat them)

1. **"Cross-architecture determinism bug."** The first framing blamed aarch64 vs x86_64. A
   controlled solo experiment (two fresh nodes, one per arch, same source) showed **identical**
   state roots for empty blocks AND a standalone EntryPoint deploy. Disproven — it was never arch.
2. **"Fresh-node forward-sync wedge (#85)."** Real and worth fixing (see PR #87), but a
   *separate* bug; it made fresh nodes wedge at height 1 with "Missing parent at admission",
   not the block-235 state-root split. Fixing it did not stop the fleet splitting.

The tell that broke both misdiagnoses: **all 4 fleet nodes ran a byte-identical binary
(`md5 53421a49`) on identical x86_64 hardware, yet computed different roots for the same
block.** That is non-determinism by definition — same code, same arch, different output.

# TRUE root cause — non-idempotent consensus state root (PR #88)

`StateDB::calculate_state_root` (`core/execution/src/state/state_db.rs`) — the **only**
consensus-critical root (the AI/storage/unified roots in `core/storage` are never in a header;
an audit confirmed zero production callers; MVCC executes serially/deterministically) — inserted
each dirty account into the persistent trie with its **current** `storage_root`, then recomputed
and wrote back a fresh `storage_root` as a side effect **after** the insert. A dirty account
stays dirty until `commit`, so:

- A second call inserted the now-updated `storage_root` → a **different root** (non-idempotent,
  proven by `calculate_state_root_is_idempotent`).
- The producer calls this 2–3×/block (`producer.rs:986,1051`); a validator calls it once
  (`canonical_apply.rs:985`). On reorg re-execution the accumulated stale `storage_root`s differ
  from the original → nodes compute different roots for the same block → split.

## Fix
1. Fold the fresh `storage_root` into the account **before** encoding/inserting → the trie value
   is a pure function of state; the computation is idempotent.
2. Insert dirty accounts in **address-sorted order** (defense-in-depth: `get_dirty_accounts()`
   iterates a `DashMap` with per-instance randomized order; the hand-rolled `Trie` is
   order-independent in every tested distribution, so this doesn't change root values, it
   guarantees them).

## Tests (all MUTATION-verified — each fails on the reverted fix, passes on the fix)
- `calculate_state_root_is_idempotent`
- `producer_multicall_and_validator_singlecall_agree_with_storage` (models the producer-vs-validator split)
- `state_root_is_operation_order_independent`
- `Trie` order-independence probes (fwd/rev + 4-order)

Full `citrate-execution` suite: 564 pass. (Note: strengthening these tests also surfaced a bug
in a *test* — `(i*37+5)%48` with `i:u8` overflows under release `overflow-checks`, which briefly
masqueraded as a phantom "second bug"; fixed to u32 math.)

# The companion sync fix (PR #87)

`block_serve::serve_blocks` returned one block per height (last-writer-wins `get_block_by_height`),
dropping the **sibling** blocks a multi-producer GhostDAG creates at each height. A joining node
never received the merge-parents canonical blocks reference → "Missing parent at admission" wedge.
Fix serves the full DAG in height-ascending order with all siblings, as complete height-groups
(+ `block_store::hashes_in_height_range`, + height-sorted admission in the `Blocks` handler).
Validated end-to-end: a fresh follower synced 0→head past the wedge against a live 2-producer DAG.

# Reroll execution (2026-07-20) — binary = main `c2c955a` (#87 + #88)

- **Binaries:** x86_64 `md5 4403c23a` (fleet, built on rpc-1), aarch64 `md5 e2a8498b` (DGX / arm).
- **Pre-reroll determinism gate:** 2 peered producers processed 11 storage-writing contract
  deploys → **A=0, B=0 state-root-mismatch**; fresh follower synced through. PASS.
- **Atomic reset:** stop-all → wipe RocksDB (preserve `noise.key` / `node.toml` / `models/`) →
  swap binary → start rpc-1 isolated → verify fresh genesis → join boots. Order is critical: a
  non-atomic reset previously let a node re-adopt the old chain.
- **Fresh genesis** `0x481a59bc` / stateRoot `0x28886cb8` on all 4 nodes.
- **Deployed** (frozen CREATE2 book): 28 core (`DeployAll`) + features + full AA via
  `DeployAndPinAA` (EntryPoint `0xC698feAf` — the exact block-235 culprit — deployed with **0
  mismatches**) + ValidatorRegistry `0x3Bf6C5bb` + membership SBT `0x149E85A3` / vault `0x0aceb7B4`.
- **4 validators registered** (`activeCount()=4`), captured in the S(2)=1800 snapshot.
- **Crossed activation 2000** (at height 2024) and kept producing. **Post-reroll state-root
  mismatch = 0 across all 4 nodes through 3300+ blocks.** Determinism fully validated live.

# Gotchas learned this reroll

- `forge script --skip-simulation` sends ~700 gas for a CREATE2 deploy → the tx fails. Use gas
  estimation (drop `--skip-simulation`, optionally `--gas-estimate-multiplier 200`).
- The AA ceremony's stale precheck: empty `CITRATE_AA_ENTRY_POINT` in `.env` lets `DeployAndPinAA`
  deploy the EntryPoint itself (WS-3). A leftover pin triggers "EntryPoint has NO code — vendor it".
- The validator ceremony's `refuse-after-700` guard is about the **epoch-1** S(1)=800 snapshot,
  which is *pre-activation and irrelevant*. Activation (2000) reads the **S(2)=1800** snapshot, so
  registering with `--force` any time before 1800 is correct.
- Fleet topology: only rpc-1 mines (boots `mining=false`, registered as eligible validators).
  Proposer selection is permissive, so rpc-1 sustains the chain. `0x0dae6809` is rpc-1's derived
  proposer (from coinbase/staker1 `0xE7509e40`).
- `nohup … &` inside a single shell invocation can be killed when the invocation returns — long
  deploys need a truly detached runner.

# Deferred to the NEXT reroll (owner decision, 2026-07-20 — no real data on chain until then)

1. **Deployer key rotation → `0xF4FE9B2c6441Ff7c081B60716a78193127919783`.** The current deployer
   `0x4250675F` was exposed by a `bash -x` trace. Do it at genesis next reroll so ALL addresses —
   fresh deployer + re-derived operators — roll out deterministically (no fund-sweep needed).
   NOTE: operator keys (`VALIDATOR_STAKER_1..4`, `GRANT_SIGNER`, `AA_SPONSOR_SIGNER`, `AA_REGISTRAR`)
   are `keccak256(DEPLOYER_PRIVATE_KEY ‖ label)` and already committed on-chain — changing the
   deployer key without re-deriving/redeploying them breaks the registered validators + SBT owner.
2. **Ecosystem reconnection:** point identity (`157.230.55.191`), bundler (`159.223.174.220`), and
   the inference gateway at the new AA addresses + restart.
3. **Co-op deploy** (net-new; frozen CREATE2 factory not yet deployed).
4. Optional now: explicit SBT/vault pin in `40204.json`; 200k grant-signer funding (no members yet).

# Canonical live addresses (post-reroll)

| Contract | Address |
|---|---|
| genesis | `0x481a59bc8826c91cd05d897fafff1bce4c394e41093f5e1c10e308e6c7d748fb` |
| EntryPoint (AA v0.7) | `0xC698feAf0FF7FdB0D60E2F620C97cB729A694975` |
| AA factory | `0x5a45B6F83050a76A81D0F2E6c857F16B37B2693b` |
| AA paymaster | `0xF14F56e812cE93544e75E841Ac6316F2d7E561b0` |
| AA walletImpl | `0x79c4A8367d2d65B162DE841fF678DB4875490b2e` |
| ValidatorRegistry | `0x3Bf6C5bb365717Bec9348b953758b196652caEdf` |
| CitrateMemberSBT | `0x149E85A3C845d10556537DcF824D148aCB904578` |
| MembershipStakeVault | `0x0aceb7B474eCC4abe12696CE48628f0CABE0267e` |

Validator stakers (= node coinbases): rpc-1 `0xE7509e40…`, boot1 `0x7509d695…`,
boot2 `0xF7198fC9…`, boot3 `0x11ec3E50…`. Full core/feature address set: `contracts/addresses/40204.json`.
