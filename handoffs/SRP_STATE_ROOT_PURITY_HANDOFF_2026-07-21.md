---
title: "SRP — State-Root Purity remediation: complete handoff (safe to clear context)"
created: 2026-07-21
branch: main
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: spec + ADR + planset written & TLC-verified; implementation gated on G0 sign-off
chain: 40204, rpc.citrate.ai
---

# TL;DR (read this, then the planset)

A cold-syncing node cannot sync chain 40204 past the first empty post-activation block.
After chasing ~6 downstream symptoms (sync target, orphan admission, the Noise-64KiB serve
cap, a mislabeled "reorg mismatch", a mislabeled "cross-arch" divergence), the **single
architectural root cause** is: **the consensus state root is NOT a pure function of committed
state.** It is folded from a persistent, never-rebuilt accumulator trie that only ever
receives the *currently-dirty* accounts, so the root is a function of each node's dirty/
insertion history. Warm fleet nodes share one history and agree on a (stale) root while their
real committed balances silently drift; a cold node rebuilds a different history and computes
the honest root, which the fleet never committed → hard `StateRootMismatch` → wedge.

**Proof it's a real consensus bug, not sync:** all 4 fleet nodes return the **same**
`stateRoot` for block 2557 but **different** `eth_getBalance` for the coinbase at that block
(rpc-1 `0xc5e5bb45…` vs boots `0x691b4bac…`). Same root, different state. It is NOT
cross-arch (x86_64 and aarch64 both compute the honest `de169b8d`).

This handoff + the ADR + planset + TLA spec are complete. **Next action: get gate G0 signed
(red-team the ADR), then start SRP-S1 Phase 1 (write the red test).** Do NOT band-aid, and do
NOT reroll before the fix lands — the chain must be rerolled *after* the fix to be genuinely
deterministic.

# The artifacts (all written, spec verified)

| Artifact | Path | State |
|---|---|---|
| TLA+ spec (acceptance oracle) | `specs/tla/consensus/StateRootPurity.tla` (+`.cfg`) | **TLC: "No error has been found."** |
| ADR (consensus decision) | `.agentile/adrs/ADR-2026-07-21-state-root-purity.md` | proposed — needs red-team + G0 sign-off |
| Planset (spec-first, gated) | `.agentile/planset/2026-07-21-srp-state-root-purity.md` | draft (SRP-S1, phases 0–4) |
| This handoff | `handoffs/SRP_STATE_ROOT_PURITY_HANDOFF_2026-07-21.md` | — |

# Root cause — exact file:line (from a code-trace study, corroborated)

- **The accumulator:** `core/execution/src/state/state_db.rs:243-276` `calculate_state_root`
  folds ONLY `get_dirty_accounts()` (`:247`) into the persistent `state_trie` (`:32`), never
  rebuilt; `commit` (`:279-284`) clears dirty right after (`:281`).
- **Three omission paths** (a changed account left out of a block's fold → stale trie value):
  1. zero-reward guard `core/execution/src/executor.rs:1281` (`amount > 0`);
  2. non-dirtying read-through `executor.rs:755-766` + `account.rs:43-46` (`load_account`);
  3. eager store-write bypass `executor.rs:805-818` (`set_balance` → store when not deferring).
- **The divergent (invisible-to-root) representation:** the durable store, read by
  `get_canonical_account` `executor.rs:646-652` — what `eth_getBalance` returns.
- **Where it wedges:** `apply_block_inner` `StateRootMismatch` `executor.rs:1134-1142`.
- **Why PR #88 didn't fix it:** #88 fixed insertion-order + storage-root side-effects
  (`state_db.rs:248,254-263`) but not the accumulator staleness — the symptom moved.

# The fix (decided in the ADR)

Make `calculate_state_root` a **pure, history-independent function of the full committed
account+storage set** (rebuild the trie from the authoritative committed state each call),
collapse the balance to one dirty-tracked representation, and close the 3 omission paths.
Correctness-first; O(N-accounts) rebuild is negligible at pilot scale; a persistent-MPT for
scale is the SRP-S2 follow-on (gated only on a benchmark regression).

**Invariants the fix must preserve** (full list in the ADR): `StateRootPurity.tla`;
`GenesisSafetyAcrossNodes` (`StateRootFor` pure+injective); the PR-#88 `idempotency_probe`
tests (`state_db.rs:510+`); snapshot/restore byte-exactness incl. `state_trie`; REVM balance
ownership (`revm_adapter.rs:337-344`); reorg `reconcile_store_from` store==memory; persist-
failure revert (`executor.rs:1148-1161`); `TransactionExecution.tla` conservation invariants.

# What is ALREADY done (do not redo)

- **Serve/sync path fixed + LIVE on all 4 fleet nodes.** The Noise transport `encrypt`
  hard-fails >65535 bytes; `MAX_RESPONSE_BYTES` was 900 KiB, so deploy-region block-serve
  responses were silently dropped. Fixed to 60 KiB (`node/src/block_serve.rs`), plus an
  orphan-buffer admission fix (`node/src/main.rs`). Branch **`fix/85-sync-partial`** (2
  commits). All 4 nodes hot-swapped (sha `be444431`). Result: a fresh node now cold-syncs
  **0→2557** cleanly — the ONLY remaining blocker is the state-root purity bug at 2558.
- **Deployer-rotation reroll is fully prepped + validated** (branch merged to `main`:
  PRs #91 sync, #92 rotation): new deployer `0x4fAB35c8`, refrozen `contracts/addresses/40204.json`
  from a ground-truth dry-run (25/44 shift), ValidatorRegistry `0x915DdE02`, SBT `0x4CE39F89`,
  vault `0x61E324cF`, treasury-signer `rekey.sh` staged (`citrate-identity`). Runbook:
  `handoffs/REROLL_2026-07-20_DEPLOYER_ROTATION_RUNBOOK.md`. **The state-root fix folds into
  the SAME reroll** (the fix does not move any CREATE2 address).

# Live fleet + git state (as of 2026-07-21)

- **Fleet:** 4 DO nodes, chain 40204 live + healthy (head ~7000+, `activeCount()=4`), all
  running the capped-serve binary. rpc-1 `142.93.58.145` (root@, sole producer), boots
  `142.93.50.217` / `143.198.134.151` / `142.93.99.212`. This chain carries the divergent
  balances — it WILL be rerolled after the fix (do not try to heal it forward).
- **citrate-chain branches:** `main` (sync #91 + rotation #92 merged); `fix/85-sync-partial`
  (serve cap + orphan buffer — the deployed content, not yet merged to main). The SRP fix
  will branch from `fix/85-sync-partial` (or main once it's merged) so the reroll binary has
  both.
- **rpc-1 build host:** `/root/citrate-chain` (source, cargo present as `/root/.cargo`);
  x86_64 reroll binaries built here. aarch64 built on the DGX.
- **Ops gotcha:** `nohup … &` inside a tool call dies when the call times out — use
  `setsid nohup … & disown` for long-lived test nodes.

# Exact next steps (SRP-S1, in order — the Agentile loop each WP)

1. **Gate G0 (WP-0.2):** red-team the ADR — a reviewer tries to name a 4th omission path or
   an invariant the rebuild breaks; fold findings in; owner signs. NOTHING else starts first.
2. **Phase 1 (WP-1.1):** write the RED integration test — produce a chain incl. an empty
   post-activation reward block, re-execute from genesis, assert BOTH root AND every account
   balance match. It must FAIL on current code (that is the oracle). Add the `idempotency_probe`
   omission-path probes (WP-1.2).
3. **Phase 2 (WP-2.1/2.2/2.3):** implement root-over-committed-set + one balance representation
   + close the 3 paths; turn the red tests green; keep ALL PR-#88 + snapshot/reorg/persist
   tests green; benchmark.
4. **Phase 3:** local 2-producer deep-sync + reorg; cold node reaches head with per-account
   balances == producer; wire the CI cold-sync balance-equality tripwire.
5. **Phase 4:** build the reroll binary (fix + serve cap + rotation), execute the practiced
   reroll runbook, prove a fresh Linux + Mac citrate-core node cold-syncs to head with
   matching balances.

# Do NOT

- Do NOT patch symptoms (target/orphan/serve/reward-math) — those are done or downstream.
- Do NOT reroll before the state-root fix — the new chain would inherit the same latent
  divergence.
- Do NOT trust a "roots match" determinism check again — the acceptance test is **per-account
  balance equality on a from-genesis cold sync** (the old proof's blind spot). CI tripwire in WP-3.2.

# Why this is a win
We caught a genuine consensus-safety divergence **before** go-live and before the TOB
handoff, formalized it as a TLA+ invariant with a red-team ADR, and the deployment runbook
is now tight from repeated practice. Fix → reroll → citrate-core syncs → hand TOB a closed,
spec-backed class instead of a latent bug.
