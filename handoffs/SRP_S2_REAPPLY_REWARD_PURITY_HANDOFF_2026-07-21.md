---
title: "SRP-S2 — reward/re-apply state-root purity: complete handoff (safe to clear context)"
created: 2026-07-21
branch: main
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: root-cause CLASS established + evidence; spec/ADR/red-test are Phase 0/1 next (G0 pending)
chain: 40204, genesis 0xd1a1941e, rpc.citrate.ai
supersedes-context: read AFTER handoffs/SRP_STATE_ROOT_PURITY_HANDOFF_2026-07-21.md (SRP-S1, DONE)
---

# TL;DR (read this, then the planset)

SRP-S1 made the **forward** state root a pure function of committed state — done, verified, and
**rerolled live** (chain crossed activation 2000 with 0 mismatches; a fresh cold node matched the
fleet on root + balances). That work is complete.

While hot-swapping the fleet to a follow-up binary, **restarting the miner mid-operation poisoned
one block (2209) and split the fleet.** That exposed a **second SRP-class bug on the path S1 did
NOT cover: the reward/§R' settlement on the RE-APPLY / RESTART / REORG path.** SRP-S2 fixes it
spec-first, then does one clean durable reroll. **Until then the chain is broken (split-brain) and
no fresh node — including citrate-core — can sync past block 2209.**

**Do the durable fix; do NOT quick-reroll on the current binary (it would re-expose the wedge).**

---

# The incident (2026-07-21) — ground truth, reproduced live

Context: after SRP-S1's reroll, the owner chose to make `CITRATE_BLOCK_V2` default-ON so
citrate-core syncs with a bare `--network testnet` (Option B — see PR #94). Rolling that binary
onto the live fleet (boots first, miner last, env kept so behavior was identical) went fine for
the 3 boots. **When rpc-1 (the only miner) was restarted last, block 2209 came out poisoned:**

| Fact | Value |
|---|---|
| Poisoned block | **2209** (`0x8a1`), hash `0xc0958f82…`, **empty** (gasUsed 0), **single-parent** (`mergeParentHashes: []`), post-activation |
| Canonical stateRoot @2209 (rpc-1) | `0x237bf250…` — **identical to block 2208's root** (applying 2209 made NO net change on the canonical chain) |
| Clean re-apply @2209 (any fresh boot) | computes `0x52e54249…` — a **state CHANGE** → hard-reject `state root mismatch (claimed 237bf250, computed 52e54249)` |
| @2207 / @2208 roots | rpc-1 == boots (`bf49ece0…` / `237bf250…`) — **fleet agreed up to 2208** |
| Effect | boots' applied tip **frozen at 2208** while DAG head advances → executed state diverges (boot coinbase `0x5e6f1b…` vs rpc-1 `0x63c5336c…`) → split-brain |

**So: the producer's reward-settlement effect for 2209 is not reproducible by a clean re-apply.**
That is the SRP impurity (root a function of node-local/transient producer state, not committed
state) — but on the **reward / re-apply** path.

## What is already RULED OUT (don't re-chase)
- **Not a merge-parent/DAG-sync gap** — 2209 is single-parent.
- **Not an unhydrated policy** — rpc-1's boot rehydration SUCCEEDED: log `VALIDATOR-S1: boot
  rehydration — durable epoch-2 snapshot (S=1800, 4 validators) reloaded`. The `None`-policy
  hard-reject (executor.rs:1305) did NOT fire.
- **Not `calculate_reward` impurity** — it's a pure fn of the block (config + height + txs),
  `core/economics/src/rewards.rs:63`.
- **Not the §R' vest on an empty block** — `settle_block_rewards` early-returns on
  `share.is_zero()` (executor.rs:1354), so an empty block does NO `creditReward`.

## The unresolved contradiction (the crux Phase 1 must pin)
`canonical_reward_config` sets `block_reward: 10` SALT/block (node/src/canonical_apply.rs), so an
empty block's BASIC reward is non-zero and *should* change state on BOTH producer and receiver —
yet rpc-1's 2209 recorded **no change** while a clean receiver computes one, AND the coinbase
balance was observed **flat 2207→2210**. Something about the producer's post-restart path either
skipped the basic credit the receiver applies, or credited via a node-local path. **Resolve this
by reproduction, not more reading.**

# Root cause — CLASS (established), 3 candidate mechanisms (Phase-1 pins ONE)

All three have the SAME fix shape (reward inputs derived only from committed state on every role):

1. **Producer enhanced-vs-basic path timing.** `producer.rs:899`
   `let use_enhanced = self.economics_manager.is_some() && !self.emit_v2_headers;`
   The enhanced path (`producer.rs:900-935`) credits a NODE-LOCAL reward (staking bonus, f64
   `reputation_score`, dynamic pricing) directly to the validator — a receiver (basic path) can
   NEVER reproduce it. If `emit_v2_headers` is false for even one block around a restart, that
   block is poisoned. VERIFY: is `emit_v2_headers`/`with_v2_headers(true)` (main.rs:2495, gated on
   `execute_on_receive_enabled`) reliably true immediately after a restart, before the first
   produced block?
2. **Basic-credit asymmetry.** Producer `basic_credits` (`producer.rs:955`) vs receiver
   `canonical_apply::reward_credits` (`node/src/canonical_apply.rs`, calls the same
   `reward_calculator.calculate_reward`). Confirm they are byte-identical for the SAME block on
   both paths (the empirical "producer no-change / receiver change" fits an asymmetry here).
3. **Reward-policy / proposer-selector reconstruction.** `hydrate_on_boot`
   (`node/src/registry_sync.rs`) restores the policy cell (`staker_of`, `priority_fee_share_bps`,
   `reward_minter`, `registry`, `epoch`, `activation_height`) + proposer selector. If the restored
   values differ by one entry from a from-genesis node's, `settle_block_rewards`
   (executor.rs:1267) resolves a different beneficiary/share → divergent `creditReward`.

# Key code map (verified this session)

- `node/src/producer.rs:878-960` — producer reward application; `:899` enhanced gate; `:928`
  enhanced direct-credit; `:947` `calculate_reward`; `:955` `basic_credits`; the
  `settle_block_rewards` call + `proposer_pubkey` source is just below 960 (read it).
- `core/execution/src/executor.rs:1267` `settle_block_rewards` (THE shared producer+receiver fn):
  `:1299-1314` policy `None` handling (hard-reject ≥ activation); `:1315` below-activation skip;
  `:1321` base-fee == `CANONICAL_BASE_FEE_PER_GAS` (0x3b9aca00) check; `:1328` staker from
  finalized snapshot; `:1342` coinbase==staker; `:1352-1356` `share.is_zero()` early-return;
  `:1359` `credit_validator_reward`; `:1387+` its body (transient minter funding + REVM
  `creditReward` system-call, balances reconciled since `StateDBAdapter::commit` discards REVM
  balance writes).
- `core/execution/src/block_rewards.rs` — §R' constants + `creditReward` ABI + `vested_share` +
  the reward-policy struct + `new_shared_reward_policy` + activation-gated import rules.
- `node/src/canonical_apply.rs` — `reward_credits` (receiver basic-credit); `canonical_reward_config`
  (block_reward 10, halving 2_100_000, treasury 10%); the applier that computed `52e54249`.
- `node/src/main.rs:1382` `execute_on_receive_enabled` (**now default true** on branch
  `srp/block-v2-default-and-sync`); `:1407-1420` `hydrate_on_boot` call; `:2495`
  `with_v2_headers(true)`.
- `node/src/registry_sync.rs` — snapshot sync, reward-policy materialization at S(E), `hydrate_on_boot`.
- Snapshot geometry: activation **2000**, EPOCH **1000**, `S(E) = E*1000 − 200` ⇒ S(2)=**1800**.

# The plan (spec-first) — `.agentile/planset/2026-07-21-srp-s2-reapply-reward-purity.md`

- **Phase 0 (G0):** `specs/tla/consensus/RewardApplyPurity.tla` (reward-settled root pure across
  producer/receiver/cold-sync/**restart**/**reorg**; TLC clean) + `ADR-2026-07-21-reapply-reward-
  purity.md` (single committed-state derivation on all roles; producer HARD-FAILS on any transient
  input; kill the enhanced path under v2 unconditionally) → red-team → owner G0.
- **Phase 1 (G1):** Rust red test — 1 producer past activation, **restart the producer's reward
  state mid-epoch**, produce an empty (and a fee-bearing) post-activation block, re-apply from
  genesis, assert per-block root + per-account balance equality. **FAILS on `main`, pins the
  mechanism.** Prefer an in-process integration test over full-node spin-up.
- **Phase 2 (G2):** the fix per the pinned mechanism; WP-1.1 GREEN; all SRP-S1 + reorg/snapshot/
  persist tests stay green.
- **Phase 3 (G3):** ONE clean reroll on the fixed binary (no mid-flight restarts), then PROVE
  restart-resilience: sync a fresh node → **restart it** → resumes without divergence; same for the
  miner. citrate-core Linux **and** Mac cold-sync AND close/reopen hold.

# Live-chain + fleet state (recovery context)

- **Chain 40204 is split-brain.** rpc-1 (142.93.58.145) solo-advancing on the poisoned chain
  (2209+). Boots boot1 142.93.50.217 / boot2 143.198.134.151 / boot3 142.93.99.212 wedged at
  applied-2208 (DAG head advancing, reject-looping block 2209). RPC (rpc.citrate.ai) is UP but
  unsyncable for fresh nodes past 2209.
- **Binaries on each node** (`/home/citrate/bin/`, user `citrate`, data `/home/citrate/.citrate`):
  live = `citrate-node` = v2-default (md5 `3fd787199a6e`, x86_64); backups
  `citrate-node.pre-v2` (the SRP-S1 reroll binary, md5 `ae8829b9e1f1`) and
  `citrate-node.pre-srp-*` (pre-SRP). Wedged boot state archived at `.citrate.wedged-*`
  (recoverable). Systemd env still has `CITRATE_BLOCK_V2=1 ACTIVATION=2000 REGISTRY=0x915DdE02…`.
- **Recovery = SRP-S2 fix → clean reroll (Phase 3).** The reroll ceremony is unchanged from
  `handoffs/REROLL_2026-07-20_DEPLOYER_ROTATION_RUNBOOK.md` — reuse it. Address book UNCHANGED
  (genesis `0xd1a1941e`; SBT `0x4CE39F89…`, vault `0x61E324cF…`, registry `0x915DdE02…`, deployer
  `0x4fAB35c8…` in `contracts/addresses/40204.json`); the fix is Rust-only so it moves no CREATE2
  address. The cold-sync acceptance gate is committed: `scripts/ci/srp_coldsync_gate.sh`.

# Git state

- **SRP-S1**: merged to main via **PR #93** (`70890ae`). Includes the #85 serve cap.
- **Option B (BLOCK_V2 default + reroll book)**: **PR #94 OPEN**, branch
  `srp/block-v2-default-and-sync`. Validated (fresh `--network testnet` node syncs) but **holds the
  restart-wedge below the surface** — MERGE ONLY AFTER SRP-S2 fixes the wedge, or the default-on
  binary will keep re-poisoning on restart.
- SRP-S2 artifacts to create on a fresh `srp/s2-*` branch: the TLA spec, the ADR, the red test.

# Reroll ops gotchas learned this session (save re-discovery)

- A node MUST run `CITRATE_BLOCK_V2=1` (or the default-on binary) or its **genesis stateRoot
  diverges** (fleet's is `0xd703e8c6…`) → sync rejects block 0 as "tampered commitment roots".
- `--bootstrap-nodes` takes a **single** value; a comma-list is parsed as ONE unresolvable address
  (0 peers). The embedded `node/config/testnet-beta.toml` already carries the 4 fleet peers, so a
  FRESH install (no `~/.citrate/node.toml`) needs no bootstrap flag; an EXISTING `~/.citrate/
  node.toml` shadows the embedded config.
- `post-reroll-membership.sh` `set -e`-aborts if `CITRATE_RPC_URL` is absent from `.env.testnet`
  (add it) AND on the `python3` hook (use `uv run python3` for the book re-pin). It re-pins SBT +
  vault + funds the grant signer 200k; it does NOT re-pin ValidatorRegistry (do that separately).
- `DeployValidatorRegistry.s.sol` needs `DEPLOYER_ADDRESS` in env; use `FOUNDRY_VIA_IR=true`.
- Empty `CITRATE_AA_ENTRY_POINT` before `regenesis.sh --with-aa` (else DeployAndPinAA errors
  "EntryPoint has NO code").
- Detach long-running nodes with `run_in_background` / `setsid` (a `nohup … &` inside one tool call
  dies when the call returns). `pkill -f coldsync` self-matches the command — kill by port or by an
  exact `binary+--data-dir /tmp/…` match. zsh does NOT word-split unquoted `$var` (`set -- $entry`
  fails — quote or use explicit fields).

# Security constraints (unchanged, still in force)
Keys never leave the DGX; private keys read from STDIN/env only, never argv/logs, never echoed;
C-1 (derive/verify addresses+selectors, never trust a handoff's); the deployer PK leak history —
never `pgrep -af` the deploy process.
