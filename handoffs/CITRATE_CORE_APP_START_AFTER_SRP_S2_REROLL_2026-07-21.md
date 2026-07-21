---
title: "citrate-core: building & starting the app after the SRP-S2 reroll (chain 40204)"
created: 2026-07-21
branch: main
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: chain rerolled on the SRP-S2-fixed binary; cold-sync ready
audience: citrate-core app/desktop team
chain: 40204, genesis 0xd1a1941e, rpc https://rpc.citrate.ai
---

# TL;DR

Chain 40204 was **cleanly rerolled** onto the SRP-S2-fixed node binary (2026-07-21). It is a
**fresh chain from genesis** but **ADDRESS-NEUTRAL** — every contract address is unchanged
(the fix is Rust-only). You can now **build the app/node from `main`** and it will **cold-sync
`--network testnet` out of the box** (v2 now defaults ON). The one thing that will bite you:
**a data dir left over from the OLD chain will NOT sync — start with a fresh data dir.**

# What changed and why

- **SRP-S2 fix (node binary):** the previous chain split-brained at block 2209 because the block
  *producer* credited a reward from node-local, non-consensus state that no other node could
  reproduce → state-root mismatch → fork. The fix removes that path so block rewards are settled
  purely from committed state, identical on producer and every follower. Followers (which is what
  citrate-core runs) never hit the producer bug, but the fix is why the fleet now emits blocks any
  follower can reproduce. Details: `handoffs/SRP_S2_REAPPLY_REWARD_PURITY_HANDOFF_2026-07-21.md`,
  ADR `.agentile/adrs/ADR-2026-07-21-reapply-reward-purity.md`.
- **`CITRATE_BLOCK_V2` now defaults ON** (`node/src/main.rs`). v2 is the live network format; a
  fresh node computes the same genesis commitment as the fleet and cold-syncs on a bare
  `--network testnet` with **no env vars and no `--bootstrap-nodes`** (the embedded
  `node/config/testnet-beta.toml` carries the 4 fleet peers). Pass `CITRATE_BLOCK_V2=0` only for an
  isolated v1 devnet. **This closes the old NodeManager gap** — `build_spec` no longer needs to set
  `CITRATE_BLOCK_V2=1` (it's harmless if it still does).

# Building the app / node

- Build from **`main`** (the SRP-S2 fix + v2-default are merged). Linux x86_64 and macOS aarch64
  both work — cross-arch determinism is proven, and the aarch64 cold-sync acceptance gate passes on
  this exact binary.
- The node binary target is `citrate` (package `citrate-node`): `cargo build --release -p citrate-node`.
- Nothing else in the build changed; the desktop bundle/dmg is built as before.

# Starting the app — what to be aware of (READ THIS)

1. **Wipe any old data dir.** If a machine ran a PRE-reroll node, its data dir (`~/.citrate`, or
   whatever citrate-core points `--data-dir` at) holds the OLD chain. It will **not** sync the new
   chain — the node resumes the stale state and the genesis/commitment won't match. **Start fresh:**
   delete/rename the data dir (or use a new one) so the node cold-syncs from genesis. First launch on
   a clean machine is fine automatically.
2. **`--network testnet` is enough.** No `CITRATE_BLOCK_V2`, no activation/registry env, no
   `--bootstrap-nodes` needed on a fresh install. (An EXISTING `~/.citrate/node.toml` shadows the
   embedded peer config — another reason to start from a clean data dir.)
3. **Cold-sync expectation:** the node downloads genesis→head, **state-root-verifies every block**,
   and matches the fleet. Genesis hash is `0xd1a1941e…`, genesis stateRoot `0xd703e8c6…`. If you see
   "tampered commitment roots" at block 0, the node is running v1 (BLOCK_V2 off) — rebuild from
   `main` or set `CITRATE_BLOCK_V2=1`.
4. **The chain has an activation at height 2000** (validator staking / §R' reward vesting turns on).
   A follower syncs across it transparently — no action needed. citrate-core does not mine, so it
   never needs the producer-side reward logic.
5. **`--bootstrap-nodes` takes a SINGLE value** if you ever set it explicitly (a comma-list is
   parsed as one unresolvable address → 0 peers). Prefer omitting it.

# Canonical addresses (UNCHANGED — the frozen book still applies)

Source of truth: `contracts/addresses/40204.json`. Highlights the app uses:
- genesis deployer `0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732`
- ValidatorRegistry `0x915DdE02831ebacFc57f329f60944492ebb0A095` (activeCount 4)
- CitrateMemberSBT `0x4CE39F891c0A519Fa0E0De97A1DD3e3f856e0cF1`
- MembershipStakeVault `0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268`
- AA: EntryPoint `0xc698feaf0ff7fdb0d60e2f620c97cb729a694975`, CitrateWalletFactory
  `0xc9c7b3d3fe28012ab5f2583a4f58531e9f26d3f5`, CitratePaymaster
  `0x0cd122ace90084afb26d5101074af15aaccc1c0e`
- Membership money service (unchanged, env-driven): core-membership + treasury-signer at
  `https://auth.citrate.ai/_ops/treasury/*` (URL + token stable across rerolls; only SBT/vault
  addresses changed on prior rerolls — this reroll reproduced them identically).

If you pin addresses in the app, no re-pin is required for this reroll (address-neutral). Verify any
pinned value against `contracts/addresses/40204.json`.

# Status of the reroll (as of this handoff)

Genesis, 4-node consensus, full contract stack (44 + AA), membership, ValidatorRegistry, and 4
validators are all deployed + verified byte-identical to the frozen book. The chain is live at
`https://rpc.citrate.ai`. Activation (height 2000) + restart-resilience are being verified on the
fleet; neither affects follower cold-sync. See `handoffs/SRP_S2_REROLL_EXECUTION_STATUS.md` for the
live gate log.
