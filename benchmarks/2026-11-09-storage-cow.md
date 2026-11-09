---
created: 2026-11-09
branch: r1007/s3-storage-cow
author: Larry Klosowski + Claude Opus 5.5 (lane STORAGE-COPY, r1007 fan-out)
status: recorded (synthetic benches and a local devnet; not a testnet or release claim)
---

# Rule 6 run: storage copy-on-write, 2026-11-09

Why: the CV-14 note (`2026-11-09-cv14-mpt-state-root.md`) found the boot
reorg-window rebuild bound by copying a touched contract's whole storage
(~40%) and freeing the copies (~27%). This branch makes a contract's slot set
a persistent map (`core/execution/src/state/slot_map.rs`) and keeps no legacy
tree under the MPT rule from genesis. It changes `citrate-execution` (a core
crate), so Rule 6 applies.

## Host

`cnv-storagecow-bench`, a temporary DO s-4vcpu-8gb in sgp1 (DO-Regular x86,
AVX2, no SHA-NI: prod-1's class, as in the CV-14 note). Ubuntu 24.04. Release
binaries built on `citrate-cnv-build-2` (rustc 1.96.0) from 3e5db765 (before)
and 494d61b0 (after), nothing else running. Droplet and firewall deleted after.

## 1. Restart rebuild per height (the 38001b47 bench, same states)

`reorg_window_rebuild_cost_per_height_legacy_vs_mpt`, 100 heights, each
changing 40 balances and 20 slots; every rebuilt root is checked. 3 runs per
arm, alternating, ms per height:

| state | arm | legacy | MPT | MPT vs legacy |
|---|---|---|---|---|
| r1006 size (132 accounts, 737 slots) | before | 9.9 / 9.8 / 12.1 | 3.21 / 2.58 / 3.43 | 3.1x / 3.8x / 3.5x |
| r1006 size | after | 11.6 / 9.8 / 11.4 | 0.58 / 0.53 / 0.45 | 20.3x / 18.4x / 25.3x |
| 10x (1,320 accounts, 7,370 slots) | before | 62.2 / 70.5 / 64.1 | 15.3 / 15.7 / 15.0 | 4.1x / 4.5x / 4.3x |
| 10x | after | 63.6 / 63.2 / 59.8 | 1.54 / 1.43 / 1.05 | 41.2x / 44.2x / 56.8x |

MPT arm, before to after: about 5.5x faster at r1006 size, about 11x at 10x.
The legacy arm is unchanged, as intended: the legacy rule keeps its tree.

## 2. Allocation counts (`core/execution/tests/storage_cow_cost.rs`)

This thread's heap allocations (debug build, red commit 9f1897ba vs green
494d61b0), one contract of 100,000 slots, snapshot ring of 16:

| operation | before | after |
|---|---|---|
| one block writing one slot (snapshot + write + storage root) | 230 MB, 2.42M allocs, 2.08M frees | 32 KB, 522 allocs, 505 frees |
| same at 1,000 slots | 2.3 MB | 28 KB |
| undo record of that block (`pre_images_since`) | 25.6 MB | 1.7 KB |
| dropping a snapshot one slot away from the live state | 680k frees | 36 frees |

Cost no longer grows with the contract (100x the slots: 1.2x the bytes).

## 3. State root alone (unchanged, for regression)

`state_root_cost_per_block_does_not_grow_with_state`, median ms per block over
3 runs: MPT incremental 0.43 / 0.80 / 1.28 (before) vs 0.35 / 0.66 / 1.26
(after) at 1x / 10x / 100x. No regression; the root was not the target.

## 4. Rule 6: local devnet, signed load

One node per arm, `citrate devnet` (chain 1337, 2 s blocks), loopback only.
`tools/citrate-bench`, 64 throwaway keys funded from the devnet's published
hardhat test account (keys deleted after each arm), 300 tx/s for 60 s, 16 in
flight per signer.

| arm | binary | included / attempted | included tx/s | avg inclusion |
|---|---|---|---|---|
| before, MPT rule | 3e5db765, `CITRATE_MPT_STATE_ROOT_HEIGHT=0` | 18,001 / 18,001 | 286.4 | 1,891 ms |
| after, MPT rule | 494d61b0, `CITRATE_MPT_STATE_ROOT_HEIGHT=0` | 18,001 / 18,001 | 292.8 | 1,967 ms |
| before, legacy | 3e5db765, `=off` | 18,001 / 18,001 | 293.7 | 2,032 ms |
| after, legacy | 494d61b0, `=off` | 18,001 / 18,001 | 292.3 | 2,044 ms |

Ground truth (on-chain nonce deltas) matched in every arm; no RPC rejections,
no inclusion timeouts. The offered rate is the limit, so this is a regression
floor, not a ceiling; the devnet state is too small to show the copy.

The after/MPT node logged `Genesis build: MPT state root active from height 0`
and a different block-0 state root from the before/MPT node (0xc617a93e... vs
0x1d974381...): block 0 is now rooted under the rule (lead decision 2).

## Reproduce

```bash
cargo test --release -p citrate-execution --test state_root_cost -- --ignored --nocapture --test-threads=1
cargo test -p citrate-execution --test storage_cow_cost -- --nocapture
```

The devnet arm is as in the CV-14 note; fund the throwaway signers in batches
of 16 (the mempool refuses a nonce more than 16 ahead, PBA-L1a-001).
