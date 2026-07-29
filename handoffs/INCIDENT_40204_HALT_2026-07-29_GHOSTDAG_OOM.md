---
created: 2026-07-29
branch: feat/m2-membership-bond-lock (working tree — uncommitted)
author: Claude (Opus 5), directed by @SaulBuilds
status: incident — root cause PROVEN; chain still halted; fix not yet written
---

# Incident — chain 40204 halted at block 54600 (GhostDAG Θ(N²) blue-set OOM)

**Impact:** chain 40204 stopped producing at block **54600** (~04:26 UTC 2026-07-29).
`rpc.citrate.ai` was in a **hard reboot loop every ~2 minutes** from 04:08 UTC until
07:40 UTC, when I stopped the node.

**Current state:** rpc-1 is **stable but not producing** — I set `mining.enabled = false`
in `/home/citrate/.citrate/node.toml` (original saved to `/root/node.toml.bak-mining-on`).
The chain remains halted. **Turning mining back on with the current binary restarts the
reboot loop within ~35 seconds.** The three bootnodes are healthy and fully synced at
54600.

---

## Root cause

`GhostDag::get_or_calculate_blue_set` (`core/consensus/src/ghostdag.rs:397-485`)
materialises **cumulative blue ancestry** into an **unbounded** `blue_cache`
(`ghostdag.rs:56` — a `HashMap<Hash, BlueSet>` with no eviction).

Phase 1 (`:415-439`) walks back the selected-parent chain until it finds a cached
ancestor. Phase 2 (`:443-476`) then composes forward and, for **every** block in that
walk, clones the parent's set (`:462`) and inserts a full cumulative `BlueSet`
(`:475`). Cost is Σᵢ₌₁..ᴺ i — **Θ(N²) in chain length**.

The trigger is an interaction with the earlier PIL-13 fix:

- PIL-13 made startup rehydration O(1) per block via `register_existing_block`, which
  deliberately **does not populate `blue_cache`** (`ghostdag.rs:502-505`).
- Its docstring asserts the anticone path "is unaffected by this lightweight
  registration" (`:512-515`). **That assumption is wrong.** It is precisely the path
  that now has no cache entry to terminate on.
- So after every restart the cache is empty, and the **first** `add_block` — from
  `node/src/admission.rs:221`/`:416` or `node/src/sync/efficient_sync.rs:207` — walks
  all the way to genesis and materialises the entire Θ(N²) ancestry in one burst.

PIL-13 did not remove the O(N²); it moved it from a slow amortised cost during
rehydration to a single catastrophic allocation on the first block admitted after
startup — which is why it now bites at N≈54.6k instead of the N=281k noted in the
source comment (`ghostdag.rs:494-495`).

Only **block-producing** nodes run this path, because the producer builds its own
`DagStore` + `GhostDag` (`node/src/producer.rs:380-382`) and wires it into admission.
That is exactly why the three non-producing bootnodes are unaffected.

## Evidence

| Observation | Measurement |
|---|---|
| Chain tip frozen | 54600 across a 45s poll; head timestamp 3.1h stale; `eth_syncing=false`, 3 peers |
| Single producer | every block 50000→54600 mined by `0x0ecbcd85…363b`, uniform 2.0000 s spacing |
| Host reboot loop | `last -x reboot`: ~2 min apart, first at 04:08 UTC |
| Killer is the node | OOM process table: `citrate-node` **31,279 MB RSS / 66 GB vm**; llama-server 430 MB; ipfs 86 MB |
| Node is OOM-immune | `citrate-node.service.d/memory.conf` sets `OOMScoreAdjust=-1000`, no cgroup cap → kernel kills ipfs/journald/llama instead, box wedges, reboots |
| Growth curve | 4.1 GB @ t+9s → 27.8 GB @ t+30s → plateau ~30 GB (RAM exhausted). ~1 GB/s |
| Not the DAG load | "DAG loaded: 54601 blocks" completes at t+4s; the burst runs t+9→t+37 |
| Not log-driven | only 52 sync iterations per 2-min boot (2 lines/s) while 30 GB is consumed — allocation is silent |
| **Producer is the trigger** | **mining OFF: RSS flat at 0.36 GB for 95s. mining ON: 30 GB in 35s.** Same binary, same height, same peers |
| Bootnodes unaffected | up 9 weeks, 2.0–2.2 GB RSS on 3 GB boxes, all three at height 54600 (`0xd548`) |

The journal only retains back to 06:06 — the loop rotated away its own origin
(808 MB across 37 boots), so the 04:08–04:26 window is unrecoverable.

## Why more RAM does not fix this

Memory grows as N² while the chain grows linearly (43,200 blocks/day at 2s). Each
doubling of RAM buys only √2× the block height — **hours, not months.** Order of
magnitude: a 16 GB member laptop dies tens of thousands of blocks earlier than a 31 GB
droplet, and both die within days. There is no capacity purchase that keeps a producer
alive; this requires a code fix.

A reroll also does **not** fix it — it resets N to 0 and buys roughly a day.

## Direct consequence for Track M

The membership programme's promise is "membership = the member's node produces blocks."
Under this bug **every member laptop that starts producing will OOM its owner's machine
within days**, and the failure presents as a whole-box hang, not a clean process crash
(`OOMScoreAdjust=-1000` means the kernel kills everything *except* the node). This
must be fixed before member nodes are told to produce.

## Fix — WRITTEN AND GREEN (uncommitted, branch `feat/m2-membership-bond-lock`)

Red-first. New regression test `merge_block_on_deep_chain_does_not_materialise_quadratic_ancestry`
(`core/consensus/src/ghostdag.rs`) rehydrates an N-block chain the way a restarting
node does, then admits ONE merge block:

- **Before:** `322,002` materialised ancestry entries at N=800 — i.e. N²/2, the
  quadratic measured exactly.
- **After:** within the O(N) bound.

Two defects, both fixed:

1. **Θ(N²) memory** — `get_or_calculate_blue_set` phase 2 cached a full cumulative
   `BlueSet` for *every* block on the genesis-deep walk (sizes 1..N). Now the running
   set is carried in a local and only the requested hash is cached. Composed values are
   unchanged; only what is *retained* differs, so no caller can observe it.
   `blue_cache` also gained a hard entry cap (`MAX_BLUE_CACHE_ENTRIES`), since an
   unbounded map of cumulative sets is O(entries × N) — the same quadratic by a slower
   route.

2. **Θ(N²) time** (found only by measuring — the memory fix alone would NOT have
   restarted the chain) — `count_blue_anticone` called `is_ancestor_of(B, block)` per
   element, and each call BFS-walks from `block` down to `B`'s height: O(depth × width)
   each, summed over an N-sized blue set. Now `collect_past` walks the block's past
   **once** and each query is a set membership, with `is_ancestor_of`'s height
   short-circuit reproduced verbatim so the answers are identical.

Measured scaling of the same test (chain build + one merge block):

| N | before time fix | after |
|---|---|---|
| 800 | 0.74 s | 0.05 s |
| 1600 | 2.79 s | 0.09 s |
| 3200 | 11.03 s | 0.17 s |
| 6400 | — | 0.35 s |

4× per doubling (quadratic) → 2× per doubling (linear). At the live height that is the
difference between ~53 minutes and a few seconds per merge block.

**Verification:** full `citrate-consensus` suite green (123 lib tests, up from 122 —
count stays monotone per Rule 2 — plus every integration suite, 0 failures);
`cargo check --workspace` clean; the pre-existing PIL-13 tripwire test
`core/sequencer/tests/producer_steady_state.rs` still passes.

**Not yet done:** nothing is committed; no binary has been built or deployed; the chain
is still halted and rpc-1 still has mining disabled. Restoring the chain needs an amd64
build on boot1 (~55 min per the fleet ops runbook), fleet distribution, then re-enabling
mining on rpc-1.

## Original fix direction (superseded by the above)

The cumulative `.blocks` set is only genuinely needed by `count_blue_anticone` for
k-cluster anticone counting (`ghostdag.rs:512-515`). Real GHOSTDAG implementations bound
that work by the k-parameter mergeset/anticone window rather than by full ancestry. The
fix is to stop materialising genesis-deep ancestry:

1. Bound the anticone walk by k (the correct fix — matches the algorithm as specified);
2. and/or seed `blue_cache` at rehydration so Phase 1 terminates at the immediate
   parent instead of genesis;
3. and give `blue_cache` an eviction bound regardless, so no single call can allocate
   without limit.

Any of these changes consensus-adjacent code and needs the full test suite plus a
coordinated fleet rebuild (amd64 build on boot1, ~55 min, per the fleet ops runbook).

**Separately, and regardless of the fix:** `OOMScoreAdjust=-1000` with no memory cap
converted a recoverable process OOM into repeated hard reboots of the host, and
destroyed the forensic evidence. The node should get a `MemoryMax` so it dies alone.
