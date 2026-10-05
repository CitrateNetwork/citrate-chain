---
title: "Agent precompile fork: LoRA, memory-anchor and agent-ops precompiles"
created: 2026-10-01
branch: hup/n5-chain-precompiles
author: Larry Klosowski + Claude Opus 5.5
status: DRAFT for review. Built and tested; NOT activated on any network. Gas values and the 40204 height are pending owner sign-off.
chain: 40204
---

# Agent precompile fork

HUP-S7.2 (federation work packages F-1, F-2, F-3). This page is the specification of
four new precompiles, the activation mechanism that gates them, and the contract-side
integration rules. Decision record: `.agentile/adrs/ADR-2026-10-01-agent-precompiles.md`.

| Address | Name | What it computes | Consumer |
|---|---|---|---|
| `0x0112` | `LORA_APPLY` | `W + (alpha / r) (B . A)` on one Q16.16 tile | adapter math on chain, small adapters, tile recompute |
| `0x0113` | `LORA_MERGE` | `sum_i w_i (alpha_i / r_i) (B_i . A_i)` on one tile | federated-learning aggregate spot checks |
| `0x0121` | `MEMORY_ANCHOR_VERIFY` | nightly anchor inclusion proof to day commitment | "prove this decision was anchored" (US-7.2 AC3) |
| `0x0122` | `AGENT_OPS` | DeviceLink / DeviceRevocation signature checks | on-chain device rosters, AgentSBT device binding |

All four are pure byte functions: no state, no I/O, no floats, no node-local runtime.
Every node computes the same bytes for the same input on any hardware.

## 1. Activation

The four addresses already lie inside the reserved Citrate ranges. Before the fork they
behave exactly as they do today, so an upgraded binary changes nothing:

| Block height | `0x0112`, `0x0113`, `0x0121`, `0x0122` |
|---|---|
| below `pba_hardening_height` | an empty account (a call succeeds with no data) |
| at/after `pba_hardening_height`, below the fork | a reserved address (every call fails) |
| at/after the fork height | the precompile |

The precompile set registered with REVM is otherwise unchanged at the fork (pure set,
reserved set, EIP-2929 warm/cold behaviour). `register_citrate_precompiles` in
`core/execution/src/revm_adapter.rs` applies the gate on both the call and the create
paths.

### How the height is set (`core/execution/src/agent_fork.rs`)

- Release pin: `AGENT_PRECOMPILES_PINS`. 40204 ships `None`: **not activated**.
- On a release network (any chain id in the pin table) only the pin sets the height.
  A config value (`[chain] agent_precompiles_height`) or env value
  (`CITRATE_AGENT_PRECOMPILES_HEIGHT`) that disagrees with the pin, or any height while
  the pin is `None`, stops the node at start-up. `off` is accepted when nothing is pinned.
- On other chains (local devnets): env, then config, then unset. An unparseable env
  value is an error.
- Genesis (height 0) is never re-judged; the boundary is inclusive.
- The node publishes the height once, first thing in `start_node`, and logs it. The
  consensus manifest (`citrate consensus`) shows it, and it enters the fingerprint only
  when set, so an unscheduled fork leaves the fingerprint pre-image unchanged.

Formal model: `specs/tla/consensus/AgentPrecompileFork.tla` (invariants `AgreeOnSet`,
`LegacyBelow`, `GenesisUntouched`, `ForkAddrsLive`, `Disjoint`).

### Scheduling the fork on 40204 (owner + operator; not done)

1. Owner: choose a height H safely above the tip at rollout (the create-nonce fix used
   about 13 hours of runway) and sign off the gas schedule below.
2. Release PR: set `AGENT_PRECOMPILES_PINS` to `(40204, Some(H))`.
3. Operator: roll the binary to every node before H; confirm `citrate consensus` shows
   the same fingerprint and `agent precompiles from height H` on each.
4. After H: run the post-activation checks in section 7 against a node.

No agent may set H, deploy, sign or send a transaction for this.

## 2. `0x0112 LORA_APPLY`

**Input:** four canonical v1 tensors (`precompiles/tensor_format.rs`), dtype `0x01`
(Q16.16, each element an 8-byte little-endian i64, as RM-M2), concatenated, nothing after:

| Tensor | Shape |
|---|---|
| `W` | `[d, k]` |
| `B` | `[d, r]` |
| `A` | `[r, k]` |
| `alpha` | `[]` (rank 0, one element) |

Caps: `d, k <= 256`, `1 <= r <= 64`. Shapes must agree.

**Output:** a Q16.16 tensor `[d, k]`:

```
delta    = q16::ops::matmul(B, A)          (row-major, inner index k)
scaled_e = delta_e.saturating_mul(alpha).saturating_div(Q16::from_int(r))
out_e    = W_e.saturating_add(scaled_e)
```

The order of operations is part of consensus and frozen once the fork is scheduled.
Arithmetic saturates at every step (i128 intermediates), as RM-M2.

**Gas:** `3000 + 4 d r k + 3 d k` (the RM-M2 matmul rate of 4 per multiply-add).
Example: `d = k = 256, r = 8` costs 2,296,760.

**Errors (the frame fails):** wrong dtype or rank, shape mismatch, a cap exceeded,
trailing bytes, gas below the schedule. Shapes and gas are checked before any element is
parsed or any output allocated.

## 3. `0x0113 LORA_MERGE`

**Input:** one byte `n` (`1..=16`), then `n` groups of four tensors, nothing after:
`B_i [d, r_i] || A_i [r_i, k] || alpha_i [] || w_i []`. Every adapter has the same `d`
and `k`; ranks may differ. Same caps as `LORA_APPLY`.

**Output:** a Q16.16 tensor `[d, k]`:

```
acc_e = 0
for i in input order:
    acc_e = acc_e.saturating_add(scaled_e(i).saturating_mul(w_i))
```

with `scaled_e(i)` as in `LORA_APPLY`. A merge of one adapter with weight 1 equals
`LORA_APPLY` onto a zero base (property-tested).

**Gas:** `3000 + sum_i (4 d r_i k + 4 d k)`.

**Tiles.** Both LoRA precompiles take one tile of at most 256 x 256 outputs. Tile
`(R, C)` of `B . A` is `B[R, :] . A[:, C]`, so any tile of a full adapter (or of a merged
aggregate) can be recomputed on chain from the matching slices. This is what lets an
aggregation challenge check one disputed tile instead of the whole tensor.

## 4. `0x0121 MEMORY_ANCHOR_VERIFY`

The on-chain twin of `citrate-agent-anchor::verify_proof` (citrate-agent-runtime). An
agent's decision records are batched per UTC day into an RFC 6962 tree; one value per
day is anchored in `AnchorRegistry` (kind `NightlyMerkle`).

**Input** (big-endian integers, packed, exact length `117 + 32 * path_len`):

| Field | Bytes |
|---|---|
| `v` (header version, must be 1) | 4 |
| `day` (UTC day number) | 8 |
| `first_seq` | 8 |
| `last_seq` | 8 |
| `count` | 8 |
| `tree_root` | 32 |
| `seq` (the record's sequence number) | 8 |
| `leaf_index` | 8 |
| `record_hash` | 32 |
| `path_len` (`<= 64`) | 1 |
| `path` (siblings, leaf to root) | `32 * path_len` |

**Output:** 32 bytes. The day commitment when the proof is valid:

```
leaf       = SHA-256(0x00 || record_hash)
node       = SHA-256(0x01 || left || right)
commitment = SHA-256("citrate.agent-anchor.nightly.v1\n" || be32(v) || be64(day)
                     || be64(first_seq) || be64(last_seq) || be64(count) || tree_root)
```

and 32 zero bytes when it is not. Valid means: `v == 1`, `count > 0`,
`last_seq - first_seq == count - 1`, `leaf_index < count`,
`first_seq + leaf_index == seq`, and the RFC 9162 section 2.1.3.2 walk from `record_hash` at
`leaf_index` in a tree of `count` leaves uses every path element and ends at `tree_root`.

A caller then checks that the commitment is in `AnchorRegistry` as a nightly root
anchored by the account it trusts (`AnchorProofs.isRecordAnchored(registry, committer,
proof)` in `contracts/src/lib/CitratePrecompiles.sol`). The committer check is required:
`AnchorRegistry.anchor` is open to every account, so a commitment being in the registry
says nothing about whose log it came from (anyone can build a day tree over any record
hash and anchor it). `isRecordAnchored` returns true only when the proof verifies, the
commitment is anchored with kind `NightlyMerkle`, and its committer is the named account.
Changing `day` yields a different day's commitment, never the anchored one.

**Gas:** `1500 + 150 * path_len`.

**Shared vector** (pinned in Rust tests; produced by the runtime crate at
`origin/main` `01a32ed` and by an independent re-implementation): a day of 5 records
(day 20362, seq 40..=44, record hashes `SHA-256("rec-<i>")`) has root
`e31cc748...a8e4` and commitment `26f10b85...98e8`.

## 5. `0x0122 AGENT_OPS`

First input byte selects the operation. Output: one 32-byte word, `1` or `0`. Malformed
input (unknown operation, wrong length) fails the frame. The precompile only verifies; it
holds no key and signs nothing.

### `0x01 DEVICE_LINK_VERIFY`

Body: `member (20) || device (20) || wallet (20) || index (u32 BE) || issued_at (u64 BE)
|| label_len (1) || label || member_sig (65) || device_sig (65) || wallet_sig (65)`.

Checks, identical to citrate-cluster (`cluster_core::device`, `cluster-daemon` verifier):

- the exact text of `DeviceLink::signing_message` (golden vector shared with
  citrate-cluster and citrate-core) is signed with EIP-191 `personal_sign` by the member
  key, the device key and the wallet, in that order;
- signatures are `r || s || v`, `v` in {0, 1, 27, 28}; high-s is refused;
- `device != member`, `device != wallet`, `index <= 1023`;
- label: 1 to 48 bytes of ASCII letters, digits, space, `.`, `_`, `-`, `'`, no leading
  or trailing space.

**Gas:** `1000 + 3 * 3000 + 6 * ceil(len(message) / 32)`.

### `0x02 DEVICE_REVOCATION_VERIFY`

Body: `member (20) || device (20) || revoked_at (u64 BE) || member_sig (65)`. Checks the
member's EIP-191 signature over `DeviceRevocation::signing_message`.

**Gas:** `1000 + 3000 + 6 * ceil(len(message) / 32)`.

## 6. Contract integration (F-1)

`contracts/src/lib/CitratePrecompiles.sol` is the one place contracts call precompiles
from. It encodes each precompile's native input and **fails closed**: a call that fails
or returns nothing reverts with `PrecompileUnavailable(address)`, and a wrong-shaped
answer reverts with `PrecompileBadOutput(address, length)`. A call to an address without
code succeeds with empty data in the EVM, so checking only the success flag is never
enough.

- `ModelRegistry`: registration and updates are records (weights at the IPFS CID); no
  precompile call. `requestInference` calls 0x0101 in its native layout
  (`model_id || caller || input`).
- `LoRAFactory`: training and merges run off chain and are recorded by the operator
  (`completeTraining`, `completeMerge`); `MergeRequested` announces a merge.
  `inferWithLoRA` calls 0x0101 with the adapter id.
- `ModelAccessControl`: inference (0x0101) and encrypted inference (0x0106) through the
  library.

On chain 40204 today no node serves 0x0101 or 0x0106 to contract code (non-deterministic
inference is not a consensus operation, audit C-01), so those calls revert; payments in
the same call revert with them. Registration, adapters, training and merge records work.

## 7. Post-activation checks (operator, after H)

A top-level call or `eth_call` whose `to` is a precompile address returns `0x` on a
Citrate node at every height: the executor hands a top-level call to REVM only when the
target account has code. The precompiles are reached from contract code. So the checks
need a calling contract:

1. Before H, on a devnet built from the release commit with
   `CITRATE_AGENT_PRECOMPILES_HEIGHT` set low: run `scripts/devnet-precompile-check.sh`.
   It deploys `PrecompileCaller` (the fixture in
   `core/execution/tests/fixtures/agent_precompile_caller_runtime.hex`, compiled from
   `contracts/test/precompiles/CitratePrecompilesFailClosed.t.sol`) with a throwaway
   devnet key, then `eth_call`s every helper with the pinned vectors in
   `core/execution/tests/fixtures/agent_precompile_vectors.json` (LoRA apply and merge,
   the section 4 anchor vector and three more, device links and revocations, each valid
   and invalid). Below the devnet height every call must revert with
   `PrecompileUnavailable(<address>)`; at and after it every call must return the pinned
   output, and on a multi-node devnet (`RPC_URLS`) every node must return the same bytes.
   The script refuses chain 40204. Local mode starts a single node itself; the header of
   the script has both invocations.
2. After H on 40204: the same `eth_call` against a probe contract the operator deploys
   (owner sign-off; no agent deploys). Expect the commitment.
3. `cargo test -p citrate-execution --test agent_precompiles_activation --test
   agent_precompiles_solidity_e2e` on the release commit.
4. The daily benchmark (Rule 6), because `citrate-execution` changed.

## 8. Measured cost

`cargo bench -p citrate-execution --bench agent_precompiles_bench` (criterion, release
profile, rustc 1.96.0, Apple M2 Max, 2026-10-04, other builds running on the machine, so
absolute times are high; compare the ratios within the run). Each case is a worst case at
the caps. The reference is the chain's own `ecrecover` (0x01) as REVM runs it in this
build, Ethereum-priced at 3000 gas.

| Case | Gas | Time | ns per gas |
|---|---:|---:|---:|
| reference: `ecrecover` 0x01 | 3,000 | 277 us | 92 |
| `DEVICE_REVOCATION_VERIFY` (1 recovery) | 4,042 | 260 us | 64 |
| `DEVICE_LINK_VERIFY` (3 recoveries, 48-byte label) | 10,066 | 710 us | 71 |
| `MEMORY_ANCHOR_VERIFY`, path of 64 | 11,100 | 35 us | 3.2 |
| `LORA_APPLY` 256 x 64 x 256 | 16,976,824 | 14.3 ms | 0.84 |
| `LORA_MERGE`, 16 adapters at the caps | 272,632,760 | 221 ms | 0.81 |

Reading: no case buys more time per gas than the chain's `ecrecover`, so the schedule is
conservative against the precompile the chain already prices. `AGENT_OPS` is closest
(its signature recoveries dominate); LoRA and the anchor walk are one to two orders of
magnitude cheaper per gas. One `LORA_APPLY` at the caps fits in a block (gas limit
30,000,000); a merge of 16 adapters at the caps does not, so the practical merge size is
bounded by the block gas limit. One machine, one run: evidence for the sign-off, not a
schedule. A quieter first run gave the same ordering (`DEVICE_REVOCATION_VERIFY` 36 ns per gas,
LoRA 0.39).

## 9. Tests

| Layer | Where | What |
|---|---|---|
| Unit | `core/execution/src/precompiles/{lora,memory_anchor,agent_ops}.rs`, `agent_fork.rs`, `precompiles/mod.rs` | arithmetic, shared vectors, golden messages, caps, gas, resolution rules, table routing |
| REVM integration | `core/execution/tests/agent_precompiles_activation.rs` | both sides of both activations through `execute_contract_call_with_context` and the create path; exact gas; byte-identical to an unassigned address below the fork |
| Solidity end to end | `core/execution/tests/agent_precompiles_solidity_e2e.rs` | forge-compiled `CitratePrecompiles` callers run in REVM: succeed after the fork, revert `PrecompileUnavailable` before it |
| Property (fuzz) | `core/execution/tests/agent_precompiles_props.rs` | totality on arbitrary bytes, merge/apply equivalence, random day batches, label rule |
| Foundry | `contracts/test/precompiles/{CitratePrecompilesFailClosed,ModelLoRAPrecompileWiring}.t.sol` | fail-closed helpers on a chain without the precompiles; anchor proofs bound to the committer and the nightly kind (against the real `AnchorRegistry`); model/LoRA contracts |
| Node | `node/src/config.rs`, `node/src/consensus_manifest.rs`, `node-app/src/main.rs` | height published first (in the node and in the RPC-only `node-app`), unset in every shipped profile, fingerprint rule |
| Benchmark | `core/execution/benches/agent_precompiles_bench.rs` | worst-case wall clock per gas (section 8) |
| Formal | `specs/tla/consensus/AgentPrecompileFork*.cfg` | TLC: shipped and pinned configs pass; the mutation config fails `AgreeOnSet` |
| Cross-repo vectors | `core/execution/tests/agent_precompile_vectors.rs` | the encoders and precompiles reproduce `tests/fixtures/agent_precompile_vectors.json`, which citrate-core's typed encoders and the devnet check consume |
| Devnet | `scripts/devnet-precompile-check.sh` | a node binary on a devnet, both sides of the fork height (run on one local node on 2026-10-04; a multi-node devnet run is the operator's) |

## 10. Pending owner sign-off

- The gas values in sections 2 to 5 (measurements in section 8).
- The 40204 activation height (section 1).
- Whether `AGENT_OPS` should carry further operations (each is a new op byte and a new
  fork).
