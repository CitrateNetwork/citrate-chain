---
created: 2026-10-01
branch: hup/n5-chain-fl
author: Larry Klosowski + Claude Opus 5.5
status: active (v1; values marked "pending owner sign-off" are placeholders)
---

# Federated LoRA round, v1 (HUP-S9.1 / S9.2)

One cluster-scoped federated round: devices train a LoRA adapter on their own verified
trajectories, a coordinator aggregates the adapter deltas through the `0x0110` Belnap-FOUR
precompile, the result is recorded on chain in `FederatedRoundLedger`, anyone can prove a wrong
round on chain during a challenge window, and settlement pays only an accepted round.

Implementations (two, deliberately independent):

| Part | Where |
|---|---|
| Device worker (`lora_delta` jobs), delta encoding, commitments | citrate-compute-pool `training-worker/src/fl/` |
| Delta upload route, aggregation, bundle, proofs, commit intent | citrate-compute-pool `training-coordinator/src/fl_upload.rs`, `fl_round.rs`, `citrate-fl-round` |
| On-chain record and fraud proofs | this repo, `contracts/src/FederatedRoundLedger.sol` |
| Independent replay (runs the precompile's kernel in process) | this repo, `tools/fl-replay` (`citrate-fl-replay`) |
| Settlement gate and intents | citrate-settlement `settlement-core::fl_gate`, `settlement-chain::fl`, `setl-fl-intents` |
| End-to-end on a local devnet | this repo, `scripts/fl/devnet-round-e2e.sh` |

All integers below are big-endian unless stated; `‖` is concatenation; `keccak` is Keccak-256.

## 1. The cluster

`registerCluster(salt, rules)` on `FederatedRoundLedger` creates a cluster whose id is
`keccak("citrate-fl-cluster/1" ‖ u64 chainid ‖ ledger ‖ coordinator ‖ salt)` and whose rules are
fixed for its life:

| Rule | v1 | Bound |
|---|---|---|
| `minParticipants` | 3 | ≥ 3 (US-9.1: at least three devices) |
| `chunkDim` | 1024 (16 in the synthetic e2e) | 1..1024 (0x0110 cap) |
| `valueScaleLog2` | 8 | ≤ 16 |
| `thresholdPos` / `thresholdNeg` | 32768 / −32768 (±0.5 on Q16) | pos > 0 > neg |
| `confidenceRule` | 1 = nonzero | only 1 |
| `weightRule` | 1 = uniform | only 1 |
| `challengeWindow` | 150 blocks suggested; 12 in the e2e | ≥ 1 |

`participants × chunkDim ≤ 4096` so one chunk's whole precompile input fits a challenge
transaction (≤ 65 KB of calldata at 16 participants).

## 2. The round config

Per round, JSON (`RoundConfig`), with its hash committed in the round record:

```
config_hash = keccak("citrate-fl-round-config/1" ‖ u64 chain_id ‖ ledger ‖ cluster_id
  ‖ base_model_sha256 ‖ start_adapter_sha256 ‖ u16 min_participants ‖ u32 chunk_dim
  ‖ u8 value_scale_log2 ‖ i64 threshold_pos ‖ i64 threshold_neg ‖ u8 confidence ‖ u8 weight
  ‖ u64 max_values ‖ u32 roster_len ‖ roster (20-byte addresses, strictly ascending))
round_id    = keccak("citrate-fl-round-key/1" ‖ u64 chain_id ‖ ledger ‖ cluster_id ‖ u64 ordinal)
```

`round_id` equals `FederatedRoundLedger.roundIdOf(clusterId, ordinal)`; ordinals are strictly
sequential per cluster. The roster lists the device keys allowed to contribute (D-31 device keys
when the cluster wiring lands). The config's rules must equal the cluster's on-chain rules; the
replay checks this against `getCluster`.

## 3. A device's contribution

The coordinator publishes one `lora_delta` job per roster device with payload
`{task, ordinal, round_id, config}`. A device takes part only if its member set it up and
consented to this round (`CITRATE_FL_CONSENT_FILE`, D-29), it is on the roster, it has not already
contributed to the round, and a trainer is configured. The base model and start adapter must be
staged and hash-verify; the dataset must be a verified trajectory export (S9.3 shape, every line
naming the verifiers that passed it).

The operator's trainer (`CITRATE_LORA_TRAINER`, inputs as `CITRATE_LORA_*` environment
variables, never on a command line) writes a trained GGUF LoRA adapter with exactly the start
adapter's tensors. The device then computes, tensor by tensor in **name order**:

```
delta[k] = Q16::from_f32((trained[k] - start[k]) * 2^value_scale_log2)   (citrate-fed-types kernel)
```

and writes the artifact (`FLD1`):

```
"FLD1" ‖ u16 version=1 ‖ u8 scale ‖ u8 0 ‖ round_id ‖ worker ‖ start_adapter_sha256
  ‖ trained_adapter_sha256 ‖ manifest_hash ‖ u32 chunk_dim ‖ u64 n ‖ n × i64
```

`manifest_hash = keccak("citrate-fl-manifest/1" ‖ u32 count ‖ per tensor in name order:
u32 name_len ‖ name ‖ u32 ndims ‖ u64 dims…)`. The delta is cut into chunks of `chunk_dim`;
`row_hash[c] = keccak(the chunk's i64 bytes)` and `delta_root` is the tree (§4) over the row
hashes. The device signs

```
delta_digest = keccak("citrate-fl-delta/1" ‖ round_id ‖ worker ‖ delta_root ‖ delta_sha256
  ‖ u64 n ‖ u32 chunk_dim)
```

with its key (65-byte recoverable signature), uploads the artifact to
`PUT /v1/fl/delta/{sha256}?job=<id>` (accepted only from the job's leaseholder, under its own
content address, bounded by the round's `max_values`), and submits the signed result. Only the
delta leaves the device; the trained adapter and the dataset do not.

## 4. The tree

Every root in this spec: `leaf(i, payload) = keccak(0x00 ‖ u32 i ‖ payload)`, the leaf list is
padded with zero words to the next power of two, `node = keccak(0x01 ‖ left ‖ right)`. A proof
is the sibling path from the leaf up; bit `j` of the index says whether the running hash is the
left (0) or right (1) child at level `j`.

## 5. Aggregation through 0x0110

Participants are ordered by ascending worker address. For chunk `c`, the `0x0110` input is

```
u32 dim ‖ u32 n ‖ rows (participant-major, n × dim × i64)
  ‖ confidences (n × dim × i64: 65536 where the value is nonzero, else 0)
  ‖ weights (n × i64: floor(65536 / n)) ‖ i64 threshold_pos ‖ i64 threshold_neg
```

and its output is `aggregated (dim × i64) ‖ states (dim × u8)`: the Q16 weighted sum (the
federated mean, with floor weights) and the Belnap state per coordinate (0 Neither: nobody moved
it; 1 True: everyone who moved it agreed on the sign; 3 Both: they disagreed). The coordinator
obtains every output from a Citrate node by `eth_call` to
`FederatedRoundLedger.belnapAggregate(bytes)`; it computes no aggregate itself. The merged
adapter is `start[k] + aggregated[k] / (65536 · 2^scale)` per value (f64, then f32), written as
F32 GGUF with the start adapter's metadata, in the start adapter's tensor order.

Golden vector (pinned by the kernel in `tools/fl-replay/tests/golden.rs`, by the forge tests and
by the compute-pool tests; first observed from the live precompile on a devnet): rows
`[65536,−32768,0,100]`, `[32768,−32768,0,50]`, `[−16384,16384,0,25]` give
`0x0000000000006aa9ffffffffffffbfff0000000000000000000000000000003903030001`.

## 6. The record

```
participants_root = tree over keccak(worker ‖ delta_root), in participant order
input_root        = tree over keccak(input_c)
output_root       = tree over keccak(output_c)
adapter_hash      = sha256(merged adapter file)
record_digest     = keccak(abi.encode(chainid, ledger, round_id, config_hash, participants_root,
                    input_root, output_root, adapter_hash, n_values, chunks, participants))
```

The coordinator's tool emits an **unsigned** `commitRound((clusterId, ordinal, configHash,
participantsRoot, participants, nValues, inputRoot, outputRoot, chunks, adapterHash))` intent; the
operator's ceremony signs it. The ledger checks the coordinator, the ordinal and the shape
(`participants ≥ minParticipants`, `chunks = ceil(nValues / chunkDim)`, non-zero roots) and
starts the window.

## 7. The challenge window

Until `deadline = commit block + challengeWindow`, anyone may prove the round wrong:

| Call | Proves | Fault |
|---|---|---|
| `challengeOutput` | the ledger re-runs `0x0110` on a committed input; the output differs from the committed one | OutputMismatch |
| `challengeRow` | a participant's row inside a committed input is not the row its committed `delta_root` holds | RowMismatch |
| `challengeRules` | a committed input breaks the cluster's rules (width, length, participant count, confidences, weights, thresholds) | RuleViolation |
| `challengeOrder` | two committed participants are not strictly ascending (a repeated device) | ParticipantOrder |

A failed challenge reverts and changes nothing, so it needs no bond. A successful one rejects the
round for good. After the deadline `finalize` accepts an unrejected round. On a chain without
`0x0110` (anvil, forge), every path that needs it reverts `PrecompileUnavailable` rather than
passing.

What the chain does **not** check, and the replay does: that each participant's `delta_root` is
the one the device signed, that devices are on the roster, that the merged adapter is start plus
aggregate, and that the config's rules equal the cluster's.

## 8. Settlement

`settlement-core::fl_gate::settle_allowed` allows settlement only when the record's status is
Accepted and the merged hash anchored on `PatronageLedger.commitRound` is the record's
`recordDigest`. `settlement-coord::Coordinator::run_fl_round` puts that gate in front of the
existing RoundBarrier and SettlementIdempotency; `setl-fl-intents` emits the unsigned intents
(exit 2, nothing written, when refused). Formal model: citrate-settlement
`formal/FlChallengeWindow.tla`.

## 9. Replay

`citrate-fl-replay --bundle bundle.json --deltas DIR [--start S --merged M] [--rules …]`
re-verifies every signature, artifact and delta root, rebuilds every chunk input, runs the
precompile's kernel (`citrate_execution::precompiles::q16::belnap`) in process, recomputes every
root and the record digest, and checks the merged adapter value by value. It shares no code with
the coordinator.

## 10. HUP-S9.1: what was enabled, and what was not

The round needs, from the chain: `0x0110` callable from contracts (live; from the PBA hardening height
its gas is priced on `n × dim`) and a contract that records rounds and
recomputes chunks through it (`FederatedRoundLedger`, new; deploy-gated, not deployed). No node or
consensus code changed, so nothing needed an activation height.

The node's in-process checkpoint learning orchestrator (`BlockProducer::enable_learning`, which
writes a `learning_root` into checkpoint headers) was **not** enabled. The round does not use it,
and enabling it is a consensus change: from the PBA activation height the `learning_root` is part
of the block hash, it is computed from each node's own gossip view (so validators would not agree
on it), and its trust weights are uniform until a consensus blue score is wired (the in-code note
says to wire that first). Turning it on needs its own activation-height-gated design and an owner
decision.

## 11. Pending owner sign-off (placeholders)

- Rules: `minParticipants` 3, `chunkDim` 1024, `valueScaleLog2` 8, thresholds ±0.5, the nonzero
  confidence rule and uniform floor weights, `challengeWindow` (150 blocks suggested).
- `MAX_CHUNK_CELLS` 4096; `max_values` per round (64M in the e2e); the delta upload cap
  (256 MiB) and dataset cap (256 MiB); the trainer timeout (6 h).
- Job tier for `lora_delta` jobs (`federated`) and vouching a cluster's own devices.
- Settlement metering for a round (the e2e uses examples × 1000 compute units at full data
  quality) and how a cluster round's ordinal maps to PatronageLedger round ids.
- Whether a successful challenge should also slash the coordinator (v1 only rejects the round;
  no bond, no slashing).

## 12. Not covered by v1

- LoRAFactory / ModelRegistry registration of the merged adapter (US-9.1 AC4): blocked on the
  model/LoRA precompile integration and the post-reroll redeploy (federation F-1, F-2, F-4).
- Real LoRA training on devices: the e2e uses a fixture trainer that learns nothing; a real
  trainer program (PEFT, MLX) is operator-supplied.
- Averaging LoRA `A` and `B` separately is the standard federated-LoRA approximation, not the
  average of the products.
- Live rounds on 40204 (≥ 3 GPU devices, the ledger and PatronageLedger deployed): operator work.
