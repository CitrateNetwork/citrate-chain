---
created: 2026-10-01
branch: hup/n5-chain-fl
author: Larry Klosowski + Claude Opus 5.5
status: active (built and proven on a local devnet; live 40204 rounds are operator work)
sprint: HUP-S9 Learn together
wp: HUP-S9.1, HUP-S9.2
issue: CitrateNetwork/citrate-federation#286
---

# HUP-S9.1 / S9.2: a federated round, end to end

Planset: citrate-core `.agentile/planset/2026-09-30-hermes-upskill/` (05 S9.1 "enable the
learning orchestrator path where required; cluster-scoped round config", S9.2 "round e2e:
coordinator, device workers, 0x0110, settlement, challenge; replay digest match"; 04 US-9.1).
Specification: [`FL_ROUND_V1.md`](FL_ROUND_V1.md).

## Data sources (Rule 7)

| Surface | Source |
|---|---|
| Aggregate per chunk | the `0x0110` precompile of a Citrate node, by `eth_call` to `FederatedRoundLedger.belnapAggregate(bytes)` |
| Round record, window, status | `FederatedRoundLedger` (`getRound`, `recordDigest`, `getCluster`) on the chain the cluster registered on |
| Device deltas | the device's operator-configured trainer output, differenced against the hash-verified start adapter |
| Training set | the member's verified trajectory export (S9.3 shape), hash-recorded in the signed result |
| Settlement anchor | `recordDigest(roundId)` of an Accepted round, anchored on citrate-coop `PatronageLedger.commitRound` |
| Replay | the delta artifacts and `citrate_execution::precompiles::q16::belnap`, in process |

## In this repo

- `contracts/src/FederatedRoundLedger.sol`: clusters with fixed rules, sequential round records,
  four on-chain fraud proofs (output recompute through 0x0110, row consistency, rules, participant
  order), finalize after the window, `recordDigest` for settlement, `belnapAggregate` view. Holds
  no value; fails closed without the precompile. Not deployed.
- `contracts/test/FederatedRoundLedger.t.sol`: 27 tests (a test double etched at `0x0110` answers
  only registered vectors; the golden vector is the live precompile's). 17/17 non-equivalent
  mutants killed; the one equivalent mutant (a redundant index-range check in `_verify`, already
  implied by the index inside the leaf preimage) led to removing that check.
- `tools/fl-replay` (`citrate-fl-replay`): the independent replay. Golden-vector tests against the
  kernel, unit tests, and fixture tests on a round recorded on a local devnet
  (`tests/fixtures/devnet-round-0`), including seven kinds of tampering.
- `scripts/fl/devnet-round-e2e.sh`: the end to end on a local devnet (below).
- No node, consensus or precompile code changed; no activation height was needed. The node's
  in-process checkpoint learning orchestrator stays off (FL_ROUND_V1 §10 says why).

## The end to end (local devnet only)

`scripts/fl/devnet-round-e2e.sh` starts a fresh `citrate devnet` (chain 1337) and runs: ledger
deploy, a check that the node's `0x0110` returns the golden vector, cluster registration, a start
adapter, the round config (Rust round id checked against `roundIdOf`), a compute-pool
coordinator with three local device workers (real NAT divergence probe for admission; fixture
trainer), aggregation through the node's `0x0110`, the independent replay, the commit, an honest
chunk challenge that reverts, the window, `finalize`, settlement through the gate onto a devnet
`PatronageLedger`, then a dishonest commit (one chunk's output replaced) that a challenger rejects
on chain through the precompile, which the replay flags and settlement refuses. With a real base
model and `LLAMA_SERVER`, it also loads the merged adapter in llama-server.

Throwaway keys on a throwaway chain: the production path signs nothing (unsigned intents for the
operator's ceremony).

## Proof (2026-10-01, this Mac, local devnet chain 1337 from the installed `citrate` 0.4.0 node)

| Check | Result |
|---|---|
| `0x0110` on the devnet node, golden vector | matches (also pinned by the kernel and the forge tests) |
| Synthetic base: 3 devices, 1,152 values, 72 chunks | PASS end to end, about 100 s |
| Gemma 4 E4B base: 3 devices, 2,269,184 values (rank-8 `attn_q`/`attn_v`), 2,216 chunks through `0x0110` | replay: 0 mismatches; record digest equal on chain, in the bundle and in the replay; honest challenge reverts `ChallengeFailed`; accepted after the window; 4 settlement intents, PatronageLedger anchors the record digest; dishonest ordinal 1 rejected on chain (chunk 1108), replay reports 12 mismatches, settlement refuses (exit 2) |
| Merged Gemma adapter in llama-server | loads; on the GPU the completion hit Metal out-of-memory (GPU shared with other work); on CPU it loads and completes (8 tokens) |
| Training | fixture trainer: no learning ran |
| forge, whole suite | 3,123 to 3,149 passed, 0 failed (one more ledger test added after that run: 27 in the file) |
| `citrate-fl-replay` | 14 tests (golden, unit, devnet fixture, seven tamper cases) |
| clippy `-D warnings` (1.98.1 and the pinned 1.96.0), fmt, semgrep tripwires, gitleaks | clean |
| slither | 2 informational: enum equality in `isAccepted`, the intentional `0x0110` staticcall (fails closed) |

## Not done here

- LoRAFactory / ModelRegistry registration (US-9.1 AC4): blocked on F-1/F-2/F-4.
- Real device training: the e2e's trainer is a fixture; a real trainer is operator-supplied.
- Live rounds on 40204: needs the ledger deployed, a PatronageLedger settler, at least three GPU
  devices and the coordinator configured (operator work, requested on #286).
- The in-node checkpoint orchestrator (`enable_learning`): a consensus change needing its own
  design and owner decision.
