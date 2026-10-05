---
created: 2026-10-01
branch: hup/n5-chain-fl
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Fixture: a federated round recorded on a local devnet

Produced by `scripts/fl/devnet-round-e2e.sh` (synthetic base mode) on 2026-10-01: three local
device workers (citrate-compute-pool `citrate-coop-worker`, fixture trainer), aggregation by
`citrate-fl-round aggregate` through the `0x0110` precompile of a local `citrate devnet` node
(chain id 1337), committed to and accepted by `FederatedRoundLedger` on that devnet.

- `bundle.json`: the coordinator's round bundle (roots, leaf hashes, signed worker results).
- `deltas/*.fld`: the three workers' delta artifacts, named by SHA-256.
- `start.gguf`, `merged.gguf`: the start adapter and the coordinator's merged adapter.

The replay tests (`tests/replay_fixture.rs`) check that this repo's independent implementation
agrees with the coordinator's on every root, the record digest and the merged adapter, and that
each kind of tampering is reported. The adapters come from a synthetic base and the fixture
trainer: no learning is represented here, only the round format.
