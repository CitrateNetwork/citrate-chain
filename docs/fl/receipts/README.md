---
created: 2026-10-01
branch: hup/n5-chain-fl
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Devnet round receipts

Receipts written by `scripts/fl/devnet-round-e2e.sh` (local paths removed). All
ran on a throwaway local devnet (chain id 1337) with throwaway keys; the trainer was the fixture
trainer, so no learning is represented.

- `2026-10-01-devnet-synthetic.json`: synthetic base, 1,152 values, 72 chunks, final contract and
  script.
- `2026-10-01-devnet-gemma-4-e4b.json`: Gemma 4 E4B base, 2,269,184 adapter values, 2,216 chunks
  through `0x0110`. The llama-server completion on the GPU ran out of Metal memory (the GPU was
  shared with other work); the receipt records the CPU recheck that loaded the merged adapter and
  completed. That run used the contract before an equivalent check was removed from `_verify`.
- `2026-10-04-devnet-synthetic.json`: the same synthetic run repeated after the fan-out 6 review
  fixes (the ledger's participant cap, roster-scoped leasing of round jobs, the coordinator's
  per-request upload files, the trainer's environment scrub, the bounded return decoding). Same
  shape and outcome: accepted after the window, record digest equal on chain, in the bundle and in
  the replay, 4 settlement intents, the dishonest ordinal 1 rejected on chain and refused by
  settlement.
