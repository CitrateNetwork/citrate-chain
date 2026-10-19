---
created: 2026-10-19T09:00:00Z
branch: ops/c3p-producer-runbook
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
---

# scripts/producers

Tools for producer operators. The procedure is [`docs/ops/PRODUCER_OPERATOR_RUNBOOK.md`](../../docs/ops/PRODUCER_OPERATOR_RUNBOOK.md); the owner's checklist is [`docs/ops/PRODUCER_OPERATOR_ONBOARDING_CHECKLIST.md`](../../docs/ops/PRODUCER_OPERATOR_ONBOARDING_CHECKLIST.md).

Python 3.10+ standard library only. None of them reads a private key, signs a transaction or sends one.

| Script | Reads | Writes | `--dry-run` |
|---|---|---|---|
| `preflight.py` | Host files and commands (stat only for key files); bootnodes and the public RPC | Nothing | Lists the checks |
| `gen_node_config.py` | A profile | `node.toml`, `citrate-node.env`, `citrate-node.service` in `--out-dir` | Prints them |
| `build_registration_tx.py` | Public RPC; `citrate-node registration-proof` (reads `proposer.key` read-only) | `--out` JSON | No chain reads; output marked DO NOT SIGN |
| `verify_producer.py` | Public RPC only | Nothing | Lists the reads |

`producerlib.py` holds the shared RPC client, ABI decoding, epoch math and profile loading. Selectors are pinned there and recomputed with a reference keccak in the tests.

## Profiles

`profiles/<name>.json` holds everything network-specific: chain id, genesis hash, public RPC, bootnodes, ValidatorRegistry address, activation height, the consensus environment and checkpoint parameters. Each value names its source under `sources`. A profile whose `status` isn't `ready`, or whose values are incomplete, is refused outside `--dry-run`.

- `40204-r1005`: the live network.
- `rehearsal-1`: `pending-genesis`. The chain team fills it when the rehearsal genesis is cut.

## Tests

```bash
python3 -m unittest discover -s scripts/producers/tests -p 'test_*.py' -v
# with a built node, also exercise the real registration-proof subcommand:
CITRATE_NODE_BIN=target/debug/citrate python3 -m unittest discover -s scripts/producers/tests -p 'test_build*.py'
```

The tests use a fake JSON-RPC server on 127.0.0.1 (`tests/rpcstub.py`), a fake host root and a fake node binary (`tests/fake_citrate_node.py`). These are test-only; the tools never import them. CI runs them in `.github/workflows/claims-truth.yml`.
