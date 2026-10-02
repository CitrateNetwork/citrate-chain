---
created: 2026-10-01T23:00:00Z
branch: hup/n5-chain-fork
author: Larry Klosowski + Claude Opus 5.5
status: active
wp: HUP-S6.10
---

# citrate-fork

The Citrate-aware dry-run fork used by the dApp forge in Citrate Core (HUP-S6.10). It runs
a plan of contract creations and calls on top of chain 40204 state with the node's own
execution rules, and reports what happened, including every Citrate precompile the plan
touched.

## Why not plain anvil

An anvil fork of 40204 runs Ethereum's precompiles only. A contract that calls a Citrate
precompile (for example `0x0110` BELNAP_AGGREGATE) reaches an empty account on anvil and
gets success with no data. A dry run there says nothing about what 40204 would do. This
fork runs the same EVM configuration the node builds:

| Behaviour | Source in this repo |
|---|---|
| Citrate precompiles | `revm_adapter::register_citrate_precompiles` (the node's bridge, not a copy) |
| PBA hardening flag | the release pin for the chain id (`citrate_consensus::hardening::PINNED_ACTIVATIONS`) |
| Value transfers made by contracts | `executor::value_semantics_at` (REVM-authoritative on 40204) |
| Contract nonces (EIP-161) | `executor::persist_contract_nonces_at` |
| EVM spec, chain id, GASPRICE | CANCUN, the endpoint's chain id, gas price 0 inside the EVM (the executor charges gas outside REVM) |

A block where the legacy value rule or the legacy nonce rule still applies is refused, not
simulated wrongly.

## What the fork cannot reproduce

`citrate-fork precompiles --block <n>` prints the table for a block. In short:

| Address | In this fork |
|---|---|
| Every pure address the node bridges into REVM (0x0107-0x0111, 0x0120, 0x0130, 0x0200-0x0202) | Real: the node's own implementation |
| 0x0108 | Real, and it fails closed like the default 40204 node build (no `halo2-verifier`) |
| 0x0130 at or above the hardening height | Unavailable unless this crate is built with `--features commd-fold-verify` (the 40204 node links the live verifier) |
| 0x0100-0x0106 inference family | Unavailable: it needs the hosted model runtime, which contract code cannot reach on 40204 either |
| 0x0112-0x013F, 0x0203-0x0209 | Unavailable: reserved, unassigned |
| 0x1000 model, 0x1002 artifact, 0x1003 governance | Unavailable: the node handles these only as the destination of a top-level transaction |

Unavailable never means simulated as success. The fork executes what the node would execute
(below the hardening height a call into an unbridged address returns success with no data,
on 40204 as here; at and above it the call fails), and the report lists each touched
unavailable address under `precompiles.unavailableTouched` so the caller can refuse it.

## Usage

```sh
cargo build -p citrate-fork --release
# state from 40204 itself, or from a local anvil fork of it (anvil --fork-url https://rpc.citrate.ai)
citrate-fork run --plan plan.json --rpc http://127.0.0.1:8545
citrate-fork precompiles --block 100000
```

The plan format is documented in `src/plan.rs`. `run` prints one JSON report and exits 0
whenever the plan executed (a reverted step is a finding inside the report); it exits 1 with
the reason on stderr when the plan could not run.

## Safety

Read-only by construction. The only JSON-RPC methods it calls are `eth_chainId`,
`eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBalance`, `eth_getTransactionCount`,
`eth_getCode` and `eth_getStorageAt`, all at one pinned block. It holds no key, signs
nothing and never sends a transaction. Balance overrides in a plan change only the fork's
in-memory copy and are listed in the report.

## Tests

```sh
cargo test -p citrate-fork
```

The anvil test runs against a real anvil when one is on `PATH` and prints `skipped`
otherwise.
