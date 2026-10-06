# Canonical contract-address table

This directory is the **single source of truth** for every Citrate
contract deployed to chain 40204. The federation (citrate-explorer,
citrate-inference-gateway, citrate-node-agent, citrate-sdk-marketplace,
citrate-gui-native, citrate-defense_prime-shell, citrate-buyer-webapp) reads
from a vendored copy of `40204.json` — no consumer ever hardcodes a
contract address again.

## Why this exists

Before WP-Z, nine source files across seven repos hardcoded the live
ModelRegistry + InferenceRouter addresses. A chain re-roll meant nine
edits + nine PRs to keep apps in sync — a class of drift that
guaranteed at least one would slip. This directory eliminates that:
post-redeploy, only `40204.json` changes; every consumer reruns
`sync-addresses` and ships a one-file PR (or a CI job does it
automatically).

## How consumers use it

Each consumer ships a tiny script (`scripts/sync-addresses.{sh,mjs}` or
similar) that:

1. Reads `../../citrate-chain/contracts/addresses/40204.json` (the
   sibling-repo path under `Citrate-Labs/`).
2. Optionally narrows the read to just the contracts the consumer
   actually uses (e.g., the explorer needs `ModelRegistry` +
   `InferenceRouter` + `EduForwarder`; the inference gateway needs
   those plus `ComputePricingOracle`).
3. Writes a vendored copy at a path the consumer's build system picks
   up — typically `src/generated/addresses.json` for TS and
   `crates/<crate>/src/generated/addresses.json` for Rust.

The vendored copies are **committed**. The build system imports them
via `import addresses from './generated/addresses.json'` (TS) or
`include_str!("generated/addresses.json")` (Rust); both are
zero-runtime-dep and CI-stable. The dev-time sync is the only
moving piece.

## Schema (`40204.json`)

| Field | What |
|-------|------|
| `chainId` | 40204 (always — this is the chain-40204 table) |
| `chainName` | Human label |
| `rpcUrl` | Canonical public RPC the apps default to |
| `explorerUrl` | Public CitrateScan URL |
| `deployer` | EOA that signed the deploy ceremonies |
| `deployedAt` | ISO-8601 timestamp of the ceremony |
| `contracts` | Address-by-name map for ceremony-deployed contracts |
| `aaStack` | EW-S1 ERC-4337 v0.7 stack (sourced from `.env.testnet`) |
| `genesis` | Contracts allocated at genesis (Arachnid CREATE2 deployer) |
| `precompiles` | Built-in addresses the executor binds (NOT contracts) |

`contracts` is the merged authoritative output of:
- `broadcast/DeployAll.s.sol/40204/run-latest.json`
- `broadcast/DeployEduStack.s.sol/40204/run-latest.json`
- `broadcast/DeployAIGateway.s.sol/40204/run-latest.json`
- `broadcast/DeployModelAccessControl.s.sol/40204/run-latest.json`
- `broadcast/DeployTEEAttestationRegistry.s.sol/40204/run-latest.json`
- `broadcast/DeployComputePoolTraining.s.sol/40204/run-latest.json`

`aaStack` mirrors `broadcast/DeployAA.s.sol/40204/run-latest.json` plus
the EntryPoint v0.7 address from `.env.testnet`.

## Regeneration

After a chain re-roll + the post-redeploy ceremony, regenerate this
file by running:

```bash
scripts/ops/emit-address-table.sh
```

The script reads every `broadcast/Deploy*.s.sol/40204/run-latest.json`
+ `.env.testnet` and emits a fresh `40204.json`. Diff the result
against the committed copy; if it changes, commit + push, then run
each consumer's `sync-addresses` script and open the one-file PRs.

### Fresh-keys reroll (2026-09-29): book comes from the chain, not broadcasts

The 2026-09-29 book was **not** produced by `emit-address-table.sh`. Its
broadcast inputs were unreliable: some scripts were run more than once
(a failed tunnel batch followed by a successful on-box batch), and some
`run-latest.json` files were overwritten by an rsync. On top of that, the
emitter falls back to stale addresses when a broadcast is missing.
Simulating the deploy scripts doesn't work either: the governance / DPF /
cit_agent / Quorum scripts use plain `new` (nonce-based CREATE), so a
simulation now prints *next-nonce* addresses that have no code.

Instead, the book is derived from the chain itself.
`40204.provenance.json` records every transaction the deployer
(`0x7DAbC319…Acdf`, r1005 reroll 2026-10-06, genesis `1dcfc490…`) sent on
the fresh chain: nonces 0–102, contiguous, all with `status=1` (no orphans
this time; the 2026-09-29 chain had nonces 0–115 under `0xa3512bE8…`). For each transaction it records the tx hash, block, the
created address, and the forge artifact whose creation code prefixes the
init code. It also marks each entry `canonical` or `orphan`, where an
orphan is the leftover of a partial first run that a complete rerun
superseded. The canonical instance was confirmed from on-chain wiring
(ownership handover, constructor references). Anyone can re-verify any
row with `cast receipt <tx>` / `cast code <address>` against
`https://rpc.citrate.ai`.

Where one contract type has several live instances, the book prefixes
the key with its role. `AnchorRegistry` is the standalone instance that
citrate-quorum's book test requires, and the others are
`QuorumAnchorRegistry` and `CitAgentAnchorRegistry`. The cit_agent
2-of-3 timelock is `CitAgentTimelock`. The coop pair and the `planned`
coop block are absent because coop is not deployed on this chain yet.

### HUP registry set (HUP-S7.1)

`OrganizationSBT`, `AgentSBT`, `CapsuleRegistry`, `AnchorRegistry`,
`BenchmarkRegistry` and `SkillRegistry` are deployed by
`script/DeployHupRegistries.s.sol` after the main ceremony, and merged into this
book by `scripts/ops/hup-book-update.py`, which re-derives each CREATE2 address
from the broadcast and checks it on chain before writing. Procedure:
[`docs/ops/HUP_REGISTRY_REDEPLOY_RUNBOOK.md`](../../docs/ops/HUP_REGISTRY_REDEPLOY_RUNBOOK.md).
`scripts/ops/hup-provenance-update.py` then appends the same broadcast to
`40204.provenance.json` (rows the book no longer pins become `superseded`), so the
ledger and the book stay in step.

## Adding a new contract

When a new ceremony script adds a contract to chain 40204:

1. Run the script; verify `broadcast/<script>.s.sol/40204/run-latest.json`
   records the deployment.
2. Run `scripts/ops/emit-address-table.sh`; verify the new contract
   appears under `contracts` in the regenerated `40204.json`.
3. Commit the new `40204.json` + the broadcast file.
4. For each consumer that needs the new address, run its
   `sync-addresses` script and update its loader to expose the new
   name. Open one PR per consumer.

## Out-of-scope (intentionally)

- **Multi-chain tables.** When Citrate ships a second chain (testnet,
  mainnet split), add `40205.json` alongside `40204.json`. Consumers
  pick by chain id at boot.
- **Versioned upgrades.** If a contract is upgraded (new address for
  the same name), bump the key (e.g., `IPFSIncentivesV2`) rather than
  silently rotating — consumers should fail-loud on a missing name.
- **Off-chain endpoints.** This file is contracts-only. RPC URLs +
  bundler URLs + identity URLs live in `.env.testnet` /
  `.env.production` per app.
