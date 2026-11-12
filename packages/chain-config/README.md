# @citratelabs/chain-config

The single source of truth for Citrate chain-40204 addresses, published as a typed
package so the federation **imports** it instead of vendoring raw JSON copies that
silently rot after every re-roll.

Generated from [`citrate-chain/contracts/addresses/40204.json`](../../contracts/addresses/40204.json)
(via [`scripts/generate.mjs`](scripts/generate.mjs)). That file remains the canonical
source; this package is its typed, versioned distribution.

## Versions

| Version | Network | Block-0 hash |
|---------|---------|--------------|
| 0.3.0 | r1007 (live since 2026-11-12T14:00Z; **not published yet**) | `0xcf68634502b4fca1e977ac8dd35aa006bb40c04208d5cd55f1c2b508bba96631` |
| 0.2.0 | r1006 (retired; root book archived as `contracts/addresses/r1006/40204.root.json`) | `0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4` |
| 0.1.0 | r1005 (retired; book archived in `contracts/addresses/r1005/`) | state root `0x1dcfc490…` |

0.2.0 is a breaking release (a new network generation): most addresses moved, the r1005-only
names `LiquidStakingPool`, `QuorumAnchorRegistry` and `CitAgentTimelock` are gone (`getAddress`
throws for them), the post-genesis registries are added under their own keys (for example
`Quorum.AnchorRegistry`), addresses are lowercase, and `governance` carries only `GOVERNANCE` and
`GUARDIAN`. New export: `genesisHash`. Check it against `eth_getBlockByNumber(0x0).hash` before
trusting any address.

0.3.0 is a new network generation. The block-0 contracts keep their addresses (CREATE2). The 28
post-genesis contracts all moved: the r1007 post-genesis deployer is new. Names are unchanged. New
export: `accounts`, the operator EOAs (for example `Bundler` and `Faucet`), which `getAddress` does
not resolve.

## Why

The 2026-07-27 federation sweep found stale vendored addresses in ~13 repos, each a
beta/mainnet blocker, because there was no shared source and the per-repo drift gates
were absent or self-referential. This package + its `check` CLI is the fix (backlog
item `CL-C2`).

## Use

```js
import { contracts, aaStack, memberSBT, genesisHash, getAddress, checkDrift } from '@citratelabs/chain-config'

contracts.X402Facilitator      // "0x0c51…"
genesisHash                    // r1006 block 0; compare with the chain at boot
aaStack.EntryPoint             // ERC-4337 entrypoint
getAddress('ComputeMarketplace')
memberSBT                       // nonce-based — getCode-verify at boot (it MOVES every re-roll)
```

## CI drift gate (every consumer repo)

Replace hand-rolled `sync-addresses` checks with a blocking step:

```yaml
- run: npx @citratelabs/chain-config check ./path/to/vendored/addresses.json
```

Exit 1 on any missing/mismatched address, so a re-roll fails CI loudly instead of
shipping dead contracts. In an on-disk federation checkout you can compare directly
against the sibling canonical file:

```bash
citrate-chain-config check ./src/generated/addresses.json \
  --canonical ../citrate-chain/contracts/addresses/40204.json
```

## Regeneration (citrate-chain, after every re-roll)

```bash
node packages/chain-config/scripts/generate.mjs          # refresh embedded snapshot
node packages/chain-config/scripts/generate.mjs --check   # CI gate: fails if stale
```

The `chain-config-selfcheck` CI job runs `--check` so the published package can never
lag the on-chain book. `src/addresses.40204.json` is generated — never hand-edit it.
