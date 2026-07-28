# @citratenetwork/chain-config

The single source of truth for Citrate chain-40204 addresses, published as a typed
package so the federation **imports** it instead of vendoring raw JSON copies that
silently rot after every re-roll.

Generated from [`citrate-chain/contracts/addresses/40204.json`](../../contracts/addresses/40204.json)
(via [`scripts/generate.mjs`](scripts/generate.mjs)). That file remains the canonical
source; this package is its typed, versioned distribution.

## Why

The 2026-07-27 federation sweep found stale vendored addresses in ~13 repos, each a
beta/mainnet blocker, because there was no shared source and the per-repo drift gates
were absent or self-referential. This package + its `check` CLI is the fix (backlog
item `CL-C2`).

## Use

```js
import { contracts, aaStack, memberSBT, getAddress, checkDrift } from '@citratenetwork/chain-config'

contracts.X402Facilitator      // "0xbd46…"
aaStack.EntryPoint             // ERC-4337 entrypoint
getAddress('ComputeMarketplace')
memberSBT                       // nonce-based — getCode-verify at boot (it MOVES every re-roll)
```

## CI drift gate (every consumer repo)

Replace hand-rolled `sync-addresses` checks with a blocking step:

```yaml
- run: npx @citratenetwork/chain-config check ./path/to/vendored/addresses.json
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
