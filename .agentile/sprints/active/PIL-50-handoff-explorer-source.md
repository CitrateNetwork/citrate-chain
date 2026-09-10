# RPC handoff — expose per-block GHOSTDAG fields

**Audience:** the owner/operator of the Citrate node RPC (`rpc.citrate.ai` /
`citrate-chain`).
**Priority:** High. It is the single blocker for the explorer's DAG-native
surfaces (block detail, live DAG view) and for the indexer's blue_score ordering.
**Effort:** small — the consensus layer already computes these fields; this is a
serialization change on the RPC response (+ the WS `newHeads` payload).

---

## The problem (observed live, 2026-06-03)

`eth_getBlockByNumber` / `eth_getBlockByHash` on `rpc.citrate.ai` return **only
standard Ethereum block fields** — there is **no per-block `blue_score`,
`selected_parent_hash`, or `merge_parent_hashes`**. Full observed key set:

```
baseFeePerGas, difficulty, extraData, gasLimit, gasUsed, hash, logsBloom, miner,
mixHash, nonce, number, parentHash, receiptsRoot, sha3Uncles, size, stateRoot,
timestamp, totalDifficulty, transactions, transactionsRoot, uncles
```

No per-block Citrate method exists either — `citrate_getBlock`,
`citrate_getDagBlock`, `citrate_getBlockByNumber`, `citrate_blockInfo`,
`citrate_getDagInfo` all return **"Method not found"**. The only DAG data
available is the **global** `citrate_getDagStats`
(`{ totalBlocks, blueBlocks, redBlocks, tipsCount, maxBlueScore, currentTips[],
height, ghostdagParams }`). Live values confirm the DAG is real and that height ≠
blue_score (e.g. `height 426267`, `maxBlueScore 145681`).

So per-block GHOSTDAG topology (blue_score, parents, blue/red, finality) **cannot
be read from RPC today**.

---

## The ask (pick A — cleanest)

### A. Add the GHOSTDAG header fields to the block response (preferred)
Add these fields to the JSON returned by `eth_getBlockByNumber` and
`eth_getBlockByHash` (the consensus `BlockHeader` already has them — see
`citrate-chain/core/consensus/src/types.rs`: `selected_parent_hash`,
`merge_parent_hashes`, `blue_score`, `blue_work`). Serialize them in the RPC block
encoder (`citrate-chain/core/api/src/eth_rpc.rs`).

**Exact field names + types the explorer already parses** (camelCase, hex-quantity
per Ethereum JSON-RPC convention):

| field | type | source |
|---|---|---|
| `blueScore` | hex uint | `header.blue_score` |
| `blueWork` | hex uint | `header.blue_work` |
| `selectedParentHash` | 32-byte hex | `header.selected_parent_hash` |
| `mergeParentHashes` | array of 32-byte hex | `header.merge_parent_hashes` |

Also include the same fields on the **`eth_subscribe("newHeads")`** payload
(`citrate-chain/core/api/src/eth_subscriptions.rs`) so the live-stream worker
doesn't have to re-fetch each block.

### B. Alternative: add `citrate_getDagBlock(ref)`
A new method returning the parsed block + the four fields above. Works too, but A
is preferred because the explorer + indexer already call the standard
`eth_getBlockBy*` path.

---

## Why these exact names
The explorer's parser already expects them verbatim — see
`citrate-explorer/src/lib/citrate/rpc.ts` (`RawCitrateBlock` /
`parseDagBlock`). With the names above, the explorer, `/api/blocks`,
`useLiveBlock`, and the indexer pick them up with **near-zero downstream code
change** (they activate automatically once `blueScore` is non-zero).

---

## What it unblocks
1. **Explorer block-detail page** — real blue_score, selected vs merge parents,
   blue/red, and depth-based finality (currently falls back to demo because the
   data isn't available).
2. **Live DAG view (explorer sprint P-5)** — the real GHOSTDAG can be streamed and
   drawn (spine + merge edges + tips + blue/red) instead of a placeholder. **This
   handoff effectively closes P-5.**
3. **Indexer (explorer S-1)** — `dag_edges` + `blue_score` ordering populate
   correctly. As built, the indexer reads these exact fields and would otherwise
   store `blue_score = 0` / no merge edges.

---

## Acceptance criteria
- `curl -s -X POST https://rpc.citrate.ai -H 'content-type: application/json' \
   --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}'`
  returns `blueScore` (non-zero), `blueWork`, `selectedParentHash`, and
  `mergeParentHashes` (array; empty is fine when a block extended a single tip).
- `eth_subscribe("newHeads")` delivers the same four fields per header.
- Values are internally consistent with `citrate_getDagStats`
  (a tip's `blueScore` ≈ `maxBlueScore`; `selectedParentHash` resolves to a known block).

Ping the explorer side when it's on `rpc.citrate.ai`; we'll flip the explorer's
block/DAG surfaces off the demo fallback (no deploy needed beyond the env already
pointing at the live RPC).

---

## References
- Explorer finding (full): `citrate-explorer/.agentile/planset/2026-06-03-citratescan-production-v1/FINDINGS-001-rpc-dag-fields.md`
- Explorer parser (expected field names): `citrate-explorer/src/lib/citrate/rpc.ts`
- Consensus header (source of truth): `citrate-chain/core/consensus/src/types.rs`
- RPC block encoder: `citrate-chain/core/api/src/eth_rpc.rs`
- WS newHeads: `citrate-chain/core/api/src/eth_subscriptions.rs`
