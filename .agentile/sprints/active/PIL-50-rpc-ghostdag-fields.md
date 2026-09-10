---
name: PIL-50
description: Expose per-block GHOSTDAG fields (blueScore, blueWork, selectedParentHash, mergeParentHashes) on the eth_getBlockBy* RPC + newHeads WS payload
created: 2026-06-03
branch: main
author: saulbuilds (Larry Klosowski)
status: shipped
---

# PIL-50 — Expose per-block GHOSTDAG fields on JSON-RPC

## Why

`rpc.citrate.ai` was the **single blocker** for the explorer's DAG-
native surfaces and for the indexer's `blue_score` ordering. The
explorer agent's handoff (`RPC_DAG_FIELDS_HANDOFF.md` at repo root)
documented the gap precisely:

> `eth_getBlockByNumber` / `eth_getBlockByHash` on `rpc.citrate.ai`
> return only standard Ethereum block fields — there is no
> per-block `blue_score`, `selected_parent_hash`, or
> `merge_parent_hashes`. ... per-block GHOSTDAG topology cannot be
> read from RPC today.

The consensus layer already had these fields on the `BlockHeader`
struct (`core/consensus/src/types.rs:175-180`). They were just being
stripped at the RPC encoder. `BlockResponse` carried two of them
(`blue_score`, `blue_work`) but not the third (`merge_parent_hashes`),
and `eth_block_json` ignored all of them entirely.

## What's been added

Four new camelCase fields on `eth_getBlockByNumber` / `eth_getBlockByHash`
JSON responses **and** on the `eth_subscribe("newHeads")` payload:

| field | type | source | empty when |
|---|---|---|---|
| `blueScore` | hex u64 | `header.blue_score` | never (genesis = 0) |
| `blueWork` | hex u128 | `header.blue_work` | never |
| `selectedParentHash` | 32-byte hex | `header.selected_parent_hash` | genesis only |
| `mergeParentHashes` | array of 32-byte hex | `header.merge_parent_hashes` | block extended a single tip |

`selectedParentHash` deliberately duplicates the existing `parentHash`
field (they're the same value) so DAG-aware callers don't have to
special-case the Citrate spelling vs the Ethereum spelling.

## Files touched

- `core/api/src/types/response.rs`
  - Added `merge_parent_hashes: Vec<Hash>` to `BlockResponse` and
    populated it from `block.header.merge_parent_hashes` in the
    `From<Block>` impl. The other two GHOSTDAG fields (`blue_score`,
    `blue_work`) were already on the struct — just unused by the
    encoder.
- `core/api/src/eth_rpc.rs`
  - `eth_block_json` now also emits `blueScore`, `blueWork`,
    `selectedParentHash`, `mergeParentHashes`. Backwards-compatible:
    Ethereum-spec callers ignore unknown fields.
- `core/api/src/eth_subscriptions.rs`
  - `BlockHeader` (the `newHeads` payload, separate type from the
    consensus header) gains the same four fields, populated in the
    `From<&Block>` impl. `#[serde(rename_all = "camelCase")]` already
    on the struct does the field-name mapping.

## Why not a separate `citrate_getDagBlock` method

The handoff explicitly preferred extending the existing
`eth_getBlockBy*` shape because the explorer + indexer already call
those — adding fields here means **zero downstream code change** on
their side. A bespoke `citrate_getDagBlock` would have meant a new
client call-site for every consumer. The Ethereum spec doesn't
forbid additional fields, just unknown *required* ones, so this is
spec-clean.

## Acceptance criteria (verified post-deploy)

| | |
|---|---|
| `eth_getBlockByNumber latest` returns `blueScore`, `blueWork`, `selectedParentHash`, `mergeParentHashes` | ✅ block 429,974: `blueScore=0x2477f`, `blueWork=0x22c7719dc0`, `selectedParentHash=0x9d06b419…`, `mergeParentHashes=[]` |
| `eth_getBlockByHash` returns the same four fields with identical values | ✅ verified — values match exactly |
| Internally consistent with `citrate_getDagStats` | ✅ latest `blueScore=149,375` vs `maxBlueScore=149,387` (12 blocks ahead, consistent with sustained 2s block time during deploy) |
| `selectedParentHash` resolves to a known block | ✅ matches the existing `parentHash` field which is already routed through `getBlockByHash` |
| `eth_subscribe("newHeads")` delivers the same four fields | ✅ `BlockHeader::from(&Block)` writes them; live WS verification deferred (requires a streaming client — the symmetry with `eth_block_json` is the assertion) |
| Pre-existing Ethereum-spec callers still work | ✅ all previous fields preserved at same key + type |

## What this unblocks (per the handoff)

- **Explorer block-detail page** — real `blueScore`, selected vs merge
  parents, blue/red, depth-based finality.
- **Live DAG view (explorer sprint P-5)** — real GHOSTDAG can be
  streamed via `eth_subscribe("newHeads")` and drawn (spine + merge
  edges + tips + blue/red).
- **Indexer (explorer S-1)** — `dag_edges` + `blue_score` ordering
  populates correctly instead of `blue_score=0` / empty edges.

## Tradeoffs / open follow-ups

- **`blueWork` is a hex string, not a JSON number.** Required because
  it's a u128 and JSON numbers cap at safe-integer range (~2^53 for
  most clients). Explorer parser already handles this — see
  `RawCitrateBlock` / `parseDagBlock` in
  `citrate-explorer/src/lib/citrate/rpc.ts`.
- **No new per-block Citrate method.** We chose the field-extension
  path (preferred by the handoff) over a bespoke `citrate_getDagBlock`.
  If a future client wants the *only* DAG view without the Ethereum
  fields, a separate method can be layered on top — the encoder
  building blocks are already in place.
- **Bluescore-ordered enumeration is not part of this fix.** The
  explorer's indexer S-1 will need `getBlocksByBlueScore(from, to)`
  or equivalent for backfill. Tracked as **PIL-50b** (deferred).

## Related

- [[PIL-12]] — the PIL-12 EthSubscriptionServer (the WS server this
  patch touches) was bound to `config.rpc.ws_addr` in this same chain
  surface earlier; that work is what made the `newHeads` payload an
  available place to thread these fields through.
- [[PIL-48]] — the receipt-side log fix from the same audit-week
  sweep. Different RPC concern but same "the data was there, the
  encoder was lossy" pattern.
