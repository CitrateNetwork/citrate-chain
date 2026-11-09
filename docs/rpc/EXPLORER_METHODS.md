---
title: "Explorer RPC methods (S3-7, CNV-RPC): request and response shapes"
created: 2026-11-07T18:00:00Z
branch: r1007/rpc-explorer
author: Larry Klosowski + Claude Opus 5.5 (MAC lane, CNV-RPC)
status: active on r1007/rpc-explorer (base r1007/genesis-candidate 28e13057); not merged
---

# Explorer RPC methods (S3-7)

These are the read-only methods the explorer lanes (EXP-S1..S3) build on. The plan is
planset `2026-11-03-r1007-v060`, `02_EXPLORER_AND_VERIFICATION.md` §3, and the semantics
are in `06_CONSENSUS_SPEC.md` §5. Every method names its data source in code
(`core/api/src/explorer_rpc.rs`, `historical_state.rs`, `trace_rpc.rs`). A value the
node does not hold is `null`, with the reason where one is useful. Nothing is estimated.

Conventions: quantities are `0x` hex strings, hashes are 32-byte `0x` hex, and
addresses are 20-byte `0x` hex. "Applied chain" means the node's executed selected
chain, the blocks reached by `selectedParent` from the applied tip.

| Method | Status on this branch | Depends on another lane |
|---|---|---|
| `citrate_getBlocksAtHeight` | implemented, tested | no |
| `citrate_getGhostdagData` | implemented, tested | no (reads S3-1 records) |
| `citrate_getSelectedChainChanges` | implemented, tested | no |
| `citrate_getAcceptingBlock` | implemented, tested (pre-mergeset semantics) | S3-3b changes the semantics, see below |
| `citrate_getFinalityStatus` | implemented, tested (subset) | `r1007/s3-finality-voting` fills the null fields |
| `citrate_getDagStats` (fixed) | implemented, tested | no |
| `eth_getBlockReceipts` | implemented, tested | S3-3b moves receipts to the accepting block |
| historical `eth_getBalance` / `eth_getTransactionCount` / `eth_getCode` / `eth_getStorageAt` / `eth_call` | implemented, tested | no |
| `debug_traceTransaction`, `debug_traceCall` (`callTracer`, `prestateTracer`) | implemented, tested | S3-3b changes what is replayed, not the output |
| `ots_getContractCreator` | implemented, tested | no |
| `net_peerInfo` (extended: each peer's last-known head) | implemented, tested | no |

"Implemented, tested" means unit and conformance tests against a real executor and a
real RocksDB store. It does not mean runtime-proven on a live network.

## Limits

- Batches stay limited to 100 calls, and the per-client buckets are unchanged
  (`rpc_limits.rs`, `rate_limit.rs`).
- Method-budget units are charged against the per-client budget of 1,000 units per
  second:

| Call | Units | Where it is charged |
|---|---|---|
| `debug_traceTransaction`, `debug_traceCall` | 100 | request middleware (`heavy_method_cost`) |
| `ots_getContractCreator` | 200 | request middleware |
| historical point read (balance, nonce, code, slot below the head) | 20 | in the handler, only when the tag names a past block |
| historical `eth_call` | 10 (as today) + 100 | in the handler |

- Traces and creator lookups have a 15 s deadline. `eth_call` keeps 5 s.
- `citrate_getSelectedChainChanges` adds at most 1,000 blocks per call (100 by default)
  and walks at most 10,000 blocks from `fromHash`.
- `citrate_getGhostdagData` searches at most 1,024 chain blocks above a block for its
  colour.

## `citrate_getBlocksAtHeight(height)`

This method returns every stored block at a DAG height, siblings included, sorted by
hash.

- **Data source:** a sibling height index (`CF_METADATA` `hsib:` ‖ height ‖ hash). It is
  written in the same batch as the block, removed by delete and purge, and rebuilt once
  from `CF_HEADERS` when a data dir from an older binary is opened.
- The old `h` ‖ height index kept only the last block stored at a height.

```json
→ {"method":"citrate_getBlocksAtHeight","params":["0x2"]}
← {"height":"0x2","blocks":[
    {"hash":"0x…a2","height":"0x2","selectedParent":"0x…a1","mergeParents":[],
     "blueScore":"0x2","blueWork":"0x14","timestamp":"0xf4242","transactionCount":3,
     "isSelectedChain":true,"hasGhostdagRecord":true},
    {"hash":"0x…b2", …, "isSelectedChain":false, …}]}
```

`height` can be a hex string or a JSON number.

## `citrate_getGhostdagData(hash)`

This method returns the persisted GHOSTDAG record of a block and the block's colour
relative to the applied chain. It returns `null` for a block the node does not store.

- **Data sources:**
  - `CF_DAG_GHOSTDAG[hash]`, the record the consensus engine wrote at admission (S3-1,
    G12), decoded and tag-checked;
  - `CF_HEADERS` for the committed header fields;
  - for the colour, the records of the applied-chain blocks above the block.
- **Pruned record:** `recordAvailable: false`, and every record field is `null`. The
  committed `header` fields are still returned.

```json
→ {"method":"citrate_getGhostdagData","params":["0x…b2"]}
← {"hash":"0x…b2","height":"0x2","recordAvailable":true,
   "selectedParent":"0x…a1","blueScore":"0x2","blueWork":"0x14",
   "mergesetBlues":["0x…a1"],"mergesetReds":[],"bluesAnticoneSizes":{"0x…a1":0},
   "mergeDepthRoot":"0x…a0",
   "header":{"selectedParent":"0x…a1","blueScore":"0x2","blueWork":"0x14"},
   "isSelectedChain":false,
   "color":"blue","mergingChainBlock":"0x…a3","blueAnticoneSize":1,"colorReason":null}
```

- `color` is `"blue"` or `"red"` once a chain block's mergeset holds the block. A chain
  block is always blue.
- `color` is `null` when the block is not merged yet, or is not merged within the
  search depth. `colorReason` says which.
- `blueAnticoneSize` is the block's entry in the merging chain block's
  `bluesAnticoneSizes`. It is `null` for a red block.

## `citrate_getSelectedChainChanges(fromHash, limit?)`

This method tells a client what changed on the applied chain since it last saw
`fromHash` as a chain block. Use it for reorg handling.

- **Data sources:** `CF_HEADERS` (the selected-parent walk), the canonical height index,
  and the applied tip.

```json
→ {"method":"citrate_getSelectedChainChanges","params":["0x…b3", 100]}
← {"removedChainBlockHashes":["0x…b3","0x…b2"],
   "commonAncestor":{"hash":"0x…a1","height":"0x1"},
   "addedChainBlocks":[{"hash":"0x…a2","height":"0x2"},{"hash":"0x…a3","height":"0x3"}],
   "addedChainBlockHashes":["0x…a2","0x…a3"],
   "more":false,
   "appliedTip":{"hash":"0x…a3","height":"0x3"}}
```

- `removedChainBlockHashes` runs from `fromHash` down, highest first. It is empty when
  `fromHash` is still on the chain.
- `addedChainBlocks` is in ascending order. `addedChainBlockHashes` lists the same
  blocks as bare hashes, in the same order (Kaspa's name; the explorer reads it). When `more` is `true`, call again from the
  last added hash.
- An unknown `fromHash` is error `-32602`. A `fromHash` more than 10,000 blocks off the
  chain is error `-32000`; resync from a chain block.

## `citrate_getAcceptingBlock(txHash)`

This method returns the chain block that executed a transaction (spec 06 §5.4).

- **Data sources:**
  - `CF_RECEIPTS[txHash]` for the block hash and number;
  - the canonical index, to check that the block is on the applied chain;
  - `CF_HEADERS` for the DAG height;
  - `CF_TRANSACTIONS` for `knownTransaction`.

```json
← {"transactionHash":"0x…","acceptingBlockHash":"0x…c2","acceptingHeight":"0x2",
   "inclusions":[{"blockHash":"0x…c2","dagHeight":"0x2","isSelectedChain":true,
                  "color":"selected_parent","outcome":"executed","status":"0x1"}],
   "inclusionsComplete":false,"knownTransaction":true,
   "semantics":"including-chain-block"}
```

**The semantics change at S3-3b (mergeset execution).**

- **On this base:** a chain block executes its own transactions, so the accepting block
  is the including block (`semantics: "including-chain-block"`). Only the receipt's block
  is listed (`inclusionsComplete: false`).
  - `color` and `outcome` use the spec 06 §5.4 words. An executed inclusion is a
    selected-chain block: `color: "selected_parent"`, `outcome: "executed"`.
  - A receipt whose block left the applied chain (a reorg) is `color: "unaccepted"`,
    `outcome: "pending"`: no chain block has executed the transaction.
- **After S3-3b:**
  - the next chain block executes a block's transactions, and `semantics` becomes
    `"accepting"`;
  - `inclusions` is read from the new `CF_TX_INCLUSIONS` index: every DAG block that
    carries the transaction, with `color` and `outcome` (`executed`, `skipped:*`,
    `pending`);
  - `inclusionsComplete` becomes `true`.
- **Explorer rule:** EVM pages use `acceptingBlockHash` and DAG pages use
  `inclusions[]`. Do not assume they are the same block.

## `citrate_getFinalityStatus`

This method reports checkpoint finality as this node holds it. It is never a
block-depth estimate (CV-8).

- **Data sources:**
  - the RPC's finalized-tag source: the verified pairs when enforcement is on, otherwise
    the height handle;
  - the highest `checkpoint:{height}` certificate in `CF_DAG_METADATA`;
  - the compiled pins (`CHECKPOINT_VOTING_PINS`, `CHECKPOINT_ENFORCEMENT_PINS`).

```json
← {"published":true,"voting":false,"mode":null,
   "quorumRule":"vote count: Checkpoint::effective_quorum of the committee (not stake-weighted on this base)",
   "chainId":"0x9d0c","votingPinned":false,"enforcementPinned":false,"enforcement":false,
   "finalizedSource":"height-handle",
   "finalized":{"height":"0x0","hash":"0x…genesis","blockHash":"0x…genesis"},
   "latestCertificate":{"height":"0x2","blockHash":"0x…","committeeSize":4,"voters":3,
     "quorum":3,"epoch":null,"stateRoot":null,"acceptedRoot":null,
     "votedStake":null,"totalStake":null,"quorumStake":null},
   "interval":"0x…","voteDepth":"0x3","pending":null,"halted":null,
   "pendingFinalityLane":["epoch","stateRoot","acceptedRoot","votedStake","totalStake",
                          "quorumStake","pending","halted"],
   "dataSource":"…"}
```

The fields listed in `pendingFinalityLane` are `null` on this base.

- **Keys shared with the finality lane and the explorer** (citrate-explorer#51,
  `src/lib/citrate/r1007.ts`, gates every finality figure on `published`):
  - `published` is `true`: this view is read from storage on every call, so one always
    exists;
  - `voting` is the compiled voting pin (`votingPinned`);
  - `mode` is `"enforced"` when verified certificates feed the finalized tag, and
    otherwise `null`, because this base cannot tell the lane's `legacy` from `observed`;
  - `quorumRule` names the count rule this base's certificates use;
  - `finalized.blockHash` repeats `finalized.hash` under the lane's name.

- **Where they come from:** branch `r1007/s3-finality-voting` (fbe06ac6, unreviewed)
  adds the v2 vote message (epoch, state root, accepted root), the stake-weighted
  quorum, and a `FinalityStatusCell` that the node's finality driver publishes, with
  pending checkpoints and the halt flag.
- **That branch registers its own `citrate_getFinalityStatus`** (with a `published` flag
  and stake fields).
- **When both land:** the finality lane's handler should replace this one. Its field
  names match the ones here (`finalized.height`, `blockHash`, `committeeSize`,
  `voters`), so explorer code written against this shape keeps working.

## `citrate_getDagStats` (fixed, chain#317)

- **`totalBlocks`:** the number of blocks in this node's chain store, from a maintained
  counter (`CF_METADATA` `block_count_v1`). The counter changes in the same batch as
  every block write, delete or purge, and is rebuilt once on open for old data dirs.
- **`blueBlocks` and `redBlocks` are removed.**
  - A store-wide blue/red tally is not a GHOSTDAG quantity, because colour is relative
    to the selected chain and changes on a reorg. The node keeps no red count.
  - Use `citrate_getGhostdagData` for per-block colour.
- **`selectedTip`** (new): the applied tip with `blueScore` and `blueWork` from its
  persisted record. `blueScore` is the number of blue blocks in the tip's past.
- **Do not compute red as `totalBlocks − blueScore`:** the two count different sets.

```json
← {"totalBlocks":7,"selectedTip":{"hash":"0x…a3","height":3,"blueScore":4,"blueWork":"0x28"},
   "tipsCount":2,"maxBlueScore":3,"currentTips":["0x…"],"height":3,"ghostdagParams":null}
```

## `eth_getBlockReceipts(block)`

This method returns every receipt of a block on the applied chain in one call.

- **Accepted block parameters:**
  - a number;
  - `latest`, `pending`, `earliest`, `finalized` or `safe`;
  - a 32-byte hash;
  - an EIP-1898 object.
- **Returns `null`** for a block that is not on the applied chain, or above the head.
- **Data source:** `CF_RECEIPTS[txHash]` for each transaction in the stored body. A
  missing receipt is an error, never a shorter list.
- **Fields that differ from `eth_getTransactionReceipt` today:**
  - `cumulativeGasUsed` is the running sum within the block;
  - `logIndex` runs across the block;
  - `logsBloom` is computed from the logs (2048-bit, keccak).

```json
→ {"method":"eth_getBlockReceipts","params":["0x2"]}
← [{"transactionHash":"0x…21","transactionIndex":"0x0","blockHash":"0x…","blockNumber":"0x2",
    "from":"0x…","to":"0x…","cumulativeGasUsed":"0x5208","gasUsed":"0x5208",
    "contractAddress":null,"logs":[],"logsBloom":"0x00…","status":"0x1","type":"0x0",
    "effectiveGasPrice":"0x3b9aca00"},
   {"transactionHash":"0x…22","transactionIndex":"0x1", "cumulativeGasUsed":"0x…(sum)", …}]
```

After S3-3b, the receipt of a transaction included in block n appears under the
accepting block (usually n+1), with that block's numbering (spec 06 §3.11).

## Historical state: balance, nonce, code, storage and `eth_call` at a block

`eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` and
`eth_call` accept a block number, a hash or an EIP-1898 object. A tag that names a
block of the applied chain below the head is now served from that block's state. This
supersedes the strict refusal of chain#425 (`fix/rpc-historical-tag-fail-closed`, which
is already in the base) wherever the state can be rebuilt.

- **Data source:** the per-block undo records (`CF_METADATA` `reorg_undo:` ‖ height). The
  node keeps them for the undo window: 10,000 heights, CV-7a (undo window =
  retention).
- **Point reads** (balance, nonce, code, slot): the value is the pre-image in the lowest
  record above the block that touched the key, or else the flat store. No state root is
  computed.
- **`eth_call`:**
  - every pre-image in the range is applied to the executor's state at the applied tip;
  - the result **must reproduce the state root committed in the block's header**, or
    the call is refused;
  - the call runs on a throwaway executor, in the block's context (its number and
    timestamp).
- **Every record is checked:** it must name the block the walk is on and that block's
  parent.
- **Fail closed:** the read is refused with code `-32000` and the message prefix
  `historical state not available on this node`, with the reason, in these cases:
  - the block is below the window;
  - a record is missing;
  - the block is off the applied chain;
  - the root does not match;
  - the head moved during the read (retry).
- **Unchanged:**
  - `eth_estimateGas` is head-only;
  - `finalized` and `safe` keep the finality guard;
  - the operator window `[rpc] serve_recent_state_tags` still applies to tags that
    cannot be rebuilt.

```json
→ {"method":"eth_getBalance","params":["0x…bb","0x2"]}            ← "0x5"
→ {"method":"eth_call","params":[{"to":"0x…","data":"0x…"},{"blockHash":"0x…"}]}
← {"error":{"code":-32000,"message":"historical state not available on this node: no undo record at height 2: …"}}
```

## `debug_traceTransaction(txHash, {tracer, tracerConfig})`

This method returns geth's `callTracer` or `prestateTracer` (non-diff) output.

- **How a transaction is traced:**
  1. The receipt names the executing block, and that block must be on the applied
     chain.
  2. The parent's state is rebuilt and checked against the parent's state root.
  3. A throwaway executor re-executes the block's transactions in order, with the
     block's EVM context and an observe-only REVM inspector attached.
  4. Every replayed receipt must match the stored one (status and gas used), or the
     trace is refused.
- **`tracerConfig`:**
  - `onlyTopCall` and `withLog` are supported for `callTracer`;
  - `diffMode` is not served.
- **Other tracers,** including the struct logger, are error `-32602`.

```json
→ {"method":"debug_traceTransaction","params":["0x…22",{"tracer":"callTracer"}]}
← {"type":"CALL","from":"0x…aa","to":"0x…factory","value":"0x0","gas":"0xf4240",
   "gasUsed":"0x…","input":"0x01","output":"0x",
   "calls":[{"type":"CREATE","from":"0x…factory","to":"0x…child","value":"0x0",
             "gas":"0x…","gasUsed":"0x…","input":"0x6001600c…","output":"0x00"}]}

→ {"method":"debug_traceTransaction","params":["0x…22",{"tracer":"prestateTracer"}]}
← {"0x…aa":{"balance":"0x…","nonce":2},
   "0x…factory":{"balance":"0x0","code":"0x36602014…","storage":{"0x00…00":"0x00…00"}}, …}
```

- **Top frame:** `gas` is the transaction's gas limit, and `gasUsed` is what the chain
  charged (the receipt).
- **No EVM:** a native transfer or a Citrate AI operation, which REVM never runs, is one
  frame built from the transaction and its receipt.
- **`prestateTracer` accounts:** every account a frame or an account-reading opcode
  named, plus the sender, the recipient and the coinbase, as they were before the
  transaction. Slots are the ones read or written by SLOAD and SSTORE.

## `debug_traceCall(callObject, blockTag, {tracer, tracerConfig})`

This method runs the same simulation as `eth_call`, traced. The simulation runs on the
head, or on a verified historical state when the tag names a past block. `to` may be
omitted, which simulates a create.

## `ots_getContractCreator(address)`

This method returns the transaction that created the code an address holds at the head,
and the account that created it: an EOA for a top-level deploy, or the factory for an
internal CREATE or CREATE2.

- **Data sources:**
  - the flat store, to check whether the address has code;
  - the undo records: the highest block whose record shows the account without code
    before it;
  - a traced replay of that block, to find which transaction and which creator.

```json
← {"hash":"0x…22","creator":"0x…factory","blockHash":"0x…","blockNumber":"0x2"}
```

- An address without code returns `null`.
- A genesis allocation returns `{"hash":null,"creator":null,"genesis":true}`.
- A creation older than the undo window is refused (`-32000`). An explorer that needs
  older creators must index them from `callTracer` output as blocks arrive.

## `net_peerInfo` (extended, core#605)

This method returns every peer the node holds, with the head the node's sync scoring
reads for it. 0.5.3's sync-truth check uses it. `net_peerInfo` is a Citrate method, not
an Ethereum one, so it is extended in place. The fields it already returned (`id`,
`addr`, `direction`) are unchanged.

- **Data source:** `PeerManager::get_all_peers()` → `PeerInfo`.
  - `headHeight` and `headHash` are `PeerInfo.head_height` and `head_hash`.
  - They are seeded from the peer's Hello/HelloAck at the handshake.
  - Every gossiped block from that peer raises them.
  - These are the values the 2 s sync tick selects on (`node/src/sync_peer.rs`).
- **Advertised, not proven held:** see `sync_peer.rs` invariant I4. That is why
  `headSource` is `"advertised"`.
- **Before the handshake completes** (`connecting`, `handshaking`), no head is known and
  both fields are `null`, not 0.
- **Blue score** (`headBlueScore`): the GHOSTDAG blue score of the same head block,
  `PeerInfo.head_blue_score`.
  - Hello/HelloAck carry no blue score, so it is `null` (and `headBlueScoreSource` is
    `null`) until a gossiped block from the peer raises the head. Then
    `headBlueScoreSource` is `"gossip"`.
  - Height, hash and blue score move together (`PeerInfo::observe_gossiped_head`), so
    they always describe one block.

### Units (CV-3: one blue score)

| Field | Unit | Same unit as |
|---|---|---|
| `headHeight` (`heightUnit: "header.height"`) | block height, `header.height` | `eth_blockNumber`, `citrate_nodeIdentity.syncState.appliedHeight` and `highestSeen` |
| `headBlueScore` (`blueScoreUnit: "ghostdag.blue_score"`) | GHOSTDAG blue score, `header.blue_score` (header-committed, validated at admission, CV-3) | `syncState.appliedBlueScore`, `citrate_getGhostdagData.blueScore` |

Compare a peer's `headHeight` with this node's `appliedHeight`, and a peer's
`headBlueScore` with `appliedBlueScore`. Never compare across the two units: with merge
parents the blue score runs ahead of the height.

`syncState.appliedBlueScore` is the applied tip's `header.blue_score` (`CF_HEADERS`), or
`null` when no tip or header is stored.

```json
→ {"method":"net_peerInfo","params":[]}
← [{"id":"12D3…","addr":"10.0.0.1:30303","direction":"outbound","state":"connected",
    "headHeight":"0x4d2","headHash":"0xabab…","headSource":"advertised",
    "heightUnit":"header.height","headBlueScore":"0x4d9","headBlueScoreSource":"gossip",
    "blueScoreUnit":"ghostdag.blue_score",
    "lastSeenSecsAgo":2,"connectedSecs":3600,"score":0}]
```

## Not served here (follow-ups)

- `trace_block`, `trace_filter` and the rest of the Otterscan `ots_*` set. The explorer
  can index internal transactions block by block with `debug_traceTransaction`, or
  with a `trace_block` built on `trace_rpc::replay_block`.
- `eth_getProof` at a block.
- `citrate_getDagBlock` (spec 06 §5.5).
