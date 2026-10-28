---
title: "RPC state reads and block tags: strict by default, operator window for deploy nodes"
created: 2026-10-28T01:10:00Z
branch: fix/rpc-historical-tag-fail-closed
author: Larry Klosowski + Claude Opus 5.5 (DGX lane)
status: active with chain#425 (PR #428). The window is an operator opt-out; whether to offer it is pending owner confirmation.
---

# RPC state reads and block tags

A Citrate node keeps one account state: the post-state of its **executed head** (the applied tip,
`citrate_executedHead`). It has no state at older heights.

Six methods read that state: `eth_call`, `eth_estimateGas`, `eth_getBalance`, `eth_getCode`,
`eth_getStorageAt` and `eth_getTransactionCount`.

## Default: strict

The block tag decides whether the read is served:

| Tag | Result |
|---|---|
| none, `latest`, `pending` | Served from the executed head's state. |
| `finalized`, `safe` (string or `{"blockNumber": …}`) | Served only when the finalized block is the executed head. Otherwise refused. |
| A number, `earliest`, a 32-byte hash, or `{"blockNumber"}` / `{"blockHash"}` | Served only when it names the executed head. |
| Any other block | Refused (see the error below). |
| Malformed tag | `-32602` invalid params. |

A refused read gets this error. The `data` field names the executed head:

```
-32000 "historical state not available on this node: …"
```

The public RPC runs strict.

## Why deploy nodes need a window: Foundry fork mode

`forge script --rpc-url …` and `anvil --fork-url …` read `eth_getBlockByNumber("latest")` once.
After that they pin every balance, nonce, code and storage read to that block's hash, either as a
bare hash or as `{"blockHash": …, "requireCanonical": false}`. A strict node refuses those reads
as soon as one more block executes, which is about 2 s. The script then aborts with
`historical state not available on this node`.

This affects our own deploy paths:
- `contracts/script/Deploy*.s.sol` through `forge script --broadcast`; the simulation runs in a pinned fork;
- `scripts/ops/regenesis.sh`;
- `scripts/ops/hup-redeploy-dryrun.sh` (`anvil --fork-url`).

## Operator window: `[rpc] serve_recent_state_tags`

```toml
[rpc]
# 0 (default) = strict. Deploy node only; never on a public RPC.
serve_recent_state_tags = 64
```

With N > 0, the node also answers the following from the executed head's state:
- a block number at most N below the head;
- a hash on the head's selected-parent chain at most N below the head;
- a stored block at most N above the head whose selected-parent chain reaches the head. This happens while the head catches up, because `latest` names the highest stored block.

These are still refused:
- anything further back;
- a sibling, or any block off the head's chain;
- an unknown hash;
- a height above the head that is not stored;
- `finalized` and `safe`.

N is clamped to 1024. The check walks at most N headers per request.

**The answer is the head's state, not the named block's state.** JSON-RPC has no response field
for a warning, so the node does two things instead. At start it logs a warning that the window is
on. For each read served under the window it logs a debug line:
`state read pinned to … served from the executed head …`.

Use the window only where that trade is acceptable, which is a deploy script's simulation. Never
use it for indexing, accounting or audits.

## Deploy path

1. Run `forge script`, `regenesis.sh` and `hup-redeploy-dryrun.sh` against an **operator node**
   that has `serve_recent_state_tags` set (64 is enough for a script of a few minutes at 2 s blocks).
   Bind it to loopback or a private network.
2. Keep public endpoints (rpc.citrate.ai and the bootnodes) strict.
3. A script that runs longer than N blocks still fails closed. Raise N on the operator node, or
   split the script.

## Evidence

- `core/api/tests/state_tag_fail_closed.rs`: the strict default, including the wrapped `finalized`/`safe` form.
- `core/api/tests/state_tag_recent_window.rs`:
  - the window rules;
  - a replay of the `forge script` request sequence, served with N = 64 and refused when strict.
- `core/api/tests/forge_fork_smoke.rs` (ignored by default): a real `forge script` against the
  crate's RPC server on loopback while the head advances. It fails when strict and completes with
  N = 64. Run it with:

  ```
  FORGE_BIN=~/.foundry/bin/forge SOLC_BIN=~/.svm/0.8.26/solc-0.8.26 \
    cargo test -p citrate-api --test forge_fork_smoke -- --ignored
  ```
