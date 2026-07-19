---
title: "Fresh-node forward-sync wedges at height 7 (Missing parent at admission) — blocks node onboarding on 40204"
created: 2026-07-19
branch: main
author: Claude (Opus 4.8) for SaulBuilds (@SaulBuilds)
status: open
priority: P0
component: node / core/network sync / consensus (GHOSTDAG admission)
audience: citrate-chain node + consensus engineers
repro_commit: eb26e8f  # origin/main, Merge PR #83 (fix/ghostdag-select-tip-determinism)
live_chain: chainId 40204, rpc.citrate.ai, genesis 0x481a59bc..., head ~73,400
---

# Fresh-node forward-sync wedges at height 7

## TL;DR
A **freshly-built node from `main@eb26e8f`** joins the live 40204 testnet correctly at the
network layer — it computes the **correct genesis** (`0x481a59bc`, matches live), completes Noise
handshakes, and holds **4 peers** (boot1/2/3 + sequencer) — but it **imports only blocks 0–7, logs
`Synchronization complete at height 7`, and then stops requesting blocks.** From that point it
merely *receives* gossiped head blocks and rejects every one with
`Rejected inconsistent block … Missing parent at admission: <hash>`. It never back-fills the
`8 → head (~73,400)` gap, so it stays wedged at height 7 indefinitely.

This blocks the entire citrate-core node-onboarding story (a user installs the desktop app, runs a
node, and it must sync to head and validate). Peering and genesis are NOT the problem — this is a
**forward-sync / gap-drain bug** in the fresh-join path.

## Why this matters
citrate-core bundles this node binary as a Tauri sidecar. The product promise is: install → run a
node → it auto-connects to 40204 and syncs to head → becomes validator-eligible. Today a fresh
node can peer but can never reach head, so no onboarded node can join the validating set.

---

## Environment
- **Node build:** `citrate-chain` `main` @ `eb26e8f` (Merge PR #83 from
  `fix/ghostdag-select-tip-determinism`). `cargo build --release -p citrate-node --bin citrate`.
- **Host:** macOS 15 (Darwin 24.6), arm64 (`aarch64-apple-darwin`).
- **Live chain:** chainId 40204, RPC `https://rpc.citrate.ai`, genesis
  `0x481a59bc8826c91cd05d897fafff1bce4c394e41093f5e1c10e308e6c7d748fb`, head ~73,400 and advancing
  ~1 block / 3 s. `web3_clientVersion` = `citrate/v0.1.0`.
- **Boot config used:** default `--network testnet` → `testnet-beta.toml` (bootnodes boot1/2/3 +
  sequencer `noise_6ee5497…@rpc.citrate.ai:30303`). Genesis profile resolves to `testnet_beta`
  (11 accounts, incl. the 4 pre-funded validator stakers) → matches live.

## Exact reproduction
```bash
cd citrate-chain
git checkout eb26e8f
cargo build --release -p citrate-node --bin citrate

DD=$(mktemp -d)
./target/release/citrate --network testnet --data-dir "$DD" \
  --rpc-addr 127.0.0.1:18552 --p2p-addr 0.0.0.0:30403

# In another shell:
curl -s -X POST 127.0.0.1:18552 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}'
#   → genesis hash 0x481a59bc...  (MATCHES live ✓)

curl -s -X POST 127.0.0.1:18552 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}'
#   → 0x4  (4 peers ✓)

# poll every 10s:
curl -s -X POST 127.0.0.1:18552 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
#   → 0x7 and STAYS 0x7 for 150s+ while live head climbs 73254 → 73416 (✗ wedged)
```

## Observed behavior (node log, verbatim excerpts)
Initial sync does a small window, then declares complete at height 7:
```
citrate_network::sync: Downloaded 64 headers (height 0-63), progress: 100.0%
citrate_network::sync: Starting block download from height 7 to 0
citrate_network::sync: SYNC_REJECT: block height=0 hash mismatch (tampered commitment roots)
citrate_network::sync: Sync validation: 1/8 blocks rejected
citrate_network::sync: Validated and imported 7/8 blocks (height 0-7), progress: 100.0%
citrate_network::sync: Synchronization complete at height 7
```
Then, indefinitely, it only rejects gossiped head blocks (note the chain of hashes — these are
consecutive NEW blocks at the network tip, each rejected because the node lacks its parent):
```
citrate: Rejected inconsistent block a8df5f65… : Missing parent at admission: 47d9c169
citrate: Rejected inconsistent block e81c6d5c… : Missing parent at admission: a8df5f65
citrate: Rejected inconsistent block ad7ca7db… : Missing parent at admission: e81c6d5c
citrate: Rejected inconsistent block 6841f10b… : Missing parent at admission: 362f2f22
…  (297 such rejections over 150 s, one per newly-gossiped tip block, from all 3 boot peers)
```
Rejection tally over the run: **297× "Missing parent at admission"**, **3× "tampered commitment
roots"** (the latter on the initial 0–7 window).

## Expected vs actual
- **Expected:** a fresh node discovers the peers' advertised head (~73,400) and drains the
  `8 → head` range (header + block download in batches), applying via execute-on-receive until it
  reaches head; thereafter live gossip extends the tip normally.
- **Actual:** the sync loop terminates at height 7 (`Synchronization complete at height 7`) and
  never issues another range request. Gossiped tip blocks arrive with parents the node doesn't
  have, and admission rejects them with no "missing parent → request ancestors/range" fallback.

## Analysis / suspected areas
Two things appear wrong, both in the fresh-join / forward-drain path (adjacent to the recently
merged sync work on `fix/ghostdag-select-tip-determinism`: *"advertise a LIVE head refreshed from
the applied tip"*, *"anchor block sync on the applied tip"*, *"forward drain"*):

1. **Premature sync completion.** `citrate_network::sync` declares
   `Synchronization complete at height 7` after the first small window instead of continuing to the
   peers' advertised head. The completion/termination condition seems to compare against the
   locally-applied tip (7) rather than the remote advertised head (~73,400), so the drain never
   continues. (The log line `Starting block download from height 7 to 0` — downloading *downward* —
   also looks suspect for a forward drain.)

2. **No missing-parent → range-request fallback in admission.** When a gossiped block is admitted
   with an unknown parent, the node logs `Missing parent at admission` and drops it, rather than
   enqueuing a request for the missing ancestor range. For a GHOSTDAG node joining with a large gap,
   gossip alone can never fill the middle; admission needs to trigger a back-fill (or the forward
   drain in (1) needs to be running so the gap closes on its own).

3. **Secondary:** the `1/8 blocks rejected … tampered commitment roots` on block `height=0` during
   the initial window — the node rejects the *peer's* genesis representation while keeping its own.
   Worth confirming this is benign (duplicate-genesis dedup) and not corrupting the window that then
   caps the node at 7.

## What "resolved" looks like (acceptance criteria)
- A fresh node built from current `main`, started with `--network testnet` against live 40204,
  **advances `eth_blockNumber` from 0 to within a few blocks of head (~73k+) unattended**, and then
  tracks the tip via gossip.
- No sustained `Missing parent at admission` rejection loop; if gossip outruns the applied tip, the
  node issues range/ancestor requests to close the gap.
- Add/keep a regression test: a node with only genesis + boot peers reaches head in a bounded time
  (the `multinode fleet harness` / two-node divergence harness is the natural home).

## Cross-references
- Full session diagnosis + the RESOLVED node-source-pin/genesis half:
  `citrate-labs/handoffs/CITRATE_CORE_NODE_SYNC_WO1_2026-07-19.md`.
- Beta plan gate BC-1.1: `citrate-federation/.agentile/planset/2026-07-19-core-beta-completion/`.

## Note on the RESOLVED half (context, no action needed)
Before this wedge was reachable, the bundled citrate-core node built from `ee1f9c1` produced the
wrong genesis (`0x6b6d8b89`, the 7-account `testnet_beta`) and got `Transport error: eof` from all
boot peers (0 peers). That was a stale node-source pin: the live chain was deployed from
`fix/ghostdag-select-tip-determinism` (11-account `testnet_beta`, genesis `0x481a59bc`). Merging
that branch to `main` (PR #83, `eb26e8f`) fixed genesis + peering — hence this report is now able to
observe the *next* failure (the forward-sync wedge above). citrate-core will pin its bundled
node-source to `eb26e8f`+.
