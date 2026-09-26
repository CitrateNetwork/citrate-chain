---
title: "R2 block-validity hardening: activation runbook for chain 40204"
created: 2026-09-25
branch: fix/pba-r2-chain-consensus
author: Larry Klosowski + Claude Opus 5.5
status: READY. Rules ship OFF on 40204; the owner schedules the height.
chain: 40204
---

# R2 block-validity hardening: activation runbook

The R2 hardening adds three block-validity rules. They switch on together, at one activation height:

| Rule | Enforced from the activation height |
|---|---|
| Transaction authentication on import | Every transaction in an imported block must authenticate from its own contents, carry its canonical id as `hash`, and match this chain id (`tx_auth::verify_for_block`). |
| Content-bound transaction root | `tx_root` must be `tx_auth::tx_root_v2`, a commitment to every consensus field of every transaction. |
| Timestamp bound | `timestamp <= selected_parent.timestamp + 3600` (`MAX_BLOCK_TIMESTAMP_ADVANCE_SECS`). |

The rest of the R2 hardening is active in every binary and doesn't change which blocks are valid.

## How the height is set

- Release pin: `PINNED_ACTIVATIONS` in `core/consensus/src/hardening.rs`, one entry per chain id. When the running chain has a pinned height, that is the height. An env or config value that disagrees (including `off`) stops the node at start-up with an error naming both values.
- Config: `[chain] pba_hardening_height = <height>` (`node/src/config.rs`).
- Env override: `CITRATE_PBA_HARDENING_HEIGHT=<height>` or `off`. An unparseable value aborts start-up.
- With no pin for the chain, the env override wins over the config value. Unset, which is the default on every shipped 40204 profile, means the rules are OFF.
- Dev profiles (`devnet.toml`, `devnet-config.toml`, the Docker devnet, `citrate devnet`) run on their own chain id, 1337, with the devnet genesis, and set `0`, so the rules are active from genesis. Genesis is never re-judged. `[chain] dev_profile = true` is refused on any chain listed in `PINNED_ACTIVATIONS` (40204 today), pinned or not.
- A release network's genesis only runs under that network's chain id (`RELEASE_GENESIS` in `hardening.rs`: the testnet-beta, team-testnet and mainnet geneses for 40204). A data directory holding one of them under another chain id refuses to start.
- The pin is keyed on the configured `[chain] chain_id`. If `CITRATE_CHAIN_ID` is set it must equal it, or the node refuses to start.
- The start-up log prints the resolved height and its source, for example `chain 40204 pba_hardening_height H (source: release pin)`, and a `Consensus fingerprint ... with activation ... = 0x...` line. Nodes that agree print the same final fingerprint. `citrate consensus` lists the compiled-in pins.

This is a consensus parameter. Two nodes with different values disagree about block validity, and the chain forks.

## Owner steps

1. **Ship the binary everywhere first**, with the height unset: producers, bootnodes, RPC nodes and the citrate-core bundled node. Confirm `citrate consensus --json` prints the same `fingerprint` everywhere.
2. **Pick `H = current_tip + margin`**, with enough margin for the slowest client release channel to upgrade. Chain 40204 produces a block every 2.0 s (measured), so 43,200 blocks is about one day and 302,400 blocks is about one week.
3. **Pin it in the release**: in the release PR, set the 40204 entry of `PINNED_ACTIVATIONS` in `core/consensus/src/hardening.rs` to `Some(H)`. Every node on that release then runs `H` without per-host settings. Remove any `pba_hardening_height` / `CITRATE_PBA_HARDENING_HEIGHT` values that differ from `H` (they now stop the node). Confirm each node logs `ACTIVE from height H [... source: release pin]` and the same activation fingerprint before the tip reaches `H`.
4. **Pre-`H` checks**:
   - Nothing on 40204 relies on `eth_sendTransaction`: `allow_eth_send_transaction = false`.
   - No node runs with `CITRATE_REQUIRE_VALID_SIGNATURE=0`.
5. **At `H`**, watch the logs for `InvalidBlockBody` or timestamp-bound rejections. Followers must track the producers.
6. **Validator registry**: configure `CITRATE_VALIDATOR_REGISTRY` on every 40204 node, together with its activation height, so proposers are registered validators.

**Rollback before `H`:** unset the height (or set `off`) on every node and restart.

**After `H`:** don't unset it. A node without the setting forks off. Don't downgrade a node past `H` either; if one was run on an older release after `H`, move its data directory aside before starting the new release again, so it resyncs from peers.

## Nodes that upgrade late

A node that is still on an older release at `H` keeps producing and accepting blocks in the pre-activation format on its own branch. When it restarts on a release with the pin:

- Before loading any stored block it checks the stored blocks at or above `H` that it has not checked before against the rules. Blocks a node stores while running with the rules are marked as checked as it runs, so later restarts only check what was stored since. It removes each invalid block and everything built on it from the block store, the DAG store and the transaction index, and logs how many it removed.
- If its applied state was built on those blocks, the start-up recovery rebuilds state from genesis along the remaining chain, then the node syncs the canonical chain from upgraded peers. No data-directory wipe is needed. The rebuild replays the chain from genesis up to the last valid block. Measured with `hardening_rejoin::tests::rebuild_time` (debug build, MacBook, blocks without transactions): 150,000 blocks rebuilt in 87 s (about 1,700 blocks/s); the full start-up adds loading those blocks into the DAG store. Blocks with transactions take longer in proportion to their execution. The replay needs the block bodies back to genesis (leave `CITRATE_DAG_PRUNE_RETAIN` unset).
- Transactions carried by the removed blocks are offered to the mempool again once the state is rebuilt.
- If the node stops after removing the blocks but before the rebuild finishes, the next start rebuilds as usual; the transactions from the removed blocks are then not offered again, so their senders resubmit them.
- A node running with `CITRATE_BLOCK_V2=0` cannot rebuild state by itself. It stops with instructions: move the data directory aside and restart to resync from peers.

Upgraded nodes count, per peer, blocks received in the pre-activation format at or after `H` that carry a valid block hash and proposer signature: metric `citrate_legacy_format_blocks_total{peer="..."}` (the first 4096 peers by id, the rest under `peer="other"`) and gauge `citrate_legacy_format_peers`, plus an info log line per peer. Use them to find nodes that have not upgraded.

## Before `H`

Below the activation height the legacy validity rules apply unchanged. The always-on hardening is in effect regardless. Schedule `H` before the bug bounty opens.
