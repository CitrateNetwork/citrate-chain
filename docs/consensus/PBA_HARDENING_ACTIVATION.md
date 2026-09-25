---
title: "PBA-R2 block-validity hardening: activation runbook for chain 40204"
created: 2026-09-25
branch: fix/pba-r2-chain-consensus
author: Larry Klosowski + Claude Opus 5.5
status: READY. Rules ship OFF on 40204; the owner schedules the height.
chain: 40204
---

# PBA-R2 block-validity hardening: activation runbook

The pre-bounty audit (2026-09-24) found three consensus holes that only a change to block validity closes. The R2 remediation ships all three behind one activation height:

| Finding | Rule enforced from the activation height |
|---|---|
| PBA-L1b-001 (CRITICAL) | Every transaction in an imported block must authenticate from its contents. Nodes never trust the `ecdsa_verified` wire flag. The tx must carry its canonical id as `hash` and be bound to this chain id (`tx_auth::verify_for_block`). |
| PBA-L1b-002 (CRITICAL) | `tx_root` must be `tx_auth::tx_root_v2`, which commits to every consensus field of every transaction, not to the peer-supplied `tx.hash`. |
| PBA-L1b-003 (CRITICAL) | `timestamp <= selected_parent.timestamp + 3600` (`MAX_BLOCK_TIMESTAMP_ADVANCE_SECS`). |

Everything else in R2 is active in every binary and doesn't change which blocks are valid:

- mempool nonce bounds
- the producer panic guard
- `clamp(now, parent.ts, parent.ts + 3600)` timestamp stamping
- the sync wall-clock bound
- canonical tx ids at ingress
- P2P AI-message bounds
- the inference dispatcher
- the handshake height clamp
- P2P typed-transaction verification

## How the height is set

- Config: `[chain] pba_hardening_height = <height>` (`node/src/config.rs`).
- Env override: `CITRATE_PBA_HARDENING_HEIGHT=<height>` or `off`. An unparseable value aborts start-up.
- Unset, which is the default for every shipped 40204 profile, means the rules are OFF. Blocks are judged by the legacy rules.
- Dev profiles (`NodeConfig::devnet()`, `node/config/devnet.toml`, `devnet-config.toml`) set `0`, so the rules are active from genesis. Genesis (height 0) is never re-judged.
- The start-up log says which applies: `PBA-R2 block-validity hardening ACTIVE from height N` or `... not scheduled`.

This is a consensus parameter. Two nodes on 40204 with different values disagree about block validity, which forks the chain. Treat it like `CITRATE_VALIDATOR_ACTIVATION_HEIGHT`.

## Owner steps (OWNER: needs fleet access; an agent cannot do this)

1. **Ship the binary everywhere first**, with the height still unset. Upgrade every block producer (DO fleet / bootnodes), every RPC node and the citrate-core bundled node. Confirm the fleet is aligned: `citrate consensus --json` must show the same `fingerprint` on each binary.
2. **Pick the height** `H = current_tip + margin`. Choose the margin so that every node, including citrate-core installs that update slowly, is upgraded well before `H`. With 1 s blocks, 86,400 blocks is about one day. Pick a margin that covers the slowest client release channel.
3. **Set the height fleet-wide**: `pba_hardening_height = H` in every 40204 config (`testnet*.toml`, `testnet-boot-*.toml`, `testnet-validator.toml`, `mainnet.toml`, `team-testnet.toml`), or `CITRATE_PBA_HARDENING_HEIGHT=H` in every systemd unit and in the citrate-core node spawn (`citrate-core/src-tauri/src/node.rs`). Restart. Every node must log `ACTIVE from height H` before the tip reaches `H`.
4. **Before `H`, confirm producer readiness:**
   - Transactions submitted with `eth_sendTransaction`, the devnet-only unsigned path, won't be included from `H` on. Make sure nothing on 40204 depends on it (`allow_eth_send_transaction` should be false on 40204; see PBA-L1a-012).
   - Nodes running with `CITRATE_REQUIRE_VALID_SIGNATURE=0` (PBA-L1a-007, CHAIN-EXEC lane) no longer produce invalid blocks from `H` on. The producer filters with the same rule followers use. Remove that override anyway.
5. **At `H`, watch** the first blocks at and after `H`:
   - no `InvalidBlockBody`, `tx_root ... does not commit`, or `PBA-L1b-003` rejections in the logs;
   - followers' applied tips track the producers;
   - `eth_getBlockByNumber(H).transactionsRoot` differs from the legacy root. This is expected: it is `tx_root_v2`.
6. **Stake-gated producer admission (PBA-L1b-001, second item).** Set `CITRATE_VALIDATOR_REGISTRY` on every 40204 node so only registered validators produce admissible blocks. This is independent of `H`, but without it anyone can propose. After `H`, a proposer can no longer forge senders, but it can still propose.

**Rollback before `H`:** unset the height (or set `CITRATE_PBA_HARDENING_HEIGHT=off`) on every node and restart. Nothing changes on chain.

**After `H`:** don't unset it. Blocks at or above `H` are only valid under the new rules. A node without the setting accepts blocks the rest of the fleet rejects, and it will fork off.

## Residual risk until `H`

Below the activation height the legacy validity rules stand:

- a proposer can include a forged-sender transaction (PBA-L1b-001);
- a relaying peer can rewrite a block body (PBA-L1b-002);
- a proposer can future-date a block (PBA-L1b-003).

The always-on parts of R2 reduce these while the rules are off:

- The producer stamps `max(now, parent.ts)`, so a future-dated tip no longer halts production.
- Sync, like gossip, rejects blocks more than 900 s in the future.
- Gossip and the mempool authenticate transactions from their contents.

The theft and wedge vectors remain open until `H`. Schedule `H` before the bug bounty opens.
