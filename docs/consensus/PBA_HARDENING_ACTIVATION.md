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

- Config: `[chain] pba_hardening_height = <height>` (`node/src/config.rs`).
- Env override: `CITRATE_PBA_HARDENING_HEIGHT=<height>` or `off`. An unparseable value aborts start-up.
- Unset, which is the default on every shipped 40204 profile, means the rules are OFF.
- Dev profiles set `0`, so the rules are active from genesis. Genesis is never re-judged.
- The start-up log states which applies.

This is a consensus parameter. Two nodes with different values disagree about block validity, and the chain forks.

## Owner steps

1. **Ship the binary everywhere first**, with the height unset: producers, bootnodes, RPC nodes and the citrate-core bundled node. Confirm `citrate consensus --json` prints the same `fingerprint` everywhere.
2. **Pick `H = current_tip + margin`**, with enough margin for the slowest client release channel to upgrade.
3. **Set it fleet-wide**: `pba_hardening_height = H` in every 40204 config, or `CITRATE_PBA_HARDENING_HEIGHT=H` in every systemd unit and in the citrate-core node spawn. Restart, and confirm each node logs `ACTIVE from height H` before the tip reaches `H`.
4. **Pre-`H` checks**:
   - Nothing on 40204 relies on `eth_sendTransaction`: `allow_eth_send_transaction = false`.
   - No node runs with `CITRATE_REQUIRE_VALID_SIGNATURE=0`.
5. **At `H`**, watch the logs for `InvalidBlockBody` or timestamp-bound rejections. Followers must track the producers.
6. **Validator registry**: configure `CITRATE_VALIDATOR_REGISTRY` on every 40204 node, together with its activation height, so proposers are registered validators.

**Rollback before `H`:** unset the height (or set `off`) on every node and restart.

**After `H`:** don't unset it. A node without the setting forks off.

## Before `H`

Below the activation height the legacy validity rules apply unchanged. The always-on hardening is in effect regardless. Schedule `H` before the bug bounty opens.
