---
title: "Reroll addendum — v2 headers (execute-on-receive) + VALIDATOR-S1 activation"
created: 2026-07-16
branch: feat/validator-registry-ed25519
author: Claude Opus 4.8 (consensus, for @SaulBuilds)
status: ADDENDUM — apply during the next clean reroll
chain: 40204
---

# Reroll addendum: activate v2 headers + VALIDATOR-S1

Two consensus features are **feature-flagged OFF by default** and are meant to activate
**at the reroll** (genesis binary + genesis-seeded state). This addendum is the activation
checklist. Link it from `scripts/ceremony/I64S1_REROLL_RUNBOOK.md`.

## A. Version-2 block headers — commit the coinbase (execute-on-receive)

**Why.** Received blocks' `state_root` is only reproducible if the block commits its
beneficiary. v2 headers add `coinbase` to `compute_hash` (see
`docs/consensus/EXECUTE_ON_RECEIVE_state_application.md`). v1 headers are unchanged, so
this MUST flip at a fresh genesis — never mid-chain (it changes the block hash).

**Activation.** Set on every producing node's environment **from genesis block 1**:

```
CITRATE_BLOCK_V2=1
```

- Effect: the producer seals `version: 2` headers with `header.coinbase = <reward addr>`
  committed in the hash. `apply_block` (execute-on-receive) can then verify received blocks.
- **All producing nodes must set this at the same genesis** — a mixed v1/v2 fleet forks
  (different block hashes for the same header). Bake it into the systemd unit / compose env
  of every fleet node before first block.
- Leave unset (or `0`) only if the reroll intentionally stays on v1 (execute-on-receive
  verification then remains unavailable — not recommended for a multi-node fleet).

## B. VALIDATOR-S1 stake-gated membership

**Why.** Enforces proposer-set membership from `ValidatorRegistry`. OFF unless configured.

**Prerequisites (before setting the env):**
1. `ValidatorRegistry` deployed (CREATE2, reroll-stable) — record its address.
2. Genesis-seed the registry with the fleet as the initial active set (each fleet node
   registered at ≥ minStake), so `activeSet()` is non-empty before the activation height.

**Activation.** On every fleet node:

```
CITRATE_VALIDATOR_REGISTRY=0x<20-byte registry address>
CITRATE_VALIDATOR_ACTIVATION_HEIGHT=<height at/after which membership is ENFORCED>
```

- Effect: the node attaches the shared proposer selector to the DAG store, enforces
  membership at/above the activation height, produces the height-binding EquivocationVote,
  and re-syncs the selector from the registry at each snapshot block S(E)=E·1000−200.
- Pick `ACTIVATION_HEIGHT` comfortably **after** the first snapshot that can see the
  genesis-seeded set (i.e. ≥ the first S(E) > 0, which is height 800) so membership is
  populated before enforcement begins. A few epochs of margin is safe.
- **Fleet-wide identical values.** All nodes must share the same registry address +
  activation height, or admission verdicts diverge (fork). Bake into every node's env.
- Depends on (A): the EquivocationVote / registry reads assume reproducible state, i.e. v2
  headers. Set `CITRATE_BLOCK_V2=1` too.

## C. Post-reroll verification
- Confirm every node logs `EXECUTE-ON-RECEIVE: sealing version-2 headers …` and
  `VALIDATOR-S1: stake-gated membership ENABLED …` at startup.
- Confirm block 1 has `version == 2` and a non-zero `header.coinbase`.
- Confirm a follower's `eth_getBalance` for a funded account matches the producer's once
  execute-on-receive is wired end-to-end (the driver — pending; see the design doc §4).
- Confirm `RegistrySync` logs `synced validator set for epoch E …` at the first S(E) ≥ 800.

## D. Rollback
Both features are env-gated: unset the vars and restart to fall back to v1 headers /
no membership enforcement. Because they only take effect from genesis, rollback is a
genesis/config decision, not a live-chain migration.
