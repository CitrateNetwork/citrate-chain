---
created: 2026-07-21T09:00:00Z
branch: srp/s3-restart-produced-purity
author: Larry Klosowski (@SaulBuilds) + Claude (Opus 4.8, 1M)
status: CODE-COMPLETE (fix + red test + ADR + tripwire, all green) — spec finalizing; then FINAL reroll
program: SRP (State-Root Purity) — Sprint S3: the resident-set / restart-produce surface
code: SRP-S3
depends-on: SRP-S1 (forward root, DONE), SRP-S2 (reward path, DONE+merged)
blocks: a restart-durable chain; safe partner distribution of the node
adr: ../adrs/ADR-2026-07-21-restart-produce-purity.md
spec: ../../specs/tla/consensus/RestartProducePurity.tla
---

> **Consensus-safety sprint (SRP class).** SRP-S1 made the forward root pure over committed
> accounts; SRP-S2 made the reward-settled root pure; SRP-S3 makes the root independent of which
> accounts are RESIDENT in memory — the surface a RESTART reconstructs differently. Spec-first,
> full Agentile loop, then one clean restart-durable reroll.

## The incident that exposed it (2026-07-21, ground truth)
The SRP-S2 reroll crossed activation 2000 with 0 mismatches (G1-G8). The restart-resilience gate
(G9) restarted the miner post-activation; the FIRST post-restart block (2041) was fine, the SECOND
— block **2042, EMPTY** — committed a root (`0x8c7c1675…`) no honest follower reproduces
(`0x01a6b4a6…`) → split-brain. On an empty block the reward is byte-identical on all roles and §R'
is inert, so the divergence is purely in the state-root fold.

## Root cause (CONFIRMED by a passing red test)
`StateDB::calculate_state_root` folds the volatile in-memory RESIDENT account map
(`all_accounts()`, state_db.rs:265). An EMPTY account (no committed state) can be resident on one
node but absent on another with identical committed state (read-through / restart reconstruction),
and folding it changes the root. `srp_s3_resident_empty_account_must_not_change_root` reproduces it
(two StateDBs, identical committed state, one extra resident empty account → different roots on
`main`). Same SRP class, on the resident-set/restart surface S1/S2 did not cover.

## Phases (each = full loop; each gate = owner sign-off)

### Phase 0 — Spec + ADR (G0)
| WP | Title | Acceptance |
|---|---|---|
| **WP-0.1** | `RestartProducePurity.tla` (+ .cfg + _buggy.cfg) — the state root is a pure function of the committed NON-EMPTY accounts, identical across producer/receiver/coldsync/restart/reorg. | TLC clean on the fix config; the buggy (fold-empties) config VIOLATES `RootAgreement` (a restart role folds an extra empty → divergent root). |
| **WP-0.2** | `ADR-2026-07-21-restart-produce-purity.md` — decision: EIP-158 empty-account exclusion + boot hard-fail; roots change, addresses don't. Red-teamed. | ADR accepted + red-teamed. |

### Phase 1 — Reproduce + pin (G1) — DONE
| **WP-1.1** | Deterministic red test: identical committed state, one extra resident empty account → assert equal roots. | FAILS on `main` (e9c9057e ≠ 76428a0c), GREEN after fix. **DONE.** |

### Phase 2 — Fix (G2) — DONE
| **WP-2.1** | EIP-158 skip in `calculate_state_root` (`AccountState::is_empty()`, after live storage_root recompute) + boot HARD-FAIL on root mismatch (main.rs). | WP-1.1 GREEN; citrate-execution 567/567, node-bin 121/121, rprime parity + rollback green; SRP-S1/S2 tripwires still pass; SRP-S3 tripwire added. **DONE.** |

### Phase 3 — Final restart-durable reroll (G3)
| **WP-3.1** | One clean reroll on the SRP-S3 binary (both arches). Genesis root CHANGES (EIP-158); addresses UNCHANGED (address-neutral). Then **prove G9 durably**: restart a fresh follower AND the miner mid-epoch post-activation → 0 divergence. citrate-core Linux+Mac cold-sync + close/reopen. | New genesis reproduced on all 4; activeCount 4; 0 mismatches across activation AND across both restarts; external cold-sync matches. Then merge SRP-S3→main + update the citrate-core handoff with the new genesis. |

## Definition of done
- `RestartProducePurity.tla` green; ADR accepted.
- The state root is pure across producer/receiver/cold-sync/**restart**/reorg (empty-account-independent).
- A miner AND a follower can be restarted mid-operation without poisoning/rejecting a block.
- Final reroll executed on the SRP-S3 binary; node is safe to distribute to partners.

## Live-chain status
Chain 40204 split-brain at block 2042 (rpc-1 solo; boots wedged applied-2041). Recovery = this fix
then a clean restart-durable reroll. Do NOT reroll on the SRP-S2 binary (re-exposes the wedge on
any restart). SRP-S2 fix is on main (260976b); SRP-S3 fix on branch srp/s3-restart-produced-purity
(21a9484) — merge to main only AFTER G3 (restart-durable reroll proven), unlike S2 which was merged
before G9 and had to be superseded.
