---
created: 2026-10-15
branch: feat/checkpoint-finality-stage1-propose
author: Larry Klosowski + Claude Opus 5.5
status: draft
---

# Checkpoint finality Stage 1: slice plan

The design is [`CHECKPOINT_FINALITY_WIRING.md`](CHECKPOINT_FINALITY_WIRING.md) (§9 Stage 1, §11 verifier revisions). This note only splits Stage 1 into reviewable PRs and records what each one proves. It does not restate the design.

Claim vocabulary: **implemented** (code + tests) ≠ **wired** (called from the running node) ≠ **runtime-proven** (seen working on the fleet) ≠ **ready** (enforced). Every slice below is off by default behind `CITRATE_CHECKPOINT_FINALITY` until the last one. Stage 3 (enforcing the floor) is a separate compiled pin (WIRING §6).

| # | Slice | WIRING refs | State |
|---|---|---|---|
| 1 | **Propose.** `checkpoint_to_propose` (newest boundary buried `D = 3` deep), epoch-pinned committee from the durable S(E) snapshot governing H, seeded by H's VRF output, `CheckpointManager::propose`, pending/voted pruning, claims tripwire requires an outbound vote | §4.1, §4.2, §11.6, §11.9, §11.11 | implemented; wired behind the flag (off); not runtime-proven |
| 2 | **Outbound vote.** If the local consensus key is in the committee: `sign_checkpoint_vote` (canonical 69-byte message), local `submit_vote`, broadcast `NetworkMessage::CheckpointVote`. Needs the key in the node context (D-4) | §4.3 | not started |
| 3 | **Early-vote buffer + relay.** Buffer votes that arrive before the local propose (keyed by `(height, hash)`), replay them on propose; re-gossip every accepted vote | §11.5 | not started |
| 4 | **Late-joiner certificates.** `GetCheckpoint` / `CheckpointCert` p2p messages; apply a verified certificate while syncing | §11.10 | not started |
| 5 | **Hash-checked floor (observe only).** Floor = `(height, hash)`; verify against the local canonical chain at run time and at boot; halt-and-alarm on mismatch. Enforcement stays pinned off | §4.5, §6 | not started |

Stage 2 (adversarial + integration tests, TLA+ in CI, WIRING §8) runs alongside slices 2–5. The fleet prerequisite (WIRING §7) is unchanged: at least 4 online validators in the governing set, which is also what MS-BOUND (bounded merge scoring) and PSET-EPOCH (admission by block epoch) unblock.

## Slice 1 notes

- **Inert by construction.** Nothing in production signs a vote, so no checkpoint can reach quorum, `latest_finalized_height()` stays 0, and the reorg floor stays at 0. `verification/check_claims.py` now requires both a production `.propose(` and a production `sign_checkpoint_vote(` before any claim may say finality runs; with only slice 1 it warns.
- **Committee determinism.** Inputs are the canonical block at H (hash and VRF output) and the durable snapshot S(E) = greatest snapshot below H. Every node that applied the same chain reads the same bytes. A node with no snapshot for S(E) does not propose (`NoCommittee`). It never falls back to the live set.
- **Bounded memory.** Pending proposals older than 16 intervals, and their replay markers, are pruned on every propose.
- **Open for review:** `D = 3` and `interval` come from WIRING §3 / D-1. The node's `[checkpoint] interval` (default 50) is used as configured. The ≤12 s target needs `interval = 2` (a config change, not in this slice).
