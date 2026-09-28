---
created: 2026-09-28T07:30:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: in-progress
issue: citrate-security#132
---

# Rescore program (647 → ~880) + checkpoint-finality spec

Operational record of the pre-audit rescore push and the finality design that anchors it. This
sprint is the DGX (chain + consensus + deployer) lane; MAC owns independent verification + citrate-core.

## Source of truth (link, don't copy — Rule 9)
- Rescore plan: the 51-task table (owner-maintained) — verified baseline **647**, ceiling **~880**.
- Ownership split: DGX = chain/consensus/deployer/all-keys; MAC = auditor/scorer + citrate-core.
- Finality spec: `docs/consensus/CHECKPOINT_FINALITY_WIRING.md` → citrate-chain **PR #248** (v2).
- Consumed evidence: citrate-security **#124/#126/#132**.

## What shipped in Phase 1 (DGX rows)
- **DEPLOYER-ADMIN 0** achieved + evidenced (see the governance-decentralization retro).
- **Linux auto-update live** — the Space `latest.json` carries all 7 platforms; a v0.3.0 Linux client
  is offered 0.3.1 with valid signatures (rescore #5).
- **/health git-sha** on identity/comms/explorer/gateway (4 PRs, rescore #10) — deploy pending.
- **Federation drift-check** unblocked with two fine-grained RO PATs (rescore #8, green).
- **Block-reward cut 10→1 SALT** started as a staged `ValidatorRegistry` governance param change
  (50%/step, 2-day timelock, ~4 steps) — NOT a fork.

## The finality design (the +42 dim-5 lever)
Checkpoint finality (WP-S.3) was **implemented + unit-tested but never called** — no production
`propose()`, no committee selection, no outbound vote — so finalized height was pinned at 0. The spec
wires the producer/outbound half and retunes the interval so **worst-case finality lands ~12 s** at the
measured 2 s block time.

**The v1→v2 story is the point of this sprint.** MAC, as the independent verifier, read the v1 spec and
returned 11 corrections — several were real safety flaws I had wrong:
- quorum `floor(2n/3)+1` (I had `ceil`, which gave 68 for n=100 and contradicted my own worked example);
- **vote at depth D, not the tip** (a tip block can lose to a heavier GhostDAG sibling; the floor would
  then lock honest nodes onto the loser) — this reworks the 12 s math and surfaces a real block-time
  decision (2 s/D=3 vs 1 s/D=5);
- enforcement is **real code** — the floor is a `(height,hash)` cert, verified against the node's own
  chain at runtime + boot, halt-not-pin on mismatch;
- **no block-validity fork at all** — votes are gossip, never in blocks, so it's a node-local rollout via
  a compiled pin, not an activation height (I had over-engineered a soft fork).

## Lessons
- **The builder/verifier split earns its keep on day one.** An independent reviewer with no stake in the
  design caught a quorum-formula error and an unsafe tip-vote that I'd have carried into code. Separating
  who-builds (DGX) from who-verifies (MAC) is not ceremony; it is how the wrong `ceil` gets caught.
- **"Specified" is not "running."** A fully-implemented, unit-tested gadget that nothing calls scores
  zero and finalizes nothing. The gap between spec and a live call site is where audits live.
- **Right-size the fork.** Not every consensus-adjacent change needs an activation height; classify what
  actually affects block validity (finality floor: nothing; block-time change: yes; gas_used/receipt_root
  fix #14: yes) before reaching for a coordinated activation.

## Next (DGX)
- Build #12 in stages: S0 (finalized/safe RPC tag + config + `floor(2n/3)+1`), S1 (flag-off producer/
  committee/vote + the verifier's liveness/epoch/prune/late-joiner fixes), S2 (adversarial tests +
  TLA+/conformance), S3 (enable via compiled pin) — the last **after** producer #2 + a real committee.
- Finality can only *finalize* once a real committee exists → coupled with the 48 h decentralization push
  (producers, signers, HSM) that the owner is leading.
