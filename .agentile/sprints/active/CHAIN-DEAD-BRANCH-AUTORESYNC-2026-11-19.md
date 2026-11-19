---
name: CHAIN-DEAD-BRANCH-AUTORESYNC
description: A node stranded on a dead branch far below its reorg floor marks itself wedged on unforgeable evidence, so the guarded cold resync recovers it (Core 0.5.6)
created: 2026-11-19T18:00:00Z
branch: fix/toodeep-wedge-autoresync
author: Larry Klosowski
status: active
---

# CHAIN-DEAD-BRANCH-AUTORESYNC: members stuck on LIGHT recover by themselves

Owner decision (2026-11-19): ship Citrate Core 0.5.6 with an auto-resync fix,
so member nodes stuck on the dead r1007 branch recover by themselves.

- Incident: `citrate-labs/handoffs/FLEET_SPLIT_2026-11-17.md` and
  `citrate-labs/handoffs/FLEET_RECOVERY_RUNBOOK_2026-11-18.md`. The fleet is on
  HEAVY, finalized at 283,600. Members on LIGHT are at 274,810, `catching_up`,
  forked at 105,024.
- Design: `.agentile/adrs/ADR-2026-11-19-dead-branch-evidence.md`.
- Base: `origin/main` 5fbcbd37 (#483). This lane does not touch fleet hosts or any operator's node.

## WP-1 Red: the member never learns its fork is too deep

- [x] `ancestor_sync::tests::a_fork_far_below_the_floor_is_located_exactly_without_a_finalized_height`.
  It ends `Budget { fetched: 0 }` on 5fbcbd37 (cnv-build-2, 29 s). Observed mode
  leaves the sync view's finalized height at 0, the common block is about
  12,650, and paging to 105,024 exceeds the 20,000-header cap.

## WP-2 Fork search (ancestor_sync.rs)

- [x] Narrowing locator (`refine_locator`). TooDeep carries `fork_hash` and the
  verified first block of the other branch (`diverged`). There is no wire
  change, and the existing round, time and header budgets apply.
- [x] Green, located in at most 6 round trips with no body. Tests: a
  narrowing answer outside the locator is Faulty; the locator shape.

## WP-3 Evidence rule (dead_branch.rs) and certificate judgement

- [x] E1 to E6 (ADR D2). The marker is recorded under the advance lock
  (`CanonicalApplicator::record_dead_branch_on_evidence`), and an evidence
  marker is cleared if the branch moves (`clear_evidence_dead_branch`).
- [x] `finality_sync::judge_foreign_certificate`, which is never installed.
  `FinalityGadget::committee_beyond_held_epochs` handles a node behind the
  governing epoch.
- [x] Wired in `main.rs`: sync-tick evidence pass, outcome feeds (tick, rx
  `Ancestor`, rx `Blocks`), and `CheckpointCertificate` routing. The data
  sources are the ancestor-sync outcomes, `CheckpointManager::latest_finalized_height`,
  `BlockStore::get_applied_tip` / `get_header` / `get_canonical_block_by_height`,
  and a peer's `CheckpointCertificate`.
- [x] Mutation tests (ADR, Tests).

## WP-4 End to end (split_heal_tests.rs)

- [x] `a_node_stranded_on_a_dead_branch_resyncs_onto_the_finalized_branch`
  covers: fork more than twice the reorg floor; not marked without the
  certificate, with one heavy peer, or with the off switch; then marked;
  `cold_resync::evaluate` (wait, then resync), the restart through
  `apply_pending_with`, identity kept, and a fresh start syncing onto HEAVY.

## WP-5 Gates (cnv-build-2, /dev/shm target, dev opt-level 2 + debug-assertions + overflow-checks)

- [x] `cargo test --workspace --no-fail-fast` (ulimit -n 65536): 6,248 passed,
  0 failed, 23 ignored (WS=0). This includes the default-suite end-to-end test
  (fork just below the floor).
- [x] The ignored end-to-end test at twice the floor, run explicitly: fork 60,
  light tip 20,260 (depth 20,200), HEAVY tip 21,220. It was marked, cold
  resynced, and back on HEAVY; the armed node sealed nothing before it was on
  HEAVY and sealed 19 blocks on HEAVY afterwards. 1,708 s.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` (the CI form)
  clean, and `cargo fmt --all --check` clean. `--all-features` fails in the
  untouched `core/execution` halo2 code (unused imports and an unknown
  `circuit-params` cfg), which predates this change.
- [x] Test count (`cargo test --workspace -- --list`, clean target dirs): base
  5fbcbd37 has 6,247 and head has 6,271 (+24, the tests this sprint adds;
  none removed).
- [x] Rule 6 benchmark, base vs head. Recipe as in #483: one loopback devnet
  node, `citrate-bench`, target 300 TPS for 60 s, release binaries.
  - 64 signers: base 277.75 TPS (inclusion 3,909 ms), head 277.78 TPS
    (3,888 ms).
  - 256 signers: base 277.91 TPS (3,846 ms), head 278.30 TPS (3,873 ms).
  - No regression. Another lane's build shared the host during the head arms,
    which could only have slowed head down.

## WP-6 Review round 1 (#486, CHANGES, no P1): a node that is catching up

Finding: any node that is catching up and whose tip stalls for 15 minutes could be
marked cheaply. Two Sybil TooDeeps plus a genuine certificate relayed from above
its tip are enough, because E4 and E5 (header age) held for every such node.

- [x] Red on 7b5d58a7 (commit 72be9a64):
  - `an_honest_peer_ahead_on_our_chain_vetoes_a_sybil_verdict`
  - `an_evidence_marker_is_withdrawn_when_the_tip_moves_and_never_resyncs`
- [x] P2-1: applicator guard tests
  (`only_an_evidence_marker_whose_tip_moved_is_cleared`, and the withdrawn test).
- [x] P2-2: `cold_resync::evaluate` re-checks an evidence marker's dead tip at
  decision time.
- [x] P2-3: E7 catch-up veto (a connected peer that answered `Extends` within 1 h).
  `Outcome::Holds` is the reply for a peer level with us. E5(i) is a durable
  local wall clock since the tip last moved (`tip_unmoved_secs`, `CF_METADATA`),
  required together with the header age.
- [x] P3-1: a certificate our chain has since applied is no evidence.
- [x] P3-2: comment on #485 adding a free-disk check and a cap of 2 asides as
  acceptance criteria. The PR body says this path makes it reachable from peers.
- [x] P3-3: the 11 CodeQL cleartext-logging asserts in `finality_sync` tests now
  print a case message, not the certificate.
- [x] Mutants (cnv-build-2; one at a time; dead_branch, cold_resync and
  ancestor_sync tests): 7 of 7 killed.
  - From the review: `clear_evidence_dead_branch` never clearing, no tip check
    in `record_dead_branch_on_evidence`, and no fork check there.
  - P3-1: no E3 on-chain re-check.
  - The new guards: no decision-time re-check, no E7 veto, no wall clock.
- [x] `cargo test --workspace --no-fail-fast`: 6,256 passed, 0 failed, 23 ignored.
  `-- --list` counts 6,279 tests, up from 6,271 at 7b5d58a7.
- [x] Member end to end at twice the floor (`--include-ignored`): fork 60,
  depth 20,200. Marked, resynced and on HEAVY; the armed node sealed nothing
  before and 19 blocks on HEAVY after. 1,230 s.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean (after one
  `manual_ok_err` fix), and `cargo fmt --all --check` clean.
- [ ] CodeQL on the pushed head: see the PR.

## Core integration (read-only, citrate-core origin/main f8e60b84)

1. The supervisor (`kit/src/supervisor.rs`) restarts the node on any exit.
   Backoff starts at 500 ms, with at most 8 retries; it resets after 90 s
   healthy, then retries slowly every 10 min. Cold resync's `exit(1)` is
   restarted.
2. Core writes no `[recovery]` section (`member-node.toml`, written only if
   absent), so the defaults apply: `cold_resync = true`, 900 s, 6 h. The DB is
   encrypted via `CITRATE_STORAGE_KEY_FILE`, which the node passes to
   `apply_pending`.
3. A follower member has an empty coinbase, so it signs no votes and the carry
   is a no-op. An armed member (`--mine --coinbase`) signs and carries.
4. Not blocking: the JS stall watchdog restarts a frozen syncing node up to 3
   times, which is harmless because E5 and the marker time are durable. D2
   liveness never restarts an incarnation that was never near the tip. An armed
   node respawns with `--mine` on an empty DB until the mining watchdog
   disarms it. `chain-aside/` has no cleanup UI. Core pins chain f4a0e600, so
   0.5.6 needs a pin bump to the merged rev.

## Daily log

- 2026-11-19: design settled and reported to the lead (approved). The owner
  decided no compiled r1007 checkpoint. Red reproduced. WP-2 to WP-4
  implemented, with the armed-member check added at the lead's request.
  chain-aside accumulation is filed as #485. PR #486 opened at ae3d32d1. The
  gates, the test count and the benchmark are recorded above.
