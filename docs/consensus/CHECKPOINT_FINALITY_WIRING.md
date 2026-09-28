# Checkpoint Finality Wiring — 12-second Deterministic Finality (WP-S.3)

**Status:** SPEC / proposed · **Target:** ≤12 s worst-case deterministic finality
**Author:** chain-ops · **Reviewers:** @CitrateNetwork/maintainers
**Related:** `FEATURE_REFERENCE.md` (WP-S.3), `specs/tla/consensus/CheckpointVoteSafety.tla`,
`docs/consensus/EXECUTE_ON_RECEIVE_state_application.md` (invariant I4), `verification/claims.json`

---

## 0. TL;DR

Checkpoint finality (Committee-BFT, WP-S.3) is **already implemented and unit-tested** in
`core/consensus/src/checkpoint.rs`. What is missing is the **producer/outbound half**: no
production code path ever *proposes* a checkpoint, *selects a committee*, *signs* a local
vote, or *broadcasts* it. As a result `CheckpointManager::latest_finalized_height()` never
leaves 0, the reorg "finalized floor" (`canonical_apply.rs:219`) is pinned at 0, and there is
no `finalized` RPC tag. This spec wires the existing pieces together, retunes the checkpoint
interval to hit ≤12 s finality at the current 2 s block time, and defines the coordinated
activation and the safety/liveness/adversarial test bar.

**Not** a block-time change (measured steady 2.00 s; retuning the interval suffices).
**Not** a genesis reroll — floor enforcement activates at a height-gated **soft fork**.
**Is** gated on a real validator committee: with a single producer, quorum is unreachable and
nothing finalizes, so this ships **flag-off** and is enabled once producer #2 + a staked
committee exist (see §7).

---

## 1. Goals / non-goals

**Goals**
- G1. Deterministic finality with a **≤12 s worst-case** and ~6–7 s average latency.
- G2. **Safety over liveness**: never finalize two conflicting checkpoints; never revert state
  below a finalized checkpoint. A stalled committee halts finality, never forks it.
- G3. Portable, deterministic committee selection and vote validation (no float, no
  platform-dependent behavior — already fixed in `CommitteeSelector::select`, audit M-04).
- G4. A `finalized` (and `safe`) RPC block tag backed by the real finalized height.
- G5. Spec-to-code conformance test in CI (also closes the dim-1 audit gap).

**Non-goals**
- Changing block time or block validity rules (tx_root, signatures) — untouched.
- Replacing GhostDAG fork-choice — checkpoint finality *constrains* it (a floor), it does not
  replace blue-score head selection between checkpoints.
- The separate depth-based `FinalityTracker` (`core/consensus/src/finality.rs`) — also unwired,
  but **out of scope**; docs state checkpoint finality overrides depth finality. Decision D-3.

---

## 2. Current state (what exists vs. what is missing)

| Piece | Status | Location |
|---|---|---|
| `Checkpoint`, `CheckpointVote` types | ✅ implemented + tested | `checkpoint.rs:127,153` |
| Domain-separated signed message (`CITRATE-CHECKPOINT-V1 ‖ chain_id ‖ height ‖ block_hash`) | ✅ | `checkpoint.rs:66` |
| `CommitteeSelector::select` (stake-weighted, integer-sqrt, deterministic) | ✅ (tests only) | `checkpoint.rs:215` |
| `CheckpointManager::{propose,submit_vote,finalize_checkpoint}` | ✅ (propose = tests only) | `checkpoint.rs` |
| `NetworkMessage::CheckpointVote` + **inbound** handler | ✅ | `protocol.rs:272`, `main.rs:3328` |
| Finalized-floor sink + 5 s poll + reorg guard (I4) | ✅ wired, fed 0 | `canonical_apply.rs:219,352`; `main.rs:1839` |
| Active validator set read from `ValidatorRegistry.activeSet()` | ✅ (feeds proposer, not committee) | `registry_sync.rs:274` |
| **Production `propose()` at checkpoint boundaries** | ❌ missing | — |
| **Committee selection fed from the active set** | ❌ missing | — |
| **Outbound vote: construct → sign → broadcast** | ❌ missing | — |
| **`finalized`/`safe` RPC block tag** | ❌ missing | `eth_rpc.rs:326` |
| **`CheckpointNodeConfig` → `CheckpointConfig` plumbing** | ❌ ignored (uses `default()`) | `config.rs:65`; `main.rs:1767` |

Everything the reorg-floor needs is already in place; it activates automatically the moment
`latest_finalized_height()` advances.

---

## 3. Parameters and the 12-second derivation

Worst-case finality latency for a block:

```
T_final(worst) = interval_blocks × block_time + T_vote_aggregation
```

Measured `block_time = 2.00 s` (steady across 1/5/50/200-block windows on live 40204).
Budget `T_vote_aggregation ≤ 2 s` (ed25519 verify is ~50 µs/vote; the constraint is gossip
propagation of committee votes, not CPU).

| interval | cadence | worst-case finality | verdict |
|---|---|---|---|
| **5** | 10 s | **~12 s** | **chosen** (target, with vote budget) |
| 4 | 8 s | ~10 s | fallback if T_vote proves > 2 s under load |
| 50 (current default) | 100 s | ~100 s+ | why finality "never felt real" |

**Chosen parameters (mainnet-target):**
- `interval = 5` blocks (10 s cadence)
- `committee_size = 100` (cap; effective = min(100, |active set|))
- `quorum = ceil(2/3 · effective_committee) + 1` — **derived from the effective committee**,
  *not* the hardcoded 67. This is the one code-behavior change to `CheckpointConfig`
  semantics: today `quorum_threshold` is a fixed 67, which can never be met below 100
  validators. **D-2.**
- Vote-aggregation budget: 2 s. If field telemetry shows p99 > 2 s, drop `interval` to 4.

Average finality ≈ `(interval/2)·block_time + T_vote ≈ 5 + 2 = 7 s`.

---

## 4. Design

### 4.1 Committee selection
At each checkpoint boundary height `H` (where `H % interval == 0`, `checkpoint.rs:121`):
`committee = CommitteeSelector::select(active_set, H, vrf_seed, committee_size)` where
`active_set: Vec<(PublicKey, u128)>` comes from `registry_sync` (`registry_sync.rs:274`, the
same source that already feeds proposer election), and `vrf_seed` is the VRF output /
randomness bound to block `H` (reuse the proposer-election beacon; the seed MUST be fixed by
`H` so every honest node derives the identical committee). Selection is already deterministic
and stake-weighted with exact integer-sqrt weighting.

### 4.2 Propose
On accepting the canonical block at a boundary height `H`, every node calls
`CheckpointManager::propose(H, block_hash_at_H, committee)`. `propose` creates the pending
`Checkpoint` that inbound votes attach to (today it is only ever called from tests, which is
the core defect). Idempotent per `(H, block_hash)`.

### 4.3 Vote (the missing outbound path)
If this node's validator key is in `committee`, it constructs `CheckpointVote { height: H,
block_hash, voter, signature }` where `signature = sign(validator_key,
canonical_vote_message(chain_id, H, block_hash))` (`checkpoint.rs:66`), submits it locally
(`submit_vote`), and **broadcasts** `NetworkMessage::CheckpointVote` (`protocol.rs:272`). This
outbound construct-sign-broadcast path does not exist today and is the primary new code.
The validator signing key is the node's consensus key (same key registered in
`ValidatorRegistry`); confirm availability in the producer context (D-4).

### 4.4 Aggregation & finalization
Inbound votes are already handled (`main.rs:3328` → `submit_vote`). On reaching quorum,
`finalize_checkpoint` marks the checkpoint finalized, persists it, and advances
`latest_finalized_height()`. Votes are validated against the committee membership, the
domain-separated message (binds `chain_id` + `height` + `block_hash`, rejecting cross-chain
and cross-height replay per TLA+ H-02), and de-duplicated per voter (equivocation → first
vote wins, second rejected/loggable-as-slashable — D-5).

### 4.5 Enforcement (already wired)
The 5 s poll (`main.rs:1839`) copies `latest_finalized_height()` into the
`finalized_height` AtomicU64 (`canonical_apply.rs:219`). The reorg guard already **rejects**
any reorg whose fork point is below that floor (invariant I4,
`canonical_apply.rs:657`). No new enforcement code — it comes alive when the floor advances.

### 4.6 RPC surface
Add `finalized` and `safe` block tags to `eth_rpc.rs` (`:326`, `:1657`). `finalized` resolves
to the block at `latest_finalized_height()`; `safe` == `finalized` for a BFT gadget (no
separate "safe" notion). Before the first finalized checkpoint, resolve to genesis (block 0),
never error. This closes the `verification/claims.json:127` gap and helps dim 8.

### 4.7 Config & remnants
- Plumb `CheckpointNodeConfig` (`config.rs:65`) → `CheckpointConfig` (today `main.rs:1767`
  ignores it and uses `default()`). Add `interval`/`committee_size` from node config; derive
  `quorum` (§3). Keep `chain_id` from the node's chain config, not the hardcoded 40204.
- Point checkpoint persistence at the dedicated `CF_CHECKPOINTS` column
  (`column_families.rs:27`, currently dead) or delete it and keep the `dag_metadata`
  `checkpoint:*` scheme — pick one, remove the dead one (D-6).

---

## 5. Safety & liveness properties (must hold; enforced by tests + TLA+)

- **S1 (no conflicting finality):** two checkpoints at the same height with different
  block_hash can never both reach quorum with an honest ≥2/3 committee.
- **S2 (no revert below finality / I4):** committed state is never reverted below
  `latest_finalized_height()`; a reorg with fork point below the floor is `Rejected`.
- **S3 (replay resistance):** a vote signed for `(chain_id', H', hash')` is rejected on any
  other `(chain_id, H, hash)` — domain separation (TLA+ `CanonicalMessageBindsChain`,
  `OnlyOwnChainVotesAccepted`).
- **S4 (committee integrity):** committee is a deterministic function of `(active_set, H,
  vrf_seed)`; all honest nodes compute the identical set; selection is unbiasable given the
  seed is fixed by `H`.
- **L1 (liveness under honest supermajority):** if > 2/3 of committee stake is honest and
  online and the network is synchronous within the round, every checkpoint height finalizes
  within `T_vote` of being proposed.
- **L2 (safe stall):** if quorum is unreachable (too few validators, censorship), finality
  halts at the last finalized height — the chain keeps producing blocks under GhostDAG, and
  resumes finalizing when quorum returns. Never a safety violation.

---

## 6. Activation (coordinated soft fork)

Enforcing the finalized floor in fork-choice is a **consensus-rule change**: pre-activation,
nodes accept reorgs the post-activation rule rejects. Therefore:

- Gate the **enforcement** (S2 reorg-floor rejection) behind an **activation height**
  `CITRATE_CHECKPOINT_FINALITY_ACTIVATION` (env + `consensus_manifest.rs`, mirroring the
  existing `CITRATE_BLOCK_V2` / registry-activation pattern, `main.rs:1786`).
- Ship the **producer/vote/RPC** machinery behind `CITRATE_CHECKPOINT_FINALITY=1`, default
  **off**. Merged flag-off it is a strict no-op (no propose, no vote, floor stays 0).
- **Rollout:** (1) merge flag-off; (2) stand up the validator committee (§7); (3) enable the
  producer flag fleet-wide and observe votes/finalization on a canary without enforcement;
  (4) set the enforcement activation height once finalization is proven healthy. No genesis
  reroll; existing state, addresses, and balances untouched.

Because activation is height-gated and every node ships the same binary, an honest fleet
transitions atomically; a straggler on the old binary would (correctly) diverge and must
upgrade — standard soft-fork discipline (see `feedback_deploy_from_main_only`).

---

## 7. Validator-set prerequisite (couples with dim-9 decentralization)

With the Mac node as sole producer, the effective committee is 1 and quorum (§3) is
unreachable → **nothing finalizes even when enabled** (this is L2, safe). Hitting 12 s
finality *in practice* therefore requires:

1. A **second (and third) independent producer** — bring the DO fleet back as validators
   after the RPC flip-back.
2. **Stake-gating live** on `ValidatorRegistry` (registrations + `minStake`) so the active set
   is Sybil-resistant.
3. A committee of **≥4** for meaningful BFT (tolerates 1 Byzantine at quorum=3); target
   growth toward `committee_size`.

Finality and decentralization are the same push; the finality flag flips on **after** the
committee exists.

---

## 8. Test bar

### 8.1 Unit / property (extend existing `checkpoint.rs` tests)
- Committee determinism across platforms; stake-weight monotonicity (proptest).
- Quorum derivation edge cases: |set| = 1,2,3,4,100; off-by-one at the quorum boundary.
- Vote validation: wrong chain_id, wrong height, wrong hash, non-committee voter, bad sig.

### 8.2 Integration (`core/consensus/tests/`, new)
- Happy path: N validators → propose → collect quorum → finalize → floor advances → a reorg
  below the floor is `Rejected` (exercises S2 end-to-end through `CanonicalApplicator`).
- `finalized`/`safe` RPC returns the finalized block; genesis before first checkpoint.

### 8.3 Adversarial (the bar Larry set — new `core/consensus/tests/adversarial_finality.rs`)
- **A1 equivocation:** a committee member double-votes two hashes at `H`; assert at most one
  finalizes, second is rejected (and flagged slashable if D-5 = yes).
- **A2 vote withholding / censorship:** up to 1/3 stake withholds → finality stalls (L2), no
  fork, resumes when they return.
- **A3 Byzantine 1/3:** exactly ⌊(n-1)/3⌋ Byzantine voters cannot force a conflicting
  finalization (S1).
- **A4 cross-chain replay:** replay a valid vote from chain_id≠40204 → rejected (S3).
- **A5 cross-height replay:** replay a vote from H'≠H → rejected (S3).
- **A6 reorg-below-finality:** attempt a deep reorg with fork point < floor → `Rejected` (S2).
- **A7 committee grinding:** attempt to bias committee via seed manipulation → seed fixed by
  `H`/beacon, no advantage (S4).
- **A8 long-range / posterior:** an old checkpoint's committee keys cannot re-finalize a
  competing history at that height (finalized set is monotone).

### 8.4 Model checking (dim-1)
Extend `specs/tla/consensus/CheckpointVoteSafety.tla` to cover S1/S2 and run TLC in CI
(advisory → gating). Add a **spec-to-code conformance test** asserting the Rust constants and
message layout match the TLA+/`FEATURE_REFERENCE.md` values (interval, quorum rule, 69-byte
message).

---

## 9. Implementation stages (each its own PR, reviewed)

- **Stage 0 — safe, non-consensus:** `finalized`/`safe` RPC tag (§4.6) + `CheckpointNodeConfig`
  plumbing + quorum derivation (§3, §4.7). No behavior change to block acceptance. Mergeable
  immediately.
- **Stage 1 — producer side, flag-off:** committee feed (§4.1), production `propose` (§4.2),
  outbound sign+broadcast vote (§4.3), behind `CITRATE_CHECKPOINT_FINALITY`. No-op until
  enabled.
- **Stage 2 — verification:** integration + adversarial tests (§8) + TLA+/conformance in CI.
- **Stage 3 — activation:** height-gated enforcement flag + rollout (§6), *after* the
  committee exists (§7).

---

## 10. Open decisions

- **D-1.** Confirm `interval = 5` (10 s) as the target; accept ~12 s worst-case. Fallback 4.
- **D-2.** Quorum derived as `ceil(2/3·n)+1` from the effective committee (replaces fixed 67).
- **D-3.** Leave depth-based `FinalityTracker` unwired / out of scope (checkpoints override).
- **D-4.** Producer has access to the validator signing key to sign votes — confirm plumbing.
- **D-5.** Equivocation handling: reject-second-only, or also emit a slashable report to the
  `ValidatorRegistry` slasher path? (Recommend: reject now, slashable-report as a follow-up.)
- **D-6.** Checkpoint persistence: adopt `CF_CHECKPOINTS` or delete it and keep the
  `dag_metadata` scheme (recommend: keep `dag_metadata`, delete the dead CF).
