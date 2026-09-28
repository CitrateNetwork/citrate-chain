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

> **Revised per MAC independent review (2026-09-28) — supersedes the first draft.**
> Two corrections drive this section: (a) **voting must happen at depth D past the
> checkpoint block**, not at the tip — a tip block can still lose to a heavier GhostDAG
> sibling, and once the floor is enforced honest nodes would lock onto the loser; and
> (b) the quorum is **`floor(2n/3)+1`** (the standard BFT bound the code uses), not
> `ceil(2n/3)+1` (which gave 68 for n=100 and contradicted §7's 3-of-4).

Worst-case finality latency for a block:

```
T_final(worst) ≈ (interval_blocks + D) × block_time + T_vote_aggregation
```

where `D` = confirmation depth: the committee signs the checkpoint block only once it is
buried `D` blocks deep, so a sibling reorg past it is negligible. Measured
`block_time = 2.00 s` (steady across 1/5/50/200-block windows on live 40204). Budget
`T_vote_aggregation ≤ 2 s` (ed25519 verify is ~50 µs/vote; the constraint is gossip
propagation, not CPU).

To hold **≤12 s**: `(interval + D) × block_time + T_vote ≤ 12` ⟹ at 2 s blocks,
`interval + D ≤ 5`.

| block_time | interval | D (safety depth) | worst-case | note |
|---|---|---|---|---|
| **2 s (no change)** | **2** | **3** | 2·(2+3)+2 = **12 s** | chosen default; D=3 is a thin but workable margin on top of BFT sigs |
| 2 s | 3 | 2 | **12 s** | more frequent checkpoints, shallower confirmations |
| **1 s (block-time change)** | 4 | 5 | 1·(4+5)+2 = **11 s** | **safer D=5** within budget — the reason to consider halving block time |

**The block-time tradeoff (decision for owner).** At 2 s blocks the ≤12 s budget forces a
shallow `D` (≤3). Halving to **1 s blocks** roughly doubles the confirmation-depth budget
(`interval+D ≤ 10`), buying a much safer `D=5` while still finishing in ~11 s. Block-time is
a cadence change (validity-affecting: timestamp spacing / difficulty) → it *would* need a
coordinated activation, unlike the rest of this design (§6). **D-1:** keep 2 s blocks with
`D=3`, or halve to 1 s for a deeper safety margin.

**Chosen parameters (mainnet-target, pending D-1):**
- `interval = 2`, `D = 3` (2 s blocks) — worst-case ~12 s, average ~9 s.
- `committee_size = 100` (cap; effective = `min(100, |active set|)`).
- `quorum = floor(2 · n / 3) + 1` over the **effective** committee `n` (67 for n=100, 3 for
  n=4). Replaces the hardcoded 67, which can never be met below 100 validators. **D-2.**
- **Minimum committee for finality = 4** (tolerates 1 Byzantine at quorum 3). Below 4, the
  node proposes/collects votes but **does not finalize** — a 1- or 2-member committee must
  never self-finalize (that is centralized rubber-stamping, not BFT). **D-2a.**
- Vote-aggregation budget: 2 s; if field p99 > 2 s, trade one block of `interval` for margin.

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

### 4.5 Enforcement (real code — a height alone is NOT enough)
> **Revised per MAC review.** The floor is a *height*, but the certificate finalizes a
> specific *hash*. Raising the floor on height alone can pin a node to the WRONG branch.

The 5 s poll (`main.rs:1839`) into the `finalized_height` AtomicU64 (`canonical_apply.rs:219`)
and the existing reorg guard (`canonical_apply.rs:657`) are the substrate, but enforcement
needs **new code**:
- The finalized floor is a **`(height, block_hash)` pair**, carried by the quorum certificate.
- **Before** raising the local floor — at run time **and at boot** — verify the certified
  `block_hash` is the block at that height on **this node's own canonical chain**. If it is
  not, the node is on a losing branch: it must **not** raise the floor blindly (that would
  lock it to the wrong branch); instead it reorgs to the certified branch if it can, else
  **halts finality progress and alarms** (a safety stop, never a silent wrong-branch pin).
- Only after the hash check passes does the reorg guard reject fork points below the floor.

### 4.6 RPC surface
Add `finalized` and `safe` block tags to `eth_rpc.rs`. **There are ~8 block-tag parse sites,
not 2** (`:329, :832, :1662, :1683, :1886, :1897, :2555, :2616`) — all must learn the new
tags, so factor a single `resolve_block_tag` helper rather than patching each. The RPC layer
**cannot read the finalized height today** — plumb a handle (the same `finalized_height`
AtomicU64 / a `get_finalized_height()` on the api object) into the RPC context. `finalized`
resolves to the block at the finalized height; `safe` == `finalized` for a BFT gadget. Before
the first finalized checkpoint, resolve to genesis (block 0), never error. Closes
`verification/claims.json:127`, helps dim 8.

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

## 6. Activation (node-local — NO block-validity fork)

> **Corrected per MAC review.** My first draft called for an activation *height*. That was
> wrong: **votes are gossip, never carried in blocks**, so finality changes fork-choice, RPC
> tags and persistence — but **block validity is unchanged**. A node on the old code simply
> doesn't enforce the floor (weaker fork-choice), it never rejects a block the new code
> accepts. So this needs **no new consensus activation height and no reroll** — it is a
> node-local rollout.

- **Rollout by a compiled pin, not an env var.** `hardening.rs` moved to compiled activation
  pins; follow that pattern for enabling floor enforcement, so the rollout point is baked into
  the binary (auditable, not a runtime toggle). Ship the producer/vote/RPC/enforcement code;
  the compiled pin decides when enforcement goes live.
- **Sequenced rollout (safety):** (1) merge with enforcement pinned OFF — producers still
  propose/sign/broadcast and RPC serves `finalized`, but the floor is observed, not enforced;
  (2) stand up the validator committee (§7); (3) observe healthy finalization on the fleet;
  (4) flip the compiled pin ON in a release once finalization is proven and late-joiners can
  fetch certificates (§ verifier-revisions #10). Existing state, addresses, balances
  untouched.
- The **reorg guard itself is already live and ungated** (`canonical_apply.rs:657`); what the
  pin gates is *raising the floor above 0*, i.e. whether finalized certificates actually
  constrain fork-choice.

A straggler on old code is weaker (won't honor finality) but not forked off — it still
accepts the same blocks. Coordinate the enable-release per `feedback_deploy_from_main_only`.

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
  Stage 1 also carries the liveness fixes (early-vote buffer + vote relay, §11.5), the
  epoch-pinned committee (§11.6), pending/voted pruning (§11.9), late-joiner certificate sync
  (§11.10), and the `check_claims.py` tightening (§11.11).
- **Stage 2 — verification:** integration + adversarial tests (§8) + TLA+/conformance in CI.
- **Stage 3 — enable:** flip the compiled enforcement pin (§6, node-local, NO activation
  height) in a release, *after* the committee exists (§7) and late-joiners can fetch certs.

---

## 10. Open decisions

- **D-1.** Block time / depth: keep **2 s blocks with `interval=2, D=3`** (~12 s), or halve to
  **1 s blocks** for a safer `D=5` at ~11 s (§3). Block-time change is the only part that
  would need a coordinated activation.
- **D-2.** Quorum = **`floor(2n/3)+1`** over the effective committee (67 for n=100, 3 for n=4).
- **D-2a.** Minimum committee for finality = **4** (no 1- or 2-member self-finalization).
- **D-3.** Leave depth-based `FinalityTracker` unwired / out of scope (checkpoints override).
- **D-4.** Producer has access to the validator signing key to sign votes — confirm plumbing.
- **D-5.** Equivocation handling: reject-second-only, or also emit a slashable report to the
  `ValidatorRegistry` slasher path? (Recommend: reject now, slashable-report as a follow-up.)
- **D-6.** Checkpoint persistence: adopt `CF_CHECKPOINTS` or delete it and keep the
  `dag_metadata` scheme (recommend: keep `dag_metadata`, delete the dead CF).

---

## 11. Verifier revisions (MAC independent review, 2026-09-28) — checklist

The §3/§4.5/§4.6/§6 rewrites above resolve MAC's points 1–4, 7, 8. The rest are folded into
the design + test bar and tracked here so #12 addresses every one:

- **(2) quorum & min committee** — `floor(2n/3)+1`, min 4 (§3, D-2/D-2a). Resolved.
- **(3) vote at depth D** — no tip voting (§3). Resolved.
- **(4) floor is a hash, enforcement is real code** — `(height,hash)` cert, verify on-chain at
  runtime + boot, halt-not-pin on mismatch (§4.5). Resolved.
- **(5) liveness — early votes & relay:** **buffer** inbound votes that arrive *before* this
  node proposes the checkpoint (keyed by `(height,hash)`, replayed into `submit_vote` on
  propose), and **re-gossip** every accepted, valid vote to peers (today the inbound handler
  `main.rs:3328` neither buffers nor relays). Add to Stage 1 + an integration test.
- **(6) epoch-pinned committee:** derive the committee from the **finalized validator-set
  snapshot of the checkpoint's OWN epoch**, not the live active set — nodes crossing an epoch
  boundary at different wall-clock times must compute the identical committee. Wire off the
  `registry_sync` epoch snapshot, not the tip. Add a cross-epoch determinism test.
- **(7) compiled pin, not env** — §6. Resolved.
- **(8) all ~8 RPC tag sites + finalized-height handle** — §4.6. Resolved.
- **(9) memory bound:** prune `pending` checkpoints and the per-height `voted` set once a
  height is finalized or falls below the floor (unbounded growth during a quorum stall today).
  Add a bound + a stall soak assertion.
- **(10) late joiners:** a syncing node must be able to **fetch finalized checkpoint
  certificates** during sync (new `GetCheckpoint`/`CheckpointCert` p2p messages + apply on
  receipt), else its floor stays 0 until it participates live. Add to Stage 1 + a sync test.
- **(11) claims tripwire:** `check_claims.py` currently passes on any non-test `.propose(`
  call — a default-off flag would false-positive "running". Tighten it (require the flag/pin
  ON **and** an outbound vote path) **in the same PR**; MAC flips the tripwire only when
  finality actually runs. Add.
- **(1, config) chain_id:** stop hard-coding 40204 in `CheckpointConfig::default` — take
  `chain_id` from node chain config so devnet 1337 signs correct vote messages (§4.7).

**Design confirmation (MAC):** node-local, **no new activation height**; votes are gossip, so
fork-choice / RPC / persistence change but block validity does not. MAC holds the full memo
with the test + mutation plan (owner to relay).

**Adjacent (#14, not this PR):** failed txs bill the full gas limit but the receipt reports
only pre-failure gas (`executor.rs:~2084/2104`) → flows into `gas_used`
(`producer.rs:1456`) and `receipt_root` (`~2241`), both in the block hash
(`types.rs:358/370`). Consensus-visible; today only `state_root` is checked by followers, so
not validity-affecting yet — but the fix changes `receipt_root`, so #14 **does** need its own
new activation height (legacy bytes identical below it, full-limit receipt at/above it).
