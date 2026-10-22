# Checkpoint Finality Wiring — 12-second Deterministic Finality (WP-S.3)

**Status:** SPEC / proposed — **not yet running** (target design, no production caller). Target design: ≤12 s worst-case deterministic finality
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
- G1. **Target design (not yet running):** deterministic finality with a **≤12 s worst-case** and ~6–7 s average latency.
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

**Signing protection (Stage 1a, PR #321 review P2).** A validator must never sign two
hashes at one height, including across restarts (sign A at H, reorg onto a shorter
branch, restart, that branch later buries B at H). Every signing decision is therefore
recorded durably **before** the vote is signed, submitted locally or broadcast:
`dag_metadata` key `checkpoint_signed:<chain_id>:<H>` → the 32-byte hash, plus
`checkpoint_signed_meta:<chain_id>` → `floor ‖ highest` (u64 BE), written in one
`KvStore::kv_write_batch` (RocksDB: `write_batch_sync`, WAL fsync before return). Each sign
attempt consults the record: same hash → idempotent re-sign (deterministic ed25519, the
identical vote); different hash → refused and logged at error level (safety stop for that
height); height `<= floor` → refused. Write failure or no persistent store → no signature
(fail closed). Records at/below the finalized height are deleted and the floor raised to it
in one synced batch; records more than 1024 boundaries below `highest` are deleted the same
way (floor raised past them), so the record is bounded and pruning never re-opens a height.
This replaces the earlier "skip boundaries already buried at startup" driver heuristic.
The record lives in the node's database: wiping the data dir while keeping `proposer.key`
discards it, exactly like a slashing-protection DB — do not do that on a voting validator.

**Data-directory wipes on a voting validator.** Any resync procedure that says "move the
chain data aside (keep the keys) and resync" also discards the signed-vote record, and a
validator that keeps `proposer.key` after such a wipe can later sign a different hash at a
height it already signed (double-signing). A voting validator must therefore do one of:
(a) keep the signed-vote record — carry the `dag_metadata` `checkpoint_signed:*` entries
(`checkpoint_signed:<chain_id>:<H>` and `checkpoint_signed_meta:<chain_id>`) over into the
new data directory; or (b) rotate its consensus key and re-register it in
`ValidatorRegistry` after the wipe, so the old record no longer applies to the key it signs
with. Non-voting nodes are unaffected. The same warning
(`citrate_storage::VOTING_VALIDATOR_WIPE_NOTE`) is part of the log line printed when a node
mints a new `proposer.key`.

**Own-vote retry (Stage 1a, PR #321 review).** A failed durable write leaves the checkpoint
pending without this node's vote. A repeat report of the same `(H, hash)` therefore retries
the own vote when it is not yet in the pending checkpoint, always through the durable
record above (a record for a different hash at `H` is still refused). The driver keeps
boundaries whose own vote failed for a transient reason (store unavailable) and re-reports
them on later passes — bounded to 60 attempts, 16 boundaries and a 256-block horizon, on a
separate canonical walk after the pass's new boundaries — until the vote is cast, refused
permanently, or the checkpoint is finalized.

**Revisit after a safety stop (Stage 1c, PR #323 review L1).** While the §4.5 safety stop is
engaged the gadget proposes and signs nothing, and the driver's cursor still moves past
newly buried boundaries. Those boundaries are therefore kept in the same bounded set
(`OwnVoteRetries`, as `Followup::Halted`: no attempt consumed; at most 32 boundaries within
the same 256-block horizon). Nothing is due while the stop is engaged; on the first pass
after it clears, they are reported again on a fresh canonical walk from the current tip, so
the node proposes and votes them on the chain it is now on. Every revisit goes through the
normal signing path (signing gate, durable record): a height this key already signed for a
different hash is refused and not revisited again. An own vote signed just before the stop
engaged (under the signing gate) and withheld from broadcast is already in the local pending
checkpoint, so the gadget would not emit it again; the driver therefore keeps that recorded
vote with the halted boundary (`OwnVoteRetries::hold`, same bounds) and, on the revisit after
the stop clears, re-broadcasts the SAME vote if its block is still canonical at that height
(PR #323 review L1a). No new signature is created for it, and the broadcast is still withheld
while the stop is engaged.

**Early-vote admission before the governing snapshot (Stage 1a, PR #321 review).** When the
snapshot that governs `H` is not on this node yet, an early vote is checked provisionally
against the latest snapshot the node holds: voters in it use the unverified quota (64),
everyone else a separate lower-priority quota (32) that cannot displace them. Both are
re-checked against the governing snapshot when it appears. Buffer eviction ties break by
arrival order, never by key bytes.

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

**Stage 1c implementation (not running: both compiled pins are OFF for 40204).**
`node/src/finality_floor.rs` (`FloorVerifier`) runs one check at boot, before any block
admission, drain or recovery, then every 5 s. Each pass:
1. takes `CheckpointManager::latest_finalized_certificate()` (memory, else the persisted
   `dag_metadata` `checkpoint:{H}`) and re-verifies it with `Checkpoint::verify_certificate`:
   status finalized, committee >= 4, votes >= `floor(2n/3)+1`, every voter a committee member,
   every signature valid for this chain id (`CheckpointError::InvalidCertificate` otherwise);
2. calls `CanonicalApplicator::verify_certified_floor(H, hash, raise)`, which walks this
   node's applied chain through the stored headers OUTSIDE the advance lock, then re-confirms
   UNDER the lock that the applied tip is unchanged (or only extended forward) and, when
   `raise`, raises the floor before releasing the lock, so a reorg cannot slip in between the
   check and the raise. Result `Match` / `Mismatch` / `NotYetApplied` / `Unverifiable`; a chain
   that steps over `H` is a `Mismatch`.

Modes, from two compiled pins in `checkpoint_gadget.rs`: voting OFF → **Legacy** (no poll; a
certificate persisted by an earlier voting-ON run is logged and ignored, never used to raise
the floor by its raw height; with voting OFF nothing can finalize, so for a node that never
ran voting this is byte-identical to the old height poll, which never moved the floor);
voting ON + `CHECKPOINT_ENFORCEMENT_PINS` OFF → **Observed** (certificates are verified and the
verified height is exported only as `citrate_finality_verified_height`; the floor is not
raised and the `finalized`/`safe` RPC tags do not advance — they stay at genesis, see §4.6);
both ON → **Enforced** (the verified certificate raises the floor and the RPC tags follow the
verified `(height, hash)` pair, §4.6). On a mismatch or an invalid certificate the floor is not
raised, the RPC tags do not advance, the gadget is halted (`SkipReason::Halted`: it proposes
and signs nothing), an `error!` "CHECKPOINT FINALITY SAFETY STOP" with operator guidance is
logged, and the metrics `citrate_finality_halted`, `citrate_finality_certificate_mismatch_total`,
`citrate_finality_verified_height` and `citrate_finality_floor_height` are exported. A
mismatch stop clears only when the certified block becomes canonical on this node through
normal fork choice; an invalid certificate never clears automatically. "Reorg to the certified
branch if it can" is deliberately NOT implemented as a forced reorg (no safe path exists for
it yet): the node halts finality and alarms instead.

### 4.6 RPC surface
Add `finalized` and `safe` block tags to `eth_rpc.rs`. **There are ~8 block-tag parse sites,
not 2** (`:329, :832, :1662, :1683, :1886, :1897, :2555, :2616`) — all must learn the new
tags, so factor a single `resolve_block_tag` helper rather than patching each. The RPC layer
**cannot read the finalized height today** — plumb a handle (the same `finalized_height`
AtomicU64 / a `get_finalized_height()` on the api object) into the RPC context. `finalized`
resolves to the block at the finalized height; `safe` == `finalized` for a BFT gadget. Before
the first finalized checkpoint, resolve to genesis (block 0), never error. Closes
`verification/claims.json:127`, helps dim 8.

**Which height the tags read (Stage 1c, PR #323 review L2, chain-team ruling).** The tags
advance only where the floor is enforced. `FloorVerifier::rpc_finalized_handle` returns the
canonical applicator's floor handle in Legacy and Observed mode — neither raises it, so
`finalized`/`safe` keep resolving to genesis exactly as today — and the verified height only
in Enforced mode. In Observed mode a reorg below a verified certificate still proceeds, so
labelling that block "finalized" over RPC would claim a guarantee the node does not give; the
verified height is visible there only through the `citrate_finality_verified_height` metric
(with `citrate_finality_floor_height` and `citrate_finality_halted`). A read-only status RPC
(mode, verified height, floor, halted) is not added in this stage: the RPC crate has no
handle to the floor verifier, and the metrics carry the same data.

**Resolve by hash, not height (Stage 1c, PR #323 review R1).** The block store's height index
is not a canonical index: every stored block writes its height key, so the last block written
at a height wins — possibly an uncertified sibling of the certified block. In Enforced mode
the tags therefore read the verifier's verified `(height, hash)` pairs
(`citrate_api::finalized_tag::FinalizedTagSource::Verified`, recorded only on a verified,
matching certificate) and every block-lookup site (`eth_getBlockByNumber`,
`eth_getBlockTransactionCountByNumber`, `eth_getTransactionByBlockNumberAndIndex`, and the
newest block of `eth_feeHistory`) fetches the certified block BY HASH. If that block is not
stored locally, the previous verified pair is served, else genesis — never a sibling. Range
reads (`eth_getLogs`; `eth_newFilter` read through `eth_getFilterLogs` /
`eth_getFilterChanges`; the `eth_feeHistory` window) take the resolved pair's height as their
bound, and when a bound is `finalized`/`safe` every height at or below the certified height is
read from the certified chain: the selected-parent
chain followed back from the certified hash (the same chain `verify_certified_floor` checks
against), via `citrate_api::finalized_tag::range_block_hashes`. A height that chain steps over
has no block (no logs; empty-slot fee defaults); heights above the certified height, and
`latest`/numeric ranges, still use the height index. The walk is bounded: a range starting
more than `FINALIZED_RANGE_MAX_WALK` (10,000) blocks below the certified height is refused with
`-32602`. A log filter keeps the anchor it resolved at creation. The
state-read guard (`eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
`eth_getStorageAt`, `eth_call`, `eth_estimateGas`) additionally requires, for a verified pair,
that the applied tip (`BlockStore::get_applied_tip`) IS the certified hash before serving
latest state under `finalized`/`safe`. Legacy and Observed keep the height-only source, which
stays at genesis.

### 4.7 Config & remnants
- Plumb `CheckpointNodeConfig` (`config.rs:65`) → `CheckpointConfig` (today `main.rs:1767`
  ignores it and uses `default()`). Add `interval`/`committee_size` from node config; derive
  `quorum` (§3). Keep `chain_id` from the node's chain config, not the hardcoded 40204.
- Point checkpoint persistence at the dedicated `CF_CHECKPOINTS` column
  (`column_families.rs:27`, currently dead) or delete it and keep the `dag_metadata`
  `checkpoint:*` scheme — pick one, remove the dead one (D-6).
  **Stage 1c:** certificates stay in `dag_metadata` `checkpoint:*`. `CF_CHECKPOINTS` stays
  listed but unused: RocksDB refuses to open a database holding a column family the open call
  does not list, and every existing node database has it, so removing it needs a `drop_cf`
  migration first (not done here).

---

## 5. Safety & liveness properties (must hold; enforced by tests + TLA+)

- **S1 (no conflicting finality):** two checkpoints at the same height with different
  block_hash can never both reach quorum with an honest ≥2/3 committee.
- **S2 (no revert below finality / I4):** once checkpoint finality runs (not in effect
  today, no production caller), committed state is never reverted below
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
  propose/sign/broadcast and certificates are verified and exported as metrics, but the
  floor is observed, not enforced, and the `finalized`/`safe` RPC tags stay at genesis
  (§4.6: they advance only once enforcement is ON);
  (2) stand up the validator committee (§7); (3) observe healthy finalization on the fleet;
  (4) flip the compiled pin ON in a release once finalization is proven and late-joiners can
  fetch certificates (§ verifier-revisions #10). Existing state, addresses, balances
  untouched.
- The **reorg guard itself is already live and ungated** (`canonical_apply.rs:657`); what the
  pin gates is *raising the floor above 0*, i.e. whether finalized certificates actually
  constrain fork-choice.
- Two separate compiled pins (`core/consensus/src/checkpoint_gadget.rs`), both OFF for 40204:
  `CHECKPOINT_VOTING_PINS` (step 1: the producer path) and `CHECKPOINT_ENFORCEMENT_PINS`
  (step 4: a verified certificate raises the floor, §4.5). Enforcement without voting has no
  effect.

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
  runtime + boot, halt-not-pin on mismatch (§4.5). Resolved. Implemented in Stage 1c
  (`node/src/finality_floor.rs`, §4.5), behind the enforcement pin (OFF).
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
  finality actually runs. Add. **Stage 1c:** "running" now requires both compiled pins ON for
  40204, a non-test `sign_checkpoint_vote(` call, and a `node/src` file that builds
  `NetworkMessage::CheckpointVote { .. }` (not a match pattern) and calls `.broadcast(`; a
  missing pin table counts as OFF with a warning (`verification/tests/test_check_claims.py`).
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
