---
title: "VALIDATOR-S1 — Stake-gated proposer eligibility (SPEC v2, post-adversarial-round-1)"
created: 2026-07-16
author: Claude Opus 4.8 (consensus owner, for @SaulBuilds)
status: DRAFT v3 — round-1 closed + D1-D4 resolved (rewards/cap/beacon/immutable); in round-2 red-team
chain: 40204
supersedes: VALIDATOR_S1_SPEC_v1.md
round1_findings: 4 red-teams, ~30 findings; 8 CRITICAL. This v2 resolves each (mapping in §11).
---

# VALIDATOR-S1 v2 — Make staking gate the validator SET (not a per-slot lottery)

## 0. The core reversal (why v1 was wrong)
v1 tried to enforce a **stake-weighted per-slot VRF lottery** at block admission.
Round-1 proved that halts a small fleet: with 4 equal validators, ~0.7⁴≈24% of
(parent,height) pairs have **no** eligible proposer, and because the VRF is
deterministic per (key,parent,height), that tip is **permanently unextendable** →
halt within ~4 blocks. **v2 enforces MEMBERSHIP only**, and makes per-slot leadership
a deterministic producer-side schedule (never an admission hard-gate).

## 1. The enforced consensus rule (Layer A — membership, integer-only)
For a block `B` at `height h` with `epoch E = h / EPOCH`:
- **Admissible iff** `B.proposer_pubkey ∈ activeSet(E)` AND `stake(pubkey,E) ≥ minStake`,
  where `activeSet(E)` / `stake` are read from the registry at the **finalized snapshot
  block `S(E)`** (§3). No lottery, no float, no threshold. Pure set membership.
- The existing ECVRF + ed25519 identity binding (`verify_vrf_with_block_signature`)
  still runs (proves the proposer controls the key + unspoofable). We KEEP the VRF
  reveal (it seeds `prevrandao`), but it is **not** an eligibility gate.
- GHOSTDAG continues to order/ finalize among the active set exactly as today.

Result: staking gates *who may be a validator at all*; within the active set, block
production is the existing permissionless DAG. This is livenesssafe for any set ≥ 1.

## 2. Per-slot leadership (Layer B — SOFT, producer-side, deterministic)
To avoid every active validator racing every slot (bandwidth/orphans), the *producer*
(`node/src/producer.rs`) only seals when it is the scheduled leader:
- `leader(h) = activeSet(E)[ h mod |activeSet(E)| ]` after sorting the set canonically
  (by pubkey bytes). Deterministic round-robin, weighted later if desired.
- **Liveness fallback:** if the scheduled leader is silent for `SLOT_TIMEOUT` (e.g.
  2 slots), the next-in-order validator may seal (deterministic backup order). This is
  a *soft* rule — a block from a non-scheduled but *active* validator is STILL admissible
  (Layer A only checks membership), so a stalled leader never halts the chain.
- No `time_factor`, no `1/sqrt(stake)`, no HashMap iteration in any consensus path.

## 3. Deterministic epoch snapshot (fixes replay/reorg/off-by-one splits)
- `EPOCH = 1000` blocks. `epoch(h) = h / EPOCH` (integer). Half-open `[E·EPOCH,(E+1)·EPOCH)`.
- `activeSet(E)` is read at the **finalized block hash** on the selected-parent chain at
  DAA-height `S(E) = E·EPOCH − SNAPSHOT_LAG`, with `SNAPSHOT_LAG = 2·FINALITY_DEPTH = 200`
  (> max reorg depth, with margin). The snapshot is a **block hash**, not a bare height,
  so all nodes read identical state. For `E·EPOCH < SNAPSHOT_LAG` (genesis era) → use the
  **genesis-seeded set** (§6).
- Eligibility for block `B` is a PURE FUNCTION of `B` (via `epoch(B.height)`), evaluated
  against an **immutable, epoch-indexed** set — never a hot-swapped mutable selector.
  Node keeps `BTreeMap<epoch, Arc<ActiveSet>>` (retain ≥ 2 epochs + current).
- Registration/exit effective-epoch is computed against the SNAPSHOT boundary, not the
  raw epoch: a tx at block `b` is effective at the first `E` with `S(E) > b` (so no
  validator is promised activation the snapshot can't see). One canonical `epoch()`/`S()`
  shared by contract and node (asserted by a cross-check test).

## 4. Enforcement activation = a consensus HEIGHT rule (not a per-node toggle)
- Enforcement is gated on `block.height ≥ ACTIVATION_HEIGHT`, a constant baked into
  genesis params / the binary — evaluated **identically on every node**, independent of
  restart order or whether a selector object is attached. Below it: legacy behavior.
- Delete reliance on `proposer_selector.is_some()` as the enforcement switch. Past
  `ACTIVATION_HEIGHT` the node **fails closed**: if it cannot materialize `activeSet(E)`
  for a block's epoch, it refuses to admit (never silent-accept), and refuses to *produce*
  until it has the set.
- Integer eligibility everywhere; `production()` (legacy-VRF cutoff = 0) forced in ALL
  constructions incl. the admission fallback (fixes the post-reroll 100k forgeable window).

## 5. Kill-switch (consensus-free recovery)
- A node config `CITRATE_ELIGIBILITY_ENFORCE={auto|off}` (default auto). `off` makes the
  node treat height as < ACTIVATION_HEIGHT (membership check skipped) WITHOUT a new binary.
  Recovery from a bad activation = restart the fleet with `off` (coordinated, all 4) — no
  block needed, no second reroll. Rehearsed on a local devnet before any live flip.
- Governance `minStake` is timelocked with a bounded per-change delta (can't be yanked to
  0/∞ right before a snapshot to flood/empty the set).

## 6. Genesis seeding (fixes the height-1 bootstrap deadlock)
- The reroll genesis **pre-populates `ValidatorRegistry` storage** (state trie) with the
  fleet (boot1/2/3 + rpc-1): their proposer pubkeys, `stake = minStake`, `status=Active`,
  `activationEpoch=0`. So `activeSet(0..)` is non-empty from block 0 — the chain can
  produce block 1 without needing a tx first. (Genesis today seeds NO set — this is a new
  genesis step, added to `core/economics/src/genesis.rs` + `regenesis.sh`.)
- Ordering invariant for any FUTURE registry redeploy without a reroll: deploy → register
  fleet → confirm `activeSet` populated + finalized → only THEN may `ACTIVATION_HEIGHT` pass.

## 7. On-chain: `ValidatorRegistry` (hardened)
Immutable logic, **no owner path** that can create/remove validators or set stake
(consensus-capture backdoor closed). Only privileged surface = timelocked `setSlasher` +
governance `minStake` (both delayed). All value moves CEI + `nonReentrant`.

- `registerValidator(bytes32 proposerPubkey, bytes ed25519Sig)` payable:
  - `msg.value ≥ minStake` (exact `≥`; no dust; bond custodied by the registry itself —
    NOT read from LiquidStakingPool, closing the withdraw-race).
  - **Proof of key control:** verify `ed25519Sig` over an **EIP-712** struct
    `Register{chainId, verifyingContract=this, staker=msg.sender, proposerPubkey, nonce}`
    using a **NEW ed25519-verify precompile** (§8) — NOT ecrecover (wrong curve). `nonce`
    = per-staker `registrationNonce++` (kills cross-registry + re-registration replay).
  - **Global pubkey uniqueness:** revert if `proposerPubkey` already bound (kills the
    node-map collision / double-weight split).
  - **Permanent ban:** revert if `slashedPubkey[pubkey]` or `slashedStaker[staker]`
    (no slash-laundering by re-registering).
  - **Set admission = top-N-by-stake** (`MAX_ACTIVE_SET=100`): if full, a new registrant
    must out-stake the current minimum, which is evicted (anti dust-stuffing DoS). Active
    set stored as a bounded, canonically-ordered enumerable structure (cheap `activeSetAt`).
  - `activationEpoch = firstEpochAfterSnapshot(block.number)` (§3).
- `increaseStake()` payable: only if `status==Active` (not while Exiting).
- `initiateUnbond(amount)`: leaves exactly `0` (→ Exiting) or `≥ minStake`; never a
  sub-minStake zombie. Sets `exitEpoch`. Funds locked ≥ `UNBOND_PERIOD`.
- `withdraw()`: `nonReentrant`, CEI, requires `status != Slashed` AND no open evidence
  window AND `now ≥ exitEpoch + UNBOND_PERIOD`. Sets `withdrawn` before transfer.
- `slash(pubkey, tier, evidence)`: only `msg.sender == slasher`; reaches funds in Active
  AND Exiting-not-withdrawn; sets `status=Slashed` + `slashedPubkey/Staker` permanent.
- **Slasher seam:** extend `NematocystSlashing` with a governance/permissionless-evidence
  entrypoint that forwards to `registry.slash`. `slasher` set immutable to that contract,
  with a governance-**timelocked** `setSlasher` escape hatch (so a bad wiring is
  recoverable without a reroll). Non-empty `evidence` + bounded `tier` required.
- `UNBOND_PERIOD ≥ ACTIVATION_DELAY + 2·FINALITY_DEPTH + MAX_EVIDENCE_LATENCY` so no
  stake-then-exit-before-slash. Equivocation evidence path is **permissionless w/ bounty**
  (anyone submits a double-sign proof → slash), so misbehavior is punished automatically.
- Views: `activeSetAt(E) → (pubkey,stake)[]` canonical order (sorted by pubkey), bounded
  ≤ MAX_ACTIVE_SET, enumerates ACTIVE only (not history) — cheap, deterministic `eth_call`.

## 8. Companion chain changes (I own these; fold into the reroll)
1. **ed25519-verify precompile** (new, e.g. `0x0121`): `verify(pubkey32, msg, sig64)→bool`,
   deterministic, gas-metered. Required for on-chain proposer-key-control proof (§7). Uses
   `ed25519_dalek` already in-tree (`consensus/src/types.rs:84`).
2. **Integer eligibility**: rewrite `is_eligible_proposer`/remove `calculate_threshold`/
   `vrf_output_to_float`/`select_proposer` f64 → membership check + integer round-robin.
   Delete `time_factor` + `1/sqrt(stake)`. Guard `total_stake==0`/`stake==0` explicitly.
3. **Height-gated enforcement** in `dag_store.rs verify_block_vrf_crypto` + attach the
   epoch-indexed set materializer in `node/src/main.rs` (not a test-only `with_proposer_selector`).
4. **Genesis set seeding** (`genesis.rs` + `regenesis.sh`).
5. **`production()` cutoff=0** in all node constructions incl. the fallback.
6. **Kill-switch config** (§5).
7. **Producer leader-gating** (`producer.rs`) — seal only when scheduled leader / after timeout.

## 9. Parameters
`minStake=32_000 SALT` (gov, timelocked). `EPOCH=1000`. `SNAPSHOT_LAG=200`.
`ACTIVATION_DELAY=1 epoch`. `UNBOND_PERIOD=` per §7 formula (≥ ~3 epochs). `MAX_ACTIVE_SET=100`.
`SLOT_TIMEOUT=2 slots`. `ACTIVATION_HEIGHT=` set post-reroll after fleet seeded/finalized.

## 10. Activation plan (halt-proof)
1. Build all §8 pieces behind `ACTIVATION_HEIGHT`/kill-switch (chain PR, security review @rule8).
2. **Local devnet rehearsal**: (a) prove membership enforcement admits fleet, rejects a
   non-registered proposer; (b) HALT DRILL — force empty set, confirm kill-switch recovers
   with no reroll; (c) ROLLBACK DRILL. Acceptance = both drills pass.
3. **Shadow on live chain** using the EXACT enforcement function (record verdict, don't
   act). Acceptance = **zero would-be self-rejections of the fleet's blocks over ≥N epochs**
   (any self-rejection = a v1-class halt pre-manifesting → do not flip).
4. **Reroll = cutover**: genesis seeds the fleet set (§6); `ACTIVATION_HEIGHT` = a low height
   AFTER genesis (set is present from block 0, so any height works); `production()` forced;
   integer math. Zero live-chain fork risk; enforcement correct from block 0.

## 11. Round-1 findings → resolution map
- Determinism f64 (C3/F4/#9): §1,§8.2 integer-only. ✓
- Lottery halts fleet (C4/#1): §0,§1 membership-only; §2 soft round-robin. ✓
- Per-node toggle fork (C1/C6/#2): §4 height rule; §3 immutable epoch-indexed set. ✓
- Snapshot ambiguity/off-by-one (C2/C10/F6): §3 finalized-hash snapshot + shared epoch fn. ✓
- Genesis bootstrap deadlock (#4): §6 genesis-state seeding. ✓
- Legacy VRF re-open (C7/#5): §4/§8.5 production() forced + reroll gate. ✓
- total_stake drift/inf/NaN (C8/#6): §3 fresh rebuild + §8.2 integer guards. ✓
- Sybil/time_factor/sqrt (F1/F7): §2 delete both; membership not lottery. ✓
- ed25519 key-control on EVM (F2-contract): §8.1 new precompile + §7 EIP-712. ✓
- Replay (F3-contract): §7 EIP-712 domain + per-staker nonce. ✓
- Pubkey uniqueness / slash-launder (F4-contract): §7 uniqueness + permanent ban. ✓
- Slasher seam missing (F5-contract): §7 NematocystSlashing forward + timelocked setSlasher. ✓
- Unbond outruns slash (F1-contract/F6-econ): §7 UNBOND formula + status-gated withdraw + auto-evidence. ✓
- Owner backdoor (F7-contract): §7 immutable, no owner inject. ✓
- Set-stuffing / view DoS (F8-contract): §7 top-N-by-stake + bounded active enumeration. ✓
- No kill-switch (#8): §5. ✓
- Shadow false-confidence (#3): §10.3 exact-function shadow + self-rejection acceptance. ✓
- Grinding via chosen parent (C9/F3-econ): open — §12.

## 12. Owner decisions — RESOLVED (2026-07-16)
D1 rewards = YES (build now, fully configurable). D2 stake cap = YES (≤ 1/3).
D3 epoch beacon = YES (include now). D4 immutable + timelocked minStake/slasher = CONFIRMED.
Detailed designs below (§R, §C, §B).

## §R — Full-node rewards (D1) — fair, equitable, CONFIGURABLE
Design goal: every *full validator node* in the active set earns for the work of
proposing + participating, sized so honest participation is EV-positive at expected
win rate. All amounts are **governance params (timelocked, bounded delta)** so the
reroll's 1-trillion-SALT max-supply tokenomics can retune them without a code change.

- **Two components, both paid to the block's admitted proposer:**
  1. **Block subsidy** `blockSubsidy` (gov param; starts small — set at reroll from the
     1T emission schedule). Minted per admitted block. MUST be bounded by a governance
     **emission cap** (`maxAnnualEmission`) so a misconfig can't hyperinflate.
  2. **Priority-fee share** — the proposer receives `priorityFeeShare` (gov param, e.g.
     50%) of the block's priority fees; the remainder is burned/treasury per the existing
     fee policy (do NOT double-count base fee).
- **Equity across full nodes (anti-centralization):** rewards accrue **pro-rata to blocks
  actually admitted** under the §2 round-robin, which is stake-*membership* based, not
  stake-*weighted* — so a minStake node and a whale node in the set earn per block equally
  for the blocks they propose. Round-robin gives each active validator an equal share of
  slots ⇒ equal expected reward per node (not per token). This is the "fair to all full
  nodes" property. (If we later want stake-weighted slot allocation, it's a gov flag —
  default = equal.)
- **Determinism:** reward computation is integer-only, a pure function of
  `(blockSubsidy@epoch, priorityFeeShare@epoch, block priority fees)` — all read from the
  **epoch snapshot** governance values (not the live tip), so every node computes the same
  issuance and the state root matches. NO float.
- **Reward can't be gamed (see round-2 targets):** paid ONLY to a proposer that passed
  Layer-A membership; empty/spam blocks earn only the subsidy (priority fees require real
  fee-paying txs); no self-tx fee-wash profit because the proposer's own priority fees net
  to ~0 after paying them. Subsidy is flat per block regardless of tx count → no incentive
  to stuff. Reward accrues to the registered `stakerAddress`, not an arbitrary coinbase.
- **Accounting:** rewards credited on-chain to `stakerAddress` (claimable), or auto-added
  to bonded stake up to a cap (gov flag). Slashed validators forfeit unclaimed rewards.

## §C — Max-stake-share cap (D2)
At the epoch snapshot, each identity's **effective stake** used anywhere (weighting, and
if D-later stake-weighted slots) is capped at `min(actualStake, floor(total_stake/3))`.
Enforced in the deterministic set build (integer). With round-robin slots (equal), the
cap mainly bounds any future stake-weighting and governance vote weight; it also caps a
whale's economic dominance signal. Canonical, integer, snapshot-fixed.

## §B — Per-slot / VRF randomness beacon (D3)
Per-slot randomness (and the `prevrandao` seed) derives from the **finalized epoch beacon**
`beacon(E) = VRF_output_of_block(S(E))` (the snapshot block), NOT the proposer-chosen
selected-parent VRF. `leader(h) = activeSet(E)[ keccak(beacon(E), h) mod |set| ]` (integer,
deterministic, un-grindable within the epoch — the proposer cannot shop parents to change
who leads). Beacon is fixed for the whole epoch and known to all nodes from the finalized
snapshot ⇒ no nothing-at-stake grinding of leadership (closes C9/F3-econ).

## §D — Governance/ownership (D4, CONFIRMED)
`ValidatorRegistry` logic is **immutable / non-upgradeable**; NO owner path creates/removes
validators or sets stake. The ONLY privileged surfaces are governance-**timelocked**:
`minStake`, `blockSubsidy`, `priorityFeeShare`, `maxAnnualEmission`, `setSlasher` — each
with a mandatory delay + bounded per-change delta so nothing can be yanked right before a
snapshot. All governance changes take effect at an epoch boundary (snapshot-read), never
mid-epoch.

---
# v4 — Round-2 resolutions (supersedes the amended parts above)
Round-2 (3 red-teams) found 3 NEW criticals from v3's own additions + confirmed the
round-1 code fixes are not yet in the binary. v4 closes each. status → v4.

## §R' Rewards (rewritten — fixes hyperinflation F1, sybil F2, empty-block F3, claim-bypass F4, reorg double-mint H-1, f64 H-2, priority-fee H-3)
- **Per-HEIGHT, selected-chain only.** One subsidy budget per height, credited only to the
  selected/blue block at that height on linearization — NEVER per raw DAG block. Idempotent
  per canonical `(height, blockHash)`; minted inside the same state batch a reorg reverts.
  Kills the k=18 DAG-width multiplier + reorg double-mint.
- **On-chain emission meter.** `emitted(E)` accumulator in registry state; once
  `emitted(E) ≥ epochBudget(maxAnnualEmission)`, subsidy = 0 for the rest of E. Hard cap,
  integer, enforced (not a passive param).
- **STAKE-WEIGHTED, not equal-per-node.** Reward ∝ the proposer's **capped effective stake**
  (§C', per beneficial owner). This makes splitting neutral (F2 sybil dies) and is the
  equitable answer: every full node earns proportional to its (capped) contribution, with
  the minStake floor guaranteeing small nodes a real share. "Equal-per-node" from v3 is
  REMOVED (it was the sybil subsidy).
- **Reward VESTS into the slashable bonded balance, locked ≥ UNBOND_PERIOD** (subject to
  slash/claw-back). No instant unslashable claim (F4).
- **Useful-work / anti-censorship gate.** Subsidy requires mergeset-completeness: the block
  must reference all blue tips it could have (GHOSTDAG knows the should-reference set);
  non-referencing forfeits subsidy (F3/F6 censorship). Empty blocks still get 0 priority-fee
  reward; subsidy alone is stake-weighted + capped so empty-spam is not profitable.
- **Priority fees must be BUILT** (they don't exist today — execution sends 100% to void).
  Define `priority = min(gas_price − base_fee, cap) × gas_used` with `checked_sub` (reject if
  `gas_price < base_fee`); accumulate priority separately from base; proposer gets
  `priorityFeeShare (<100%, gov)` of the priority pool via **strict reallocation** of the
  already-charged fee (remove the current send-to-void so no wei is both burned and minted);
  base burned/treasury. Integer-only; a dedicated path — **delete the `enhanced_rewards.rs`
  f64/reputation/congestion path** from the consensus reward (H-2).
- **Beneficiary = registry `stakerAddress`** looked up by `proposer_pubkey`, NOT
  `header.coinbase`; importers reject a block whose credit ≠ registry stakerAddress.
- Configurability: `blockSubsidy, priorityFeeShare, maxAnnualEmission` are gov params with
  absolute floor/ceiling (§D') for the coming 1-trillion-SALT schedule.

## §B' Beacon + leadership (rewritten — fixes single-block grind F5/#1, §2↔§B contradiction)
- **Leadership = equal round-robin `leader(h) = activeSet(E)[ h mod |set| ]`** (canonical
  sort by pubkey). Deterministic, exactly equal, UN-grindable. This is the sole leader
  function (delete the v3 `keccak(beacon,h)` form — it was multinomial + grindable).
- **Beacon is a RANDAO-style accumulator**, used ONLY to seed `prevrandao` (application
  randomness), NOT leadership: `beacon(E) = fold(vrf_reveal.output over finalized
  selected-chain blocks in [S(E)−EPOCH, S(E)))`. No single proposer controls it (marginal
  last-revealer influence = withhold-only, ≤1 bit per controlled slot).

## §7' Registry hardening (adds: eviction-capture C-1, fake-proof slash C-2, ed25519 canon C-3, ratchet H-4)
- **Seed the fleet at `genesisBond = k·minStake`, k ≥ 4** (not exactly minStake), so it can't
  be out-staked at the floor. **No eviction of an active, producing member** by marginal
  over-stake; a newcomer to a FULL set must exceed the incumbent-min by `EVICTION_MARGIN`
  (gov, ≥25%) AND eviction is rate-limited by a **per-epoch churn cap** (max evictions/epoch).
  Eviction ordering uses **actual bonded stake**, not capped effective.
- **minStake absolute floor/ceiling** in immutable code (not just bounded delta); **active
  validators grandfathered** against minStake increases (an increase applies to new/next-
  activation only, never demotes a sitting member) — kills the governance ratchet (H-4).
- **Slash requires a real double-sign proof verified ON-CHAIN:** two headers `H1,H2` with
  `H1.height==H2.height`, `proposer==pubkey` for both, `hash(H1)!=hash(H2)`, and BOTH ed25519
  sigs valid (strict, via the precompile) over the canonical header preimage. Dedup by
  `usedEquivocation[keccak(sorted(h1,h2))]`. No "evidence.length>0" trust. Bounty paid from
  the **slashed stake, ≤10%**, self-submission excluded (kills fake-proof griefing C-2 +
  bounty-farming M-3). Slash reaches Active + Exiting-not-withdrawn funds AND unvested rewards.
- **ed25519 canonicalization:** precompile uses `verify_strict`; registration rejects
  non-canonical + small-order/torsion pubkeys and **stores the canonical 32 bytes** as the
  uniqueness/ban key (kills encoding-variant ban/uniqueness bypass C-3). Node block-verify
  (`crypto.rs`/`vrf.rs`) harmonized to `verify_strict` so on-chain == consensus.

## §8.1' ed25519 precompile placement
Address MUST live in a ROUTED precompile page (extend `is_precompile` + `execute_pure` +
`PURE_PRECOMPILE_ADDRESSES` + the routing test) — `0x0121` is currently UNROUTED → a CALL
would hit an empty account and silently "succeed" (M-2). Fixed gas, validate `len==32/64`,
return false (never panic) on malformed input; pin `ed25519-dalek`/`curve25519-dalek` versions.

## §5' Kill-switch (fixes per-node-toggle fork #4)
Enforcement-pause is a **consensus-visible governance record** ("enforcement suspended for
heights [H1,H2]", in genesis params / a system contract), evaluated identically by every
node — NOT a per-node env var. If too heavy for beta: DELETE the env override and accept that
recovery from a bad activation is a coordinated reroll (already rehearsed §10). No local
consensus-rule toggle.

## §6' Genesis seeding (fixes dual-source split #5)
ONE materializer: the node ALWAYS reads the set through the deployed `activeSetAt()` getter,
including at genesis (read genesis-seeded storage through the getter) — no separate genesis-
set code path. Genesis sets the registry account's **code AND storage atomically** at the
canonical address. Cross-check test: `genesis_seeded_set == activeSetAt(0)` byte-identical
(extend the shared `epoch()/S()` test).

## §1' Equivocation (fixes sibling-flood #6)
Admission REJECTS the 2nd+ distinct block from the same `(proposer, height)` (turn the
read-only `detect_equivocation` into a bounded hard reject) — caps a proposer's own
duplicates without touching cross-validator liveness (does not reintroduce the v1 halt).

## §3' Snapshot finality (fixes heuristic-depth split #7)
Anchor `S(E)` to a **BFT checkpoint** (`CheckpointManager`), not heuristic depth-finality, so
all honest nodes provably agree on the snapshot block hash. Size `SNAPSHOT_LAG` against the
checkpoint interval. If BFT checkpoints aren't available that deep, document the residual as
depth-finality-bounded and set lag accordingly.

## §C' Cap
Per **beneficial owner** (not msg.sender). Capped effective stake used for reward-weighting +
governance signal only; **actual bonded stake** used for eviction ordering + withdrawal.
Guard `total_stake==0`. Note: with ≤3 validators the 1/3 cap is a no-op — capture is bounded
by the §7' churn-cap + margin + genesisBond, not by §C.

## Governance param reads (fixes M-1)
A gov value is in force for epoch E iff its timelock `ETA ≤ block(S(E))`. ALL consensus reads
(eligibility, reward, cap, minStake) read as-of the finalized snapshot `S(E)` — never the tip.
Same cross-check test as §3.

## ⚠ Spec-only vs code (reviewers flagged)
Round-1 CRITICALs C3(f64)/C7(legacy-VRF fallback `new()` at dag_store.rs:509)/C8(total_stake==0)
are still LIVE in the binary. They close ONLY when §8 code lands + the determinism cross-check
tests pass. "Resolved" in the maps means "design-resolved"; the gate for the reroll is
CODE-resolved + drills green.

## v4 residual risk = implementation-level, not design
Architecture has converged (membership-only, height-gated, integer, immutable registry,
per-height stake-weighted capped rewards, RANDAO beacon, on-chain-verified slash). The
remaining risks (determinism, precompile routing, reward mint accounting, priority-fee build)
are CODE-level — closed by implementation + the mandated harness (determinism cross-checks,
halt/rollback drills, exact-function shadow mode), which is where a final review should target
the actual diff, not more prose.
