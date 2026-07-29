---
created: 2026-07-29
branch: main (working tree — uncommitted)
author: Claude (Opus 5), directed by @SaulBuilds
status: response — answers M-1 (consensus call, DGX's to make), corrects a blocking
  premise in the M-2 spec, and grades the Track A claims against source
relates:
  - citrate-core/docs/DGX_HANDOFF_CONSENSUS_AND_ALF_2026-07-28.md   (the ask)
  - citrate-core/docs/MEMBERSHIP_STAKE_LOCK_DESIGN_2026-07-28.md    (lock spec)
  - citrate-core/docs/adr/ADR-2026-07-27-membership-stakes-the-validator-bond.md
---

# DGX response — M-1 answered, M-2 premise corrected, Track A graded (2026-07-29)

Everything below is cited to source in `citrate-chain @ addfa95` and
`citrate-compute-pool @ working tree`.

---

## M-1 — CONSENSUS ANSWER: neither (a) nor (b). Take (c).

**Decision: consensus does not change. `ValidatorRegistry` stays the single source of
the proposer set. The vault becomes a custodial *bonding agent* that registers on the
member's behalf and holds the withdrawal keys.**

Consequence the owner asked for up front: **no reroll, no coordinated fleet activation
height, no node rebuild.** Track M becomes contract-only work.

### Why (a) — "consensus also honors `MembershipStakeVault.meetsRequirement`" — is rejected

Four independent blockers, any one of which is disqualifying:

1. **The vault has no proposer identity.** Consensus selects by 32-byte ed25519
   proposer pubkey (`ValidatorRegistry.sol:117` `_validators[pubkey]`,
   `core/consensus/src/crypto.rs:139-154`). The vault maps `address → shares`
   (`MembershipStakeVault.sol:142`). To honor it, the vault would need pubkey binding
   *and* ed25519 proof-of-key-control — i.e. a second validator registry living inside
   a money vault. That is strictly more new contract surface than option (c).
2. **It creates unslashable block producers.** Equivocation slashing operates on
   `bondedStake + escrow + vestedRewards` held *inside the registry*
   (`ValidatorRegistry.sol:420-426`). Vault value is stSALT in `LiquidStakingPool` —
   the registry cannot reach it. Worse, pool slashes are **socialized across all
   stakers** (`MembershipStakeVault.sol:40-49`), so slashing one equivocator would
   debit innocent stakers. VALIDATOR-S1's entire deterrent evaporates.
3. **It puts an off-chain oracle inside consensus.** `attributedStake =
   pool.previewWithdraw(shares)` (`MembershipStakeVault.sol:359-361`) floats with the
   pool's oracle-reported share price. Reading that at the epoch snapshot makes the
   proposer set a function of when an oracle report lands relative to S(E).
4. It is a real consensus **rule** change — a fleet-wide binary + coordinated
   activation height, and the one branch of this decision that could force a reroll.

### Why (b) — "the vault registers the member in `ValidatorRegistry` on grant" — is impossible as written

Right instinct, but it cannot be built literally:

1. **One staker address = one validator.** `registerValidator` reverts
   `StakerHasValidator()` when `pubkeyOfStaker[msg.sender] != 0`
   (`ValidatorRegistry.sol:243`, set at `:279`). A single vault contract can bond
   **exactly one member, ever**. This is the hard blocker.
2. **Timing.** Registration requires the member's ed25519 proposer key to sign a digest
   that binds the staker address (`ValidatorRegistry.sol:244-248`). At grant time — the
   moment of payment — the member has no node and no proposer key. Grant and bond are
   necessarily **two transactions**, not one.
3. **`staker = msg.sender` = the vault** (`:266`), and `claimRewards` (`:517`),
   `initiateUnbond` (`:298`), `withdraw` (`:325`) are all `v.staker == msg.sender`.
   Good for the lock — but the member's *rewards* then need an explicit forward path,
   or membership silently confiscates earnings.

### (c) — the design that works: custodial bond, member-controlled key, vault-controlled principal

1. **Per-member bond escrow.** On grant, the vault deploys a deterministic minimal-proxy
   `MemberBond` clone (CREATE2, salt = member address). The clone is the `staker` for
   that member's registry entry. This sidesteps the one-pubkey-per-staker limit
   *without touching a live consensus-critical contract*.
2. **`activate(pubkey, ed25519Sig)`** — member-callable through the app's
   SignatureCeremony once the node is synced; the clone calls
   `registerValidator{value: principal}`. The app signs the digest over the **clone
   address**, which is CREATE2-deterministic and computable before deployment.
3. **Rewards belong to the member.** Clone `claimRewards` → forwards to the member
   wallet. Only **principal** is locked. (`ripeRewards` are claimable while Active —
   `ValidatorRegistry.sol:92` — so this works with no registry change.)
4. **Lock + KYC live on the clone**: `initiateUnbond`/`withdraw` gated on
   `block.number >= unlockBlock` **AND** the SBT `kycVerified` read, KYC checked first
   per owner decision A.6. The registry's own `EXIT_LOCK_EPOCHS` stacks on top —
   defense in depth, not a conflict.
5. **Consensus reads nothing new.** Registry semantics, `activeSet()`, the epoch
   snapshot, and the equivocation path are all untouched.

### The honest cost of (c), and the alternative if the owner rejects it

(c) adds **one new contract type**, against the owner's "do NOT add new contracts."

The variant that honors that instruction literally: add a governance-set `custodians`
allowlist to `ValidatorRegistry`, exempt from `StakerHasValidator`. I do **not**
recommend it:

- it mutates a live T1 consensus-critical contract;
- it breaks a stated invariant that is asserted in the suite
  (`contracts/test/invariant/ValidatorRegistryInvariant.t.sol:288`, "staker->pubkey
  binding");
- `ValidatorRegistry` is `Governable` with an `immutable rewardMinter` — **not
  upgradeable**. Changing it means redeploy + re-pin + **all four live validators
  re-register** + a node env change across the fleet.

Strictly more disruptive than one clone. **Owner's call; my recommendation is (c).**

---

## M-2 — a blocking correction before any of the three items

**The lock spec's premise that the vault stakes the grant into `LiquidStakingPool` is
incompatible with owner decision A.1 ("the locked 32k IS the validator bond").** The
same 32k cannot be simultaneously pool-staked as stSALT and bonded as native
`msg.value` in the registry. `grant()` deposits into the pool today
(`MembershipStakeVault.sol:221`).

So M-2 gains a **step zero**, and it reorders the rest:

- **M-2.0 (new, blocking).** Replace the pool-deposit leg with the bond-escrow leg.
  This changes what `attributedShares` / `attributedStake` / `isValidatorEligible`
  *mean* — they can no longer be stSALT previews. Do this before the UUPS conversion,
  not after, so the storage layout is frozen once and only once.
- **M-2.1 UUPS.** As specified. `immutable pool` (`:131`) disappears with M-2.0, which
  removes one of the two immutables that block initialization anyway.
- **M-2.2 `unlockBlock` = `grantBlock + LOCK_BLOCKS`.** `LOCK_BLOCKS` needs the
  **measured** 40204 block time — I have not measured it and will not guess it. That
  number is an input to the contract, so it gets measured against live 40204 before the
  constant lands.
- **M-2.3 KYC gate.** Recommend spec option (i), the SBT attestation — `CitrateMemberSBT`
  is in this same contract set (`contracts/src/core_membership/CitrateMemberSBT.sol`),
  so adding and reading a `kycVerified` flag is in-repo work, not a cross-team
  dependency.

Two of the vault's own open questions change shape under (c) and should be re-answered
rather than carried forward: **Q3** (clawback) and **Q6** (who owns value above nominal
principal — under bonding, rewards are a separate registry-held bucket, so Q6 largely
dissolves).

---

## Correction to the brief: the vault is CREATE2, not nonce-based

The handoff says "the vault is nonce-based, so a new (upgradeable) deployment gets a NEW
address". The conclusion is right, the reason is wrong, and the difference changes the
checklist.

`contracts/script/DeployCoreMembership.s.sol:20-22` deploys both the SBT and the vault
through the **genesis Arachnid factory** via `new X{salt: Salts.salt("X")}(…)`, so each
address is a pure function of `(salt, init_code)` — explicitly "reroll-stable". A chain
reroll therefore does **not** move the vault.

What moves it is changing the **init_code** — which is exactly what M-2 does (new
bytecode for the lock, and a changed constructor/initializer arg once `pool` stops being
`immutable` under UUPS). The script's own comment at `:44` says as much: change a
constructor arg and "the SBT + vault CREATE2 addresses MOVE".

Practical consequences for the M-2 landing checklist, beyond the re-pin already listed:
- update the CREATE2 tripwire `contracts/test/core_membership/CoreMembershipCreate2.t.sol`,
  which pins the expected addresses and will fail closed on the move (working as intended);
- re-pin `contracts/addresses/40204.json`, then re-run the consumers' generated books —
  `citrate-core/scripts/sync-addresses.py` embeds them at compile time, so a desktop build
  carries whatever it was built with;
- the droplet treasury-signer env and core-membership's pins move with it.

Under UUPS the address moves **once**, on this deployment; every later change is an
in-place upgrade behind the proxy. That is the payoff for doing M-2.1 first.

## M-3 — audit

Agreed: T1 money, independent @rule8 audit before deploy. Note the audit scope under
(c) is *larger* than the handoff assumed — it covers the clone factory and the
clone↔registry interaction, not just the vault.

---

## Track A — claims graded against source

- **A-2 "training-worker is an event logger only" — CONFIRMED, and understated in one
  direction.** `citrate-compute-pool/training-worker/src/bin/main.rs:14-16` says so in
  its own header; the loops poll and `dispatch_logs` only logs (`:294-298`). But
  `worker.rs`, `candle_backend.rs`, `pipeline.rs` and five integration tests
  (`tests/four_stage_pipeline_happy_path.rs` et al) all exist. **A-2 is wiring, not
  greenfield.**
- **A-1 "no coordinator" — CONFIRMED for training, but there is a production pattern to
  port.** `citrate-compute-pool/pool-coordinator` is a real ~4.6k-line binary that
  already does epoch-elected coordination and provider dispatch — but against
  `ComputePool.ComputeRequested`, i.e. **inference** (`pool-coordinator/src/main.rs:1-8`;
  zero `training`/`ComputePoolTraining` references anywhere in its sources). A-1 should
  be scoped as a port to `ComputePoolTraining`, not a new service.
- **A-3 / A-4 — not verified.** I did not inspect `ContributionAccounting` or the coop
  instantiation path. Stating that plainly rather than echoing the handoff.

Track A shares no file and no contract with Track M and does not block it. It needs its
own sprint.

---

## What I need from the owner

1. **(c) vs the `custodians` variant** — one new clone contract, or mutate the live
   `ValidatorRegistry`. My recommendation is (c).
2. **Go/no-go on building M-2** (T1 money contract, red/green then audit) — and whether
   that jumps the queue ahead of Track A.
3. **Confirmation that rewards are the member's** and only principal is locked. The
   handoff never says this explicitly, and (c) forces the question into the open.
