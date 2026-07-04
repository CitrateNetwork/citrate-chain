---
created: 2026-07-04T00:00:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Fable 5
status: draft
program: VALIDATOR (new program — desktop validators; the largest of the NATIVE-R1 wave)
code: VALIDATOR-S1
repos: citrate-chain (consensus/execution) + citrate-gui-native (embedded node, onboarding UX)
companion: ../../../handoffs/CITRATE_NATIVE_REVAMP_MASTER_BRIEF.md (§5 honest participation, §10.2)
depends-on: 2026-07-04-econ-s1-emission-config.md (min-stake 3,200 + new emission + producer redeploy land FIRST)
ratified: 2026-07-04 — owner: pursue real desktop validators; ~3.2M SALT grant budget / first 1000 validators; min_validator_stake → 3,200; Sybil resistance = AUTHSPINE KYC gate on grant claims
---

> **Status (2026-07-04): DRAFT — planset written now, execution follows ECON-S1.**
> Source of truth: `handoffs/CITRATE_NATIVE_REVAMP_MASTER_BRIEF.md` §5. This is a
> **consensus program, not a UI sprint**, and the largest program in the wave: it
> turns "everyone who opens the app adds to the node count and earns visibly" from
> marketing into consensus reality. Phase gates are hard: no phase starts before the
> previous gate is signed.

# Planset — VALIDATOR-S1: real desktop validators

> **Goal.** The embedded node in citrate-gui-native becomes a true validating node —
> executes transactions, verifies state roots, participates in VRF proposer election
> with real stake — funded by a KYC-gated bootstrap grant (one KYC'd identity = one
> 3,200 SALT grant, first 1000 validators), with earnings the dashboard can display
> **honestly**.

## Current truth (verified in brief §5, 2026-07-04)
- The embedded node **syncs and stores only**: `citrate-gui-native
  desktop_app/src/services/node_service.rs:446–494` stores blocks without executing
  them — no tx execution, no state-root verification, no block production, no reward.
- Block production is VRF+stake gated and in practice done by the single sequencer.
- **Security hole to close:** `proposer_selector` is `Option` and **unenforced when
  `None`** — a node without a selector configured skips proposer-eligibility
  enforcement. Desktop validation cannot ship over that hole.
- Dashboard "SALT earned" = session balance delta (`main.rs:2940–2957`) — cosmetic.
- At the ECON-S1 emission (0.00001 SALT/2s block) the block-reward trickle is
  **symbolic**; the honest earnings story is **grant + contribution streams**
  (ContributionAccounting, compute opt-in, PIN pinning), which remain complementary
  and ship first.

## Scope (in)
ADR for the participation/security model; execute+state-verify in the embedded
node; VRF proposer participation incl. closing the `proposer_selector: None` hole;
the 3.2M SALT bootstrap grant program (AUTHSPINE-gated); in-app validator
onboarding; honest earnings accounting + display.

## Scope (out) — honest boundaries
- **Emission/config/min-stake changes** — ECON-S1 (hard dependency, lands first).
- **Delegation / staking pools / mobile validators** — not in S1.
- **Full slashing economics** — the ADR must *specify* the liveness/fault model, but
  implementing slashing beyond what the ADR marks launch-blocking is a follow-on
  sprint (VALIDATOR-S2 candidate).
- **Real network-node-count metric** (peer census/registry, brief §5 last bullet) —
  tracked, but only the interim fix ships here: stop labeling balance-delta as
  "earned" (Phase 4).
- **PIN/compute contribution rails themselves** — separate programs (NATIVE-R1-S3,
  SELL); Phase 4 only *reads* them for display.

## Phase gates + work packages

Acceptance criteria name their data source per Rule 11. **Each gate = owner
sign-off recorded in gates.yaml before the next phase starts.**

### Phase 0 — ADR first (gate G0) · repo: citrate-chain
| WP | Title | Acceptance |
|---|---|---|
| **WP-1** | **ADR-desktop-validator-participation** — the participation/security model: what a desktop validator must execute/verify; VRF election rules for intermittent (laptop-lid) validators; **mandatory enforcement when `proposer_selector` is `None`** (fail-closed, not skip); liveness expectations + fault handling; grant Sybil model (one-KYC-identity-one-grant via the AUTHSPINE entitlement claim); grant disbursement mechanism (contract vs treasury-multisig) — decided, not deferred | ADR merged + red-teamed; every later WP in this planset cites the ADR section it implements. **Source:** the ADR document itself + red-team notes. **This WP blocks all others.** |

### Phase 1 — Execute + state-verify (gate G1) · repos: chain + gui-native
| WP | Title | Acceptance |
|---|---|---|
| **WP-2** | Embedded node executes transactions and verifies state roots (replace the store-only path at `node_service.rs:446–494` with execute-then-store) | Syncing from genesis, every accepted block's locally-computed state root matches the header; an injected block with a bad state root is **rejected**, not stored. **Source:** local re-execution output vs block-header `state_root`, under an integration test with a tampered block fixture. |
| **WP-3** | Divergence handling + resource budget | On mismatch: halt-and-alert (per ADR), never silently follow; execution stays within a desktop budget (measured sync-from-genesis wall-clock + memory published in the gate note). **Source:** node divergence log events + measured benchmark artifact. |

### Phase 2 — VRF proposer participation (gate G2) · repos: chain + gui-native
| WP | Title | Acceptance |
|---|---|---|
| **WP-4** | **Close the `proposer_selector: None` hole** (chain) — eligibility enforcement is unconditional per the ADR | A block from an ineligible proposer is rejected by all nodes even when a receiver has no selector configured; regression test pins fail-closed behavior. **Source:** `core/consensus/src/vrf.rs` `is_eligible_proposer` + block-validation path under adversarial test. |
| **WP-5** | Desktop VRF participation — the embedded node with ≥3,200 staked SALT (ECON-S1 WP-5 floor) enters proposer election, produces + broadcasts blocks when elected | On a multi-node testnet, a desktop-profile validator produces blocks that boot fleet nodes accept; election frequency ≈ stake share over N≥10k blocks. **Source:** block-producer field + VRF proof of accepted live-testnet blocks, tallied against on-chain stake. |

### Phase 3 — Bootstrap grant program (gate G3) · repos: chain + identity
| WP | Title | Acceptance |
|---|---|---|
| **WP-6** | Grant mechanism per ADR: ~3.2M SALT budget, 3,200 SALT × first 1000 validators; claim requires a KYC-verified AUTHSPINE identity; **one identity = one grant** | Second claim from the same identity (any wallet) rejects; budget exhausts at exactly 1000 grants; claims without the KYC entitlement reject. **Source:** the AUTHSPINE entitlement claim (`https://citrate.ai/entitlement` via auth.citrate.ai) + the grant registry's on-chain state. |
| **WP-7** | Grant → stake provisioning — claimed grant lands as bonded validator stake (not a free-spend transfer), per ADR bonding/unbond rules | Post-claim, the claimant passes `is_eligible_proposer`; unbonding follows the ADR schedule under test. **Source:** on-chain stake table read by the VRF eligibility check. |

### Phase 4 — Onboarding UX + honest earnings (gate G4) · repo: gui-native
| WP | Title | Acceptance |
|---|---|---|
| **WP-8** | In-app validator onboarding: KYC status → grant claim → stake → "validating" status, with clear failure states | A fresh install reaches "validating" through the app alone (plus KYC at auth.citrate.ai); each step's state is read from its real source, no optimistic UI. **Source:** entitlement claim (KYC), grant registry (claim), stake table (bond), local node status (validating). |
| **WP-9** | **Honest earnings display** — delete the balance-delta "earned" (`main.rs:2940–2957`); replace with real accounting: attributable block rewards + grant + contribution streams (ContributionAccounting, compute, PIN), each labeled by source; block-reward line is honest about being symbolic at the new emission | Every displayed number traces to a named on-chain source in code review; a snapshot test covers the zero-block-reward case with grant + contributions present. **Source:** per-source on-chain queries (coinbase attribution, grant registry, ContributionAccounting ledger) — never a session balance diff. |

## Dependency table (cross-planset)

| Edge | Direction | Why |
|---|---|---|
| **ECON-S1 → VALIDATOR-S1** | hard prerequisite | min-stake 3,200 (WP-5 there) sizes the grant; new emission + runtime cap must be live before 1000 new validators mint anything |
| AUTHSPINE (live) → Phase 3 | prerequisite (already met) | KYC gate is the Sybil resistance; entitlement claim is the grant's data source |
| NATIVE-R1-S2 WP-1 survey → Phase 4 | input | owner's dashboard scoring feeds the earnings-UX backlog |
| NATIVE-R1-S3 (PIN) ‖ Phase 4 | display-only coupling | pinning earnings appear in WP-9 as a contribution stream once S3 lands; WP-9 must not block on it |
| gui-native chain-rev pin | mechanical | Phases 1–2 need the gui-native workspace pin bumped to the chain rev carrying WP-2/4/5 (`[[drift]]`) |

## Sequencing + honest sizing
Strictly ADR-first; Phases 1→2→3→4 with signed gates. **Largest program in the
wave: 6–10 weeks across two repos**, dominated by Phase 1 (making stored history
executable on consumer hardware) and Phase 2 (consensus-facing change requiring
adversarial review). Phases can NOT be parallelized across the gate boundaries;
within a phase, chain and gui-native halves can run in parallel. Execution begins
only after ECON-S1 WP-7 (producer redeploy) verifies live.

## References / rules
- Master brief: `/home/saul/Projects/Citrate-Labs/handoffs/CITRATE_NATIVE_REVAMP_MASTER_BRIEF.md` (§5, §9, §10.2)
- `citrate-federation/.agentile/rules/CORE_RULES.md` — Rule 8 (zero unwraps in the
  new consensus path), Rule 11 (data sources above), Rule 12 (`[[drift]]` gui-native
  ← citrate-chain rev; grant registry ← identity claims), Rule 13 (G2 and G3 are
  visibility-flip-class: owner sign-off in gates.yaml).
