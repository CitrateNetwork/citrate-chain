---
created: 2026-04-07T07:00:00Z
branch: quorum-execution-v1
author: Claude (zooid: architect)
sprint: level-a
status: active
scope: Auditor pre-ceremony signoff artifact
---

# Auditor Pre-Signoff

## Purpose

Before the real genesis ceremony runs, the auditor signs this document. The signature means: **if the ceremony scripts execute cleanly against the conditions defined below, the auditor agrees to consider A-10, B-6, B-7, and B-9 closed without further review.**

This document is the auditor's commitment that the ceremony materials are acceptable. It is NOT the auditor's signature on the ceremony itself — that comes from `99_signatures.txt` after the real run.

## What the Auditor Is Signing Off On

The auditor has reviewed and accepts the following:

### 1. Ceremony Materials

- [ ] `ceremony.sh` — reviewed line-by-line, no suspicious operations
- [ ] `provision-host.sh` — reviewed line-by-line, role-appropriate permissions
- [ ] `keystore_protocol.md` — key handling is sound
- [ ] `CEREMONY_CHECKLIST.md` — phases are ordered correctly, gates are enforceable
- [ ] `sdk-tests.yml` and `release.yml` — CI reflects real on-disk layout after Track 1 fixes

### 2. Contract Suite

The ceremony will deploy contracts from the following scripts:

- [ ] `contracts/script/DeployAll.s.sol` — core contract suite
- [ ] `contracts/script/DeployAIGateway.s.sol` — portable AI gateway contracts
- [ ] `contracts/script/DeployEduStack.s.sol` — institutional education contracts

The auditor explicitly accepts that `contracts/script/DeployForwarderPilot.s.sol`
is **not** part of the canonical ceremony deployment surface. It is a
parameterized helper for non-canonical pilot experiments and must not be used
to establish testnet source-of-truth addresses.

The auditor has reviewed each script for:
- Correct constructor arguments
- Correct deployment order (no dependency cycles)
- No owner/admin set to an address the operator cannot control
- No hardcoded addresses from prior deployments that would break after re-genesis
- The expected unique contract count matches `scripts/ceremony/CONTRACT_SCOPE.md`

### 3. Chain Configuration

- [ ] Chain ID for testnet beta: **40204**
- [ ] Block time: **2 seconds**
- [ ] Target finality: **≤ 12 seconds**
- [ ] Checkpoint interval: **50 blocks**
- [ ] Committee size: **100 validators** (quorum 67)
- [ ] These values match `.agentile/CONFIG.md` and `.agentile/source_of_truth/CONSTANTS.md`

### 4. Deployer Key Policy

- [ ] Deployer key is single-use for this ceremony
- [ ] Deployer key is stored in Foundry keystore, not env var
- [ ] Deployer address has been reported out-of-band
- [ ] Deployer address funding transaction has been verified
- [ ] Post-ceremony, the deployer key will be retired, not deleted

### 5. Quarantined Issues

The following known issues are explicitly quarantined for the ceremony. The auditor accepts that these are NOT blockers for Level A closure, but ARE blockers for Level B:

- [ ] **B-3 identity runtime sources**: provider_id and device_id use pre-district stand-ins (`CITRATE_EDU_PROVIDER_ID` env var or wallet address; `hostname:wallet_addr` for device). Real SSO/MDM integration is a Level B migration.
- [ ] **B-12 contract audit**: no external professional audit yet. Pilot goes out with self-audit + TLA+ evidence only.
- [ ] **B-4 packaging**: pilot ships as a tarball + install script, not OS-native installers (`.dmg`/`.msi`/`.deb`). Code signing certs not yet procured.
- [ ] **Python SDK**: non-canonical, opt-in CI only.
- [ ] **`CONFIG.md:36` deployment address drift**: will be fixed in this ceremony's Phase 3.4 constant propagation step.

### 6. Closure Conditions

The auditor agrees that the following gates are considered closed after a successful Phase 3 ceremony run:

- [ ] **A-10** — Bootnode + diagnostics (closure: 3+ bootnodes provisioned via `provision-host.sh bootnode`, client config supports multi-bootnode list, simulated failover documented)
- [ ] **B-6** — Multi-bootnode failover (closure: 3 geographically-separated bootnodes visible in proof bundle, failover test captured)
- [ ] **B-7** — District-scale load tests (closure: benchmark in proof bundle shows no regression at 1000 TPS)
- [ ] **B-9** — Production chain config stabilized (closure: `CONFIG.md` updated with new addresses in Phase 3.4, git tag created)

A-16 (Sprint K residual triage) was already closed in a prior pass; the ceremony does not affect it.

### 7. Abort Policy

The auditor has read and accepts the abort conditions in `CEREMONY_CHECKLIST.md`:

1. Deployer key compromise suspected
2. Any contract deployment produces zero bytecode
3. Benchmark shows >10% regression vs baseline
4. Any gate in `ceremony.sh` fails
5. Any of the three parties on the call objects
6. Network connectivity issue that cannot be resolved in 15 minutes

The auditor commits to calling abort if any of these conditions arise during the live ceremony.

### 8. Rehearsal Requirement

- [ ] The auditor has reviewed Phase 1 rehearsal proof bundle
- [ ] The auditor has reviewed Phase 2 rehearsal proof bundle
- [ ] Both rehearsals were clean (no errors, artifacts match expected structure)
- [ ] The auditor accepts the rehearsal evidence as sufficient precondition for Phase 3

## What the Auditor Is NOT Signing Off On

To keep this artifact precise:

- The auditor is NOT signing off on the contract code itself (that's the B-12 audit)
- The auditor is NOT signing off on the Learning Center pilot deployment (that's a separate pilot signoff)
- The auditor is NOT signing off on site/marketing claims (those stay restrained per the locked strategy)
- The auditor is NOT signing off on Level C gates (mainnet readiness is future work)

## Signatures

### Operator
Name: __________________________
Address: ________________________
Date: ___________________________
Signature: ______________________

### Auditor
Name: __________________________
Date: ___________________________
Signature: ______________________

### Stakeholder
Name: Saul
Date: ___________________________
Signature: ______________________

---

## References

- `ceremony.sh`
- `provision-host.sh`
- `keystore_protocol.md`
- `CEREMONY_CHECKLIST.md`
- `CONTRACT_SCOPE.md`
- `.agentile/CONFIG.md`
- `.agentile/quorum/11_SIGNER_READY_PRODUCTION_READINESS_CHECKLIST.md`
- `.agentile/quorum/12_A16_SPRINT_K_RESIDUAL_TRIAGE.md`
- `.agentile/docs/reports/2026-04-07_SDK_CANONICALITY_AUDIT.md`
