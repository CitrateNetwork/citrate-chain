---
created: 2026-04-07T06:30:00Z
branch: quorum-execution-v1
author: Claude (zooid: architect)
sprint: level-a
status: active
scope: Genesis ceremony execution checklist
---

# Ceremony Checklist

## Purpose

Ordered, auditable, single-session checklist for running a Citrate genesis ceremony. This document is the script the ceremony operator follows, live, in order.

Every checkbox corresponds to a concrete action with an evidence artifact. Nothing is considered "done" unless the artifact exists and the auditor signs off.

---

## Phase 0 — Pre-Ceremony (T minus 7+ days)

These steps happen asynchronously before the live ceremony session. The ceremony itself cannot start until every box in Phase 0 is checked.

### 0.1 — Procurement

- [ ] **Apple Developer ID** purchased (if macOS is in pilot scope): <URL>
- [ ] **Windows Authenticode certificate** purchased (if Windows is in pilot scope): <URL>
- [ ] **Vercel account** created for `console.citrate.ai`, `schools.citrate.ai`, `docs.citrate.ai`
- [ ] **DNS records** reserved for all subdomains (no content deployed yet)
- [ ] **Resend account** created for transactional email
- [ ] **Sumsub account** created for KYC distribution gate
- [ ] **Audit vendor shortlist** documented (2-3 firms) in `.agentile/launch/AUDIT_VENDOR_SHORTLIST.md`

### 0.2 — Infrastructure Provisioning

- [ ] **3 rehearsal hosts** provisioned (any cloud, Ubuntu 22.04 LTS, destroyable after rehearsal)
- [ ] **3+ real bootnode hosts** provisioned (geographically separated, stable)
- [ ] **1 real RPC host** provisioned with DNS and TLS via Caddy
- [ ] **1 dedicated deployer host** (fresh VM or clean laptop) for ceremony signing
- [ ] All hosts have `provision-host.sh <role>` run successfully
- [ ] SSH access verified from operator workstation to all hosts

### 0.3 — Keys & Keystore

- [ ] Deployer key generated per `keystore_protocol.md`
- [ ] Deployer address reported to auditor and stakeholder out-of-band
- [ ] Deployer address funded with ceremony gas budget (see section 0.5)
- [ ] Funding transaction verified by auditor
- [ ] Passphrase stored in operator's password manager

### 0.4 — Code & Git State

- [ ] Ceremony is running at a specific git commit, identified by hash: `__________________`
- [ ] Commit is signed: `git log --show-signature -1 <hash>`
- [ ] `cargo test --workspace` passes on the ceremony commit
- [ ] `forge test` passes on the ceremony commit
- [ ] All known blocking issues are either resolved or explicitly quarantined in `AUDITOR_PRE_SIGNOFF.md`

### 0.5 — Ceremony Budget

- [ ] Gas budget calculated (approx estimate): `___________ SALT`
- [ ] Deployer address funded with gas budget + 50% buffer
- [ ] Budget source documented (which treasury address sent funds)

### 0.6 — Documents Reviewed

- [ ] `ceremony.sh` reviewed line-by-line by auditor
- [ ] `provision-host.sh` reviewed line-by-line by auditor
- [ ] `keystore_protocol.md` reviewed by auditor
- [ ] This `CEREMONY_CHECKLIST.md` reviewed by auditor
- [ ] `AUDITOR_PRE_SIGNOFF.md` signed by all three parties

**PHASE 0 GATE:** Do not proceed to Phase 1 until every box above is checked and `AUDITOR_PRE_SIGNOFF.md` has three signatures.

---

## Phase 1 — Rehearsal Run #1 (disposable infra)

### 1.1 — Environment Setup

- [ ] Three rehearsal hosts are up and reachable
- [ ] `provision-host.sh deployer` has run on the deployer host
- [ ] `provision-host.sh bootnode` has run on at least one rehearsal bootnode
- [ ] Fresh genesis generated on the rehearsal bootnode

### 1.2 — Rehearsal Ceremony

- [ ] `export CEREMONY_MODE=rehearsal` set on deployer host
- [ ] `export CEREMONY_RPC_URL=http://<rehearsal-rpc>:8545`
- [ ] `export CEREMONY_DEPLOYER_ACCOUNT=rehearsal-deployer`
- [ ] `export CEREMONY_DEPLOYER_ADDRESS=<rehearsal-deployer-address>`
- [ ] `./ceremony.sh` runs successfully (no errors)
- [ ] Output directory captured: `ceremony-output/<timestamp>/`

### 1.3 — Artifact Verification

- [ ] `00_preflight.log` contains the git commit hash
- [ ] `10_genesis.json` matches the rehearsal chain genesis
- [ ] `20_deployment_txs.jsonl` has >= 35 contract deployment transactions
- [ ] `30_address_table.md` has all expected contracts with addresses
- [ ] `30_address_table.json` parses as valid JSON
- [ ] `40_code_verification.log` shows 0 failures
- [ ] `50_benchmark.md` shows no regression vs baseline
- [ ] `60_proof_bundle.tar.gz` exists and extracts cleanly
- [ ] `60_bundle.sha256` verifies against the bundle

### 1.4 — Post-Rehearsal Cleanup

- [ ] Rehearsal deployer key retired (marker file written)
- [ ] Rehearsal hosts destroyed (if disposable)
- [ ] Rehearsal proof bundle archived for reference
- [ ] Any issues found during rehearsal documented in a delta file

**PHASE 1 GATE:** If any issue was found, fix the issue, commit the fix, and return to Phase 0.4 with the new commit hash. If clean, proceed to Phase 2.

---

## Phase 2 — Rehearsal Run #2 (second disposable infra)

This is a repeat of Phase 1 on different disposable infrastructure, using a different rehearsal deployer key. The goal is to catch any host-specific or deployer-specific drift.

- [ ] Fresh disposable hosts provisioned (NOT the same ones from rehearsal #1)
- [ ] Fresh rehearsal deployer key generated
- [ ] Ceremony runs clean end-to-end
- [ ] Output artifacts match Phase 1 structure (not exact content — addresses differ)
- [ ] Delta vs Phase 1 reviewed: only expected differences (addresses, tx hashes, timestamps)

**PHASE 2 GATE:** Two clean rehearsals completed. If there was any inconsistency between them that can't be explained by known variation, go back to Phase 0.4. If clean, proceed to Phase 3.

---

## Phase 3 — Real Freeze Ceremony (live, production infra)

This is the one-shot, real freeze. Do NOT proceed unless Phases 0-2 are all green.

### 3.1 — Final Sign-Off

- [ ] Operator, auditor, and stakeholder all on a live call
- [ ] Phase 0, 1, 2 gates all confirmed closed on the call
- [ ] Proof bundles from Phases 1 and 2 shown on screen to all three parties
- [ ] Stakeholder verbally authorizes the real ceremony: "proceed"

### 3.2 — Real Run

- [ ] `export CEREMONY_MODE=real`
- [ ] Env vars point at real production infrastructure
- [ ] Operator runs `./ceremony.sh`
- [ ] At each `PROCEED` gate, operator reads the prompt aloud to the call
- [ ] All three parties agree before operator types `PROCEED`

### 3.3 — Live Artifact Review

- [ ] `30_address_table.md` contents read aloud and verified
- [ ] `40_code_verification.log` shows 0 failures
- [ ] `50_benchmark.md` shows no regression
- [ ] `60_proof_bundle.tar.gz` hash captured and agreed on by all three parties

### 3.4 — Constant Propagation

- [ ] `CONFIG.md` updated with new deployment addresses
- [ ] `.agentile/launch/DEPLOYED_CONTRACTS_<TIMESTAMP>.md` committed
- [ ] Learning Center `config.rs` addresses updated
- [ ] SDK addresses NOT in SDK (per audit report) — skip
- [ ] Any consumer script (buyer-smoke.ts, etc.) addresses updated
- [ ] Single atomic git commit captures all constant updates
- [ ] Commit signed by operator
- [ ] Commit tagged: `ceremony-<timestamp>`

### 3.5 — Signatures

- [ ] `99_signatures.txt` filled in by all three parties
- [ ] Operator signature + date
- [ ] Auditor signature + date
- [ ] Stakeholder signature + date
- [ ] Signed file committed to `.agentile/ceremonies/<timestamp>/`

### 3.6 — Post-Ceremony Announcement

- [ ] Ceremony closure journal written at `.agentile/docs/journals/<timestamp>_CEREMONY_CLOSURE.md`
- [ ] Status page updated (if `status.citrate.ai` exists)
- [ ] Pilot operators notified that constants are frozen
- [ ] A-10, B-6, B-7, B-9 marked as closed in the signer checklist

**PHASE 3 GATE:** Ceremony complete. Level A fully signed. Pilot deployment can begin.

---

## Abort Conditions

Any of these conditions triggers an immediate ABORT:

1. Deployer key compromise suspected
2. Any contract deployment produces zero bytecode
3. Benchmark shows >10% regression vs baseline
4. Any gate in `ceremony.sh` fails
5. Any of the three parties on the call objects
6. Network connectivity issue that cannot be resolved in 15 minutes

ABORT means: stop, document what happened, fix the issue, restart from Phase 0.4 with a new commit hash. Abort is NOT a failure — it is the intended behavior when something is wrong.

---

## Time Estimate

| Phase | Expected Duration |
|-------|-------------------|
| Phase 0 procurement | 3-7 days (async) |
| Phase 0 infra provisioning | 2-4 hours |
| Phase 1 rehearsal #1 | 45-90 minutes |
| Phase 2 rehearsal #2 | 45-90 minutes |
| Phase 3 real ceremony | 60-120 minutes (live call) |
| Phase 3.4 constant propagation | 30-60 minutes |
| Phase 3.5-3.6 closure | 30-60 minutes |

Total live-session time for Phase 3: approximately 2-4 hours including review and commit.

---

## See Also

- `ceremony.sh` — the script this checklist runs
- `provision-host.sh` — host prep script
- `keystore_protocol.md` — key handling protocol
- `LOCAL_REHEARSAL.md` — safe disposable local practice path
- `AUDITOR_PRE_SIGNOFF.md` — the artifact the auditor signs before the ceremony
