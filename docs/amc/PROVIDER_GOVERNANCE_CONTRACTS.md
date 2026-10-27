---
created: 2026-10-26T19:30:00-07:00
branch: feat/amc-provider-governance-contracts
author: Larry Klosowski (owner) + Claude Opus 5.5 (MAC lane, contracts)
status: spec + implementation (not deployed; audit required)
planset: amc053 (0.5.3), 06_CONTRACTS.md
adr: ADR-2026-10-26-byok-provider-governance (P-12, P-13, P-14, P-15)
---

# AMC provider-governance contracts

**Status: not deployed. Not part of r1006 or the 12-01 genesis set.** These four contracts are deployed after genesis by
the GOVERNANCE timelock (ADR P-13), and only after an audit (planset Q-11). No existing contract, deploy script, genesis
or ceremony script or address book is changed by this work.

| Contract | Source | Tests |
|---|---|---|
| ProviderRegistry | `contracts/src/amc/ProviderRegistry.sol` | `contracts/test/amc/ProviderRegistry.t.sol` |
| UsageReceipts | `contracts/src/amc/UsageReceipts.sol` | `contracts/test/amc/UsageReceipts.t.sol` |
| OrgBudgets | `contracts/src/amc/OrgBudgets.sol` | `contracts/test/amc/OrgBudgets.t.sol` |
| WorkAttestations | `contracts/src/amc/WorkAttestations.sol` | `contracts/test/amc/WorkAttestations.t.sol` |
| Source fences | `scripts/ci/amc_surface_tripwire.sh` | `--self-test`; `.github/workflows/amc-tripwires.yml` |

## 1. Source of truth

The interfaces, state machines, access-control table and invariants are defined in the federation planset
`citrate-federation/.agentile/planset/2026-10-26-amc053/06_CONTRACTS.md` (fed#403). This document does not copy them. It
records what the implementation decided where the planset leaves room, the deltas from the original brief, and the
threat model.

Principles the code holds to, from 06 section 1:

- **No content on chain.** Only public ids, salted hashes and governance state.
- **The chain narrows and never widens (RT-3).** No function can add a host, path, model or vendor for core to call. No
  function can raise a member's local caps or move SALT.
- **No funds.** No `payable`, `receive`, `fallback` or value-bearing call (tripwire A1, plus a runtime test per
  contract).
- **No proxies.** A v2 is a new deployment and a profile update.

## 2. Implementation decisions inside the planset's room

| Contract | Decision | Why |
|---|---|---|
| all | Governance is `Governable` (two-step), seeded with the GOVERNANCE `TimelockController`. Constructor admins go through `InitialAdmin.check`. | Reuse. It also keeps PBA-L2-002 (the CREATE2-factory admin) and the pba-r2 semgrep rules satisfied. |
| ProviderRegistry | `vetoWindow` is a constructor argument bounded to 1 h to 7 d. The planset value is 24 h. | The owner question on delist timing is still open, so the value is set at deployment rather than in code. |
| ProviderRegistry | `guardian` is set in the constructor and replaced only by `setGuardian` (governance). It cannot equal governance. | 06 section 7 step 4. RT-15. |
| ProviderRegistry | `delist` also applies to `PendingListing` (withdrawing a proposal) and `EmergencyDelisted` (confirming one). | It gives governance a way to withdraw or confirm. It opens no path to `Listed`. |
| ProviderRegistry | `isListedWith(id, compiledHostsCommitment)` is the single check core makes before it reads a key. | It returns true only when the provider is `Listed` and its commitment equals core's compiled entry. |
| UsageReceipts | `schema` must be nonzero. `SCHEMA_V1 = 1`. A zero root is refused. | Verifiers read the schema byte from their own table. There is no on-chain schema registry and no governance. |
| OrgBudgets | `raiseDelay` is a constructor argument bounded to 1 h to 7 d. The planset value is 24 h. | The owner question is pending. |
| OrgBudgets | Removing a ceiling (`clearCeiling`) counts as a raise and waits `raiseDelay`. A new write always cancels an unmatured raise. | Without this, a stolen admin key could open spend at once through removal, or through a stale queued raise. |
| OrgBudgets | `effectiveCeilingOf(org, member)` is the minimum of the member ceiling, the org default and the global max, each counted only when set. `ceilingOf` returns one slot's own value. | Narrowing only. A member ceiling can never loosen the org default. |
| OrgBudgets | `setCeiling` above a set global max reverts. A later, lower global max clamps `effectiveCeilingOf`. | Invariant: no effective ceiling exceeds the global max. |
| OrgBudgets | A deactivated org (OrganizationSBT `isActive == false`) may only lower. The admin seat lapses if the holder changes. | Fail closed. |
| WorkAttestations | `id = keccak256(abi.encode(a))`. Only the AgentSBT owner may attest, and not while the agent is quarantined. Revocation is sticky. A counterparty may acknowledge once, and never its own attestation or a revoked one. | 06 section 5 and RT-17. |
| WorkAttestations | Benchmarks link by the shared AgentSBT id and are never copied or written. | `BenchmarkRegistry` series are keyed by `msg.sender` (PBA-L2-061), so a write from this contract would merge every member into one committer. The join is `byAgent(agentId)` next to `BenchmarkRegistry.getMetric(attester, agentId, ...)` (see `test_benchmarkJoinByAgentId`). |

## 3. Deltas from the original brief (superseded by the planset red team)

| Brief item | Planset finding | What shipped |
|---|---|---|
| ProviderRegistry stores pinned hosts and a model list | RT-3, critical: a chain that can add a host is a key-exfiltration path | Commitments only. Hosts stay compiled in core. Tripwire A2 fails if the registry ever stores a string. |
| UsageReceipts: node-key-signed batch with root, count, period and signer | RT-4: counts and totals leak spend, and unsalted roots can be confirmed by guessing | Per-member daily commit of the root and the day only. Leaves are salted off chain. Tripwire A3 pins the `Receipt` struct. |
| OrgBudgets: SALT budgets with spend attested by the org's nodes | RT-1: there is no SALT/USD rate, and the UI truth contract forbids pairing them. RT-5: a client-enforced ceiling is not a security boundary | A unit per ceiling (`SALT_WEI`, `VENDOR_LIST_MICRO_USD`, `TOKENS`) and no rate. No on-chain spend ledger; evidence comes from revealed receipts. |
| WorkAttestations: hash, model id, cost and signer | 06 section 5: no model or provider name | The model class (0 to 4) and verifier bits. No cost. |
| Guardian veto through the timelock canceller | RT-15: a timelock-wide veto can block the guardian's own replacement | A registry-local veto over the listing queue. The guardian holds no timelock role in the tests (`test_guardianCannotBlockItsReplacement`). |

## 4. Threat model

The attackers considered:

- any address;
- a compromised member wallet;
- a compromised org admin key;
- a compromised GUARDIAN;
- a compromised GOVERNANCE (3 of 5);
- an RPC that lies to core;
- a chain observer.

### Spam

**ProviderRegistry**
- Exposure: none. Every write needs governance or the guardian, except `finalizeListing`.
- Mitigation: `finalizeListing` changes state only for a pending listing whose window has passed. Calling it early or twice reverts.

**UsageReceipts**
- Exposure: anyone can commit roots under their own address.
- Mitigation: records are namespaced by committer (the AnchorRegistry layout), so spam never touches another member's days. There is one record per day, so a committer's own series is bounded at one entry a day. Reads are paged and clamp at the tail.

**OrgBudgets**
- Exposure: writes need the OrganizationSBT holder or the admin it appointed.
- Mitigation: none needed beyond that gate.

**WorkAttestations**
- Exposure: any AgentSBT owner can attest freely.
- Mitigation: records are listed per agent and attestations are the member's own claims. A consumer filters by agent and by acknowledgement. AgentSBT minting is capped per member (`maxAgentsPerMember`).

### Griefing

**ProviderRegistry**
- Exposure: a compromised guardian can veto every listing or emergency-delist every provider. The result is denial of service, not exfiltration.
- Mitigation: governance replaces the guardian with `setGuardian`, and the guardian cannot block that call (RT-15). Relisting waits the 48 h timelock plus the veto window. A lying RPC can likewise only report a false delist (RT-3).

**UsageReceipts**
- Exposure: none across members.

**OrgBudgets**
- Exposure: a stolen admin key can lower a ceiling to 0 at once, which blocks the org's cloud calls.
- Mitigation: the holder removes the admin with `setOrgAdmin(0)` and raises again after `raiseDelay`. A stolen key cannot raise at once.

**WorkAttestations**
- Exposure: acknowledgements by strangers.
- Mitigation: an acknowledgement records receipt, not approval. The `(id, counterparty)` pair is the record, so readers choose whom to trust.

### Replay

**ProviderRegistry**
- Exposure: governance operations.
- Mitigation: replay is the timelock's concern (operation ids, salts, predecessor).

**UsageReceipts**
- Exposure: none. There are no signatures. The transaction sender is the subject, and `(committer, day)` is written at most once.

**OrgBudgets**
- Exposure: none. There are no signatures.

**WorkAttestations**
- Exposure: none. There are no signatures.
- Mitigation: a re-sent attestation has the same `id` and reverts `AlreadyAttested`. The `attester` field must equal the sender, so a third party cannot replay a claim it saw.

### Signer or key compromise

**ProviderRegistry**
- Exposure: a compromised GOVERNANCE (3 of 5) can list any provider id with any commitment.
- Mitigation: core still refuses unless the commitment equals its own compiled entry, so no new host is reachable (RT-3). The guardian can veto within the window.

**UsageReceipts**
- Exposure: a compromised wallet can commit false roots for days not yet committed.
- Mitigation: a later honest commit for that day is impossible, but a reveal against a false root fails for the honest record. Members commit daily, so the gap is short.
- Still open: whether to bound how far back a day may be backfilled (§5 Q-U1).

**OrgBudgets**
- Exposure: see Griefing. A compromised OrganizationSBT holder is the org's own root of trust.
- Mitigation: OrganizationSBT `deactivate` (its owner) blocks raises and admin changes.

**WorkAttestations**
- Exposure: a compromised wallet can attest and revoke for its own agents.
- Mitigation: AgentSBT `quarantine` (its owner) blocks new attestations at once.

### Privacy leakage through hashes

**ProviderRegistry**
- Exposure: none. Commitments are over public documents.

**UsageReceipts**
- Exposure: a root over low-entropy usage records could be confirmed by guessing. Committing also links the wallet to a daily activity pattern.
- Mitigation: each leaf is `SHA-256(domain ‖ salt_i ‖ record)` with a 32-byte random salt kept only in the sealed local salts file (RT-4, X-5). No count or total is stored on chain. Committing is opt-in and off by default, and the UI says what it links.

**OrgBudgets**
- Exposure: ceilings are public. They reveal budget policy, not usage.
- Mitigation: none needed. The planset states this openly.

**WorkAttestations**
- Exposure: an unsalted `taskHash` or artifact hash of a guessable brief or file would confirm it.
- Mitigation: both are salted commitments (06 section 5). The contract cannot enforce salting, so core's calldata allowlist tripwire (G6) is the enforcement point. `verifierBits` and `modelClass` are coarse by design.

### Value

**All four contracts**
- Exposure: none. No contract holds or moves value.
- Mitigation: tripwire A1, `_assertRejectsValue` in every suite, and an invariant `balance == 0`.

## 5. Open design questions (for the owner and DGX)

- **Q-8(b): latency of an emergency delist.** The registry acts at once when the guardian calls it. If the guardian seat
  is the GUARDIAN `TimelockController`, its own 1 h delay applies; if it is a direct 2-of-3 path, the delist is
  immediate. The contract works either way. The question is which address is installed as `guardian`. The genesis
  `MultisigProposer` can target only its own timelock (#324), so a direct path needs a new 2-of-3 or a second allowed
  target.
- **Q-8(a): coexistence with the genesis canceller.** Chain #324 gives `GuardianCanceller` the `CANCELLER_ROLE` on the
  GOVERNANCE timelock, which is a timelock-wide veto that excludes only operations that remove the guardian. RT-15
  (X-6) asks for a veto local to the registry. These contracts implement the local veto and hold no timelock role. Two
  decisions need DGX agreement with C2 D5: whether the timelock-wide canceller stays, and whether `setGuardian` on the
  registry belongs in `GuardianCanceller`'s non-cancellable class.
- **Parameter values.** `vetoWindow` and `raiseDelay` are constructor arguments bounded to 1 h to 7 d; the planset
  suggests 24 h for each. Delist timing is an open owner question.
- **Q-3: units.** `SALT_WEI` applies to SALT-paid work only; BYOK spend uses `VENDOR_LIST_MICRO_USD` and `TOKENS`. Owner
  answer pending. The contract stores no rate in any case.
- **Q-10: who administers an org.** The OrganizationSBT holder plus one appointed admin is implemented. An admin set, or
  the org's `signing_authority`, would be a small change.
- **Commitment updates.** `updateCommitments` moves a `Listed` provider back to `PendingListing`, so core stops using it
  for the 48 h timelock plus the veto window, as 06 section 2 specifies. The alternative keeps the old commitment
  active until the new one finalizes: more state, no outage. It needs a decision before the interfaces freeze.
- **Q-U1: backfill bound.** UsageReceipts accepts any closed day. Bounding it (for example to the last 30 days) limits
  what a compromised wallet can pre-empt, at the cost of a member who was offline longer.
- **RT-2 / Q-9: the deploy batch.** WorkAttestations needs AgentSBT and OrganizationSBT, and OrgBudgets needs
  OrganizationSBT. Neither is in the genesis set. The benchmark join needs BenchmarkRegistry. All three join the
  post-genesis batch, or their surfaces stay "not available yet".
- **Q-11: audit.** The planset recommends an external audit scoped to these four contracts and the deploy script.
- **Deploy script.** Not included: it is WP-S4-DEPLOY (DGX), and nothing here deploys.
