---
created: 2026-10-26T19:30:00-07:00
branch: feat/amc-provider-governance-contracts
author: Larry Klosowski (owner) + Claude Opus 5.5 (MAC lane, contracts)
status: spec + implementation (not deployed; audit required); owner decisions of 2026-10-26 applied
planset: amc053 (0.5.3), 06_CONTRACTS.md
adr: ADR-2026-10-26-byok-provider-governance (P-12, P-13, P-14, P-15)
---

# AMC provider-governance contracts

**Status: not deployed. Not part of r1006 or the 12-01 genesis set.** These four contracts are deployed after genesis by
the GOVERNANCE timelock (ADR P-13), and only after an audit: internal Agentile-Audit with a cross-model quorum, no
external firm (owner decision Q-11, 2026-10-26). No existing contract, deploy script, genesis
or ceremony script or address book is changed by this work.

| Contract | Source | Tests |
|---|---|---|
| ProviderRegistry | `contracts/src/amc/ProviderRegistry.sol` | `contracts/test/amc/ProviderRegistry.t.sol` |
| UsageReceipts | `contracts/src/amc/UsageReceipts.sol` | `contracts/test/amc/UsageReceipts.t.sol` |
| OrgBudgets | `contracts/src/amc/OrgBudgets.sol` | `contracts/test/amc/OrgBudgets.t.sol` |
| WorkAttestations | `contracts/src/amc/WorkAttestations.sol` | `contracts/test/amc/WorkAttestations.t.sol` |
| RegistryGuardian2of3 | `contracts/src/amc/RegistryGuardian2of3.sol` | `contracts/test/amc/RegistryGuardian2of3.t.sol` |
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
| ProviderRegistry | `vetoWindow` is a constructor argument bounded to 1 h to 7 d. The deploy profile uses `DEFAULT_VETO_WINDOW` = 24 h, the planset default. | Owner, 2026-10-26: no other value decided, so it stays a bounded deploy-time parameter. |
| ProviderRegistry | `updateCommitments` queues the new commitments beside the old ones. The provider stays `Listed` on the old ones until the new ones clear the timelock and the veto window; then `finalizeUpdate` (anyone) swaps them atomically. A guardian `veto` drops the queued update and keeps the listing; `emergencyDelist` and `delist` still act at once and drop it. | Owner decision 2026-10-26: no outage on a commitment update. Invariant: a `Listed` provider always answers `isListedWith` on its current commitment. |
| ProviderRegistry | The guardian can also `pause` the whole registry: `isListedWith` answers false and nothing finalizes. Only governance can `unpause`. | Owner decision Q-8(b): the guardian can remove or pause, never add. |
| ProviderRegistry | `guardian` is set in the constructor and replaced only by `setGuardian` (governance). It cannot equal governance. | 06 section 7 step 4. RT-15. |
| ProviderRegistry | `delist` also applies to `PendingListing` (withdrawing a proposal) and `EmergencyDelisted` (confirming one). | It gives governance a way to withdraw or confirm. It opens no path to `Listed`. |
| ProviderRegistry | `isListedWith(id, compiledHostsCommitment)` is the single check core makes before it reads a key. | It returns true only when the provider is `Listed` and its commitment equals core's compiled entry. |
| UsageReceipts | `schema` must be nonzero. `SCHEMA_V1 = 1`. A zero root is refused. | Verifiers read the schema byte from their own table. There is no on-chain schema registry and no governance. |
| OrgBudgets | Only the OrganizationSBT holder sets or clears ceilings. There is no appointed admin. `RAISE_DELAY` is a constant 24 h. | Owner decision Q-10, 2026-10-26. |
| OrgBudgets | Removing a ceiling (`clearCeiling`) counts as a raise and waits `RAISE_DELAY`. A new write always cancels an unmatured raise. | Without this, a stolen holder key could open spend at once through removal, or through a stale queued raise. |
| OrgBudgets | `effectiveCeilingOf` takes the payment kind (`SaltPaid` or `VendorKey`) and reverts `UnitNotForPayment` across the split: `SALT_WEI` binds only SALT-paid work, `VENDOR_LIST_MICRO_USD` and `TOKENS` only vendor-key spend. | Owner decision Q-3, 2026-10-26: a SALT ceiling can never apply to BYO vendor spend, and no rate exists. |
| OrgBudgets | `effectiveCeilingOf(org, member)` is the minimum of the member ceiling, the org default and the global max, each counted only when set. `ceilingOf` returns one slot's own value. | Narrowing only. A member ceiling can never loosen the org default. |
| OrgBudgets | `setCeiling` above a set global max reverts. A later, lower global max clamps `effectiveCeilingOf`. | Invariant: no effective ceiling exceeds the global max. |
| OrgBudgets | A deactivated org (OrganizationSBT `isActive == false`) may only lower. | Fail closed. |
| UsageReceipts | `maxBackfillDays` is a constructor argument bounded to 1 to 366. The deploy profile uses `DEFAULT_MAX_BACKFILL_DAYS` = 90. A closed day older than that is refused with `DayTooOld`. | Owner, 2026-10-26: cap backfill at 90 days to match history retention, as a bounded deploy-time parameter. |
| RegistryGuardian2of3 | The guardian seat is a direct 2-of-3 with no delay, bound to one registry. It can only call `emergencyDelist`, `veto` and `pause`. Its owners are fixed; a proposal expires after 1 day and runs once. Rotation is a new instance plus `ProviderRegistry.setGuardian`, which it cannot block. | Owner decision Q-8(b), 2026-10-26. Tripwire A4 pins the three actions. |
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
| Spend attested against the budget by the org's nodes; org admins | RT-5, owner Q-10 | Holder-only ceilings; no node or admin roles. |

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
- Exposure: writes need the OrganizationSBT holder.
- Mitigation: none needed beyond that gate.

**WorkAttestations**
- Exposure: any AgentSBT owner can attest freely.
- Mitigation: records are listed per agent and attestations are the member's own claims. A consumer filters by agent and by acknowledgement. AgentSBT minting is capped per member (`maxAgentsPerMember`).

### Griefing

**ProviderRegistry**
- Exposure: a compromised guardian (2 of 3 keys) can veto every listing, emergency-delist every provider or pause the registry. The result is denial of service, not exfiltration: no guardian action adds anything.
- Mitigation: governance replaces the guardian with `setGuardian`, and the guardian cannot block that call (RT-15). Relisting waits the 48 h timelock plus the veto window. A lying RPC can likewise only report a false delist (RT-3).

**UsageReceipts**
- Exposure: none across members.

**OrgBudgets**
- Exposure: a stolen holder key can lower a ceiling to 0 at once, which blocks the org's cloud calls.
- Mitigation: a stolen key cannot raise at once (`RAISE_DELAY`, 24 h). The OrganizationSBT owner can `deactivate` the org, which blocks raises; the org's own root of trust is the holder.

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
- Mitigation: a later honest commit for that day is impossible, but a reveal against a false root fails for the honest record. Backfill is capped (90 days in the deploy profile), so a stolen key can pre-empt only that window.

**OrgBudgets**
- Exposure: see Griefing. The OrganizationSBT holder is the org's only budget authority and its own root of trust.
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

## 5. Owner decisions (2026-10-26) and what stays open

Decided and implemented:

- **Q-3, split by what is paid.** `SALT_WEI` ceilings bind only SALT-paid work. Vendor-key ceilings are in vendor
  list-price micro-USD and in tokens. There is no rate. `effectiveCeilingOf` refuses to answer across the split
  (`UnitNotForPayment`), so a SALT ceiling can never be applied to BYO vendor spend.
- **Q-8(b), a direct guardian with no delay.** `RegistryGuardian2of3` is the guardian seat: 2 of 3 fixed owners, no
  delay, and only `emergencyDelist`, `veto` and `pause`. It cannot list, restore, unpause or touch a role.
- **Q-8(a), coexistence with #324's `GuardianCanceller`.** This PR does not change #324. The two veto paths are separate:
  - `GuardianCanceller` (#324) holds `CANCELLER_ROLE` on the GOVERNANCE timelock. The GUARDIAN council can cancel any
    queued GOVERNANCE operation except one that only removes or replaces the guardian. That covers a queued
    `ProviderRegistry.proposeListing` or `updateCommitments` before it executes.
  - The registry's own veto (`veto`, through `RegistryGuardian2of3`) acts after the timelock has executed, inside the
    registry's veto window, and only on that registry's listing queue.
  - The registry seat holds no timelock role, so it cannot cancel `ProviderRegistry.setGuardian` (RT-15).
    `GuardianCanceller` could, because `setGuardian` on the registry is not in its non-cancellable class. **Flag for DGX
    to reconcile with C2 D5:** either add `ProviderRegistry.setGuardian` to `GuardianCanceller`'s guardian-removal
    class, or accept that the GUARDIAN council can delay a rotation of the registry seat. The owners of the two seats
    may be the same people; their keys and contracts are distinct.
- **Q-9, post-genesis deploy batch: all of them.** The batch is these five contracts (`ProviderRegistry`,
  `RegistryGuardian2of3`, `UsageReceipts`, `OrgBudgets`, `WorkAttestations`) plus `BenchmarkRegistry`, `AnchorRegistry`,
  `AgentSBT` and `OrganizationSBT`. `InferenceRouter` joins only once its held CHAIN-B items close.
- **Q-10, holder only.** Only the OrganizationSBT holder administers an org's budgets. Lowering is immediate; raising
  waits 24 h (`RAISE_DELAY`).
- **Q-11, audit.** An internal Agentile-Audit with a cross-model quorum, scoped to these contracts and the deploy
  script. No external firm.
- **Commitment updates, no outage.** The old commitment stays active until the new one clears the timelock and the
  veto window, then swaps atomically (`finalizeUpdate`). The guardian can still delist at once.
- **Veto window and backfill, not decided by the owner.** Both are bounded deploy-time parameters. The deploy profile
  uses the planset's 24 h veto window and a 90-day backfill cap (matching history retention).

Still open:

- **Deploy script.** Not included: it is WP-S4-DEPLOY (DGX), and nothing here deploys. It must deploy
  `RegistryGuardian2of3` and pass it to `ProviderRegistry` (or install it with `setGuardian`), and use the
  deploy-profile values above.
- **GuardianCanceller class (Q-8(a)).** As above, for DGX with C2 D5.
