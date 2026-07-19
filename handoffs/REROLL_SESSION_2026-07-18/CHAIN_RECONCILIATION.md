---
created: 2026-07-18
branch: fix/ghostdag-select-tip-determinism
author: Claude Opus 4.8 (1M), directed by @SaulBuilds
status: reconciliation — BLOCKING decisions for owner
---

# Canonical-chain reconciliation (rpc.citrate.ai, chainId 40204, head ~0x9731 / 38705)

Derived from live `eth_getCode` over every broadcast address (80 pairs) + the
committed address book. **Verified against the chain, not the book (C-1).**

## Headline finding: the address book disagrees with the live chain on the AA money path

The live canonical chain runs the **ORIGINAL** AA + membership addresses. The
committed book (`contracts/addresses/40204.json`) lists the **ROTATED / re-deployed**
addresses — which have **no code on this chain**.

| Component | BOOK address (services read this) | Live on chain? | ORIGINAL address (from broadcast) | Live? |
|---|---|---|---|---|
| CitrateWalletFactory | 0x7b0eCE41…560c6 | ❌ empty | 0x5a45b6f8…2693b | ✅ 5.8KB |
| CitratePaymaster | 0x44AE1e0b…7d62 | ❌ empty | 0xf14f56e8…561b0 | ✅ 14KB |
| CitrateWallet (impl) | 0xe641a41b…30087 | ❌ empty | 0x79c4a836…90b2e | ✅ 49KB |
| CitrateMemberSBT | 0x16041DDF…2a66 | ❌ empty | 0x7be005aa…8a7c4 | ✅ 19.8KB |
| MembershipStakeVault | 0x94c0A523…Eec2 | ❌ empty | 0x0aceb7b4…0267e | ✅ 9.1KB |
| EntryPoint | 0x077Fbc33…54Ef | ❌ empty | (vendored separately — locate) | ? |

**The money path WORKS** — the ORIGINAL SBT `0x7be005aa` renders `tokenURI(0)`
on-chain. The earlier session's "money path proven" was true; it lives at the
original address, not the book's. The 3 AA modules (WebAuthn/ECDSA/Guardian),
the business stack, and ValidatorRegistry (`0x3bf6c5bb`) match the book and are live.

**Interpretation:** the July-15 AA rotation (to 0x7b0eCE41 / 0x44AE1e0b) and the
book's membership addresses were **never applied to the chain rpc.citrate.ai now
serves** — OR were lost when the DB was reset during this session's sync debugging.
The chain is a MIX: July-5-era business+AA (original addrs) + July-17 ValidatorRegistry.
`.env.testnet` AA pins (repo-root/droplet, not in this worktree) almost certainly
point at the rotated addresses → any service using them targets empty addresses.

## On-chain census (verified)

- **LIVE (has code): 38** contracts — business stack, AA original, membership
  original, 3 AA modules, ValidatorRegistry.
- **NOT deployed at any known address: ~37**, in three buckets:

### Bucket A — book is wrong, DO NOT redeploy (live at original addr)
CitrateWalletFactory (rotated), CitratePaymaster (rotated), + membership/wallet/EntryPoint rows above.

### Bucket B — superseded old versions, live at the BOOK address (not missing)
ComputeVerifier `0x3ebfd…` (live at book `0x61bf65…`), ComputeMarketplace `0x2efca2…` (live at book `0xd7a20ba…`).

### Bucket C — core feature contracts genuinely undeployed (~16)
AggregationChallenge, AIModelRegistryPortable, AIInferenceRouterPortable,
AILearningCycleCorePortable, ModelAccessControl, KYCRegistry, IPFSIncentivesV2,
IPFSIncentivesV3, TEEAttestationRegistry, ComputePoolTraining, ComputePoolPipeline,
EduForwarder (Forwarder `0xe9fffad…`), InstitutionalVault, ClassroomClusterV1,
BudgetAllocation, CashoutRequest, + CitrateCooperativeFactory (co-op, never deployed).

### Bucket D — Boeing/BFR federation demo stack genuinely undeployed (~21)
AppRegistry, EntityRegistry, SupplierRegistry, PartProvenanceRegistry,
ReleaseManifestRegistry, CrossOrgEnvelope/Index, MultiSigEnvelope, TenantHierarchy,
RoleEscalation, RoleGrantTenantIndex, SponsorEvidenceRegistry, ClassificationRegistry,
ContradictionLedger, MoqRegistry, AuditBundleRegistry, TripwireRegistry,
TinaWorkpaperRegistry, BoeingComplianceRegistry, BoeingFLScopeIndex,
AgentDecisionRegistryV2. (DeployBfr02–17 scripts; not in the core address book.)

## Blocking decisions (owner)

1. **Canonical AA/membership addresses.** The chain and the book/services disagree.
   - (A) **Live-chain-wins** — regenerate the book + re-point services/.env.testnet to the
     original live addresses. No money-critical redeploy; money path already works. *Lowest risk.*
   - (B) **Book/rotation-wins** — re-apply RotateFactoryPaymaster + redeploy membership to
     book addresses; strands the currently-live SBT #0; needs keys. *Money-critical.*
   - (C) **Investigate** why the chain diverged from the intended reroll before either.

2. **Deploy scope** for genuinely-missing (Buckets C/D): core features only, or + Boeing/BFR.
