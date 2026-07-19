---
created: 2026-07-18
branch: fix/ghostdag-select-tip-determinism
author: Claude Opus 4.8 (1M), directed by @SaulBuilds
status: canonical-truth handoff — READ THIS BEFORE TOUCHING CHAIN 40204 ADDRESSES
---

# Chain 40204 — Canonical Truth (post-reconciliation 2026-07-18)

**Audience:** every agent/service that reads contract addresses or precompiles for
chain 40204. This supersedes any earlier address list. Everything here was verified
against the **live chain** (`eth_getCode` / `eth_call` on `https://rpc.citrate.ai`),
not against handoffs (C-1). Where the book and the chain disagreed, **the chain won**.

---

## TL;DR — what changed and what you must do

1. **Precompiles have NO on-chain bytecode — by design.** `eth_getCode(0x0108)`
   returning `0x` is CORRECT. They are native node code. Do not "deploy" them, do not
   treat empty code as a gap. The precompile map in `contracts/addresses/40204.json`
   was wrong (listed nonexistent `State*` precompiles at 0x1000/1001/1003); it is now
   the authoritative 21-entry native map. See §1.

2. **The AA money path lives at the ORIGINAL addresses, not the rotated ones.** The
   book + `.env.testnet` + running services pointed at the July-15 ROTATED addresses
   (factory `0x7b0eCE41`, paymaster `0x44AE1e0b`, SBT `0x16041DDF`) which have **no
   code on the live chain**. The reroll deployed the ORIGINAL CREATE2 addresses, and
   they are live + functional. The book is now fixed to the live set. **Services still
   hold the dead rotated pins — owner must re-point (§3).**

3. **New contracts were deployed** this session to their (deterministic, on-book)
   addresses — core feature stack + Learning Center + co-op factory. See §2/§4.

4. **The Boeing/BFR federation stack is NOT auto-deployable** — its scripts are
   explicitly human-in-loop / staged / non-deterministic. See §5 for the turnkey process.

---

## §1 — Precompiles (native; no bytecode)

Implemented in `core/execution/src/precompiles/`, dispatched into REVM by
`revm_adapter.rs::register_citrate_precompiles` (both call + create entry points).
Proven working: 559 lib unit tests pass; the `0x0120` ed25519 precompile fired live
4× (ValidatorRegistry fail-closed proof-of-possession → 4 validators registered).

| Addr | Name | Family |
|---|---|---|
| 0x01–0x09 | ecrecover…blake2f | standard EVM (present, omitted from book) |
| 0x0100–0x0106 | ModelDeploy / ModelInference / BatchInference / ModelMetadata / (0x0104 legacy proof stub) / ModelBenchmark / ModelEncryption | inference (needs hosted model runtime) |
| 0x0107 / 0x0108 / 0x0109 | TensorCommit / **InferenceProofVerify (Halo2-KZG, the live verifier)** / MerkleVerifyTensor | verification |
| 0x010A–0x010F | Tensor{Matmul,Dot,Softmax,Relu,Linear,Transpose}Q16 | Q16.16 compute |
| 0x0110 / 0x0111 | BelnapAggregate / RoutingInference | learning |
| 0x0120 | Ed25519Verify | signature |
| 0x0200–0x0202 | X402{Eip712,TransferAuth,BatchPayment}Verify | x402 payment |

**Gone/never existed:** `StateModel 0x1000`, `StateArtifact 0x1001`, `StateGovernance
0x1003`. Do not reference them. `0x0104` is a legacy proof stub — use `0x0108`.

---

## §2 — Canonical AA + membership addresses (LIVE — use these)

| Component | LIVE address (canonical) | ~~Dead rotated (do NOT use)~~ |
|---|---|---|
| EntryPoint | `0xc698feaf0ff7fdb0d60e2f620c97cb729a694975` | ~~0x077Fbc33~~ |
| CitrateWalletFactory | `0x5a45b6f83050a76a81d0f2e6c857f16b37b2693b` | ~~0x7b0eCE41~~ |
| CitratePaymaster | `0xf14f56e812ce93544e75e841ac6316f2d7e561b0` | ~~0x44AE1e0b~~ |
| CitrateWallet (impl) | `0x79c4a8367d2d65b162de841ff678db4875490b2e` | ~~0xe641a41b~~ |
| WebAuthnP256Validator | `0x97ff6d1c4d2f4337ec09f2a1c01808016f728def` | (unchanged) |
| CitrateECDSAValidator | `0xd2d35421379ae5b461e216bfcdd1b7e6a64bbc40` | (unchanged) |
| GuardianRecoveryModule | `0x381b5848f3b5d73ff67b745624780a43682456ce` | (unchanged) |
| CitrateMemberSBT | `0x7be005aa8c45c1695b4c75468c6ca8b40238a7c4` | ~~0x16041DDF~~ |
| MembershipStakeVault | `0x0aceb7b474ecc4abe12696ce48628f0cabe0267e` | ~~0x94c0A523~~ |

The live SBT renders `tokenURI(0)` on-chain (money path proven). ValidatorRegistry
`0x3bf6c5bb365717bec9348b953758b196652caedf` is live with 4 active validators.

---

## §3 — OWNER ACTION: re-point services from rotated → live addresses

`.env.testnet` (repo-root `/home/saul/Projects/Citrate-Labs/.env.testnet`) still has
the DEAD rotated pins. Every service reading it (identity, bundler, treasury-signer,
core-membership) is currently targeting empty addresses. Update these keys:

```
CITRATE_AA_ENTRY_POINT     0x077Fbc33… → 0xc698feaf0ff7fdb0d60e2f620c97cb729a694975
CITRATE_AA_FACTORY         0x7b0eCE41… → 0x5a45b6f83050a76a81d0f2e6c857f16b37b2693b
CITRATE_AA_PAYMASTER       0x44AE1e0b… → 0xf14f56e812ce93544e75e841ac6316f2d7e561b0
CITRATE_AA_WALLET_IMPL     0xe641A41b… → 0x79c4a8367d2d65b162de841ff678db4875490b2e
CITRATE_MEMBER_SBT_ADDRESS 0x16041DDF… → 0x7be005aa8c45c1695b4c75468c6ca8b40238a7c4
MEMBERSHIP_STAKE_VAULT_ADDRESS 0x94c0A523… → 0x0aceb7b474ecc4abe12696ce48628f0cabe0267e
```
(validators / guardian / registrar / sponsor / identity-signer pins already match.)

Then redeploy/restart identity + bundler + treasury-signer + core-membership so they
read the new pins, and re-run any on-chain re-pinning identity does at boot
(setIdentitySigner / paymaster registerWallet) against the LIVE addresses. Left as an
owner step because it touches the keystore + running production services.

---

## §4 — Deploy status this session

**VERIFIED: full book census = 54/54 addresses have code on-chain, 0 dead.**
All 17 new contracts landed at their exact deterministic (on-book) addresses;
deployer nonce 48 → 65. Confirmed via `eth_getCode`.

- **Corrected in the book (no chain write):** precompile map; AA + membership → live.
- **Deployed (deterministic CREATE2 → on-book addresses, all verified live):**
  ModelAccessControl `0x8e5967da`, TEEAttestationRegistry `0xc1c0d8`,
  ComputePoolTraining `0x7c4f71`, FederatedLearning set (KYCRegistry `0x2a82a9`,
  IPFSIncentivesV2 `0x7e3c93`, IPFSIncentivesV3 `0x629f7c`, AggregationChallenge
  `0xe7d7eb`, ComputePoolPipeline `0xc2ddf9`), AIGateway Portables (AIModelRegistry
  `0xda30a0`, AIInferenceRouter `0x8603b1`, AILearningCycleCore `0xe30d18`),
  EduStack (InstitutionalVault `0x73beb0`, ClassroomClusterV1 `0xfda1a1`, EduForwarder
  `0xe9fffad`, BudgetAllocation `0xc26d0d`, CashoutRequest `0x70782e`),
  CitrateCooperativeFactory `0x6fe6fd2a`.
- After deploys land: regenerate `40204.json` via `scripts/ops/emit-address-table.sh`
  and confirm every address has code.

---

## §5 — Boeing/BFR federation stack (NOT yet deployed — turnkey process)

~21 contracts (AppRegistry, EntityRegistry, SupplierRegistry, PartProvenanceRegistry,
ReleaseManifestRegistry, CrossOrg{Envelope,Index}, MultiSigEnvelope, TenantHierarchy,
RoleEscalation, RoleGrantTenantIndex, SponsorEvidenceRegistry, ClassificationRegistry,
ContradictionLedger, MoqRegistry, AuditBundleRegistry, TripwireRegistry,
TinaWorkpaperRegistry, BoeingComplianceRegistry, BoeingFLScopeIndex,
AgentDecisionRegistryV2) via `DeployBfr02Rbac … DeployBfr17Release`.

**Why not auto-deployed:** these scripts are **CREATE (nonce-based, NOT CREATE2)** and
are explicitly documented as **`--broadcast` HUMAN-IN-LOOP**, staged, with address
recording between stages (`DEPLOYED_CONTRACTS_2026_05_10.md`) and at least one
hardcoded cross-stage reference (`DeployBfr09` `MULTISIG_ENVELOPE_STAGE_1`). Blindly
sequencing them would land contracts at NEW addresses and mis-wire the cross-stage refs.

**To deploy correctly (owner-supervised):** run in ascending order 02→05→06→07→08→09→
10→11→12→13→15→16→17, with `ROOT_GOVERNANCE=0x98a32D944e9138B14A35b5D4dcE53339570F371A`
for 02/05/06/07, verifying each stage's address and patching any downstream hardcoded
reference before proceeding. These are NOT in the core `40204.json`; record them in a
dedicated BFR address file.
