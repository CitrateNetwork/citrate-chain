---
title: "Reroll runbook — deployer rotation + resilient sync + frozen address book (chain 40204)"
created: 2026-07-20
branch: reroll-prep/deployer-rotation
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: PREP COMPLETE — book frozen + validated by local dry-run; reroll not yet executed
chain: 40204, genesis 0x481a59bc, rpc.citrate.ai
---

# TL;DR

The next reroll rotates the **deployer key** (old `0x4250675F` was exposed by a
`bash -x` trace) to a fresh DGX-generated deployer **`0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732`**
(private key never leaves the DGX). Because every operator/staker key is
`keccak256(DEPLOYER_PRIVATE_KEY ‖ label)`, the leak **transitively compromised
all derived keys** — so the deployer, all 4 validator stakers, the grant signer,
the AA sponsor, and the AA registrar rotate together. That moves **28 contract
addresses** (25 core/feature + AA factory + AA paymaster + ValidatorRegistry/SBT/vault).

Every shifted address below was recomputed from **ground truth** — a full local
`regenesis.sh --with-aa` dry-run against a fresh new-deployer genesis (44 contracts
+ 7 AA deployed and code-verified) — NOT hand-computed. The book
`contracts/addresses/40204.json` is regenerated and frozen; `SBT/vault/registry`
projections come from the re-pinned forge CREATE2 tripwires. This reroll also
carries the **resilient full-replay sync fix** (PR #91) so citrate-core nodes sync
at any depth on a healthy fleet.

# Security rationale (why the whole derived set rotates)

`derive-operator-keys.sh` / `derive-validator-stakers.sh` derive every operator key
as `keccak256(DEPLOYER_PRIVATE_KEY_bytes ‖ utf8(label))`. Knowing the deployer PK
lets anyone recompute: the 4 stakers, GRANT_SIGNER, AA_SPONSOR_SIGNER, AA_REGISTRAR.
The old deployer PK was echoed by a trace → **all of them are compromised** → all
rotate at genesis. `.env.testnet` already holds the fresh set (addr↔key verified
consistent for deployer, identity signer, sponsor, grant signer).

# New root identities

| Role | OLD | NEW |
|---|---|---|
| Deployer | `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` | `0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732` |
| Validator staker 1 (rpc-1) | `0xE7509e40…df5b` | `0x0ecbcd8557781161A41b34dEE55Ee5A00561363b` |
| Validator staker 2 (boot1) | `0x7509d695…9e80` | `0xE62219971c2E929e6932D9332c17739888e1658F` |
| Validator staker 3 (boot2) | `0xF7198fC9…13e6` | `0xac8e8B2e6f4F9cfd7E4E88a66D3906f6e97222B8` |
| Validator staker 4 (boot3) | `0x11ec3E50…9ec3` | `0xFa5FC645a2e45688D1726C38516B93aF374f6975` |
| Grant signer (SBT+vault owner) | `0x9aFFF274…8A50` | `0xF42a19194fee89E71dC4b8631a71a9CeCf42B483` |
| AA sponsor signer | (old) | `0x676b00c12A958de4901CFa1c81C84086C5DA8ed8` |
| AA identity signer | (rotated) | `0x8A9062625E98666Fc0072Ee2E7CB8AB08Bd1b651` |

# Repo edits already made (this prep)

- `core/economics/src/genesis.rs` — `TESTNET_DEPLOYER_ADDRESS` + `VALIDATOR_STAKER_{1..4}_ADDRESS` → new. Rebuilt; genesis funds new deployer 10M + 4 stakers 40k each (verified live on a fresh local node).
- `contracts/script/DeployValidatorRegistry.s.sol` — `GENESIS_DEPLOYER` (governance_ + slasher_) → new deployer. Moves registry `0x3Bf6C5bb → 0x915DdE02831ebacFc57f329f60944492ebb0A095`.
- `contracts/script/DeployCoreMembership.s.sol` — `FROZEN_OWNER` → new grant signer. Moves SBT `→ 0x3e0c2B1cD29a615E4eA2E263C8e7df3Aef243E42`, vault `→ 0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268`.
- `contracts/test/CoreMembershipCreate2.t.sol` — tripwire re-pinned to the new owner/hashes/projections (7/7 green).
- `contracts/addresses/40204.json` — regenerated from the dry-run (canonical frozen book).

# Address shift ledger (25 of 44 core/feature shift)

| Contract | OLD | NEW |
|---|---|---|
| AIInferenceRouterPortable | `0x8603b169c45d1b739af5ce6342864192257f164b` | `0x6828165d5ef3e01ba5c83e00d81563d342bd138f` |
| AILearningCycleCorePortable | `0xe30d184e2a2cee5bee0429d5cb94ce55dc832c89` | `0x615297a23f954681ef4b648eaaf722455eca925c` |
| AgentDecisionRegistry | `0xcfc17e8688c6ed918ca8802260ac98b5249a663a` | `0x728dbe86ce56123a5c1ddc248392940d7d2d30f9` |
| BudgetAllocation | `0xc26d0d8c0478ea4595348d02fff4536ee7a9eab6` | `0x6644f15b4552cbe9de196dcee06d32bf53630376` |
| BulkComputeGateway | `0xf96584f9019619a827d170d5fd233fef391cc8ab` | `0x30a698aacb29729d98724cc4b07f44c9d4a948ad` |
| CashoutRequest | `0x70782e9ff764c4c00c2ac46126fc4fb9ee622fbe` | `0xc3e348b10113426df2145a97bacbd5ed97cef889` |
| ClassroomClusterV1 | `0xfda1a1e5fc0b08eac91a883b550b69e391b36856` | `0x9d87eebbff15fca367e1a2a0c2df96e8dcf9a268` |
| ComputeMarketplace | `0xd7a20ba719c96954c2ed8a0b62ba1649cc19d599` | `0x5872cdf95812ca6d2b6f5db0353158d709336fd2` |
| ComputePoolPipeline | `0xc2ddf9dd186781697ed9c16af3bb36e42a79f4ad` | `0x5a0437ac03ca92113962f1e4f3d15e062b942bde` |
| ComputePoolTraining | `0x7c4f7109db40b70aa03de0f6cd59d9b8a6487aa6` | `0x6eb7d4160ebfaf92cd9377114160da62c09f87bf` |
| ComputeVerifier | `0x61bf65b6e912a55f727714e5b3300bd3bbbb028c` | `0xbaf099c0b58cf47a62d4c34a140707625fff80d8` |
| EduForwarder | `0xe9fffad1c2442179cfe6264d71c6caf75d0f2f1a` | `0x50a798eaab184eeb11a27fbc1333b85646c1582a` |
| IPFSIncentivesV2 | `0x7e3c937af313e06e648e26e98f251684c4d82b4d` | `0xc29c439f625c6f5366f93e5b5133ae00c08c3c4c` |
| IPFSIncentivesV3 | `0x629f7cd4aeade49e4b27c9a39237d132f9ff39f4` | `0xb024ad0b5aefa87fa1e10234afc85b6128932df4` |
| InstitutionalVault | `0x73beb03dc3d15561e3678281da903faa3c676f18` | `0xafcf6276dc315d31212ab3611b7067eb910ded87` |
| KYCRegistry | `0x2a82a9e18adb79e2e2306243bd5df13fbfb949fa` | `0xcf41a81c8dfcdb6e61febfc34670964d226b33ed` |
| MarketMakerAllocation | `0x60ea46d244c02b04baf79d729d9f25dc1ef903b6` | `0xa87fae5cf5110c2efcbc927597f3a69284871868` |
| MentorMatcher | `0xe0a176b26065d267476aeb69e2c266db7d0fdd9d` | `0x2e6b446c318d8be06cbd8a581e3bfcde4b2db7cd` |
| ModelMarketplace | `0x385a670ef1cc98f7fb3d5136e8c66b593fc1c9f9` | `0xbb6f62b6357022d6119985acc13f5ee24ef02a27` |
| SpecRegistry | `0x8d079ff2cf38f8f46012220d2534c541976f2c4e` | `0x2938320ab38373d1d7d025067f2361187f46e4bd` |
| StablecoinTreasury | `0xa97ee61e0c8375540e643db09a44150caa388771` | `0x0e9c5953bd7c77252119e32f989ba94f735c8599` |
| TEEAttestationRegistry | `0xc1c0d8587a2a36ca8a7e95275c5cad0d523e777e` | `0x4df26aae3619f449a142d237ed818ebf7c186ed5` |
| TestnetFarmingAccounting | `0xce1c27218315dff16cd923215f3efe7537abca83` | `0x5d65ef6166c87521cf4e879cf3ac344cb5b655be` |
| TreasuryGovernor | `0x4cd381027c3fb856e0398e20df9f09e842e529ea` | `0x62e268f2fca3bbd25115e26a8af81319f9e8b3bb` |
| X402Facilitator | `0x81efcb971d7d1f2a277e5c1c6643164c65769abf` | `0xbd46ef689499017c3bd2afdd13fd453d95abee2d` |

**Unchanged (19):** AIModelRegistryPortable, AggregationChallenge, ClassroomRegistry, ComputePool, ComputePricingOracle, ContributionAccounting, DisputeResolution, HeartbeatMonitor, IPFSIncentives, InferenceRouter, LearningCycleManager, LearningPool, LiquidStakingPool, LoRAFactory, ModelAccessControl, ModelRegistry, NematocystSlashing, WrappedSALT, X402Paywall

### AA stack
| Contract | OLD | NEW | |
|---|---|---|---|
| CitrateECDSAValidator | `0xd2d35421379ae5b461e216bfcdd1b7e6a64bbc40` | `0xd2d35421379ae5b461e216bfcdd1b7e6a64bbc40` | same |
| CitratePaymaster | `0xf14f56e812ce93544e75e841ac6316f2d7e561b0` | `0x0cd122ace90084afb26d5101074af15aaccc1c0e` | **SHIFT** |
| CitrateWallet | `0x79c4a8367d2d65b162de841ff678db4875490b2e` | `0x79c4a8367d2d65b162de841ff678db4875490b2e` | same |
| CitrateWalletFactory | `0x5a45b6f83050a76a81d0f2e6c857f16b37b2693b` | `0xc9c7b3d3fe28012ab5f2583a4f58531e9f26d3f5` | **SHIFT** |
| EntryPoint | `0xc698feaf0ff7fdb0d60e2f620c97cb729a694975` | `0xc698feaf0ff7fdb0d60e2f620c97cb729a694975` | same |
| GuardianRecoveryModule | `0x381b5848f3b5d73ff67b745624780a43682456ce` | `0x381b5848f3b5d73ff67b745624780a43682456ce` | same |
| WebAuthnP256Validator | `0x97ff6d1c4d2f4337ec09f2a1c01808016f728def` | `0x97ff6d1c4d2f4337ec09f2a1c01808016f728def` | same |

# ValidatorRegistry / membership (separate deploy scripts, pinned outside 40204.json)

| Contract | OLD | NEW |
|---|---|---|
| ValidatorRegistry | `0x3Bf6C5bb365717Bec9348b953758b196652caEdf` | `0x915DdE02831ebacFc57f329f60944492ebb0A095` |
| CitrateMemberSBT | `0x149E85A3C845d10556537DcF824D148aCB904578` | `0x3e0c2B1cD29a615E4eA2E263C8e7df3Aef243E42` |
| MembershipStakeVault | `0x0aceb7B474eCC4abe12696CE48628f0CABE0267e` | `0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268` |

# Reroll execution sequence (mirrors the validated dry-run)

1. **Binary:** build main + PR #91 (sync) + genesis rotation. x86_64 for the fleet
   (build on rpc-1), aarch64 for the DGX.
2. **Fleet env (identical on ALL 4 nodes — a single drift forks):**
   `CITRATE_BLOCK_V2=1  CITRATE_VALIDATOR_ACTIVATION_HEIGHT=2000`
   `CITRATE_VALIDATOR_REGISTRY=0x915DdE02831ebacFc57f329f60944492ebb0A095`  ← **changed**
3. **node.toml coinbase per node → new stakers:** rpc-1 `0x0ecbcd85…`, boot1 `0xE6221997…`,
   boot2 `0xac8e8B2e…`, boot3 `0xFa5FC645…`.
4. **Atomic reset** (stop-all → wipe RocksDB, preserve noise.key/node.toml/models → swap
   binary → start rpc-1 isolated → verify fresh genesis `0x481a59bc` → join boots).
5. **Deploy** with the new deployer env: `ENV_TESTNET=.env.testnet bash scripts/ops/regenesis.sh --with-aa`
   then `scripts/ops/post-reroll-membership.sh` (SBT+vault) + `DeployValidatorRegistry`.
   `CITRATE_AA_ENTRY_POINT` must be **empty** so DeployAndPinAA deploys the deterministic EntryPoint (still `0xC698feAf`).
6. **Register 4 validators** (staker == coinbase) BEFORE snapshot S(2)=1800; `--force` ok pre-1800.
7. **Verify** determinism (0 state-root mismatch) across activation 2000 + a fresh node full-replays to head (PR #91).

# Downstream re-pins (GATED — do NOT run until the reroll is live)

- **Consumers** (emit-address-table list): explorer, inference-gateway, node-agent,
  sdk-marketplace, gui-native, boeing-shell, buyer-webapp → each repo's `sync-addresses`.
- **treasury-signer droplet** — rekey the grant signer to the new key for
  `0xF42a19194fee89E71dC4b8631a71a9CeCf42B483` (owns new SBT+vault); update its env; restart.
- **identity / bundler** — re-pin AA factory `0xc9c7b3d3fe28012ab5f2583a4f58531e9f26d3f5`
  + paymaster `0x0cd122ace90084afb26d5101074af15aaccc1c0e`; `setIdentitySigner`
  to `0x8A906262…`; fund + re-pin per AA_STACK_RESTORE runbook.
- **core-membership** — re-pin SBT `0x3e0c2B1c…` + vault `0x61E324cF…`.

# Not changed / not in scope

- EntryPoint + AA validators + walletImpl: deterministic (no owner arg) — **unchanged**.
- 19 core contracts with no owner arg — **unchanged**.
- Boeing/BFR + co-op: still deliberately excluded (co-op CREATE2 factory exceeds EIP-170 in this deploy path).
- Treasury/faucet/team EOAs: independent keys (not deployer-derived) — **unchanged**.
