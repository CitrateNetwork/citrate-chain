---
created: 2026-07-18
branch: fix/ghostdag-select-tip-determinism
author: Claude Opus 4.8 (1M), directed by @SaulBuilds
status: reference — post-reroll deployment inventory, on-chain-verified
---

# Deployment inventory — chain 40204 reroll (2026-07-18)

Every deployment from this session, with a one-line description and its address/URL.
On-chain contracts were verified live via `eth_getCode` (byte counts confirmed non-zero).

## Chain / network

| What | Where | Notes |
|---|---|---|
| Citrate chain | chain-id **40204**, `https://rpc.citrate.ai` | rerolled (state reset), producing; ~31k+ blocks |
| rpc-1 (sole producer) | droplet `142.93.58.145` (nyc1) | canonical node; VALIDATOR-S1 §R' active (activation height 2000) |
| boot-1 / boot-2 / boot-3 | `142.93.50.217` (nyc1) / `143.198.134.151` (sfo3) / `142.93.99.212` (fra1) | followers; b1 converging, b2/b3 pending a sync-path fix |

## Smart contracts — Account Abstraction (ERC-4337)

| Contract | Address | Description |
|---|---|---|
| EntryPoint | `0xC698feAf0FF7FdB0D60E2F620C97cB729A694975` | ERC-4337 v0.7 UserOp entry point |
| CitrateWalletFactory | `0x5a45B6F83050a76A81D0F2E6c857F16B37B2693b` | deploys smart wallets (CREATE2) |
| CitrateWallet (impl) | `0x79c4A8367d2d65B162DE841fF678DB4875490b2e` | smart-wallet implementation |
| CitratePaymaster | `0xF14F56e812cE93544e75E841Ac6316F2d7E561b0` | sponsors gas (25 SALT deposited) |
| GuardianRecoveryModule | `0x381B5848f3B5d73FF67b745624780a43682456Ce` | social recovery (unchanged across rerolls) |
| WebAuthnP256Validator | `0x97ff6d1c4d2f4337ec09f2a1c01808016f728def` | passkey signature validator |
| CitrateECDSAValidator | `0xd2d35421379ae5b461e216bfcdd1b7e6a64bbc40` | ECDSA signature validator |

## Smart contracts — membership money path

| Contract | Address | Description |
|---|---|---|
| CitrateMemberSBT | `0x7bE005aA8c45C1695b4C75468c6cA8B40238A7C4` | soulbound membership token; **on-chain SVG art** (no IPFS) |
| MembershipStakeVault | `0x0aceb7B474eCC4abe12696CE48628f0CABE0267e` | stakes membership grants into the pool |
| LiquidStakingPool | `0xFD272195B55Cb4F5A240a5bE75AABaB0D1C5685E` | staking pool the vault feeds |

## Smart contracts — VALIDATOR-S1 (new this reroll)

| Contract | Address | Description |
|---|---|---|
| ValidatorRegistry | `0x3Bf6C5bb365717Bec9348b953758b196652caEdf` | stake-gated validator set; §R' priority-fee reallocation (100% share, 10 SALT/block subsidy, 32k min stake); 4 validators registered/active |

## Smart contracts — business / ecosystem stack (28, DeployAll)

| Contract | Address |
|---|---|
| ModelRegistry | `0xf64636d56ec9e0c406149b34ea9c5c5d80b342c0` |
| WrappedSALT | `0xaa918302b94a4b0e75e01e019cc6b819b4f7c906` |
| AgentDecisionRegistry | `0xcfc17e8688c6ed918ca8802260ac98b5249a663a` |
| SpecRegistry | `0x8d079ff2cf38f8f46012220d2534c541976f2c4e` |
| IPFSIncentives | `0x209ac724f7b11d5d6e68cfe985cd628011fd8a1b` |
| X402Facilitator | `0x81efcb971d7d1f2a277e5c1c6643164c65769abf` |
| X402Paywall | `0x8ed4dce2e9b24bfbfe4c31227bb163de81cd3000` |
| ContributionAccounting | `0xcdd2477387279c7d44a1053f44db5dac0fd8faef` |
| NematocystSlashing | `0xfeb23abd20084d36a1145da8a2dc04e8b48f65c7` |
| MarketMakerAllocation | `0x60ea46d244c02b04baf79d729d9f25dc1ef903b6` |
| ModelMarketplace | `0x385a670ef1cc98f7fb3d5136e8c66b593fc1c9f9` |
| InferenceRouter | `0xcdca7e85598485a562606cf8beec757dd265477f` |
| LoRAFactory | `0x6e564d22949992705b5de7108b2c68d3554d5863` |
| LearningPool | `0xfc514b826daee16c590f86ad83370f4fb8a1d564` |
| LearningCycleManager | `0xa82d2959966492279c7baaf8ced1bdb114c978cb` |
| ClassroomRegistry | `0x47ff1d5f980fda1b5faa06f93808f70b6eb3c5b8` |
| MentorMatcher | `0xe0a176b26065d267476aeb69e2c266db7d0fdd9d` |
| ComputeVerifier | `0x61bf65b6e912a55f727714e5b3300bd3bbbb028c` |
| ComputeMarketplace | `0xd7a20ba719c96954c2ed8a0b62ba1649cc19d599` |
| ComputePool | `0xeed18c3c32389affec78d5e233e56d5e6a65baf1` |
| HeartbeatMonitor | `0xe9eaac272844f342266862bbefc6d117a227ad9b` |
| DisputeResolution | `0x7c4588974896f2666b0cd96788f28fa6834bee61` |
| ComputePricingOracle | `0xdcebd5ec209161810c85f3d97e194f0f0d02b02d` |
| StablecoinTreasury | `0xa97ee61e0c8375540e643db09a44150caa388771` |
| BulkComputeGateway | `0xf96584f9019619a827d170d5fd233fef391cc8ab` |
| TestnetFarmingAccounting | `0xce1c27218315dff16cd923215f3efe7537abca83` |
| TreasuryGovernor | `0x4cd381027c3fb856e0398e20df9f09e842e529ea` |
| ArachnidDeterministicDeployer | `0x4e59b44847b379578588920cA78FbF26c0B4956C` | CREATE2 factory (genesis-seeded) |

## Operator keys (derived from DEPLOYER_PRIVATE_KEY — no new secrets)

| Role | Address |
|---|---|
| Genesis deployer | `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` (registry governance/slasher) |
| Grant / treasury signer | `0x9aFFF274d888F2545c91dA223578c260E6508A50` (owns SBT + vault; funded 200k, spent ~32k on the e2e test) |
| AA sponsor signer | `0x03067c230C3a13F801B2C285f43D1C6264d6b2a4` |
| AA identity signer | `0x8A9062625E98666Fc0072Ee2E7CB8AB08Bd1b651` |
| Validator stakers (=coinbases) | `0xE7509e40…` (rpc-1) · `0x7509d695…` (boot1) · `0xF7198fC9…` (boot2) · `0x11ec3E50…` (boot3) |

## Services / apps (reconnected or set up this session)

| Service | URL / location | Status |
|---|---|---|
| Identity / OIDC / KYC | `https://auth.citrate.ai` · droplet `157.230.55.191` | live; AA repointed; registerWallet gap fixed |
| ERC-4337 bundler | droplet `159.223.174.220` | live; EntryPoint repointed to `0xC698fe…` |
| Treasury-signer | `https://auth.citrate.ai/_ops/treasury` · `127.0.0.1:8790` | live; SBT/vault repinned |
| core-membership (money webapp) | `https://membership.citrate.ai` (Vercel) | live; SBT/vault repinned; **Neon DB provisioned + migrated** |
| core-membership DB | Neon Postgres (`neondb`) | 6 tables migrated; AES-256-GCM field encryption (keys outside Neon) |
| radar (devrel dApp) | `https://radar.citrate.ai` (Vercel) | live; addresses updated |
| citrate-core (desktop) | source updated (Mac build pending) | address seed updated on branch |
| explorer | `https://explorer.citrate.ai` | live (unaffected — business addrs unchanged) |
| comms relay | `https://comms.citrate.ai` | ⚠ 502 at check time — pre-existing, worth verifying (not touched this session) |

## On-chain verification summary
- **39 / 39 core reroll contracts deployed** (verified by `eth_getCode`, all non-zero bytecode).
- The 24 non-deployed book entries are: 7 precompiles/EOA (no bytecode by design) + 17 feature-stack contracts (edu / federated-learning / TEE / AI-gateway / co-op) deployed by **separate ceremonies, out of this reroll's scope**.
