# Deployed Contract Addresses — Testnet (Chain 40204)

*Re-genesis: April 1, 2026*
*Deployer: 0x4250675F9015E65fC866F3a373F82bb9DFc000c6*
*Authoritative source: `.agentile/launch/DEPLOYED_CONTRACTS_2026_04_01.md`*

## Live Contracts (9 deployed post-re-genesis)

### Core

| Contract | Address | Bytes |
|----------|---------|-------|
| ModelRegistry | `0x077fbc3338a9e6bad90a3a041e6b7425689754ef` | 11,262 |
| WrappedSALT | `0x1AFE987622ab5AdD275D2Fd21248F77F5e00667f` | ~4,200 |
| ModelMarketplace | `0xc0fDE3a8a42f6479Cf12B4A5489E7A988C918e23` | 12,103 |
| InferenceRouter | `0x11399989175783CDCa8ECB095835c8cD4720C6Fc` | 8,951 |

### Economics

| Contract | Address | Bytes |
|----------|---------|-------|
| LiquidStakingPool | `0xD71B7e33e447e062F4e796DEF686156805820b29` | 5,434 |
| ContributionAccounting | `0x1B6AEED728F53b48e1eD831b04A1F4812F48e928` | 3,855 |

### Learning

| Contract | Address | Bytes |
|----------|---------|-------|
| LearningPool | `0x1f73BB479f397A34B5E3145e51d25bC5007273Bf` | 6,056 |

### Compute

| Contract | Address | Bytes |
|----------|---------|-------|
| ComputeMarketplace | `0xA6a4122126A75611eA06241E404327ADdFe8eB5e` | 16,146 |
| ComputeVerifier | `0x0aaa6e00FCab1dA5599F6DCE86e361A5e03A5759` | 8,313 |

## Not Yet Redeployed (21 contracts)

These contracts exist in `contracts/src/` but have not been redeployed after the April 1 re-genesis. UI and docs must treat them as unavailable until redeployed.

DisputeResolution, TreasuryGovernor, NematocystSlashing, ClassroomRegistry, LearningCycleManager, LoRAFactory, MarketMakerAllocation, X402Facilitator, X402Paywall, IPFSIncentives, HeartbeatMonitor, AgentDecisionRegistry, SpecRegistry, ColorCirclesNFT, Counter, StablecoinTreasury, TestnetFarmingAccounting, BulkComputeGateway, ComputePool, ComputePricingOracle, ModelAccessControl.

## Genesis Accounts

| Account | Address | Allocation |
|---------|---------|------------|
| Treasury | `0xacEAA7d00C024d32e6E0A07094ceB1a7706786D1` | 500M SALT |
| Faucet (operational) | `0x9dc0537b73bd472d1e10860d828e193997f23b85` | 50M SALT |
| Deployer | `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` | 10M SALT |
| Team/Dev | `0xb6E9A558a4f9DC9E3F667a3B446a48bddF671126` | 10M SALT |
| Validator | `0x04ABaE08aC643b2C518F22e212A27f7B6e14b4C3` | 5M SALT |
