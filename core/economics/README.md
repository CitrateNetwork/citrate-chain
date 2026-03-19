# citrate-economics

Tokenomics, reward distribution, governance, and economic policy for the Citrate blockchain.

## Overview

This crate implements the complete economic layer for Citrate's SALT token (1 billion total supply, 18 decimals). It covers the full lifecycle of network economics: genesis configuration with initial token distribution, block reward calculation with halving schedules, enhanced multi-factor reward distribution based on validator performance and AI contributions, dynamic gas pricing that responds to network utilization, on-chain governance with proposal/vote mechanics, and multi-party revenue sharing across validators, model creators, infrastructure providers, and the treasury.

The crate also provides specialized support for institutional operators (e.g., school node pilots) with tailored reward profiles covering block validation, model hosting, adapter creation, and data provision. A lenient slashing policy accommodates institutional scheduling constraints while maintaining network security through equivocation penalties. The estimator module enables forward-looking reward projections for institutional onboarding.

All economic parameters are configurable and can be modified through the governance system, enabling the network to adapt its economic policy over time without hard forks.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `token` | `src/token.rs` | SALT token: `Token` struct with balances, minting, burning, transfers; `TokenConfig` with 18 decimals and 1B supply |
| `rewards` | `src/rewards.rs` | Base block reward calculation with halving schedule, inference bonuses, model deployment bonuses, treasury allocation |
| `genesis` | `src/genesis.rs` | Genesis configuration: initial account balances, treasury address, team allocations, ecosystem fund, mining pool cap |
| `governance` | `src/governance.rs` | On-chain governance: `GovernanceManager` for proposals, voting, delegation, execution; proposal types include parameter changes, network upgrades, treasury spending, emergency actions, marketplace governance |
| `dynamic_pricing` | `src/dynamic_pricing.rs` | EIP-1559-style dynamic gas pricing: `DynamicPricingManager` adjusts prices based on block utilization, supports AI inference and model deployment cost multipliers |
| `enhanced_rewards` | `src/enhanced_rewards.rs` | Multi-factor reward distribution: performance bonuses (30%), AI contribution rewards (25%), network health bonuses (20%), long-term staking bonuses (25%) |
| `revenue_sharing` | `src/revenue_sharing.rs` | Multi-party revenue sharing: splits fees across validators (23%), model creators (30%), infrastructure (15%), treasury (12%), stakers (15%), x402 facilitators (5%) |
| `unified_economics` | `src/unified_economics.rs` | Unified economic manager: integrates token, governance, pricing, rewards, and revenue sharing; computes quadratic voting power combining token holdings, gas usage, staking, and reputation |
| `institutional` | `src/institutional.rs` | Institutional operator reward profiles: block validation, model hosting, adapter creation, data provision rewards with configurable caps and uptime requirements |
| `slashing` | `src/slashing.rs` | Institutional slashing policy: equivocation (10%), invalid state transition (15%), censorship (5%) penalties; grace periods, cooldowns, no downtime penalties for institutions |
| `estimator` | `src/estimator.rs` | Monthly reward projection calculator for institutional operators based on expected uptime, model count, adapter and dataset contributions |
| `lib` | `src/lib.rs` | Module declarations, public re-exports, constants (`TOKEN_SYMBOL`, `TOKEN_NAME`, `TOTAL_SUPPLY`), unit conversion helpers (`latt_to_wei`, `wei_to_latt`) |

## Public API

### Token
- **`Token::new(config)`** -- Create token with initial distribution
- **`TokenConfig`** -- Name ("Citrate"), symbol ("SALT"), 18 decimals, 1B total supply
- **`DECIMALS`** -- Constant: 18

### Rewards
- **`RewardCalculator::new(config)`** -- Create calculator with `RewardConfig`
- **`RewardCalculator::calculate_block_reward(block)`** -- Compute validator + treasury reward with halving
- **`BlockReward`** -- Struct: `validator_reward`, `treasury_reward`, `total_reward`

### Genesis
- **`GenesisConfig`** -- Chain ID, initial accounts, treasury, team allocations, ecosystem fund
- **`GenesisAccount`** -- Address, balance, nonce, optional code

### Governance
- **`GovernanceManager::new(config)`** -- Create governance system
- **`GovernanceManager::create_proposal(...)`** -- Submit a proposal (requires threshold SALT)
- **`GovernanceManager::cast_vote(proposal_id, voter, vote_type, power)`** -- Vote on proposal
- **`GovernanceManager::delegate(from, to)`** -- Delegate voting power
- **`ProposalType`** -- Enum: `ParameterChange`, `NetworkUpgrade`, `TreasurySpend`, `Emergency`, `MarketplaceGovernance`
- **`ProposalStatus`** -- Enum: `Pending`, `Active`, `Succeeded`, `Defeated`, `Executed`, `Expired`, `Cancelled`

### Dynamic Pricing
- **`DynamicPricingManager::new(config)`** -- Create pricing manager
- **`DynamicPricingManager::update_pricing(metrics)`** -- Adjust gas price based on utilization
- **`DynamicPricingManager::get_operation_cost(op_type, compute_units)`** -- Get cost for AI operations
- **`OperationType`** -- Enum: `StandardTransfer`, `ContractCall`, `AIInference`, `ModelDeployment`, `Training`, `Storage`

### Enhanced Rewards
- **`EnhancedRewardConfig`** -- Multi-factor reward pools: performance (30%), AI (25%), health (20%), staking (25%)
- **`ValidatorPerformance`** -- Uptime, blocks proposed, latency, attestation rate
- **`AIContribution`** -- Models hosted, inference quality, training contributions
- **`NetworkHealth`** -- Peer count, propagation time, fork rate

### Revenue Sharing
- **`RevenueShareManager::new(config)`** -- Create revenue sharing system
- **`RevenueShareManager::record_revenue(pool, amount)`** -- Record revenue by pool type
- **`RevenueShareManager::distribute()`** -- Execute distribution across stakeholders
- **`RevenuePool`** -- Enum: `GasFees`, `AIInference`, `ModelDeployment`, `ModelTraining`, `MarketplaceFees`, `SlashingRedistribution`, `FacilitatorFees`
- **`StakeholderType`** -- Enum: `Validator`, `ModelCreator`, `Infrastructure`, `Treasury`, `Staker`, `Facilitator`

### Unified Economics
- **`UnifiedEconomicsManager::new(config)`** -- Integrated economic manager
- **`VotingPower`** -- Quadratic voting power combining token, gas usage, staking, and reputation
- **`EconomicState`** -- Snapshot: total supply, circulating supply, gas price, staked amount, treasury

### Institutional
- **`InstitutionalRewardCalculator::new(config)`** -- Calculator for institutional operators
- **`InstitutionalOperatorProfile`** -- Operator address, uptime, models hosted, adapters created, datasets provided
- **`InstitutionalRewardBreakdown`** -- Per-type reward amounts
- **`InstitutionalRewardType`** -- Enum: `BlockValidation`, `ModelHosting`, `AdapterCreation`, `DataProvision`

### Slashing
- **`InstitutionalSlashingManager::new(config)`** -- Slashing manager for institutional operators
- **`SlashingOffense`** -- Enum: `Equivocation`, `InvalidStateTransition`, `TransactionCensorship`
- **`InstitutionalSlashingConfig`** -- Penalties, grace periods, cooldowns, no downtime penalties

### Estimator
- **`InstitutionalRewardEstimator::new(config)`** -- Monthly reward projector
- **`EstimationParams`** -- Expected uptime, model count, adapters/month, datasets/month
- **`MonthlyProjection`** -- Per-month breakdown and cumulative totals

### Constants & Helpers
- **`TOKEN_SYMBOL`** -- `"SALT"`
- **`TOKEN_NAME`** -- `"Citrate"`
- **`TOTAL_SUPPLY`** -- `1_000_000_000`
- **`latt_to_wei(latt)`** -- Convert SALT to wei (smallest unit)
- **`wei_to_latt(wei)`** -- Convert wei to SALT

## Usage

```rust
use citrate_economics::*;

// Token setup
let token = Token::new(TokenConfig::default());

// Block rewards with halving
let calculator = RewardCalculator::new(RewardConfig::default());
let reward = calculator.calculate_block_reward(&block);

// Governance
let mut governance = GovernanceManager::new(GovernanceConfig::default());
let proposal_id = governance.create_proposal(proposer, ProposalType::ParameterChange {
    parameter: "base_gas_price".to_string(),
    new_value: U256::from(2_000_000_000),
}, current_block)?;

// Dynamic pricing
let mut pricing = DynamicPricingManager::new(DynamicPricingConfig::default());
let update = pricing.update_pricing(utilization_metrics)?;

// Unit conversion
let wei = latt_to_wei(100); // 100 SALT in wei
```

## Tests

```bash
cargo test -p citrate-economics
```

149 tests across all modules (all passing), covering token operations, reward calculations with halving, governance proposal lifecycle, dynamic pricing adjustments, revenue sharing distribution, institutional reward profiles, slashing policies, and reward estimation projections.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `citrate-execution` | `Address` type, execution layer integration |
| `citrate-consensus` | `Block` type for reward calculation |
| `citrate-storage` | Storage layer integration |
| `primitive-types` | `U256` for high-precision token arithmetic |
| `serde` | Serialization of economic configurations and state |
| `anyhow` | Error handling |
| `thiserror` | Error type derivation |
| `tracing` | Structured logging |
| `proptest` | Property-based testing (dev) |
