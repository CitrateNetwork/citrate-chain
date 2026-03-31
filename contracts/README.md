# Citrate Smart Contracts

30+ Solidity contracts powering Citrate's on-chain AI infrastructure, compute marketplace, learning center, and token economics. Built and tested with [Foundry](https://book.getfoundry.sh/).

## Contract Surface

| Domain | Key Contracts |
|--------|---------------|
| **AI & Marketplace** | ModelRegistry, ModelMarketplace, ModelAccessControl, InferenceRouter, LoRAFactory, AgentDecisionRegistry, SpecRegistry |
| **Compute** | ComputeMarketplace, ComputeVerifier, ComputePool, HeartbeatMonitor, DisputeResolution, BulkComputeGateway, ComputePricingOracle |
| **Learning Center** | LearningPool, LearningCycleManager, ClassroomRegistry, ContributionAccounting, NematocystSlashing |
| **Staking & Treasury** | LiquidStakingPool, WrappedSALT, IPFSIncentives, MarketMakerAllocation, TreasuryGovernor, StablecoinTreasury |
| **Other** | ColorCirclesNFT, Counter, TestnetFarmingAccounting |

All contracts are in `src/`. Tests are in `test/`. Deploy scripts are in `script/`.

## Build and Test

```bash
forge build                    # Compile all contracts
forge test -vv                 # Run all tests (verbose)
forge test --gas-report        # Run with gas reporting
forge fmt                      # Format Solidity
```

## Deploy

We recommend deploying via Forge scripts. Point `--rpc-url` at a running Citrate node (devnet or testnet).

```bash
# Deploy to local devnet
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast

# Deploy to testnet
forge script script/Deploy.s.sol --rpc-url https://rpc.citrate.ai --private-key $PRIVATE_KEY --broadcast
```

If deployment fails, verify the node is reachable with `curl http://localhost:8545` and check that your account has sufficient SALT for gas.

## Live Testnet Contracts

27 contracts are deployed on the Citrate testnet (chain ID 40204). Key addresses:

| Contract | Testnet Address |
|----------|----------------|
| ModelRegistry | `0x02F03Ac1aAFf621D458F403965A3355F720D077b` |
| WrappedSALT | `0x4Cba023420A6B0aeD33204082D9E29f9a450a9A2` |
| ComputeMarketplace | `0x6003aD2727BF4253A5c0bd9F0d10713829320B98` |
| LearningPool | `0xE701D7368DD7fF46C63DfA7fE439f61011cEb6b2` |
| LiquidStakingPool | `0xcDb76eb5D32ea31DD9c05095C970b8A44AE89390` |
| X402Facilitator | `0x05209FE13D705CfECE27C7084F741B65Ae45c5c8` |

Full list: [DEPLOYED_ADDRESSES.md](./DEPLOYED_ADDRESSES.md)

## Interacting with Contracts

```bash
# Query the ModelRegistry on testnet
cast call 0x02F03Ac1aAFf621D458F403965A3355F720D077b "modelCount()" \
  --rpc-url https://rpc.citrate.ai

# Check WrappedSALT supply
cast call 0x4Cba023420A6B0aeD33204082D9E29f9a450a9A2 "totalSupply()" \
  --rpc-url https://rpc.citrate.ai

# Deploy your own contract
forge create src/Counter.sol:Counter --rpc-url https://rpc.citrate.ai \
  --private-key $PRIVATE_KEY
```

If a call fails, verify the node is reachable: `curl -s https://rpc.citrate.ai -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'`

For full Foundry docs, see [book.getfoundry.sh](https://book.getfoundry.sh/).
