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
The scripts themselves are signer-agnostic; the signer is chosen by the Forge CLI.

```bash
# Deploy to local devnet
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --private-key $PRIVATE_KEY --broadcast

# Deploy to testnet
forge script script/Deploy.s.sol --rpc-url https://rpc.citrate.ai \
  --account ceremony-deployer \
  --sender $DEPLOYER_ADDRESS \
  --broadcast
```

If deployment fails, verify the node is reachable with `curl http://localhost:8545` and check that your account has sufficient SALT for gas.

## Live Testnet Contracts

Addresses are not copied into this README, because hand-copied tables go stale at every re-roll and a
transfer to a stale, codeless address strands the value. Read them from one of these instead:

- The address book: [`contracts/addresses/40204.json`](addresses/40204.json) (the single source of truth).
- The rendered page: [docs.citrate.ai/chain/addresses](https://docs.citrate.ai/chain/addresses).

Not every book entry is deployed. At the last check, 57 of the 76 application and account-abstraction
entries have code on chain 40204; the 19 governance and cooperative entries listed in
[`verification/claims.json`](../verification/claims.json) (`deployed_contracts`) have no code. Before you
send value to any address, confirm it has code:

```bash
cast code <address> --rpc-url https://rpc.citrate.ai   # "0x" means nothing is deployed there
python3 verification/check_address_code.py --check      # read-only sweep of the whole book
```

## ZK-tier compute jobs: client contract

`ComputeMarketplace` binds ZK proofs to the job through the public inputs the
0x0108 v1 inference circuit proves: `input_commitment ‖ model_commitment ‖
output_commitment`, each a canonical BN254 scalar (`< ComputeVerifier.BN254_SCALAR_MODULUS`).

- **Which jobs:** any job whose effective tier is `ZKProof`, whether requested
  explicitly or **auto-upgraded because `maxPrice` exceeds 10 SALT**
  (`ComputeVerifier.VALUE_THRESHOLD`).
- **Requester:** pass the circuit's 32-byte **input commitment** as `inputHash`
  (not a keccak/sha hash of the input bytes); `modelHash` must also be `< r`.
  Otherwise `postJob` / `autoAssignJob` revert.
- **Provider:** after proving, call `submitCommitment(jobId,
  verifier.zkProofCommitment(jobId, proofData))`; at least one block later call
  `submitResult(jobId, outputCommitment32, proofData)` where `proofData =
  proofLen ‖ proof ‖ publicInputs(96 bytes)`. The provider may re-commit until
  it reveals. Malformed output commitments revert (no slash).
  Provider tooling must always reveal the proof it last committed; only the
  latest commitment is checked, so revealing an earlier one fails verification.
- **Payment:** `completeJob` is accepted `DISPUTE_WINDOW` (100) blocks after a
  Valid verdict.
- **TEE tier:** oracles sign `ComputeVerifier.teeAttestationDigest(jobId, attestation)`
  (EIP-191 wrapped).

## Interacting with Contracts

```bash
# Read an address from the book, then query it
BOOK=contracts/addresses/40204.json
MODEL_REGISTRY=$(jq -r '.contracts.ModelRegistry' $BOOK)
WSALT=$(jq -r '.contracts.WrappedSALT' $BOOK)

cast call $MODEL_REGISTRY "modelCount()" --rpc-url https://rpc.citrate.ai
cast call $WSALT "totalSupply()" --rpc-url https://rpc.citrate.ai

# Deploy your own contract
forge create src/Counter.sol:Counter --rpc-url https://rpc.citrate.ai \
  --private-key $PRIVATE_KEY
```

If a call fails, verify the node is reachable: `curl -s https://rpc.citrate.ai -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'`

For full Foundry docs, see [book.getfoundry.sh](https://book.getfoundry.sh/).
