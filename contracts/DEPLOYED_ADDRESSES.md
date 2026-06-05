# Deployed Contract Addresses — Testnet Beta (Chain 40204)

> **Canonical source of truth**: the JSON broadcast files under
> `contracts/broadcast/<Script>.s.sol/40204/run-latest.json` (6 scripts:
> DeployAll, DeployModelAccessControl, DeployTEEAttestationRegistry,
> DeployComputePoolTraining, DeployEduStack, DeployAIGateway), aggregated
> in `contracts/broadcast/_address_table/30_address_table.json`.
> Cross-reference any address via `eth_getCode` to
> `https://rpc.citrate.ai` (or `http://142.93.58.145:8545` if DNS
> hasn't propagated yet).

## Chain metadata

| Field | Value |
|---|---|
| **Chain ID** | `40204` |
| **Native symbol** | `SALT` (testnet `tCTR` for outward branding) |
| **Block time** | 2s target |
| **Consensus** | GhostDAG (k=18) |
| **Canonical RPC (HTTP)** | `https://rpc.citrate.ai` (Cloudflare-proxied → `142.93.58.145`) |
| **Canonical RPC (raw)** | `http://142.93.58.145:8545` |
| **WebSocket** | `wss://rpc.citrate.ai` (or `ws://142.93.58.145:8546`) |
| **Bootnodes** | `boot{1,2,3}.citrate.ai` (nyc1/sfo3/fra1) |
| **Deployer EOA** | `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` (BFR-15) |
| **Snapshot last verified** | 2026-05-24 |
| **Contract count** | **39** (deduped; 6 scripts, 41 CREATE events) |
| **Status** | live — pilot testnet-beta, partner onboarding open |

## Pre-funded genesis accounts

| Address | Initial balance | Role |
|---|---|---|
| `0xaceaa7d00c024d32e6e0a07094ceb1a7706786d1` | 500M SALT | Genesis treasury / mint authority |
| `0xf4adb1734f7bd9f8979bd53b2bf6d7690d562b6d` | 50M SALT | Reserve |
| `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` | 10M SALT | **Deployer EOA** (BFR-15) — coinbase + 39-contract deployer |
| `0xb6e9a558a4f9dc9e3f667a3b446a48bddf671126` | 10M SALT | Reserve |
| `0x04abae08ac643b2c518f22e212a27f7b6e14b4c3` | 5M SALT | Reserve |
| `0x6680b43af09d9b351332bf5378eb580e3b390182` | 10M SALT | Faucet signing key (deterministic from `citrate-faucet-testnet-v1`) |

## Contracts (alphabetical)

| Contract | Address |
|---|---|
| AIInferenceRouterPortable | `0xbf62ee8ee209321bbddf5dd15afd77ac327367cd` |
| AILearningCycleCorePortable | `0x4ee0bef59a87a9ea3f91b80fd68ebfe69e72075a` |
| AIModelRegistryPortable | `0xbaa2505d0446043be3540c0b9150c6df42d33180` |
| AgentDecisionRegistry | `0x0aaa6e00fcab1da5599f6dce86e361a5e03a5759` |
| BudgetAllocation | `0xd85e83cab6c5947e2cc5e77244edfce110309724` |
| BulkComputeGateway | `0x7efc1eb17beff413e1af7fb3bb541e895c307300` |
| CashoutRequest | `0x6b3c47d2807ec9bc7d2aee030845b4225dd693ab` |
| ClassroomClusterV1 | `0x3bc867e60d13a825a57a5fbc3a53c4f710ac8f76` |
| ClassroomRegistry | `0x7e7a3db3be6fe4bea06acdbb772786432e1293e3` |
| ComputeMarketplace | `0xf3f9f72ea2bb3f763b07390b7257da643b8ee9b6` |
| ComputePool | `0x8b36c15552394ce44173a29d054dc5ca482e65d3` |
| ComputePoolTraining | `0xf1eae5dd4a1639922ea610142f7ce51330065b57` |
| ComputePricingOracle | `0xa1eed6ae021504e2a1e310e6c0f7c1a0c5bf4647` |
| ComputeVerifier | `0x86d918808b48ad543c9c816b5303b7dbcb0e321f` |
| ContributionAccounting | `0x1afe987622ab5add275d2fd21248f77f5e00667f` |
| DisputeResolution | `0x6884ef1907468a13265a0bbb67da20ef4b52199b` |
| Forwarder | `0x2a3a7fe1619e10f9dda80ced394ebdffb90d9cbe` |
| HeartbeatMonitor | `0x46773aeca885be65cd313b7d9bce9625767d40b5` |
| IPFSIncentives | `0xa6a4122126a75611ea06241e404327addfe8eb5e` |
| InferenceRouter | `0xad7c3135c1b9b3189208fd617b6b058c1c0469f3` |
| InstitutionalVault | `0x1f17fc3525e540cfd14ed0270a87c159c56aadee` |
| LearningCycleManager | `0x20a0b74c766e84b20558abd76a7a0fd6434a4c4c` |
| LearningPool | `0x9a58e44f8dd6fd6a75637a32e6e51c16440996f8` |
| LiquidStakingPool | `0xd71b7e33e447e062f4e796def686156805820b29` |
| LoRAFactory | `0xac6bfb1709bcba5a005fe2823b4d8bc55db2b7d9` |
| MarketMakerAllocation | `0xf61e79af3bc2a905695e45b0fa7a43f9141a554a` |
| MentorMatcher | `0xd29d4d059808adc43b761f41c675f1eb546e1a19` |
| ModelAccessControl | `0xf7c3180dda79fb046173d96d172bf43b70174031` |
| ModelMarketplace | `0x11a5e6f57751d8fa1c5b58ad2bf13528160985f0` |
| ModelRegistry | `0x077fbc3338a9e6bad90a3a041e6b7425689754ef` |
| NematocystSlashing | `0x425064443c3c3392c47dcbe10d455831545efd9b` |
| SpecRegistry | `0x1b6aeed728f53b48e1ed831b04a1f4812f48e928` |
| StablecoinTreasury | `0x828c6b831c4ce08170bc3efc6f6026dc44b20dfa` |
| TEEAttestationRegistry | `0xc12dbcdb80ef2ae675315f455210f39a736a373c` |
| TestnetFarmingAccounting | `0x516380b0acef9a9541641c85dbe0bf89b3e56977` |
| TreasuryGovernor | `0x26333384a517c50d8b116979490b4ad1506f1f9a` |
| WrappedSALT | `0x1f73bb479f397a34b5e3145e51d25bc5007273bf` |
| X402Facilitator | `0xc0fde3a8a42f6479cf12b4a5489e7a988c918e23` |
| X402Paywall | `0x11399989175783cdca8ecb095835c8cd4720c6fc` |

## Pilot caveats

- **InstitutionalVault** (Learning Center stack) was deployed with
  \`SIGNER_1 = deployer + SIGNER_2/3 = random throwaway addresses\`.
  The 2-of-3 multisig is **non-operational** until signers are rotated.
  Acceptable for pilot — vault isn't exercised on testnet. Rotate
  signers at mainnet ceremony per the chain-reroll runbook.
- All deploys are unsigned (no cosign certs at this stage per handoff
  §14). Verification by SHA-256 + on-chain `eth_getCode` cross-check.

## How to regenerate

If the chain is re-rolled or contracts re-deployed:

```bash
cd citrate-chain/contracts
DEPLOYER_ADDRESS=0x4250675F9015E65fC866F3a373F82bb9DFc000c6 \
  forge script script/DeployAll.s.sol --rpc-url http://142.93.58.145:8545 \
  --private-key "$(tr -d '[:space:]' < ~/.citrate-deployer.key)" \
  --broadcast --slow
# repeat for the other 5 scripts (ModelAccessControl, TEEAttestationRegistry,
# ComputePoolTraining, EduStack, AIGateway)

# Then aggregate + push to GUI configs:
../scripts/ceremony/sync-gui-addresses.sh \
  contracts/broadcast/_address_table/30_address_table.json \
  /path/to/citrate-learning-center
```

---

## EW-S1 — ERC-4337 Embedded Wallet Stack (chain 40204)

Per `citrate-federation/.agentile/sprints/active/2026-06-05-ew-s1-passkey-aa.md`.
Deployed via `script/aa/DeployAA.s.sol`. **Pre-audit; ship with
"small-value only" UI copy until external audit lands.**

| Contract | Address | Role |
|---|---|---|
| `WebAuthnP256Validator` | _pending broadcast_ | Kernel plug-in: gate UserOps on a registered WebAuthn passkey |
| `CitrateECDSAValidator` | _pending broadcast_ | Kernel plug-in: secondary validator for gui-native / wallet-extension EOA enrollment |
| `GuardianRecoveryModule` | _pending broadcast_ | M-of-N social-guardian "rotate signer" recovery |
| `Kernel implementation` | _pending broadcast_ | ZeroDev Kernel v3 (vendored from `lib/kernel`) implementation behind every CREATE2 ERC-1967 proxy clone |
| `CitrateWalletFactory` | _pending broadcast_ | Identity-keyed CREATE2 (`salt = keccak256(userId)`) + EIP-191 permit gate |
| `CitratePaymaster` | _pending broadcast_ | Per-user-per-day cap (100k default) + recovery budget (200k/event) + first-op budget (300k once/wallet) |
| `EntryPoint` (external) | **set via `CITRATE_AA_ENTRY_POINT` env at deploy** | eth-infinitism v0.7 reference EntryPoint; must be deployed separately before AA stack |

### Required env at deploy

| Var | Note |
|---|---|
| `CITRATE_AA_ENTRY_POINT` | EntryPoint v0.7 address on chain 40204 (deploy via `eth-infinitism/account-abstraction`'s own script first) |
| `CITRATE_AA_IDENTITY_SIGNER` | Operator EOA whose signature authorises factory deploys (lives in auth.citrate.ai env) |
| `CITRATE_AA_OWNER` | Owner of factory + paymaster — operator multisig in prod |
| `CITRATE_AA_DAILY_CAP` | Default `100000` (gas units) |
| `CITRATE_AA_RECOVERY_CAP` | Default `200000` |
| `CITRATE_AA_FIRST_OP_CAP` | Default `300000` |

Run after the EntryPoint is on chain:

```bash
CITRATE_AA_ENTRY_POINT=0x... \
CITRATE_AA_IDENTITY_SIGNER=0x... \
CITRATE_AA_OWNER=0x... \
forge script script/aa/DeployAA.s.sol \
  --rpc-url https://rpc.citrate.ai \
  --account ceremony-deployer \
  --sender 0x4250675F9015E65fC866F3a373F82bb9DFc000c6 \
  --broadcast
```

Addresses populate in `contracts/broadcast/aa/DeployAA.s.sol/40204/run-latest.json`
and this table updates with the canonical values after the broadcast lands.
