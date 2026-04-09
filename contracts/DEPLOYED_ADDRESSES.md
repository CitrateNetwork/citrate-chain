# Deployed Contract Addresses — Testnet Beta (Chain 40204)

> **Canonical source of truth**: the JSON broadcast files under
> `citrate_v0.01.1/contracts/broadcast/{DeployAll,DeployAIGateway,DeployEduStack,DeployModelAccessControl}.s.sol/40204/run-latest.json`,
> cross-referenced against the live chain via
> `eth_getCode` queries to `https://rpc2.citrate.ai` or direct
> `http://159.65.227.42:8545`.
>
> **This markdown is a convenience snapshot, not the canon.** The chain
> may be rerolled again before the real 40204 freeze; when that happens
> the broadcast files regenerate and this file should be regenerated
> alongside them, or trusted only as historical context for the run
> whose timestamp it carries.

- **Chain ID**: 40204
- **Canonical bootnode**: `159.65.227.42` (droplet)
- **Public RPC (primary)**: `https://rpc.citrate.ai` (Cloudflare-proxied → droplet)
- **Public RPC (cloudflared tunnel)**: `https://rpc2.citrate.ai` (second path to the same droplet)
- **Explorer**: `https://explorer.citrate.ai`
- **Faucet**: `https://faucet.citrate.ai`
- **Snapshot last verified**: 2026-04-08, block 772
- **Contract count**: **36** (27 core + 3 AI gateway + 5 edu + 1 model access control)
- **Status**: dry-run — chain will be rerolled before the real ceremony freeze

---

## Correction Note (2026-04-08)

**The prior version of this document was significantly stale and
should not have been relied on for auditor-facing release truth.**
Codex's audit pass on 2026-04-08 flagged the following specific
issues, which this rewrite resolves:

1. **Contract count was wrong.** Prior said "17 deployed"; the
   current chain has **36** deployed and verified.
2. **Vault signers were Hardhat defaults.** Prior listed
   `0xf39Fd6e5...`, `0x70997970...`, `0x3C44Cddd...` as vault
   signers — those are Anvil account indices 0/1/2, not the real
   operator-controlled addresses. The canonical signer set is
   listed below.
3. **Devnet coinbase was wrong.** Prior said `0xf39Fd6e5...`
   (Hardhat #0); the real droplet coinbase is
   `0x60434243d776D0C492EbdbE6FEF67deC7Be356c5` (`citrate-devops`).
4. **"Not Yet Redeployed (21 contracts)" list was entirely wrong.**
   All 21 of those contracts (`DisputeResolution`, `TreasuryGovernor`,
   `NematocystSlashing`, `ClassroomRegistry`, `LearningCycleManager`,
   `LoRAFactory`, `MarketMakerAllocation`, `X402Facilitator`,
   `X402Paywall`, `IPFSIncentives`, `HeartbeatMonitor`,
   `AgentDecisionRegistry`, `SpecRegistry`, `StablecoinTreasury`,
   `TestnetFarmingAccounting`, `BulkComputeGateway`, `ComputePool`,
   `ComputePricingOracle`, `ModelAccessControl`, plus two stragglers)
   **are in fact deployed** on the current chain. The list is removed.
5. **Address → name labels were shuffled.** The prior version was
   written from a deployment script that ordered contracts
   differently, so while the `ModelRegistry` address (deterministic
   from the deployer at nonce 0) happened to match, several other
   labels pointed at the wrong current-chain contracts. For example,
   the prior `WrappedSALT` address is actually the current
   `ContributionAccounting`. This rewrite labels from the current
   broadcast files directly.
6. **Stale cross-references.** Prior cited
   `.agentile/launch/DEPLOYED_CONTRACTS_2026_04_06.md` as canonical;
   that file is also stale. This rewrite points at the broadcast
   files and live RPC as the only authoritative sources.

The prior version's git history is preserved in the repository log —
this is a rewrite commit, not an amend.

---

## Deployer & Signer Accounts

| Role | Address | Source |
|------|---------|--------|
| **Genesis deployer** (used for all 36 deploys) | `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` | `.env.testnet` `DEPLOYER_PRIVATE_KEY` |
| **Droplet coinbase / RELAYER** | `0x60434243d776D0C492EbdbE6FEF67deC7Be356c5` | `citrate-devops` Foundry keystore account |
| **Vault SIGNER_1** | `0xC1476Bb534a008cA183091dDFEd557029E788528` | Saul's operator-provided |
| **Vault SIGNER_2** | `0x9f5B156C53305D4b20c94ca08E3219D1C0e7401a` | Saul's operator-provided |
| **Vault SIGNER_3 / GOVERNANCE** | `0xD245Ae7D7567B2d83C5d3ad9638611d7623ceb94` | Saul's operator-provided |

**Vault**: 2-of-3 multi-sig using SIGNER_1/2/3 above. GOVERNANCE is
the same address as SIGNER_3 for this dry run; may be separated for
the real ceremony.

---

## Live Contracts — 36 Total

All addresses below have been cross-verified against the live chain
at block 772 (2026-04-08) via `eth_getCode` against
`https://rpc2.citrate.ai`. Zero failures.

### Core Suite (27) — `script/DeployAll.s.sol`

| # | Contract | Address |
|---|----------|---------|
| 1 | `ModelRegistry` | `0x077fbc3338a9e6bad90a3a041e6b7425689754ef` |
| 2 | `WrappedSALT` | `0x1f73bb479f397a34b5e3145e51d25bc5007273bf` |
| 3 | `AgentDecisionRegistry` | `0x0aaa6e00fcab1da5599f6dce86e361a5e03a5759` |
| 4 | `SpecRegistry` | `0x1b6aeed728f53b48e1ed831b04a1f4812f48e928` |
| 5 | `IPFSIncentives` | `0xa6a4122126a75611ea06241e404327addfe8eb5e` |
| 6 | `X402Facilitator` | `0xc0fde3a8a42f6479cf12b4a5489e7a988c918e23` |
| 7 | `X402Paywall` | `0x11399989175783cdca8ecb095835c8cd4720c6fc` |
| 8 | `LiquidStakingPool` | `0xd71b7e33e447e062f4e796def686156805820b29` |
| 9 | `ContributionAccounting` | `0x1afe987622ab5add275d2fd21248f77f5e00667f` |
| 10 | `NematocystSlashing` | `0x425064443c3c3392c47dcbe10d455831545efd9b` |
| 11 | `MarketMakerAllocation` | `0xf61e79af3bc2a905695e45b0fa7a43f9141a554a` |
| 12 | `ModelMarketplace` | `0x11a5e6f57751d8fa1c5b58ad2bf13528160985f0` |
| 13 | `InferenceRouter` | `0xad7c3135c1b9b3189208fd617b6b058c1c0469f3` |
| 14 | `LoRAFactory` | `0xac6bfb1709bcba5a005fe2823b4d8bc55db2b7d9` |
| 15 | `LearningPool` | `0x9a58e44f8dd6fd6a75637a32e6e51c16440996f8` |
| 16 | `LearningCycleManager` | `0x20a0b74c766e84b20558abd76a7a0fd6434a4c4c` |
| 17 | `ClassroomRegistry` | `0x7e7a3db3be6fe4bea06acdbb772786432e1293e3` |
| 18 | `ComputeVerifier` | `0xd29d4d059808adc43b761f41c675f1eb546e1a19` |
| 19 | `ComputeMarketplace` | `0x8951ae72e5479cae28ef7bb3caa4207d5719e24b` |
| 20 | `ComputePool` | `0x86d918808b48ad543c9c816b5303b7dbcb0e321f` |
| 21 | `HeartbeatMonitor` | `0xf3f9f72ea2bb3f763b07390b7257da643b8ee9b6` |
| 22 | `DisputeResolution` | `0x8b36c15552394ce44173a29d054dc5ca482e65d3` |
| 23 | `ComputePricingOracle` | `0x46773aeca885be65cd313b7d9bce9625767d40b5` |
| 24 | `StablecoinTreasury` | `0x6884ef1907468a13265a0bbb67da20ef4b52199b` |
| 25 | `BulkComputeGateway` | `0xa1eed6ae021504e2a1e310e6c0f7c1a0c5bf4647` |
| 26 | `TestnetFarmingAccounting` | `0x828c6b831c4ce08170bc3efc6f6026dc44b20dfa` |
| 27 | `TreasuryGovernor` | `0x7efc1eb17beff413e1af7fb3bb541e895c307300` |

### AI Gateway Suite (3) — `script/DeployAIGateway.s.sol`

EIP portable implementations, deployable on any EVM chain.

| # | Contract | EIP Level | Address |
|---|----------|-----------|---------|
| 28 | `AIModelRegistryPortable` | L0 + L1 | `0x541923570df41b307ca037fdd0fb508502885455` |
| 29 | `AIInferenceRouterPortable` | L2 | `0x516380b0acef9a9541641c85dbe0bf89b3e56977` |
| 30 | `AILearningCycleCorePortable` | L3 | `0x26333384a517c50d8b116979490b4ad1506f1f9a` |

### Education Stack (5) — `script/DeployEduStack.s.sol`

Institutional education contracts, deployed in dependency order.

| # | Contract | Address | Governance |
|---|----------|---------|------------|
| 31 | `InstitutionalVault` | `0x18d3e03eb3364f63db8e4f6bbd078ad8098c2c2b` | 2-of-3 multi-sig (SIGNER_1/2/3) |
| 32 | `ClassroomClusterV1` | `0x00132c0f7fad65a6d54d2c561dc4609237437449` | Vault |
| 33 | `Forwarder` | `0xcb5fcad35f892e7e1da4bb4d17a48dd9e056583e` | Vault (device/session validation) |
| 34 | `BudgetAllocation` | `0xdaff2b9dc254b6cb3040f8f14304d30e136fa136` | Vault |
| 35 | `CashoutRequest` | `0xb87a4f754ca316d2416553d04f4eded26424b536` | Vault |

### Model Access Control (1) — `script/DeployModelAccessControl.s.sol`

Deployed as its own ceremony step per
`.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md`
scope-decision rules.

| # | Contract | Address |
|---|----------|---------|
| 36 | `ModelAccessControl` | `0x4ee0bef59a87a9ea3f91b80fd68ebfe69e72075a` |

---

## Genesis Allocations

From `node/config/testnet-beta.toml`, pre-deploy, at chain start:

| Account | Address | Allocation |
|---------|---------|------------|
| Treasury | `0xacEAA7d00C024d32e6E0A07094ceB1a7706786D1` | 500,000,000 SALT |
| Faucet (operational) | `0xF4ADb1734f7Bd9f8979BD53b2bf6D7690D562B6D` | 50,000,000 SALT |
| Deployer | `0x4250675F9015E65fC866F3a373F82bb9DFc000c6` | 10,000,000 SALT |
| Team/Dev | `0xb6E9A558a4f9DC9E3F667a3B446a48bddF671126` | 10,000,000 SALT |
| Validator | `0x04ABaE08aC643b2C518F22e212A27f7B6e14b4C3` | 5,000,000 SALT |

### Post-deploy state, verified 2026-04-08 block 772

Deployer (`0x4250...c6`) balance: **3,999,999.886661... SALT**.
Decrement from genesis ≈ 6,000,000.21 SALT, accounted for by:

- ~0.21 SALT of gas consumed across the 36 contract deployments
- 1,000,000 SALT transferred to `citrate-devops` `0x60434243...` (droplet coinbase + relayer)
- 1,000,000 SALT transferred to `SIGNER_1` `0xC1476Bb5...`
- 1,000,000 SALT transferred to `SIGNER_2` `0x9f5B156C...`
- 1,000,000 SALT transferred to `SIGNER_3 / GOVERNANCE` `0xD245Ae7D...`
- 1,000,000 SALT transferred to `faucet-ed25519-drip` `0x6680b43a...` (the faucet binary's
  deterministic ed25519 default key, required because the current
  faucet crate signs natively with ed25519 not secp256k1)
- 1,000,000 SALT transferred to `faucet-secp256k1-topup` `0xF4ADb173...`
  (on top of the 50M genesis allocation — symbolic, the genesis alloc
  is plenty)
- negligible transfer-tx gas

Deployer nonce: **42** (36 deploys + 6 funding transfers).

---

## Verification

To re-verify this snapshot from scratch:

```bash
# extract addresses from broadcast files
for s in DeployAll DeployAIGateway DeployEduStack DeployModelAccessControl; do
  jq -c --arg src "$s" '.transactions[] | select(.transactionType == "CREATE")
    | {script: $src, name: .contractName, address: .contractAddress}' \
    "citrate_v0.01.1/contracts/broadcast/$s.s.sol/40204/run-latest.json"
done
# → 36 lines

# cross-check every address has code on the live chain
for addr in $(jq -r '.address' ...); do
  curl -sf -X POST https://rpc2.citrate.ai \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$addr\",\"latest\"],\"id\":1}"
done
# → every result must be a non-"0x" bytecode string
```

---

## What This File Is Not

- **Not a release manifest.** The real 40204 ceremony hasn't run yet.
  This is a dry-run snapshot against a chain that will be rerolled.
- **Not a mapping from source file to deploy order.** That lives in
  the deploy scripts themselves
  (`script/Deploy{All,AIGateway,EduStack,ModelAccessControl}.s.sol`)
  plus the broadcast JSONs.
- **Not a source of truth for the friendly DNS names.** `rpc.citrate.ai`,
  `explorer.citrate.ai`, and `faucet.citrate.ai` are live as of
  2026-04-08 (Cloudflare-proxied to the droplet). `rpc2.citrate.ai`
  remains as a second path via the cloudflared tunnel. The raw
  droplet IP `159.65.227.42` is a fallback of last resort.

---

## See Also

- `.agentile/docs/journals/2026-04-08T14_DROPLET_STANDUP_SPARK_RETIRED.md`
  — narrative of the droplet stand-up that produced this deployment
- `.agentile/docs/journals/2026-04-08T03_BUG_FIXES_VALIDATED_END_TO_END.md`
  — validation of Codex's four bug fixes against this chain
- `.agentile/docs/essays/2026-04-08_HEADER_SYNC_IS_NOT_STATE_SYNC.md`
  — the sync protocol finding that came out of trying to run a peer
- `.agentile/quorum/18_CEREMONY_GO_AHEAD_AND_BENCHMARK_EXECUTION_STRATEGY.md`
  — auditor strategy doc that gates the real ceremony
