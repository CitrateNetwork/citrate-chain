// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";

// Core
import "../src/ModelRegistry.sol";
import "../src/WrappedSALT.sol";
import "../src/X402Facilitator.sol";
import "../src/X402Paywall.sol";
import "../src/ModelMarketplace.sol";
import "../src/InferenceRouter.sol";
// ModelAccessControl is deployed in its own ceremony step so the canonical
// address table can still include it without coupling OZ imports into this script.
import "../src/LoRAFactory.sol";
import "../src/IPFSIncentives.sol";

// Economics
import "../src/LiquidStakingPool.sol";
import "../src/ContributionAccounting.sol";
import "../src/NematocystSlashing.sol";
import "../src/MarketMakerAllocation.sol";

// Compute
import "../src/ComputeMarketplace.sol";
import "../src/ComputeVerifier.sol";
import "../src/ComputePool.sol";
import "../src/HeartbeatMonitor.sol";
import "../src/DisputeResolution.sol";
import "../src/ComputePricingOracle.sol";

// Treasury & Governance
import "../src/StablecoinTreasury.sol";
import "../src/BulkComputeGateway.sol";
import "../src/TestnetFarmingAccounting.sol";
import "../src/TreasuryGovernor.sol";

// Learning
import "../src/LearningPool.sol";
import "../src/LearningCycleManager.sol";
import "../src/ClassroomRegistry.sol";

// Agent
import "../src/AgentDecisionRegistry.sol";
import "../src/SpecRegistry.sol";

/**
 * @title DeployAll
 * @notice Deploys all 31 Citrate production contracts in dependency order.
 *         Run: forge script script/DeployAll.s.sol --rpc-url http://localhost:8545 --broadcast -vvvv
 */
contract DeployAll is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();

        console.log("=== Citrate Full Contract Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("");

        // The signer is selected by the forge CLI, not by this script.
        vm.startBroadcast();

        // =====================================================================
        // Layer 1: Core Infrastructure (no dependencies)
        // =====================================================================
        console.log("--- Layer 1: Core Infrastructure ---");

        ModelRegistry registry = new ModelRegistry();
        console.log("  ModelRegistry:", address(registry));

        WrappedSALT wsalt = new WrappedSALT();
        console.log("  WrappedSALT:", address(wsalt));

        AgentDecisionRegistry agentRegistry = new AgentDecisionRegistry(deployer);
        console.log("  AgentDecisionRegistry:", address(agentRegistry));

        // RM-L / WP-L1.1: SpecRegistry now requires governance address
        // at deploy. Pass `deployer` for testnet; production should pass
        // the multisig per the L1.6 genesis runbook.
        SpecRegistry specRegistry = new SpecRegistry(deployer);
        console.log("  SpecRegistry:", address(specRegistry));

        IPFSIncentives ipfs = new IPFSIncentives();
        console.log("  IPFSIncentives:", address(ipfs));

        // =====================================================================
        // Layer 2: Payment & Access (depends on Layer 1)
        // =====================================================================
        console.log("--- Layer 2: Payment & Access ---");

        X402Facilitator facilitator = new X402Facilitator(
            address(wsalt),
            deployer,  // treasury
            100        // 1% fee
        );
        console.log("  X402Facilitator:", address(facilitator));

        X402Paywall paywall = new X402Paywall(address(wsalt), 1 ether);
        console.log("  X402Paywall:", address(paywall));

        // ModelAccessControl is deployed by DeployModelAccessControl.s.sol
        console.log("  ModelAccessControl: separate ceremony step");

        // =====================================================================
        // Layer 3: Economics (staking, contribution, slashing)
        // =====================================================================
        console.log("--- Layer 3: Economics ---");

        LiquidStakingPool stakingPool = new LiquidStakingPool();
        console.log("  LiquidStakingPool:", address(stakingPool));

        ContributionAccounting contributions = new ContributionAccounting();
        console.log("  ContributionAccounting:", address(contributions));

        NematocystSlashing slashing = new NematocystSlashing();
        console.log("  NematocystSlashing:", address(slashing));

        MarketMakerAllocation mmAlloc = new MarketMakerAllocation(
            deployer,   // market maker (deployer for now, DAO changes later)
            deployer    // governance
        );
        console.log("  MarketMakerAllocation:", address(mmAlloc));

        // =====================================================================
        // Layer 4: AI & Learning
        // =====================================================================
        console.log("--- Layer 4: AI & Learning ---");

        ModelMarketplace modelMarketplace = new ModelMarketplace(
            address(registry),
            deployer   // treasury
        );
        console.log("  ModelMarketplace:", address(modelMarketplace));

        InferenceRouter router = new InferenceRouter(address(registry));
        console.log("  InferenceRouter:", address(router));

        LoRAFactory loraFactory = new LoRAFactory(address(registry));
        console.log("  LoRAFactory:", address(loraFactory));

        LearningPool learningPool = new LearningPool();
        console.log("  LearningPool:", address(learningPool));

        LearningCycleManager cycleManager = new LearningCycleManager();
        console.log("  LearningCycleManager:", address(cycleManager));

        ClassroomRegistry classroom = new ClassroomRegistry();
        console.log("  ClassroomRegistry:", address(classroom));

        // =====================================================================
        // Layer 5: Compute Marketplace
        // =====================================================================
        console.log("--- Layer 5: Compute Marketplace ---");

        // Deploy verifier first (ComputeMarketplace depends on it)
        ComputeVerifier verifier = new ComputeVerifier(deployer);
        console.log("  ComputeVerifier:", address(verifier));

        ComputeMarketplace computeMarketplace = new ComputeMarketplace(
            address(verifier),
            deployer  // treasury
        );
        console.log("  ComputeMarketplace:", address(computeMarketplace));

        ComputePool computePool = new ComputePool();
        console.log("  ComputePool:", address(computePool));

        HeartbeatMonitor heartbeat = new HeartbeatMonitor(
            50,   // heartbeat interval (blocks)
            3     // max missed before suspension
        );
        console.log("  HeartbeatMonitor:", address(heartbeat));

        DisputeResolution dispute = new DisputeResolution(
            10 ether,  // 10 SALT dispute bond
            10         // max bisection rounds
        );
        console.log("  DisputeResolution:", address(dispute));

        ComputePricingOracle oracle = new ComputePricingOracle(
            13,    // $0.13/PFLOP-hour
            100    // $1.00/SALT
        );
        console.log("  ComputePricingOracle:", address(oracle));

        // =====================================================================
        // Layer 6: Treasury & Governance
        // =====================================================================
        console.log("--- Layer 6: Treasury & Governance ---");

        StablecoinTreasury treasury = new StablecoinTreasury(deployer);
        console.log("  StablecoinTreasury:", address(treasury));

        BulkComputeGateway gateway = new BulkComputeGateway(
            address(treasury),
            address(oracle),
            deployer   // admin
        );
        treasury.setAuthorizedActivityRecorder(address(gateway), true);
        console.log("  BulkComputeGateway:", address(gateway));

        TestnetFarmingAccounting farming = new TestnetFarmingAccounting(
            address(contributions),
            address(treasury),
            deployer   // governance
        );
        console.log("  TestnetFarmingAccounting:", address(farming));

        TreasuryGovernor governor = new TreasuryGovernor(
            address(stakingPool),
            address(treasury),
            deployer,           // guardian
            1_000_000_000 ether // total SALT supply (1B)
        );
        console.log("  TreasuryGovernor:", address(governor));

        vm.stopBroadcast();

        // =====================================================================
        // Summary
        // =====================================================================
        console.log("");
        console.log("=== DEPLOYMENT COMPLETE ===");
        console.log("Chain ID:", block.chainid);
        console.log("Total contracts deployed: 27");
        console.log("");
        console.log("--- Contract Addresses ---");
        console.log("ModelRegistry         :", address(registry));
        console.log("WrappedSALT           :", address(wsalt));
        console.log("AgentDecisionRegistry :", address(agentRegistry));
        console.log("SpecRegistry          :", address(specRegistry));
        console.log("IPFSIncentives        :", address(ipfs));
        console.log("X402Facilitator       :", address(facilitator));
        console.log("X402Paywall           :", address(paywall));
        console.log("ModelAccessControl    : separate ceremony step");
        console.log("LiquidStakingPool     :", address(stakingPool));
        console.log("ContributionAccounting:", address(contributions));
        console.log("NematocystSlashing    :", address(slashing));
        console.log("MarketMakerAllocation :", address(mmAlloc));
        console.log("ModelMarketplace      :", address(modelMarketplace));
        console.log("InferenceRouter       :", address(router));
        console.log("LoRAFactory           :", address(loraFactory));
        console.log("LearningPool          :", address(learningPool));
        console.log("LearningCycleManager  :", address(cycleManager));
        console.log("ClassroomRegistry     :", address(classroom));
        console.log("ComputeMarketplace    :", address(computeMarketplace));
        console.log("ComputeVerifier       :", address(verifier));
        console.log("ComputePool           :", address(computePool));
        console.log("HeartbeatMonitor      :", address(heartbeat));
        console.log("DisputeResolution     :", address(dispute));
        console.log("ComputePricingOracle  :", address(oracle));
        console.log("StablecoinTreasury    :", address(treasury));
        console.log("BulkComputeGateway    :", address(gateway));
        console.log("TestnetFarmingAcct    :", address(farming));
        console.log("TreasuryGovernor      :", address(governor));
    }
}
