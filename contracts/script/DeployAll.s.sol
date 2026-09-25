// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";

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
import "../src/MentorMatcher.sol";

// Agent
import "../src/AgentDecisionRegistry.sol";
import "../src/SpecRegistry.sol";

/**
 * @title DeployAll
 * @notice Deploys the core Citrate production contracts in dependency order.
 *         Run: forge script script/DeployAll.s.sol --rpc-url http://localhost:8545 --broadcast -vvvv
 *
 *         This is one of six ceremony steps. The full reroll runs:
 *           1. DeployAll.s.sol                  (this script — 28 contracts)
 *           2. DeployModelAccessControl.s.sol   (1 contract — separated due to OZ deps)
 *           3. DeployTEEAttestationRegistry.s.sol (1 contract — CM-08)
 *           4. DeployComputePoolTraining.s.sol  (1 contract — CM-07)
 *           5. DeployEduStack.s.sol             (5 contracts — Learning Center)
 *           6. DeployAIGateway.s.sol            (3 contracts — edu/ai-gateway)
 *         Total: 39 contracts. See scripts/regenesis.sh for the orchestration.
 *
 *         PBA-L2-002 (pre-bounty audit 2026-09-24): every contract whose admin /
 *         owner / governance used to be `msg.sender` now receives it explicitly
 *         (`GOVERNANCE` env, default = the deployer). `msg.sender` inside a
 *         salted constructor is the CREATE2 factory, which orphaned 21 live
 *         contracts. After deploying, `_assertAdmins` re-reads every admin slot
 *         and reverts the run if any names the factory or not the intended key.
 *
 *         Re-runnable: a contract whose salted CREATE2 address already holds
 *         code (so, by construction, the same init code) is reused; only the
 *         rest are deployed, as ordinary `new X{salt:}()` so broadcast records
 *         and the address-table emitter keep working.
 */
contract DeployAll is ScriptEnv, AdminChecks, Create2Deploy {
    /// Every address this script deploys (returned for the post-deploy check
    /// and for the in-process test in test/pba_r2/).
    struct Deployed {
        address registry;
        address wsalt;
        address agentRegistry;
        address specRegistry;
        address ipfs;
        address facilitator;
        address paywall;
        address stakingPool;
        address contributions;
        address slashing;
        address mmAlloc;
        address modelMarketplace;
        address router;
        address loraFactory;
        address learningPool;
        address cycleManager;
        address classroom;
        address mentorMatcher;
        address verifier;
        address computeMarketplace;
        address computePool;
        address heartbeat;
        address dispute;
        address oracle;
        address treasury;
        address gateway;
        address farming;
        address governor;
    }

    function run() external {
        deploy();
    }

    function deploy() public returns (Deployed memory d) {
        address deployer = deployerAddress();
        return deployWith(deployer, envAddressOr("GOVERNANCE", deployer), envAddressOr("GUARDIAN", deployer));
    }

    /// @notice The ceremony with explicit keys (no environment reads), so a
    ///         caller or test is not affected by concurrently changing env.
    function deployWith(address deployer, address governance, address guardian) public returns (Deployed memory d) {

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

        ModelRegistry registry = (_isLive("ModelRegistry", abi.encodePacked(type(ModelRegistry).creationCode, abi.encode(governance)))
            ? ModelRegistry(payable(_create2Address("ModelRegistry", abi.encodePacked(type(ModelRegistry).creationCode, abi.encode(governance)))))
            : new ModelRegistry{salt: Salts.salt("ModelRegistry")}(governance));
        console.log("  ModelRegistry:", address(registry));

        WrappedSALT wsalt = (_isLive("WrappedSALT", type(WrappedSALT).creationCode)
            ? WrappedSALT(payable(_create2Address("WrappedSALT", type(WrappedSALT).creationCode)))
            : new WrappedSALT{salt: Salts.salt("WrappedSALT")}());
        console.log("  WrappedSALT:", address(wsalt));

        AgentDecisionRegistry agentRegistry = (_isLive("AgentDecisionRegistry", abi.encodePacked(type(AgentDecisionRegistry).creationCode, abi.encode(deployer)))
            ? AgentDecisionRegistry(payable(_create2Address("AgentDecisionRegistry", abi.encodePacked(type(AgentDecisionRegistry).creationCode, abi.encode(deployer)))))
            : new AgentDecisionRegistry{salt: Salts.salt("AgentDecisionRegistry")}(deployer));
        console.log("  AgentDecisionRegistry:", address(agentRegistry));

        // RM-L / WP-L1.1: SpecRegistry now requires governance address
        // at deploy. Pass `deployer` for testnet; production should pass
        // the multisig per the L1.6 genesis runbook.
        SpecRegistry specRegistry = (_isLive("SpecRegistry", abi.encodePacked(type(SpecRegistry).creationCode, abi.encode(deployer)))
            ? SpecRegistry(payable(_create2Address("SpecRegistry", abi.encodePacked(type(SpecRegistry).creationCode, abi.encode(deployer)))))
            : new SpecRegistry{salt: Salts.salt("SpecRegistry")}(deployer));
        console.log("  SpecRegistry:", address(specRegistry));

        IPFSIncentives ipfs = (_isLive("IPFSIncentives", abi.encodePacked(type(IPFSIncentives).creationCode, abi.encode(governance)))
            ? IPFSIncentives(payable(_create2Address("IPFSIncentives", abi.encodePacked(type(IPFSIncentives).creationCode, abi.encode(governance)))))
            : new IPFSIncentives{salt: Salts.salt("IPFSIncentives")}(governance));
        console.log("  IPFSIncentives:", address(ipfs));

        // =====================================================================
        // Layer 2: Payment & Access (depends on Layer 1)
        // =====================================================================
        console.log("--- Layer 2: Payment & Access ---");

        X402Facilitator facilitator = (_isLive("X402Facilitator", abi.encodePacked(type(X402Facilitator).creationCode, abi.encode(
            address(wsalt),
            deployer,  // treasury
            100,       // 1% fee
            governance // admin + facilitator (PBA-L2-002)
        )))
            ? X402Facilitator(payable(_create2Address("X402Facilitator", abi.encodePacked(type(X402Facilitator).creationCode, abi.encode(
            address(wsalt),
            deployer,  // treasury
            100,       // 1% fee
            governance // admin + facilitator (PBA-L2-002)
        )))))
            : new X402Facilitator{salt: Salts.salt("X402Facilitator")}(
            address(wsalt),
            deployer,  // treasury
            100,       // 1% fee
            governance // admin + facilitator (PBA-L2-002)
        ));
        console.log("  X402Facilitator:", address(facilitator));

        X402Paywall paywall = (_isLive("X402Paywall", abi.encodePacked(type(X402Paywall).creationCode, abi.encode(address(wsalt), 1 ether, governance)))
            ? X402Paywall(payable(_create2Address("X402Paywall", abi.encodePacked(type(X402Paywall).creationCode, abi.encode(address(wsalt), 1 ether, governance)))))
            : new X402Paywall{salt: Salts.salt("X402Paywall")}(address(wsalt), 1 ether, governance));
        console.log("  X402Paywall:", address(paywall));

        // ModelAccessControl is deployed by DeployModelAccessControl.s.sol
        console.log("  ModelAccessControl: separate ceremony step");

        // =====================================================================
        // Layer 3: Economics (staking, contribution, slashing)
        // =====================================================================
        console.log("--- Layer 3: Economics ---");

        LiquidStakingPool stakingPool = (_isLive("LiquidStakingPool", abi.encodePacked(type(LiquidStakingPool).creationCode, abi.encode(governance)))
            ? LiquidStakingPool(payable(_create2Address("LiquidStakingPool", abi.encodePacked(type(LiquidStakingPool).creationCode, abi.encode(governance)))))
            : new LiquidStakingPool{salt: Salts.salt("LiquidStakingPool")}(governance));
        console.log("  LiquidStakingPool:", address(stakingPool));

        ContributionAccounting contributions =
            (_isLive("ContributionAccounting", abi.encodePacked(type(ContributionAccounting).creationCode, abi.encode(governance)))
            ? ContributionAccounting(payable(_create2Address("ContributionAccounting", abi.encodePacked(type(ContributionAccounting).creationCode, abi.encode(governance)))))
            : new ContributionAccounting{salt: Salts.salt("ContributionAccounting")}(governance));
        console.log("  ContributionAccounting:", address(contributions));

        NematocystSlashing slashing = (_isLive("NematocystSlashing", abi.encodePacked(type(NematocystSlashing).creationCode, abi.encode(governance)))
            ? NematocystSlashing(payable(_create2Address("NematocystSlashing", abi.encodePacked(type(NematocystSlashing).creationCode, abi.encode(governance)))))
            : new NematocystSlashing{salt: Salts.salt("NematocystSlashing")}(governance));
        console.log("  NematocystSlashing:", address(slashing));

        MarketMakerAllocation mmAlloc = (_isLive("MarketMakerAllocation", abi.encodePacked(type(MarketMakerAllocation).creationCode, abi.encode(
            deployer,   // market maker (deployer for now, DAO changes later)
            deployer    // governance
        )))
            ? MarketMakerAllocation(payable(_create2Address("MarketMakerAllocation", abi.encodePacked(type(MarketMakerAllocation).creationCode, abi.encode(
            deployer,   // market maker (deployer for now, DAO changes later)
            deployer    // governance
        )))))
            : new MarketMakerAllocation{salt: Salts.salt("MarketMakerAllocation")}(
            deployer,   // market maker (deployer for now, DAO changes later)
            deployer    // governance
        ));
        console.log("  MarketMakerAllocation:", address(mmAlloc));

        // =====================================================================
        // Layer 4: AI & Learning
        // =====================================================================
        console.log("--- Layer 4: AI & Learning ---");

        ModelMarketplace modelMarketplace = (_isLive("ModelMarketplace", abi.encodePacked(type(ModelMarketplace).creationCode, abi.encode(
            address(registry),
            deployer,  // treasury
            governance // admin (PBA-L2-002)
        )))
            ? ModelMarketplace(payable(_create2Address("ModelMarketplace", abi.encodePacked(type(ModelMarketplace).creationCode, abi.encode(
            address(registry),
            deployer,  // treasury
            governance // admin (PBA-L2-002)
        )))))
            : new ModelMarketplace{salt: Salts.salt("ModelMarketplace")}(
            address(registry),
            deployer,  // treasury
            governance // admin (PBA-L2-002)
        ));
        console.log("  ModelMarketplace:", address(modelMarketplace));

        InferenceRouter router = (_isLive("InferenceRouter", abi.encodePacked(type(InferenceRouter).creationCode, abi.encode(address(registry), governance)))
            ? InferenceRouter(payable(_create2Address("InferenceRouter", abi.encodePacked(type(InferenceRouter).creationCode, abi.encode(address(registry), governance)))))
            : new InferenceRouter{salt: Salts.salt("InferenceRouter")}(address(registry), governance));
        console.log("  InferenceRouter:", address(router));

        LoRAFactory loraFactory = (_isLive("LoRAFactory", abi.encodePacked(type(LoRAFactory).creationCode, abi.encode(address(registry), governance)))
            ? LoRAFactory(payable(_create2Address("LoRAFactory", abi.encodePacked(type(LoRAFactory).creationCode, abi.encode(address(registry), governance)))))
            : new LoRAFactory{salt: Salts.salt("LoRAFactory")}(address(registry), governance));
        console.log("  LoRAFactory:", address(loraFactory));

        LearningPool learningPool = (_isLive("LearningPool", type(LearningPool).creationCode)
            ? LearningPool(payable(_create2Address("LearningPool", type(LearningPool).creationCode)))
            : new LearningPool{salt: Salts.salt("LearningPool")}());
        console.log("  LearningPool:", address(learningPool));

        LearningCycleManager cycleManager =
            (_isLive("LearningCycleManager", abi.encodePacked(type(LearningCycleManager).creationCode, abi.encode(governance)))
            ? LearningCycleManager(payable(_create2Address("LearningCycleManager", abi.encodePacked(type(LearningCycleManager).creationCode, abi.encode(governance)))))
            : new LearningCycleManager{salt: Salts.salt("LearningCycleManager")}(governance));
        console.log("  LearningCycleManager:", address(cycleManager));

        ClassroomRegistry classroom = (_isLive("ClassroomRegistry", type(ClassroomRegistry).creationCode)
            ? ClassroomRegistry(payable(_create2Address("ClassroomRegistry", type(ClassroomRegistry).creationCode)))
            : new ClassroomRegistry{salt: Salts.salt("ClassroomRegistry")}());
        console.log("  ClassroomRegistry:", address(classroom));

        // RM-FL-4: MentorMatcher pairs mentors↔mentees from the
        // federated learning cohort. Wires to ContributionAccounting
        // for lazy per-(addr, dim) score reads — the matcher does not
        // mirror that state; it staticcalls it on demand. Governance
        // is the deployer for testnet; mainnet should use the multisig.
        MentorMatcher mentorMatcher = (_isLive("MentorMatcher", abi.encodePacked(type(MentorMatcher).creationCode, abi.encode(deployer)))
            ? MentorMatcher(payable(_create2Address("MentorMatcher", abi.encodePacked(type(MentorMatcher).creationCode, abi.encode(deployer)))))
            : new MentorMatcher{salt: Salts.salt("MentorMatcher")}(deployer));
        mentorMatcher.setContributionAccounting(address(contributions));
        console.log("  MentorMatcher:", address(mentorMatcher));

        // =====================================================================
        // Layer 5: Compute Marketplace
        // =====================================================================
        console.log("--- Layer 5: Compute Marketplace ---");

        // Deploy verifier first (ComputeMarketplace depends on it)
        ComputeVerifier verifier = (_isLive("ComputeVerifier", abi.encodePacked(type(ComputeVerifier).creationCode, abi.encode(deployer, governance)))
            ? ComputeVerifier(payable(_create2Address("ComputeVerifier", abi.encodePacked(type(ComputeVerifier).creationCode, abi.encode(deployer, governance)))))
            : new ComputeVerifier{salt: Salts.salt("ComputeVerifier")}(deployer, governance));
        console.log("  ComputeVerifier:", address(verifier));

        ComputeMarketplace computeMarketplace = (_isLive("ComputeMarketplace", abi.encodePacked(type(ComputeMarketplace).creationCode, abi.encode(
            address(verifier),
            deployer,  // treasury
            governance // governance (PBA-L2-002)
        )))
            ? ComputeMarketplace(payable(_create2Address("ComputeMarketplace", abi.encodePacked(type(ComputeMarketplace).creationCode, abi.encode(
            address(verifier),
            deployer,  // treasury
            governance // governance (PBA-L2-002)
        )))))
            : new ComputeMarketplace{salt: Salts.salt("ComputeMarketplace")}(
            address(verifier),
            deployer,  // treasury
            governance // governance (PBA-L2-002)
        ));
        console.log("  ComputeMarketplace:", address(computeMarketplace));

        ComputePool computePool = (_isLive("ComputePool", abi.encodePacked(type(ComputePool).creationCode, abi.encode(governance)))
            ? ComputePool(payable(_create2Address("ComputePool", abi.encodePacked(type(ComputePool).creationCode, abi.encode(governance)))))
            : new ComputePool{salt: Salts.salt("ComputePool")}(governance));
        console.log("  ComputePool:", address(computePool));

        HeartbeatMonitor heartbeat = (_isLive("HeartbeatMonitor", abi.encodePacked(type(HeartbeatMonitor).creationCode, abi.encode(
            50,        // heartbeat interval (blocks)
            3,         // max missed before suspension
            governance // governance (PBA-L2-002)
        )))
            ? HeartbeatMonitor(payable(_create2Address("HeartbeatMonitor", abi.encodePacked(type(HeartbeatMonitor).creationCode, abi.encode(
            50,        // heartbeat interval (blocks)
            3,         // max missed before suspension
            governance // governance (PBA-L2-002)
        )))))
            : new HeartbeatMonitor{salt: Salts.salt("HeartbeatMonitor")}(
            50,        // heartbeat interval (blocks)
            3,         // max missed before suspension
            governance // governance (PBA-L2-002)
        ));
        console.log("  HeartbeatMonitor:", address(heartbeat));

        DisputeResolution dispute = (_isLive("DisputeResolution", abi.encodePacked(type(DisputeResolution).creationCode, abi.encode(
            10 ether,  // 10 SALT dispute bond
            10,        // max bisection rounds
            governance // governance (PBA-L2-002)
        )))
            ? DisputeResolution(payable(_create2Address("DisputeResolution", abi.encodePacked(type(DisputeResolution).creationCode, abi.encode(
            10 ether,  // 10 SALT dispute bond
            10,        // max bisection rounds
            governance // governance (PBA-L2-002)
        )))))
            : new DisputeResolution{salt: Salts.salt("DisputeResolution")}(
            10 ether,  // 10 SALT dispute bond
            10,        // max bisection rounds
            governance // governance (PBA-L2-002)
        ));
        console.log("  DisputeResolution:", address(dispute));

        ComputePricingOracle oracle = (_isLive("ComputePricingOracle", abi.encodePacked(type(ComputePricingOracle).creationCode, abi.encode(
            13,        // $0.13/PFLOP-hour
            100,       // $1.00/SALT
            governance // governance (PBA-L2-002)
        )))
            ? ComputePricingOracle(payable(_create2Address("ComputePricingOracle", abi.encodePacked(type(ComputePricingOracle).creationCode, abi.encode(
            13,        // $0.13/PFLOP-hour
            100,       // $1.00/SALT
            governance // governance (PBA-L2-002)
        )))))
            : new ComputePricingOracle{salt: Salts.salt("ComputePricingOracle")}(
            13,        // $0.13/PFLOP-hour
            100,       // $1.00/SALT
            governance // governance (PBA-L2-002)
        ));
        console.log("  ComputePricingOracle:", address(oracle));

        // =====================================================================
        // Layer 6: Treasury & Governance
        // =====================================================================
        console.log("--- Layer 6: Treasury & Governance ---");

        StablecoinTreasury treasury = (_isLive("StablecoinTreasury", abi.encodePacked(type(StablecoinTreasury).creationCode, abi.encode(deployer)))
            ? StablecoinTreasury(payable(_create2Address("StablecoinTreasury", abi.encodePacked(type(StablecoinTreasury).creationCode, abi.encode(deployer)))))
            : new StablecoinTreasury{salt: Salts.salt("StablecoinTreasury")}(deployer));
        console.log("  StablecoinTreasury:", address(treasury));

        BulkComputeGateway gateway = (_isLive("BulkComputeGateway", abi.encodePacked(type(BulkComputeGateway).creationCode, abi.encode(
            address(treasury),
            address(oracle),
            deployer   // admin
        )))
            ? BulkComputeGateway(payable(_create2Address("BulkComputeGateway", abi.encodePacked(type(BulkComputeGateway).creationCode, abi.encode(
            address(treasury),
            address(oracle),
            deployer   // admin
        )))))
            : new BulkComputeGateway{salt: Salts.salt("BulkComputeGateway")}(
            address(treasury),
            address(oracle),
            deployer   // admin
        ));
        treasury.setAuthorizedActivityRecorder(address(gateway), true);
        console.log("  BulkComputeGateway:", address(gateway));

        TestnetFarmingAccounting farming = (_isLive("TestnetFarmingAccounting", abi.encodePacked(type(TestnetFarmingAccounting).creationCode, abi.encode(
            address(contributions),
            address(treasury),
            deployer   // governance
        )))
            ? TestnetFarmingAccounting(payable(_create2Address("TestnetFarmingAccounting", abi.encodePacked(type(TestnetFarmingAccounting).creationCode, abi.encode(
            address(contributions),
            address(treasury),
            deployer   // governance
        )))))
            : new TestnetFarmingAccounting{salt: Salts.salt("TestnetFarmingAccounting")}(
            address(contributions),
            address(treasury),
            deployer   // governance
        ));
        console.log("  TestnetFarmingAccounting:", address(farming));

        TreasuryGovernor governor = (_isLive("TreasuryGovernor", abi.encodePacked(type(TreasuryGovernor).creationCode, abi.encode(
            address(stakingPool),
            address(treasury),
            guardian, // guardian (PBA-L2-001: set GUARDIAN to the multisig)
            1_000_000_000 ether // total SALT supply (1B)
        )))
            ? TreasuryGovernor(payable(_create2Address("TreasuryGovernor", abi.encodePacked(type(TreasuryGovernor).creationCode, abi.encode(
            address(stakingPool),
            address(treasury),
            guardian, // guardian (PBA-L2-001: set GUARDIAN to the multisig)
            1_000_000_000 ether // total SALT supply (1B)
        )))))
            : new TreasuryGovernor{salt: Salts.salt("TreasuryGovernor")}(
            address(stakingPool),
            address(treasury),
            guardian, // guardian (PBA-L2-001: set GUARDIAN to the multisig)
            1_000_000_000 ether // total SALT supply (1B)
        ));
        console.log("  TreasuryGovernor:", address(governor));

        vm.stopBroadcast();

        d = Deployed({
            registry: address(registry),
            wsalt: address(wsalt),
            agentRegistry: address(agentRegistry),
            specRegistry: address(specRegistry),
            ipfs: address(ipfs),
            facilitator: address(facilitator),
            paywall: address(paywall),
            stakingPool: address(stakingPool),
            contributions: address(contributions),
            slashing: address(slashing),
            mmAlloc: address(mmAlloc),
            modelMarketplace: address(modelMarketplace),
            router: address(router),
            loraFactory: address(loraFactory),
            learningPool: address(learningPool),
            cycleManager: address(cycleManager),
            classroom: address(classroom),
            mentorMatcher: address(mentorMatcher),
            verifier: address(verifier),
            computeMarketplace: address(computeMarketplace),
            computePool: address(computePool),
            heartbeat: address(heartbeat),
            dispute: address(dispute),
            oracle: address(oracle),
            treasury: address(treasury),
            gateway: address(gateway),
            farming: address(farming),
            governor: address(governor)
        });
        // PBA-L2-002 tripwire: fail the run if any admin slot is orphaned.
        _assertAdmins(d, deployer, governance);

        // =====================================================================
        // Summary
        // =====================================================================
        console.log("");
        console.log("=== DEPLOYMENT COMPLETE ===");
        console.log("Chain ID:", block.chainid);
        console.log("Total contracts deployed: 28");
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
        console.log("MentorMatcher         :", address(mentorMatcher));
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

    /// @notice PBA-L2-002 post-deploy assertion: every admin / owner /
    ///         governance slot names the intended key and never the CREATE2
    ///         factory. Also sweeps every deployed address generically.
    function _assertAdmins(Deployed memory d, address deployer, address governance) internal view {
        _assertAdminRole("ModelRegistry", d.registry, governance);
        _assertAdminRole("IPFSIncentives", d.ipfs, governance);
        _assertAdminRole("X402Facilitator", d.facilitator, governance);
        _assertAdminRole("ModelMarketplace", d.modelMarketplace, governance);
        _assertAdminRole("InferenceRouter", d.router, governance);
        _assertAdminRole("LoRAFactory", d.loraFactory, governance);
        _assertGovernance("LiquidStakingPool", d.stakingPool, governance);
        _assertGovernance("ContributionAccounting", d.contributions, governance);
        _assertGovernance("NematocystSlashing", d.slashing, governance);
        _assertGovernance("LearningCycleManager", d.cycleManager, governance);
        _assertGovernance("ComputeVerifier", d.verifier, governance);
        _assertGovernance("ComputeMarketplace", d.computeMarketplace, governance);
        _assertGovernance("ComputePool", d.computePool, governance);
        _assertGovernance("HeartbeatMonitor", d.heartbeat, governance);
        _assertGovernance("DisputeResolution", d.dispute, governance);
        _assertGovernance("ComputePricingOracle", d.oracle, governance);
        // Contracts that already took an explicit key (deployer) keep it.
        _assertGovernance("MentorMatcher", d.mentorMatcher, deployer);
        _assertGovernance("StablecoinTreasury", d.treasury, deployer);
        (bool ok, address provider) = _readAddress(d.paywall, abi.encodeWithSignature("provider()"));
        require(ok && provider == governance, "X402Paywall: provider is not the intended key");

        address[28] memory all = [
            d.registry, d.wsalt, d.agentRegistry, d.specRegistry, d.ipfs, d.facilitator, d.paywall,
            d.stakingPool, d.contributions, d.slashing, d.mmAlloc, d.modelMarketplace, d.router,
            d.loraFactory, d.learningPool, d.cycleManager, d.classroom, d.mentorMatcher, d.verifier,
            d.computeMarketplace, d.computePool, d.heartbeat, d.dispute, d.oracle, d.treasury,
            d.gateway, d.farming, d.governor
        ];
        for (uint256 i = 0; i < all.length; i++) {
            _assertNoFactoryAdmin("DeployAll", all[i]);
        }
    }
}
