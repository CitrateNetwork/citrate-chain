// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/LearningCycleManager.sol";
import "../src/ContributionAccounting.sol";

/// @title OpenStarterCycle — redeploy governable learning contracts + open cycle 1.
/// @notice SFL-04 WP-4.1 (absorbs PIL-04 WP-4.1/4.2). The 2026-07-05 DeployAll
///         run deployed `LearningCycleManager` and `ContributionAccounting` via
///         CREATE2 (salted `new`), so `Governable(msg.sender)` captured the
///         deterministic CREATE2 proxy (0x4e59b44847b379578588920cA78FbF26c0B4956C)
///         as governance, and DeployAll performs no post-deploy transfer for
///         them. Governance transfer is two-step and only callable by current
///         governance, so governance on those instances is permanently burned:
///         `openCycle` / `addRecorder` can never execute there.
///
///         This script therefore:
///           1. redeploys both contracts with PLAIN CREATE (unsalted `new`),
///              so `msg.sender` in the constructor is the broadcasting EOA and
///              governance is held by the deployer;
///           2. authorizes the deployer as a contribution recorder (testnet
///              posture; workers/daemon get added as recorders in SFL-04 WP-4.5);
///           3. opens learning cycle 1 anchored to the next BFT checkpoint
///              boundary (interval 50 blocks, per consensus config).
///
///         After broadcasting, regenerate the canonical address table
///         (`scripts/ops/emit-address-table.sh`) so `addresses/40204.json`
///         picks up the new addresses — the old (governance-burned) instances
///         stay on-chain but nothing should reference them.
///
///         The same burned-governance pattern affects 9 more Governable
///         contracts from DeployAll (AggregationChallenge, ComputeMarketplace,
///         ComputePricingOracle, DisputeResolution, ComputePool,
///         ComputeVerifier, HeartbeatMonitor, LiquidStakingPool,
///         NematocystSlashing). Remediating those is tracked in the SFL-04
///         sprint file, not here.
///
///   Usage (dry-run):
///     forge script script/OpenStarterCycle.s.sol \
///       --rpc-url https://rpc.citrate.ai --sender <deployer-address>
///   Usage (broadcast, signer supplied by CLI per ScriptEnv policy):
///     forge script script/OpenStarterCycle.s.sol \
///       --rpc-url https://rpc.citrate.ai --broadcast --slow \
///       --private-key $CITRATE_DEPLOYER_KEY
contract OpenStarterCycle is ScriptEnv {
    /// BFT checkpoint interval on 40204 (blocks). Mirror of consensus config.
    uint256 internal constant CHECKPOINT_INTERVAL = 50;

    function run() external {
        vm.startBroadcast();

        // 1. Fresh instances with governance = broadcasting EOA (plain CREATE).
        LearningCycleManager cycleManager = new LearningCycleManager();
        ContributionAccounting contributions = new ContributionAccounting();
        console2.log("LearningCycleManager (governed):", address(cycleManager));
        console2.log("ContributionAccounting (governed):", address(contributions));
        console2.log("governance:", cycleManager.governance());

        // 2. Deployer can record contributions on testnet.
        contributions.addRecorder(msg.sender);

        // 3. Open cycle 1 at the next checkpoint boundary.
        uint256 checkpointHeight =
            ((block.number / CHECKPOINT_INTERVAL) + 1) * CHECKPOINT_INTERVAL;
        cycleManager.openCycle(checkpointHeight);
        console2.log("cycle opened, id:", cycleManager.currentCycleId());
        console2.log("checkpoint height:", checkpointHeight);

        vm.stopBroadcast();
    }
}
