// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/boeing/AuditBundleRegistry.sol";

/// @title DeployBfr10Assistant — Stage 8 broadcast
/// @notice Deploys the BFR-10 NEW contract (AuditBundleRegistry) to
///         chain 40204. AgentDecisionRegistryV2 already exists at
///         Stage 1 (0x4a8665…820E40) and is reused.
///
/// @dev Per BFR-08/09 pattern, broadcast is HUMAN-IN-LOOP (Saul holds
///      the deployer key in .env.testnet). The dry-run output is the
///      acceptance evidence used in DEPLOYED_CONTRACTS_2026_05_10.md
///      Stage 8 section.
///
/// Usage:
///   forge script script/DeployBfr10Assistant.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract DeployBfr10Assistant is ScriptEnv {
    function run() external returns (address auditBundleRegistry) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== BFR-10 Assistant deployment (Stage 8) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        AuditBundleRegistry abr = new AuditBundleRegistry(governance);
        console.log("AuditBundleRegistry:  ", address(abr));

        // Self-authorize the deployer EOA as a recorder so the
        // initial post-deploy E2E tests can anchor session bundles
        // without a separate cast send round-trip.
        abr.setRecorder(deployer, true);
        console.log("Recorder set: deployer authorized");

        vm.stopBroadcast();

        auditBundleRegistry = address(abr);

        console.log("=== Stage 8 complete ===");
        console.log("Append address to DEPLOYED_CONTRACTS_2026_05_10.md");
        console.log("Update CONFIG.md 'BFR Boeing-side contracts' table");
    }
}
