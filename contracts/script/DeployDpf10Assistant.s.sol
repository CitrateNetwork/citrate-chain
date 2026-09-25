// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./lib/GovernanceOps.sol";
import "../src/defense_prime/AuditBundleRegistry.sol";

/// @title DeployDpf10Assistant — Stage 8 broadcast
/// @notice Deploys the DPF-10 NEW contract (AuditBundleRegistry) to
///         chain 40204. AgentDecisionRegistryV2 already exists at
///         Stage 1 (0x4a8665…820E40) and is reused.
///
/// @dev Per DPF-08/09 pattern, broadcast is HUMAN-IN-LOOP (Saul holds
///      the deployer key in .env.testnet). The dry-run output is the
///      acceptance evidence used in DEPLOYED_CONTRACTS_2026_05_10.md
///      Stage 8 section.
///
/// Usage:
///   forge script script/DeployDpf10Assistant.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract DeployDpf10Assistant is ScriptEnv, GovernanceOps {
    function run() external returns (address auditBundleRegistry) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-10 Assistant deployment (Stage 8) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        AuditBundleRegistry abr = new AuditBundleRegistry(governance);
        console.log("AuditBundleRegistry:  ", address(abr));

        // Self-authorize the deployer EOA as a recorder so the
        // initial post-deploy E2E tests can anchor session bundles
        // without a separate cast send round-trip.
        _govCall(governance, deployer, address(abr), abi.encodeWithSignature("setRecorder(address,bool)", deployer, true), "abr.setRecorder(deployer, true)");
        console.log("Recorder set: deployer authorized");

        vm.stopBroadcast();

        auditBundleRegistry = address(abr);

        console.log("=== Stage 8 complete ===");
        console.log("Append address to DEPLOYED_CONTRACTS_2026_05_10.md");
        console.log("Update CONFIG.md 'DPF DefensePrime-side contracts' table");
    }
}
