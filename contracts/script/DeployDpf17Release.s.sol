// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/defense_prime/ReleaseManifestRegistry.sol";

/// @title DeployDpf17Release - Stage 15 broadcast (FINAL stage of DPF program)
/// @notice Deploys ReleaseManifestRegistry. Deployer self-authorizes
///         as recorder so CI release runs can broadcast.
contract DeployDpf17Release is ScriptEnv {
    function run() external returns (address rel) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-17 Release deployment (Stage 15 - FINAL) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        ReleaseManifestRegistry reg = new ReleaseManifestRegistry(governance);
        console.log("ReleaseManifestRegistry:  ", address(reg));
        reg.setRecorder(deployer, true);
        console.log("Recorder set: deployer");

        vm.stopBroadcast();

        rel = address(reg);
        console.log("=== Stage 15 complete - DPF program contract surface COMPLETE ===");
    }
}
