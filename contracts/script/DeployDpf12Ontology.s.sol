// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/defense_prime/EntityRegistry.sol";

/// @title DeployDpf12Ontology — Stage 10 broadcast
/// @notice Deploys the DPF-12 NEW contract (EntityRegistry) to chain
///         40204. Deployer self-authorizes as recorder so the E2E
///         suite can write without a separate cast send.
contract DeployDpf12Ontology is ScriptEnv {
    function run() external returns (address entityRegistry) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-12 Ontology deployment (Stage 10) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        EntityRegistry er = new EntityRegistry(governance);
        console.log("EntityRegistry:  ", address(er));
        er.setRecorder(deployer, true);
        console.log("Recorder set: deployer");

        vm.stopBroadcast();

        entityRegistry = address(er);

        console.log("=== Stage 10 complete ===");
    }
}
