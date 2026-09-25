// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./lib/GovernanceOps.sol";
import "../src/defense_prime/TinaWorkpaperRegistry.sol";

/// @title DeployDpf13Procurement — Stage 11 broadcast
/// @notice Deploys TinaWorkpaperRegistry to chain 40204. Deployer
///         self-authorizes as recorder.
contract DeployDpf13Procurement is ScriptEnv, GovernanceOps {
    function run() external returns (address tina) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-13 Procurement deployment (Stage 11) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        TinaWorkpaperRegistry reg = new TinaWorkpaperRegistry(governance);
        console.log("TinaWorkpaperRegistry:  ", address(reg));
        _govCall(governance, deployer, address(reg), abi.encodeWithSignature("setRecorder(address,bool)", deployer, true), "reg.setRecorder(deployer, true)");
        console.log("Recorder set: deployer");

        vm.stopBroadcast();

        tina = address(reg);
        console.log("=== Stage 11 complete ===");
    }
}
