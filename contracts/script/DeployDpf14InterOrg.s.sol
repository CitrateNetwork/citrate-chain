// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/defense_prime/CrossOrgEnvelope.sol";

/// @title DeployDpf14InterOrg — Stage 12 broadcast
/// @notice Deploys CrossOrgEnvelope to chain 40204. Deployer self-
///         authorizes as recorder.
contract DeployDpf14InterOrg is ScriptEnv {
    function run() external returns (address crossOrg) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-14 Inter-Org deployment (Stage 12) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        CrossOrgEnvelope env = new CrossOrgEnvelope(governance);
        console.log("CrossOrgEnvelope:  ", address(env));
        env.setRecorder(deployer, true);
        console.log("Recorder set: deployer");

        vm.stopBroadcast();

        crossOrg = address(env);
        console.log("=== Stage 12 complete ===");
    }
}
