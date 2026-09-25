// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./lib/GovernanceOps.sol";
import "../src/defense_prime/TripwireRegistry.sol";

/// @title DeployDpf15Compliance — Stage 13 broadcast
/// @notice Deploys TripwireRegistry. Deployer self-authorizes as
///         both recorder + resolver.
contract DeployDpf15Compliance is ScriptEnv, GovernanceOps {
    function run() external returns (address tripwire) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-15 Compliance deployment (Stage 13) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        TripwireRegistry reg = new TripwireRegistry(governance);
        console.log("TripwireRegistry:  ", address(reg));
        _govCall(governance, deployer, address(reg), abi.encodeWithSignature("setRecorder(address,bool)", deployer, true), "reg.setRecorder(deployer, true)");
        _govCall(governance, deployer, address(reg), abi.encodeWithSignature("setResolver(address,bool)", deployer, true), "reg.setResolver(deployer, true)");
        console.log("Recorder + resolver set: deployer");

        vm.stopBroadcast();

        tripwire = address(reg);
        console.log("=== Stage 13 complete ===");
    }
}
