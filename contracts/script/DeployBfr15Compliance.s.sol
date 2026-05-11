// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/boeing/TripwireRegistry.sol";

/// @title DeployBfr15Compliance — Stage 13 broadcast
/// @notice Deploys TripwireRegistry. Deployer self-authorizes as
///         both recorder + resolver.
contract DeployBfr15Compliance is ScriptEnv {
    function run() external returns (address tripwire) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== BFR-15 Compliance deployment (Stage 13) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        TripwireRegistry reg = new TripwireRegistry(governance);
        console.log("TripwireRegistry:  ", address(reg));
        reg.setRecorder(deployer, true);
        reg.setResolver(deployer, true);
        console.log("Recorder + resolver set: deployer");

        vm.stopBroadcast();

        tripwire = address(reg);
        console.log("=== Stage 13 complete ===");
    }
}
