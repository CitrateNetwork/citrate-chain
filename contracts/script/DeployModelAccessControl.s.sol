// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/ModelAccessControl.sol";

/// @title DeployModelAccessControl
/// @notice Deploys ModelAccessControl as a standalone ceremony step.
contract DeployModelAccessControl is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();

        console.log("=== Deploying ModelAccessControl ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast();

        ModelAccessControl accessControl = new ModelAccessControl();
        console.log("ModelAccessControl:", address(accessControl));

        vm.stopBroadcast();
    }
}
