// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "../src/ModelAccessControl.sol";

/// @title DeployModelAccessControl
/// @notice Deploys ModelAccessControl as a standalone ceremony step.
contract DeployModelAccessControl is ScriptEnv, AdminChecks {
    function run() external {
        address deployer = deployerAddress();
        // PBA-L2-002: explicit owner; msg.sender in a salted ctor is the CREATE2 factory.
        address owner_ = envAddressOr("GOVERNANCE", deployer);

        console.log("=== Deploying ModelAccessControl ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast();

        ModelAccessControl accessControl = new ModelAccessControl{salt: Salts.salt("ModelAccessControl")}(owner_);
        console.log("ModelAccessControl:", address(accessControl));

        vm.stopBroadcast();
        _assertOwner("ModelAccessControl", address(accessControl), owner_);
    }
}
