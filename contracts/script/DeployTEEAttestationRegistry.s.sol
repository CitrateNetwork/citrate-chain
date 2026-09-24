// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "../src/TEEAttestationRegistry.sol";

/// @title DeployTEEAttestationRegistry
/// @notice CM-08 — TEE attestation registry for pipeline-parallel inference.
///         Constructor takes initial governance; defaults to deployer.
///         Real ceremony should pass GOVERNANCE=<Safe>.
contract DeployTEEAttestationRegistry is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== Deploying TEEAttestationRegistry (CM-08) ===");
        console.log("Deployer:  ", deployer);
        console.log("Governance:", governance);
        console.log("Chain ID:  ", block.chainid);

        vm.startBroadcast();
        TEEAttestationRegistry registry = new TEEAttestationRegistry{salt: Salts.salt("TEEAttestationRegistry")}(governance);
        vm.stopBroadcast();

        console.log("TEEAttestationRegistry:", address(registry));
    }
}
