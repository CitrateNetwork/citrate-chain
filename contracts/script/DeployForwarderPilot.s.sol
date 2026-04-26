// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;
import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/edu/Forwarder.sol";

/// @notice Helper script for non-canonical pilot forwarding experiments.
/// @dev This script is intentionally parameterized. It must never hardcode
///      prior deployment addresses or be treated as the canonical ceremony source.
contract DeployForwarderPilot is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();
        address cluster = vm.envAddress("CLUSTER_ADDRESS");
        address vault = vm.envAddress("VAULT_ADDRESS");
        address governance = envAddressOr("FORWARDER_GOVERNANCE", deployer);
        address relayer = envAddressOr("RELAYER", deployer);
        address pilotTarget = envAddressOr("FORWARDER_TARGET", address(0));

        vm.startBroadcast();
        Forwarder f = new Forwarder(governance, cluster, vault);
        console.log("Forwarder (pilot):", address(f));

        if (governance == deployer) {
            f.addRelayer(relayer);
            console.log("Relayer authorized:", relayer);
            if (pilotTarget != address(0) && pilotTarget != vault) {
                f.setTargetAllowed(pilotTarget, true);
                console.log("Pilot target allowed:", pilotTarget);
            } else if (pilotTarget == vault) {
                console.log("Pilot target was vault; not allowed:", pilotTarget);
            }
        } else {
            console.log("Governance is not deployer; authorize relayer manually:", relayer);
            if (pilotTarget != address(0)) {
                console.log("Governance is not deployer; allow pilot target manually:", pilotTarget);
            }
        }

        vm.stopBroadcast();
    }
}
