// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./lib/GovernanceOps.sol";
import "../src/defense_prime/DefensePrimeComplianceRegistry.sol";
import "../src/defense_prime/RoleGrantTenantIndex.sol";

/// @title DeployDpf11Governance — Stage 9 broadcast
/// @notice Deploys the DPF-11 NEW contract pair
///         (DefensePrimeComplianceRegistry + RoleGrantTenantIndex) to chain
///         40204.
///
/// @dev Both contracts use deployer EOA as initial governance, and the
///      deployer self-authorizes as recorder on each so the E2E suite
///      can write without a separate cast send roundtrip.
///
/// Usage:
///   forge script script/DeployDpf11Governance.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract DeployDpf11Governance is ScriptEnv, GovernanceOps {
    function run() external returns (address compliance, address roleIdx) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-11 Governance deployment (Stage 9) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        DefensePrimeComplianceRegistry bcr = new DefensePrimeComplianceRegistry(governance);
        console.log("DefensePrimeComplianceRegistry:  ", address(bcr));
        _govCall(governance, deployer, address(bcr), abi.encodeWithSignature("setRecorder(address,bool)", deployer, true), "bcr.setRecorder(deployer, true)");
        console.log("BCR recorder set: deployer");

        RoleGrantTenantIndex rgti = new RoleGrantTenantIndex(governance);
        console.log("RoleGrantTenantIndex:      ", address(rgti));
        _govCall(governance, deployer, address(rgti), abi.encodeWithSignature("setRecorder(address,bool)", deployer, true), "rgti.setRecorder(deployer, true)");
        console.log("RGTI recorder set: deployer");

        vm.stopBroadcast();

        compliance = address(bcr);
        roleIdx = address(rgti);

        console.log("=== Stage 9 complete ===");
        console.log("Append addresses to DEPLOYED_CONTRACTS_2026_05_10.md");
        console.log("Update CONFIG.md 'DPF DefensePrime-side contracts' table");
    }
}
