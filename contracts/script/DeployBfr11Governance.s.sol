// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/boeing/BoeingComplianceRegistry.sol";
import "../src/boeing/RoleGrantTenantIndex.sol";

/// @title DeployBfr11Governance — Stage 9 broadcast
/// @notice Deploys the BFR-11 NEW contract pair
///         (BoeingComplianceRegistry + RoleGrantTenantIndex) to chain
///         40204.
///
/// @dev Both contracts use deployer EOA as initial governance, and the
///      deployer self-authorizes as recorder on each so the E2E suite
///      can write without a separate cast send roundtrip.
///
/// Usage:
///   forge script script/DeployBfr11Governance.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract DeployBfr11Governance is ScriptEnv {
    function run() external returns (address compliance, address roleIdx) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== BFR-11 Governance deployment (Stage 9) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        BoeingComplianceRegistry bcr = new BoeingComplianceRegistry(governance);
        console.log("BoeingComplianceRegistry:  ", address(bcr));
        bcr.setRecorder(deployer, true);
        console.log("BCR recorder set: deployer");

        RoleGrantTenantIndex rgti = new RoleGrantTenantIndex(governance);
        console.log("RoleGrantTenantIndex:      ", address(rgti));
        rgti.setRecorder(deployer, true);
        console.log("RGTI recorder set: deployer");

        vm.stopBroadcast();

        compliance = address(bcr);
        roleIdx = address(rgti);

        console.log("=== Stage 9 complete ===");
        console.log("Append addresses to DEPLOYED_CONTRACTS_2026_05_10.md");
        console.log("Update CONFIG.md 'BFR Boeing-side contracts' table");
    }
}
