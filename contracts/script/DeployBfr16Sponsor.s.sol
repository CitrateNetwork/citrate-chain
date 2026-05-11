// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/boeing/SponsorEvidenceRegistry.sol";

/// @title DeployBfr16Sponsor — Stage 14 broadcast
/// @notice Deploys SponsorEvidenceRegistry. Deployer self-authorizes
///         as recorder so the evidence-bundle anchoring script can
///         broadcast without separate cast send.
contract DeployBfr16Sponsor is ScriptEnv {
    function run() external returns (address sponsor) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== BFR-16 Sponsor Evidence deployment (Stage 14) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        SponsorEvidenceRegistry reg = new SponsorEvidenceRegistry(governance);
        console.log("SponsorEvidenceRegistry:  ", address(reg));
        reg.setRecorder(deployer, true);
        console.log("Recorder set: deployer");

        vm.stopBroadcast();

        sponsor = address(reg);
        console.log("=== Stage 14 complete ===");
    }
}
