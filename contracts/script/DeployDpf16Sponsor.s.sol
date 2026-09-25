// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./lib/GovernanceOps.sol";
import "../src/defense_prime/SponsorEvidenceRegistry.sol";

/// @title DeployDpf16Sponsor — Stage 14 broadcast
/// @notice Deploys SponsorEvidenceRegistry. Deployer self-authorizes
///         as recorder so the evidence-bundle anchoring script can
///         broadcast without separate cast send.
contract DeployDpf16Sponsor is ScriptEnv, GovernanceOps {
    function run() external returns (address sponsor) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== DPF-16 Sponsor Evidence deployment (Stage 14) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        SponsorEvidenceRegistry reg = new SponsorEvidenceRegistry(governance);
        console.log("SponsorEvidenceRegistry:  ", address(reg));
        _govCall(governance, deployer, address(reg), abi.encodeWithSignature("setRecorder(address,bool)", deployer, true), "reg.setRecorder(deployer, true)");
        console.log("Recorder set: deployer");

        vm.stopBroadcast();

        sponsor = address(reg);
        console.log("=== Stage 14 complete ===");
    }
}
