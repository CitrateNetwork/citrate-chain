// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/boeing/AppRegistry.sol";
import "../src/boeing/CrossOrgIndex.sol";

/// @title DeployBfr09AppsContracts — Stage 7 broadcast
/// @notice Deploys the BFR-09 contract pair (AppRegistry + CrossOrgIndex)
///         to chain 40204. Both contracts are independent of each other;
///         AppRegistry takes the MultiSigEnvelope address from Stage 1
///         as its envelope oracle. CrossOrgIndex is standalone.
///
/// @dev Per the established BFR pattern, `--broadcast` is HUMAN-IN-LOOP
///      (Saul holds the deployer key in .env.testnet). The dry-run
///      output is the acceptance evidence used in the deployment
///      manifest update (Stage 7 section).
///
/// Usage:
///   forge script script/DeployBfr09AppsContracts.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract DeployBfr09AppsContracts is ScriptEnv {
    /// @notice MultiSigEnvelope deployed in BFR-08 Stage 1.
    /// @dev Hardcoded for testnet; production would read from env.
    address constant MULTISIG_ENVELOPE_STAGE_1 = 0x05825775315f3d074db9F948713D05059e12a8Fd;

    function run() external returns (address appRegistry, address crossOrgIndex) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);
        address envelopeOracle = envAddressOr("MULTISIG_ENVELOPE", MULTISIG_ENVELOPE_STAGE_1);

        console.log("=== BFR-09 Apps & Contracts deployment (Stage 7) ===");
        console.log("Deployer:        ", deployer);
        console.log("Governance:      ", governance);
        console.log("Envelope oracle: ", envelopeOracle);
        console.log("Chain ID:        ", block.chainid);

        vm.startBroadcast();

        AppRegistry ar = new AppRegistry(governance, envelopeOracle);
        console.log("AppRegistry:    ", address(ar));

        CrossOrgIndex coi = new CrossOrgIndex(governance);
        console.log("CrossOrgIndex:  ", address(coi));

        vm.stopBroadcast();

        appRegistry = address(ar);
        crossOrgIndex = address(coi);

        console.log("=== Stage 7 complete ===");
        console.log("Append addresses to DEPLOYED_CONTRACTS_2026_05_10.md");
        console.log("Update CONFIG.md 'BFR Boeing-side contracts' table");
    }
}
