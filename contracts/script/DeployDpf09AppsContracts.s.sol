// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/defense_prime/AppRegistry.sol";
import "../src/defense_prime/CrossOrgIndex.sol";

/// @title DeployDpf09AppsContracts — Stage 7 broadcast
/// @notice Deploys the DPF-09 contract pair (AppRegistry + CrossOrgIndex)
///         to chain 40204. Both contracts are independent of each other;
///         AppRegistry takes the MultiSigEnvelope address from Stage 1
///         as its envelope oracle. CrossOrgIndex is standalone.
///
/// @dev Per the established DPF pattern, `--broadcast` is HUMAN-IN-LOOP
///      (Saul holds the deployer key in .env.testnet). The dry-run
///      output is the acceptance evidence used in the deployment
///      manifest update (Stage 7 section).
///
/// Usage:
///   forge script script/DeployDpf09AppsContracts.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract DeployDpf09AppsContracts is ScriptEnv {
    /// @notice MultiSigEnvelope deployed in DPF-08 Stage 1.
    /// @dev Hardcoded for testnet; production would read from env.
    address constant MULTISIG_ENVELOPE_STAGE_1 = 0x05825775315f3d074db9F948713D05059e12a8Fd;

    function run() external returns (address appRegistry, address crossOrgIndex) {
        address deployer = deployerAddress();
        address governance = requiredGovernance("GOVERNANCE", deployer);
        address envelopeOracle = envAddressOr("MULTISIG_ENVELOPE", MULTISIG_ENVELOPE_STAGE_1);
        // G5: MULTISIG_ENVELOPE_STAGE_1 is an OLD-chain address with no code after a
        // reroll; AppRegistry embeds this oracle in its constructor args, so wiring it
        // to a dead address would silently ship a broken registry. Fail-closed on 40204:
        // the ceremony must forward the freshly-deployed MultiSigEnvelope (runtime, like
        // VALIDATOR_REGISTRY). Off-chain dev keeps the constant default.
        require(
            block.chainid != 40204 || envelopeOracle.code.length != 0,
            "MULTISIG_ENVELOPE must be set to the deployed envelope on 40204 (old default has no code)"
        );

        console.log("=== DPF-09 Apps & Contracts deployment (Stage 7) ===");
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
        console.log("PBA-L2-012: governance MUST call AppRegistry.setApproverPolicy(approvers, threshold)");
        console.log("  before any proposeApp (proposals revert NoApproverPolicy until then).");
        console.log("Append addresses to DEPLOYED_CONTRACTS_2026_05_10.md");
        console.log("Update CONFIG.md 'DPF DefensePrime-side contracts' table");
    }
}
