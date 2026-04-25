// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/ComputePoolTraining.sol";

/// @title DeployComputePoolTraining
/// @notice CM-07 WP-07.1 deployment script for ComputePoolTraining.
///         Stand-alone v3 contract at a fresh address; does NOT
///         affect CM-05's ComputePool.
///
/// @dev Usage:
///
///   # Testnet dry-run (simulate only)
///   forge script script/DeployComputePoolTraining.s.sol \
///     --rpc-url $CITRATE_TESTNET_RPC \
///     --sender $DEPLOYER_ADDRESS
///
///   # Testnet broadcast (requires signing method — keystore/HSM/etc)
///   GOVERNANCE=0x... \
///   forge script script/DeployComputePoolTraining.s.sol \
///     --rpc-url $CITRATE_TESTNET_RPC \
///     --broadcast \
///     --keystore ~/.citrate/deployer.json \
///     --account deployer
///
///   # Post-deploy committee seeding (separate ceremony — see
///   # SeedTrainingCommittee.s.sol, to be authored when ≥3 named
///   # committee addresses are finalized with governance)
///
/// Env vars:
///   - CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS — the signer
///     (required by ScriptEnv)
///   - GOVERNANCE — address that will own committee admin. Falls
///     back to the deployer if not set; override for production.
contract DeployComputePoolTraining is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== ComputePoolTraining deployment ===");
        console.log("Deployer:   ", deployer);
        console.log("Governance: ", governance);

        vm.startBroadcast();
        ComputePoolTraining pool = new ComputePoolTraining(governance);
        vm.stopBroadcast();

        console.log("ComputePoolTraining deployed at:", address(pool));
        console.log("");
        console.log("=== Post-deploy checklist ===");
        console.log("1. Update SDK address book:");
        console.log("   sdks/javascript/citrate-marketplace/src/contracts.ts");
        console.log("   TESTNET_ADDRESSES.computePoolTraining = <above>");
        console.log("");
        console.log("2. Rebuild + publish SDK:");
        console.log("   cd sdks/javascript/citrate-marketplace && npm run build");
        console.log("");
        console.log("3. Update buyer-webapp SDK pin if needed:");
        console.log("   buyer-webapp/package.json");
        console.log("");
        console.log("4. Seed committee (requires GOVERNANCE key):");
        console.log("   pool.setCommittee(member_1, true)");
        console.log("   pool.setCommittee(member_2, true)  // meet COMMITTEE_QUORUM=2");
        console.log("   pool.setCommittee(member_3, true)  // recommended: 3+ for safety");
        console.log("");
        console.log("5. Run end-to-end smoke test against live testnet:");
        console.log("   forge script script/SmokeTestTraining.s.sol (to be authored)");
    }
}
