// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {SupplierRegistry} from "../src/boeing/SupplierRegistry.sol";
import {MoqRegistry} from "../src/boeing/MoqRegistry.sol";

/// @title DeployBfr06Suppliers — Foundry deployment script for BFR-06 Suppliers + MOQ
/// @notice Deploys SupplierRegistry and MoqRegistry to chain 40204
///         (Citrate testnet), per the staged plan in
///         `.agentile/launch/2026-05-10-bfr-testnet-deployment-plan.md`
///         (Stage 3 — DEP-3 + DEP-8).
///
/// @dev Important correction vs the original deployment plan: the
///      contracts are **independent** of each other. The plan's
///      v1 wording suggested MoqRegistry takes a SupplierRegistry
///      address as a constructor argument; inspection of
///      `src/boeing/MoqRegistry.sol:97` and
///      `src/boeing/SupplierRegistry.sol:106` confirms both have the
///      same `constructor(address initialGovernance)` signature with
///      no cross-reference. They can be deployed in either order or
///      in parallel; this script deploys both in a single broadcast
///      block for atomicity (one tx-batch, one operator approval).
///
///      Both contracts revert on `address(0)` governance and emit
///      `RecorderSet` / governance events for post-deploy wiring.
///
///      `--broadcast` is HUMAN-IN-LOOP (Saul holds the deployer
///      wallet) per the established BFR pattern.
///
/// Usage:
///   # Dry-run (CI-friendly):
///   forge script script/DeployBfr06Suppliers.s.sol \
///       --rpc-url https://rpc.citrate.ai
///
///   # Gas estimate:
///   forge script script/DeployBfr06Suppliers.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --gas-estimate-multiplier 200
///
///   # Live broadcast (Saul only):
///   ROOT_GOVERNANCE=0x... forge script script/DeployBfr06Suppliers.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOY_KEY \
///       --broadcast
///
/// After broadcast:
///   1. Verify each address: `cast code <addr> --rpc-url https://rpc.citrate.ai`
///   2. Append both addresses to .agentile/launch/DEPLOYED_CONTRACTS_2026_05_10.md
///   3. Update the "Deployed Contracts" table in .agentile/CONFIG.md
///   4. (Operator step) authorize the BFR program's recorder address
///      on each registry: `cast send <registry> "setRecorder(address,bool)" \
///      <recorder> true --private-key $GOVERNANCE_KEY`
contract DeployBfr06Suppliers is Script {
    struct DeployedAddresses {
        address supplierRegistry;
        address moqRegistry;
    }

    /// @notice Address that becomes governance for both contracts.
    ///         In dry-run this is `msg.sender`; in live broadcast it
    ///         must be the root-tenant multi-sig executor passed via
    ///         env `ROOT_GOVERNANCE`.
    function _governance() internal view returns (address) {
        try vm.envAddress("ROOT_GOVERNANCE") returns (address g) {
            return g;
        } catch {
            return msg.sender;
        }
    }

    function run() external returns (DeployedAddresses memory addrs) {
        address governance = _governance();

        vm.startBroadcast();

        // 1. SupplierRegistry — Boeing supplier lifecycle + qualification
        //    Constructor: (address initialGovernance), reverts on zero.
        SupplierRegistry sr = new SupplierRegistry(governance);
        console2.log("SupplierRegistry deployed at:", address(sr));

        // 2. MoqRegistry — supplier MOQ commitments + variance tracking.
        //    Independent of SupplierRegistry; same governance pattern.
        //    Constructor: (address initialGovernance), reverts on zero.
        MoqRegistry mr = new MoqRegistry(governance);
        console2.log("MoqRegistry deployed at:", address(mr));

        vm.stopBroadcast();

        addrs = DeployedAddresses({
            supplierRegistry: address(sr),
            moqRegistry: address(mr)
        });

        console2.log("=== BFR-06 Suppliers + MOQ deployment complete ===");
        console2.log("Governance:", governance);
        console2.log("Append addresses to DEPLOYED_CONTRACTS_2026_05_10.md");
        console2.log("Operator follow-up: setRecorder(<recorder>, true) on both registries");
    }
}
