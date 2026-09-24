// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {PartProvenanceRegistry} from "../src/defense_prime/PartProvenanceRegistry.sol";

/// @title DeployDpf05Provenance — Foundry deployment script for DPF-05 Provenance
/// @notice Deploys PartProvenanceRegistry to chain 40204 (Citrate testnet),
///         per the staged plan in
///         `.agentile/launch/2026-05-10-dpf-testnet-deployment-plan.md`
///         (Stage 2 — DEP-2 + DEP-7).
///
/// @dev Per the established DPF pattern, `--broadcast` is HUMAN-IN-LOOP
///      (Saul holds the deployer wallet). The dry-run output is the
///      acceptance evidence used in the deployment manifest update.
///
///      Constructor data source: PartProvenanceRegistry takes a single
///      `address initialGovernance` argument (see line 151 of
///      `src/defense_prime/PartProvenanceRegistry.sol`). The same `_governance()`
///      env-or-msg.sender pattern as `DeployDpf02Rbac.s.sol` is used so
///      live deployments pass `ROOT_GOVERNANCE=<root multisig>` and dry-runs
///      transparently use the script's `msg.sender` for simulation.
///
///      Optional post-deploy wiring (NOT in this script — operator step):
///      after DPF-02's ContradictionLedger is also live, the operator
///      should call:
///          cast send <registry> "setContradictionLedger(address)" \
///              <contradictionLedger> --rpc-url https://rpc.citrate.ai \
///              --private-key $GOVERNANCE_KEY
///      The script intentionally does NOT do this so each deploy stage
///      stays atomic (see §"Deployment order" of the deployment plan).
///
/// Usage:
///   # Dry-run (CI-friendly, no broadcast):
///   forge script script/DeployDpf05Provenance.s.sol \
///       --rpc-url https://rpc.citrate.ai
///
///   # Gas estimate:
///   forge script script/DeployDpf05Provenance.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --gas-estimate-multiplier 200
///
///   # Live broadcast (Saul only):
///   ROOT_GOVERNANCE=0x... forge script script/DeployDpf05Provenance.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOY_KEY \
///       --broadcast
///
/// After broadcast:
///   1. Verify deployed code: `cast code <addr> --rpc-url https://rpc.citrate.ai`
///   2. Append the address to .agentile/launch/DEPLOYED_CONTRACTS_2026_05_10.md
///   3. Update the "Deployed Contracts" table in .agentile/CONFIG.md
///   4. (Operator step) wire setContradictionLedger if Stage 1 has landed
contract DeployDpf05Provenance is Script {
    struct DeployedAddresses {
        address partProvenanceRegistry;
    }

    /// @notice Address that becomes governance for the contract.
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

        // PartProvenanceRegistry — single contract for DPF-05.
        // Records part lineage events; recorders and the optional
        // contradiction-ledger link are added post-deploy by the
        // governance multi-sig (see contract docs).
        PartProvenanceRegistry ppr = new PartProvenanceRegistry(governance);
        console2.log("PartProvenanceRegistry deployed at:", address(ppr));

        vm.stopBroadcast();

        addrs = DeployedAddresses({partProvenanceRegistry: address(ppr)});

        console2.log("=== DPF-05 Provenance deployment complete ===");
        console2.log("Governance:", governance);
        console2.log("Append address to DEPLOYED_CONTRACTS_2026_05_10.md");
        console2.log("Operator follow-up: setRecorder(<recorder>, true)");
        console2.log("Operator follow-up: setContradictionLedger(<ledger>) once DPF-02 Stage 1 is live");
    }
}
