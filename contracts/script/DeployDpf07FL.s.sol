// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {DefensePrimeFLScopeIndex} from "../src/defense_prime/DefensePrimeFLScopeIndex.sol";

/// @title DeployDpf07FL — Foundry deployment script for DPF-07 Federated Learning scope index
/// @notice Deploys DefensePrimeFLScopeIndex to chain 40204 (Citrate testnet),
///         per the staged plan in
///         `.agentile/launch/2026-05-10-dpf-testnet-deployment-plan.md`
///         (Stage 4 — DEP-4 + DEP-9).
///
/// @dev Important correction vs the original deployment plan: the
///      contract is **independent** of TenantHierarchy. The plan's
///      v1 wording suggested DefensePrimeFLScopeIndex would take a
///      TenantHierarchy address as a constructor argument; inspection
///      of `src/defense_prime/DefensePrimeFLScopeIndex.sol:67` confirms the
///      constructor is the same governance-only pattern as the
///      other DPF DefensePrime contracts:
///          constructor(address initialGovernance)
///      with no cross-reference. The pool/scope linkage to other
///      contracts is handled by recorder authorizations and
///      `tag()` events post-deploy, not at construction.
///
///      The script can therefore deploy in any order relative to
///      Stage 1 (DPF-02 RBAC). It does NOT need TENANT_HIERARCHY_ADDR
///      to be set in env. Stage ordering preserved in the plan only
///      to keep operator approvals batched logically.
///
///      `--broadcast` is HUMAN-IN-LOOP (Saul holds the deployer
///      wallet) per the established DPF pattern.
///
///      Mythril G-4 gate confirmed CLEAN (2026-05-10 re-run, 13s).
///
/// Usage:
///   # Dry-run (CI-friendly):
///   forge script script/DeployDpf07FL.s.sol \
///       --rpc-url https://rpc.citrate.ai
///
///   # Gas estimate:
///   forge script script/DeployDpf07FL.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --gas-estimate-multiplier 200
///
///   # Live broadcast (Saul only):
///   ROOT_GOVERNANCE=0x... forge script script/DeployDpf07FL.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOY_KEY \
///       --broadcast
///
/// After broadcast:
///   1. Verify deployed code: `cast code <addr> --rpc-url https://rpc.citrate.ai`
///   2. Append the address to .agentile/launch/DEPLOYED_CONTRACTS_2026_05_10.md
///   3. Update the "Deployed Contracts" table in .agentile/CONFIG.md
///   4. (Operator step) authorize the DPF-07 FL recorder address:
///        cast send <addr> "setRecorder(address,bool)" <recorder> true \
///            --private-key $GOVERNANCE_KEY
contract DeployDpf07FL is Script {
    struct DeployedAddresses {
        address defense_primeFLScopeIndex;
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

        // DefensePrimeFLScopeIndex — single contract for DPF-07.
        // Tags FL pools with DefensePrime scope identifiers. The pool/scope
        // linkage is recorder-authorized post-deploy via setRecorder
        // and emitted via tag() events; nothing about LearningPool or
        // TenantHierarchy is referenced in the constructor.
        DefensePrimeFLScopeIndex bflsi = new DefensePrimeFLScopeIndex(governance);
        console2.log("DefensePrimeFLScopeIndex deployed at:", address(bflsi));

        vm.stopBroadcast();

        addrs = DeployedAddresses({defense_primeFLScopeIndex: address(bflsi)});

        console2.log("=== DPF-07 FL deployment complete ===");
        console2.log("Governance:", governance);
        console2.log("Append address to DEPLOYED_CONTRACTS_2026_05_10.md");
        console2.log("Operator follow-up: setRecorder(<recorder>, true)");
    }
}
