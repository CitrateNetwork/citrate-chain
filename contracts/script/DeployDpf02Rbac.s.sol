// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {TenantHierarchy} from "../src/rbac/TenantHierarchy.sol";
import {RoleEscalation} from "../src/rbac/RoleEscalation.sol";
import {ClassificationRegistry} from "../src/rbac/ClassificationRegistry.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";
import {AgentDecisionRegistryV2} from "../src/rbac/AgentDecisionRegistryV2.sol";
import {ContradictionLedger} from "../src/rbac/ContradictionLedger.sol";

/// @title DeployDpf02Rbac — Foundry deployment script for DPF-02 RBAC contracts
/// @notice Deploys all 6 DPF-02 contracts to chain 40204 (Citrate testnet)
///         in dependency order. Per `audits/dpf-02-deploy-plan.md`.
///
/// @dev Per WP-10 acceptance: this script's `--dry-run` output is the
///      acceptance evidence. Actual `--broadcast` is HUMAN-IN-LOOP
///      (Saul holds the deployer wallet).
///
/// Usage:
///   # Dry-run (CI-friendly, no broadcast):
///   forge script script/DeployDpf02Rbac.s.sol \
///       --rpc-url https://rpc.citrate.ai
///
///   # Live broadcast (Saul only):
///   forge script script/DeployDpf02Rbac.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOY_KEY \
///       --broadcast
///
/// After broadcast, append addresses to DEPLOYED_ADDRESSES.md.
contract DeployDpf02Rbac is Script {
    struct DeployedAddresses {
        address tenantHierarchy;
        address roleEscalation;
        address classificationRegistry;
        address multiSigEnvelope;
        address agentDecisionRegistryV2;
        address contradictionLedger;
    }

    /// @notice Address that becomes governance for the contracts that
    ///         take a `governance` constructor argument. In dry-run
    ///         mode this is the script's `msg.sender`; in live mode
    ///         it should be the root-tenant multi-sig executor address
    ///         (passed via env `ROOT_GOVERNANCE`).
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

        // 1. TenantHierarchy — no contract dependencies. Root tenant
        //    initialized lazily by the deployer's first initRoot call
        //    via the multi-sig (NOT by this script).
        TenantHierarchy th = new TenantHierarchy();
        console2.log("TenantHierarchy deployed at:", address(th));

        // 2. ClassificationRegistry — depends on governance only.
        ClassificationRegistry cr = new ClassificationRegistry(governance);
        console2.log("ClassificationRegistry deployed at:", address(cr));

        // 3. RoleEscalation — depends on its initial role-admin (set
        //    to governance; can be expanded post-deploy).
        RoleEscalation re = new RoleEscalation(governance);
        console2.log("RoleEscalation deployed at:", address(re));

        // 4. MultiSigEnvelope — no contract dependencies.
        MultiSigEnvelope mse = new MultiSigEnvelope();
        console2.log("MultiSigEnvelope deployed at:", address(mse));

        // 5. AgentDecisionRegistryV2 — depends on governance only.
        AgentDecisionRegistryV2 adrv2 = new AgentDecisionRegistryV2(governance);
        console2.log("AgentDecisionRegistryV2 deployed at:", address(adrv2));

        // 6. ContradictionLedger — depends on governance + references
        //    AgentDecisionRegistryV2 by decision_id (off-chain link).
        ContradictionLedger cl = new ContradictionLedger(governance);
        console2.log("ContradictionLedger deployed at:", address(cl));

        vm.stopBroadcast();

        addrs = DeployedAddresses({
            tenantHierarchy: address(th),
            roleEscalation: address(re),
            classificationRegistry: address(cr),
            multiSigEnvelope: address(mse),
            agentDecisionRegistryV2: address(adrv2),
            contradictionLedger: address(cl)
        });

        console2.log("=== DPF-02 RBAC deployment complete ===");
        console2.log("Governance:", governance);
        console2.log("Append addresses to DEPLOYED_ADDRESSES.md");
    }
}
