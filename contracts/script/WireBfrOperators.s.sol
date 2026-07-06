// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @notice Minimal interfaces — avoids recompiling the full contracts.
///         Function selectors match the live deployed bytecode.
interface IClassificationRegistry {
    function addOracleSigner(address signer) external;
}
interface IAgentDecisionRegistryV2 {
    function setRecorder(address recorder, bool authorized) external;
}
interface IContradictionLedger {
    function setResolver(address resolver, bool authorized) external;
}
interface IPartProvenanceRegistry {
    function setRecorder(address recorder, bool authorized) external;
    function setContradictionLedger(address ledger) external;
}
interface ISupplierRegistry {
    function setRecorder(address recorder, bool authorized) external;
}
interface IMoqRegistry {
    function setRecorder(address recorder, bool authorized) external;
}
interface IBoeingFLScopeIndex {
    function setRecorder(address recorder, bool authorized) external;
}

/// @title WireBfrOperators — Operator wiring sweep for the BFR contract suite
/// @notice Authorizes a recorder/resolver/oracle address on every contract
///         deployed in BFR-08 stages 1-4 that needs an admin-side activation
///         to be usable. Also wires PartProvenanceRegistry to the Stage-1
///         ContradictionLedger so step-anomalies can be reported.
///
/// @dev Address constants are pinned to the 2026-05-10 testnet broadcasts
///      documented in `.agentile/launch/DEPLOYED_CONTRACTS_2026_05_10.md`.
///      Re-deploying the suite requires re-pinning these constants OR
///      reading from an env-driven address registry (future work).
///
///      The "recorder" address can be overridden via env `OPERATOR_RECORDER`.
///      If unset, falls back to `msg.sender` (= deployer for the testnet
///      bootstrap path). This is the intentional default for a
///      single-operator demo chain; production deployments authorize a
///      dedicated recorder key separate from the deployer.
///
///      OUT OF SCOPE (deferred to a separate runbook):
///        - TenantHierarchy.initRoot(...) — needs root multi-sig config
///          (admins set + threshold + hkdf_salt + classification_max).
///          HUMAN-IN-LOOP per the deployment plan's RISK #6.
///        - RoleEscalation.setRoleAdmin(<multi-sig>, true) — needs the
///          finalized root multi-sig address.
///        - Governance transfer (deployer EOA → multi-sig) — same.
///
/// Usage:
///   # Dry-run:
///   forge script script/WireBfrOperators.s.sol \
///       --rpc-url https://rpc.citrate.ai
///
///   # Live broadcast (Saul only; uses deployer key from .env.testnet):
///   forge script script/WireBfrOperators.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
contract WireBfrOperators is Script {
    // ── Live addresses (chain 40204, deployed 2026-05-10) ───────────

    // Stage 1 — BFR-02 RBAC
    // Repointed 2026-07-03 to the fresh BFR-DEMO deploy on 40204 (harvest_bfr_addresses.sh).
    address constant TENANT_HIERARCHY            = 0x9101f6f1AB0A9FFF84e61B8D9E426E22723bc765;
    address constant CLASSIFICATION_REGISTRY     = 0xd4b1680684106888b7c55d19fB236b41c192340e;
    address constant ROLE_ESCALATION             = 0xC9B8c0bd4BDf70502095276dEE2b3f4d5da1488e;
    address constant MULTISIG_ENVELOPE           = 0x01f6293FEB59C5950A484F35CE4317B40d8F76be;
    address constant AGENT_DECISION_REGISTRY_V2  = 0xb524C66176f11613c3A43b0B7DB796cce607C013;
    address constant CONTRADICTION_LEDGER        = 0x8997e9838Fe5BB451d9D518FaEF5e4Bac49e341D;

    // Stages 2-4 — Boeing-side
    address constant PART_PROVENANCE_REGISTRY    = 0xb0c35160C8d49fB589dd7FED1b8737F885d9e60a;
    address constant SUPPLIER_REGISTRY           = 0xB2bD1c4084341f04b34e8EAb01D3cAF776816306;
    address constant MOQ_REGISTRY                = 0xc6955562E15E822F0177618052c1Abe15BE1789C;
    address constant BOEING_FL_SCOPE_INDEX       = 0x5c24659E68285497E43F18C429151E902abf528A;

    function _recorder() internal view returns (address) {
        try vm.envAddress("OPERATOR_RECORDER") returns (address r) {
            return r;
        } catch {
            return msg.sender;
        }
    }

    function run() external {
        address recorder = _recorder();
        console2.log("=== BFR operator wiring sweep ===");
        console2.log("Recorder/resolver/oracle target:", recorder);

        vm.startBroadcast();

        // 1. ClassificationRegistry: enable recorder as HR oracle signer
        //    (gate for setClearance). msg.sender (deployer) must be governance.
        IClassificationRegistry(CLASSIFICATION_REGISTRY).addOracleSigner(recorder);
        console2.log("  [1/8] ClassificationRegistry.addOracleSigner: OK");

        // 2. AgentDecisionRegistryV2: enable recorder
        //    (gate for record()).
        IAgentDecisionRegistryV2(AGENT_DECISION_REGISTRY_V2).setRecorder(recorder, true);
        console2.log("  [2/8] AgentDecisionRegistryV2.setRecorder: OK");

        // 3. ContradictionLedger: enable resolver
        //    (gate for resolveOpenContradiction).
        IContradictionLedger(CONTRADICTION_LEDGER).setResolver(recorder, true);
        console2.log("  [3/8] ContradictionLedger.setResolver: OK");

        // 4. PartProvenanceRegistry: enable recorder
        //    (gate for recordStep).
        IPartProvenanceRegistry(PART_PROVENANCE_REGISTRY).setRecorder(recorder, true);
        console2.log("  [4/8] PartProvenanceRegistry.setRecorder: OK");

        // 5. PartProvenanceRegistry → ContradictionLedger
        //    (verifyChain looks up open contradictions on the ledger).
        IPartProvenanceRegistry(PART_PROVENANCE_REGISTRY).setContradictionLedger(CONTRADICTION_LEDGER);
        console2.log("  [5/8] PartProvenanceRegistry.setContradictionLedger: OK");

        // 6. SupplierRegistry: enable recorder
        ISupplierRegistry(SUPPLIER_REGISTRY).setRecorder(recorder, true);
        console2.log("  [6/8] SupplierRegistry.setRecorder: OK");

        // 7. MoqRegistry: enable recorder
        IMoqRegistry(MOQ_REGISTRY).setRecorder(recorder, true);
        console2.log("  [7/8] MoqRegistry.setRecorder: OK");

        // 8. BoeingFLScopeIndex: enable recorder
        //    (gate for tag()).
        IBoeingFLScopeIndex(BOEING_FL_SCOPE_INDEX).setRecorder(recorder, true);
        console2.log("  [8/8] BoeingFLScopeIndex.setRecorder: OK");

        vm.stopBroadcast();

        console2.log("=== Wiring sweep complete ===");
        console2.log("Recorder/resolver/oracle now authorized on 8 contracts.");
        console2.log("Deferred to operator runbook: TenantHierarchy.initRoot, RoleEscalation admin transfer, governance hand-off to multi-sig.");
    }
}
