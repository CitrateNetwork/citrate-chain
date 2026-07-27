// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {GovernanceTemplateRegistry} from "../src/quorum/GovernanceTemplateRegistry.sol";
import {GovernanceProtocolFactory, ITenantHierarchy} from "../src/quorum/GovernanceProtocolFactory.sol";
import {PolicyBinding} from "../src/quorum/PolicyBinding.sol";
import {CapabilityGrant} from "../src/quorum/CapabilityGrant.sol";
import {VoteAllowance} from "../src/quorum/VoteAllowance.sol";
import {Sortition} from "../src/quorum/Sortition.sol";
import {MeetingRegistry} from "../src/cit_agent/MeetingRegistry.sol";

/// @title DeployQuorumS6 — the citrate-quorum governance set (QRM-S6.9)
///
/// Deploys the seven contracts sprint QRM-S6 produced. The eight seed templates
/// are deliberately NOT deployed here: the factory instantiates them per tenant
/// from registered bytecode, so a template's on-chain existence is a
/// `templateId` in the registry, not an address.
///
/// ## What this script does not do, and why
///
/// **It does not register the seed templates.** `GovernanceTemplateRegistry`
/// requires a non-empty `auditCID` on every row, by design — that requirement is
/// the entire point of the contract, which exists to make "only audited bytecode
/// governs" checkable rather than procedural. There are no audit artifacts yet
/// (S6.10 is the internal pass, and R11 stands: no external audit exists
/// anywhere in the federation). Registering with a placeholder CID would defeat
/// the one invariant this registry is for, so registration is a separate
/// ceremony that happens when there is something real to point at.
///
/// **It does not bind anything.** A `PolicyBinding` with no bindings returns
/// `Allow` + `PB_UNGOVERNED`, which is the honest state for a tenant that has
/// not configured governance yet — and quorum records that as `ungoverned` and
/// alerts on it rather than treating it as approval.
///
/// ## Dependency order
///
/// `TenantHierarchy` must already be deployed AND its root seeded, or three of
/// these bind immutably to a dead address. Pass it explicitly rather than
/// reading a book, so the ceremony cannot silently inherit a stale pin.
contract DeployQuorumS6 is Script {
    struct Deployed {
        address meetingRegistry;
        address templateRegistry;
        address protocolFactory;
        address policyBinding;
        address capabilityGrant;
        address voteAllowance;
        address sortition;
    }

    function run() external returns (Deployed memory out) {
        address governance = vm.envAddress("ROOT_GOVERNANCE");
        address tenants = vm.envAddress("TENANT_HIERARCHY");

        // Fail closed rather than deploy something permanently pointed at
        // nothing: these are `immutable` constructor args and cannot be fixed
        // afterwards.
        require(governance != address(0), "ROOT_GOVERNANCE is zero");
        require(tenants != address(0), "TENANT_HIERARCHY is zero");
        require(tenants.code.length > 0, "TENANT_HIERARCHY has no code - redeploy the RBAC set first");

        vm.startBroadcast();

        MeetingRegistry meetings = new MeetingRegistry();
        console2.log("MeetingRegistry deployed at:", address(meetings));

        GovernanceTemplateRegistry registry = new GovernanceTemplateRegistry(governance);
        console2.log("GovernanceTemplateRegistry deployed at:", address(registry));

        GovernanceProtocolFactory factory =
            new GovernanceProtocolFactory(registry, ITenantHierarchy(tenants));
        console2.log("GovernanceProtocolFactory deployed at:", address(factory));

        PolicyBinding binding = new PolicyBinding(factory, ITenantHierarchy(tenants));
        console2.log("PolicyBinding deployed at:", address(binding));

        CapabilityGrant grants = new CapabilityGrant(ITenantHierarchy(tenants));
        console2.log("CapabilityGrant deployed at:", address(grants));

        VoteAllowance allowances = new VoteAllowance();
        console2.log("VoteAllowance deployed at:", address(allowances));

        Sortition sortition = new Sortition();
        console2.log("Sortition deployed at:", address(sortition));

        vm.stopBroadcast();

        console2.log("=== QRM-S6 governance set deployed ===");
        console2.log("Governance:", governance);
        console2.log("TenantHierarchy:", tenants);
        console2.log("Templates registered: 0 (no audit artifacts yet - see NatSpec)");

        out = Deployed({
            meetingRegistry: address(meetings),
            templateRegistry: address(registry),
            protocolFactory: address(factory),
            policyBinding: address(binding),
            capabilityGrant: address(grants),
            voteAllowance: address(allowances),
            sortition: address(sortition)
        });
    }
}
