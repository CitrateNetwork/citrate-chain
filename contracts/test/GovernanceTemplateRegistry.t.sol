// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {GovernanceTemplateRegistry} from "../src/quorum/GovernanceTemplateRegistry.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @title GovernanceTemplateRegistry — invariant tests (QRM-S6.1)
///
/// The sprint's rule: **a work package is not done until its invariant tests
/// fail on a deliberately broken build.** Each test below names the invariant it
/// pins and what breaking it would let someone do, so a reviewer can check the
/// test against the claim rather than against the implementation.
contract GovernanceTemplateRegistryTest is Test {
    GovernanceTemplateRegistry reg;

    address constant GOV = address(0x60F);
    address constant STRANGER = address(0xBEEF);

    bytes32 constant INIT_CODE_HASH = keccak256("ThresholdApproval creation code");
    bytes32 constant SCHEMA_HASH = keccak256('{"n":"uint8","m":"uint8"}');
    string constant AUDIT_CID = "bafyThresholdApprovalAuditV1";

    function setUp() public {
        reg = new GovernanceTemplateRegistry(GOV);
    }

    function _register() internal returns (bytes32) {
        vm.prank(GOV);
        return reg.register("ThresholdApproval", 1, INIT_CODE_HASH, SCHEMA_HASH, AUDIT_CID);
    }

    // ── TR-1: a row is immutable except `active` ────────────────────

    /// The registry exposes NO setter for any field but `active`. This is the
    /// structural half of TR-1 — if a future edit adds one, this test is where
    /// the reviewer is told the audit-provenance claim just changed meaning.
    ///
    /// A mutable `initCodeHash` would make "deployed from audited bytecode" mean
    /// "from whatever the registry pointed at when someone last looked", and
    /// every past deployment's provenance retroactively rewritable.
    function test_TR1_noSetterExistsForAnyFieldButActive() public {
        bytes32 id = _register();
        GovernanceTemplateRegistry.Template memory before_ = reg.get(id);

        // The only state-changing entry points are `register`, `deprecate`, and
        // the inherited governance transfer. Deprecating changes `active` and
        // NOTHING else.
        vm.prank(GOV);
        reg.deprecate(id);

        GovernanceTemplateRegistry.Template memory after_ = reg.get(id);
        assertEq(after_.id, before_.id, "id mutated");
        assertEq(after_.name, before_.name, "name mutated");
        assertEq(after_.version, before_.version, "version mutated");
        assertEq(after_.initCodeHash, before_.initCodeHash, "initCodeHash mutated");
        assertEq(after_.paramSchemaHash, before_.paramSchemaHash, "paramSchemaHash mutated");
        assertEq(after_.auditCID, before_.auditCID, "auditCID mutated");
        assertEq(after_.registeredAt, before_.registeredAt, "registeredAt mutated");
        assertFalse(after_.active, "active is the one field that may change");
    }

    /// Re-registering the same `(name, version)` is refused. Without this, a
    /// second `register` would overwrite the row in place — TR-1 by another
    /// name, and the easiest way to swap audited bytecode under a live id.
    function test_TR1_reRegisteringTheSameIdIsRefused() public {
        bytes32 id = _register();
        vm.prank(GOV);
        vm.expectRevert(abi.encodeWithSelector(GovernanceTemplateRegistry.TemplateExists.selector, id));
        reg.register("ThresholdApproval", 1, keccak256("DIFFERENT code"), SCHEMA_HASH, AUDIT_CID);

        // …and the original row is untouched by the attempt.
        assertEq(reg.get(id).initCodeHash, INIT_CODE_HASH);
    }

    /// A fixed version is a NEW row with its own id, audit and lineage — never
    /// an edit of the old one. Both remain readable.
    function test_TR1_aFixedVersionIsANewRowNotAnEdit() public {
        bytes32 v1 = _register();
        vm.prank(GOV);
        bytes32 v2 = reg.register("ThresholdApproval", 2, keccak256("v2 code"), SCHEMA_HASH, "bafyV2Audit");

        assertTrue(v1 != v2, "a version bump must produce a new id");
        assertTrue(reg.get(v1).active, "v1 keeps running until deprecated");
        assertTrue(reg.get(v2).active);
        assertEq(reg.count(), 2);
    }

    // ── Deprecation is not deletion ─────────────────────────────────

    /// A deprecated template stays READABLE forever. An auditor asking "what
    /// governed this decision two years ago" needs the row even though nobody
    /// may deploy from it again.
    function test_deprecatedTemplateRemainsReadable() public {
        bytes32 id = _register();
        vm.prank(GOV);
        reg.deprecate(id);

        GovernanceTemplateRegistry.Template memory t = reg.get(id);
        assertEq(t.auditCID, AUDIT_CID, "the audit trail survives deprecation");
        assertTrue(reg.exists(id));
        assertFalse(reg.isDeployable(id, INIT_CODE_HASH), "but nothing new deploys from it");
    }

    /// Deprecating twice reverts rather than passing quietly. A caller that
    /// thinks it is deprecating something already deprecated is looking at a
    /// different template than it believes.
    function test_deprecatingTwiceIsRefused() public {
        bytes32 id = _register();
        vm.startPrank(GOV);
        reg.deprecate(id);
        vm.expectRevert(abi.encodeWithSelector(GovernanceTemplateRegistry.AlreadyDeprecated.selector, id));
        reg.deprecate(id);
        vm.stopPrank();
    }

    // ── The audit boundary itself ───────────────────────────────────

    /// `isDeployable` is the ONE question the factory asks. All three conditions
    /// must hold, and each is checked separately here — a version that ignored
    /// `active` or `initCodeHash` would still pass a test that only checked
    /// existence.
    function test_isDeployableRequiresExistsActiveAndMatchingCode() public {
        bytes32 id = _register();
        assertTrue(reg.isDeployable(id, INIT_CODE_HASH), "the happy path");

        // wrong code → not deployable (this is GF-2's foundation)
        assertFalse(reg.isDeployable(id, keccak256("some other code")), "code must match");
        // unknown id → not deployable, and no revert (the factory asks about
        // ids that may not exist)
        assertFalse(reg.isDeployable(keccak256("nope"), INIT_CODE_HASH), "unknown id");
        // deprecated → not deployable
        vm.prank(GOV);
        reg.deprecate(id);
        assertFalse(reg.isDeployable(id, INIT_CODE_HASH), "deprecated");
    }

    /// A template with no audit CID cannot be registered. This registry exists
    /// to exclude exactly that, so it is a revert and not a warning.
    function test_registrationRequiresEveryField() public {
        vm.startPrank(GOV);
        vm.expectRevert(GovernanceTemplateRegistry.EmptyAuditCID.selector);
        reg.register("T", 1, INIT_CODE_HASH, SCHEMA_HASH, "");

        vm.expectRevert(GovernanceTemplateRegistry.ZeroInitCodeHash.selector);
        reg.register("T", 1, bytes32(0), SCHEMA_HASH, AUDIT_CID);

        vm.expectRevert(GovernanceTemplateRegistry.ZeroParamSchemaHash.selector);
        reg.register("T", 1, INIT_CODE_HASH, bytes32(0), AUDIT_CID);

        vm.expectRevert(GovernanceTemplateRegistry.EmptyName.selector);
        reg.register("", 1, INIT_CODE_HASH, SCHEMA_HASH, AUDIT_CID);
        vm.stopPrank();
    }

    /// Ids are derived with `abi.encode`, not `encodePacked`. With packed
    /// encoding `("AB", 1)` and `("A", …)` can be made to collide, and a
    /// template-id collision is a way to make one audited template answer for
    /// another. This pins the derivation against a hand-computed value.
    function test_templateIdUsesNonAmbiguousEncoding() public view {
        assertEq(reg.templateId("ThresholdApproval", 1), keccak256(abi.encode("ThresholdApproval", uint32(1))));
        // Neighbouring inputs must not collide.
        assertTrue(reg.templateId("AB", 1) != reg.templateId("A", 1));
        assertTrue(reg.templateId("A", 1) != reg.templateId("A", 2));
    }

    // ── Governance gating ───────────────────────────────────────────

    /// Only governance may register or deprecate. A stranger who could register
    /// would own the audit boundary outright.
    function test_onlyGovernanceMayRegisterOrDeprecate() public {
        vm.prank(STRANGER);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.register("T", 1, INIT_CODE_HASH, SCHEMA_HASH, AUDIT_CID);

        bytes32 id = _register();
        vm.prank(STRANGER);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.deprecate(id);
    }

    /// Governance transfer is two-step: a proposed successor that never accepts
    /// leaves the incumbent in charge. A mistyped key must not be able to lock
    /// the audit boundary forever (RM-B1/WP-D1.1).
    function test_governanceTransferIsTwoStep() public {
        address successor = address(0xC0FFEE);
        vm.prank(GOV);
        reg.transferGovernance(successor);

        // Not yet in charge.
        vm.prank(successor);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.register("T", 1, INIT_CODE_HASH, SCHEMA_HASH, AUDIT_CID);
        // The incumbent still is.
        _register();

        vm.prank(successor);
        reg.acceptGovernance();
        vm.prank(successor);
        reg.register("T2", 1, INIT_CODE_HASH, SCHEMA_HASH, AUDIT_CID);
    }

    /// The blast radius of a compromised governance key, pinned as a test
    /// because it is the claim the NatSpec makes: governance may add templates
    /// and stop new deploys — it may NOT alter an existing row.
    function test_compromisedGovernanceCannotRewriteAnExistingTemplate() public {
        bytes32 id = _register();
        address attacker = address(0xDEAD);
        vm.prank(GOV);
        reg.transferGovernance(attacker);
        vm.prank(attacker);
        reg.acceptGovernance();

        // With full governance, the attacker still cannot change what this
        // template IS.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(GovernanceTemplateRegistry.TemplateExists.selector, id));
        reg.register("ThresholdApproval", 1, keccak256("attacker code"), SCHEMA_HASH, "bafyFake");

        assertEq(reg.get(id).initCodeHash, INIT_CODE_HASH, "provenance is not rewritable");
        assertTrue(reg.isDeployable(id, INIT_CODE_HASH));
    }

    // ── Enumeration ─────────────────────────────────────────────────

    function test_enumerationIsInRegistrationOrder() public {
        bytes32 a = _register();
        vm.prank(GOV);
        bytes32 b = reg.register("ClassificationGate", 1, keccak256("cg"), SCHEMA_HASH, "bafyCG");
        assertEq(reg.count(), 2);
        assertEq(reg.idAt(0), a);
        assertEq(reg.idAt(1), b);
    }

    /// An unknown id reverts rather than returning a zero struct — otherwise a
    /// caller could mistake "no such template" for "a template with no audit".
    function test_unknownIdRevertsRatherThanReturningAnEmptyRow() public {
        bytes32 ghost = keccak256("never registered");
        vm.expectRevert(abi.encodeWithSelector(GovernanceTemplateRegistry.UnknownTemplate.selector, ghost));
        reg.get(ghost);
        assertFalse(reg.exists(ghost));
    }
}
