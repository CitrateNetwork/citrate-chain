// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AgentDecisionRegistryV2} from "../src/rbac/AgentDecisionRegistryV2.sol";

/// @title AgentDecisionRegistryV2.t — BFR-02-WP6 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/AgentDecisionLog.tla`.
///      ≥30 delta tests covering every cited invariant + 3 fuzz targets.
contract AgentDecisionRegistryV2Test is Test {
    AgentDecisionRegistryV2 internal r;

    bytes32 constant DEC_A = keccak256("decision-a");
    bytes32 constant DEC_B = keccak256("decision-b");
    bytes32 constant DEC_C = keccak256("decision-c");
    bytes32 constant USER = keccak256("user-1");
    bytes32 constant USER2 = keccak256("user-2");
    bytes32 constant TENANT = keccak256("tenant-1");
    bytes32 constant TENANT2 = keccak256("tenant-2");
    bytes32 constant CORR = keccak256("corr-1");
    bytes32 constant CORR2 = keccak256("corr-2");
    bytes32 constant ART_ROOT = keccak256("artifact-root");

    address internal governance = address(0xA1);
    address internal recorder = address(0xB1);
    address internal stranger = address(0x5);

    function setUp() public {
        r = new AgentDecisionRegistryV2(governance);
        vm.prank(governance);
        r.setRecorder(recorder, true);
    }

    // ── Constructor + governance ────────────────────────────────────

    function test_constructor_setsGovernance() public view {
        assertEq(r.governance(), governance);
    }

    function test_constructor_revertsOnZeroGovernance() public {
        vm.expectRevert(AgentDecisionRegistryV2.ZeroGovernance.selector);
        new AgentDecisionRegistryV2(address(0));
    }

    function test_setRecorder_byGovernance() public {
        address recorder2 = address(0xB2);
        vm.prank(governance);
        r.setRecorder(recorder2, true);
        assertTrue(r.is_recorder(recorder2));
    }

    function test_setRecorder_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.NotGovernance.selector, stranger
            )
        );
        r.setRecorder(stranger, true);
    }

    function test_setRecorder_emitsEvent() public {
        vm.prank(governance);
        vm.expectEmit(true, false, false, true);
        emit AgentDecisionRegistryV2.RecorderSet(address(0xB2), true);
        r.setRecorder(address(0xB2), true);
    }

    // ── record happy path ──────────────────────────────────────────

    function test_record_basic() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "approval", "kba", "");
        AgentDecisionRegistryV2.Decision memory d = r.getDecision(DEC_A);
        assertEq(d.decision_id, DEC_A);
        assertEq(d.user, USER);
        assertEq(d.tenant, TENANT);
        assertEq(d.corr_id, CORR);
        assertEq(uint8(d.class), 0);
        assertEq(d.description, "approval");
        assertEq(d.auth_mode, "kba");
        assertEq(d.status, "Verified");
    }

    function test_record_emitsDecisionRecorded() public {
        vm.prank(recorder);
        vm.expectEmit(true, true, true, true);
        emit AgentDecisionRegistryV2.DecisionRecorded(
            DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance
        );
        r.record(
            DEC_A, USER, TENANT, CORR,
            AgentDecisionRegistryV2.EventClass.Provenance,
            "approval", "kba", ART_ROOT, ""
        );
    }

    function test_record_defaultsToVerifiedStatus() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        assertEq(r.getDecision(DEC_A).status, "Verified");
    }

    function test_record_acceptsCustomStatus() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "Pending");
        assertEq(r.getDecision(DEC_A).status, "Pending");
    }

    function test_record_storesArtifactRoot() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        assertEq(r.getDecision(DEC_A).artifact_root, ART_ROOT);
    }

    function test_record_storesTimestamp() public {
        vm.warp(1234567);
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        assertEq(r.getDecision(DEC_A).ts, 1234567);
    }

    function test_record_indexesByUser() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        _record(DEC_B, USER, TENANT, CORR2, AgentDecisionRegistryV2.EventClass.Audit, "y", "kba", "");
        bytes32[] memory ids = r.byUser(USER);
        assertEq(ids.length, 2);
        assertEq(ids[0], DEC_A);
        assertEq(ids[1], DEC_B);
    }

    function test_record_indexesByTenant() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        _record(DEC_B, USER2, TENANT, CORR2, AgentDecisionRegistryV2.EventClass.Audit, "y", "kba", "");
        bytes32[] memory ids = r.byTenant(TENANT);
        assertEq(ids.length, 2);
    }

    function test_record_indexesByCorr() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        _record(DEC_B, USER, TENANT2, CORR, AgentDecisionRegistryV2.EventClass.Audit, "y", "kba", "");
        bytes32[] memory ids = r.byCorrId(CORR);
        assertEq(ids.length, 2);
    }

    function test_record_indexesByClass() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Supplier, "x", "kba", "");
        _record(DEC_B, USER2, TENANT, CORR2, AgentDecisionRegistryV2.EventClass.Supplier, "y", "kba", "");
        _record(DEC_C, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Audit, "z", "kba", "");
        bytes32[] memory supplierIds = r.byClass(AgentDecisionRegistryV2.EventClass.Supplier);
        assertEq(supplierIds.length, 2);
        bytes32[] memory auditIds = r.byClass(AgentDecisionRegistryV2.EventClass.Audit);
        assertEq(auditIds.length, 1);
    }

    // ── record revert paths ────────────────────────────────────────

    function test_record_revertsForNonRecorder() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.NotRecorder.selector, stranger
            )
        );
        r.record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", ART_ROOT, "");
    }

    /// @dev Cites `ListUnique` invariant.
    function test_ListUnique_revertsOnDuplicate() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.DecisionAlreadyExists.selector, DEC_A
            )
        );
        r.record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "y", "kba", ART_ROOT, "");
    }

    function test_record_revertsOnEmptyAuthMode() public {
        vm.prank(recorder);
        vm.expectRevert(AgentDecisionRegistryV2.EmptyAuthMode.selector);
        r.record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "", ART_ROOT, "");
    }

    function test_record_revertsOnEmptyDescription() public {
        vm.prank(recorder);
        vm.expectRevert(AgentDecisionRegistryV2.EmptyDescription.selector);
        r.record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "", "kba", ART_ROOT, "");
    }

    // ── AppendOnly invariant ────────────────────────────────────────

    /// @dev Cites `AppendOnly` — record() never mutates an existing entry.
    function test_AppendOnly_secondRecordWithSameIdReverts() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "first", "kba", "");
        vm.prank(recorder);
        vm.expectRevert();
        r.record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Audit, "second", "kba", ART_ROOT, "");
        // Original record is preserved.
        assertEq(r.getDecision(DEC_A).description, "first");
    }

    function test_AppendOnly_describesPreservedAcrossUpdates() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "original", "kba", "");
        vm.prank(recorder);
        r.dispute(DEC_A, "operator contests", CORR);
        // Description and other immutable fields remain unchanged.
        AgentDecisionRegistryV2.Decision memory d = r.getDecision(DEC_A);
        assertEq(d.description, "original");
        assertEq(d.auth_mode, "kba");
    }

    // ── dispute ────────────────────────────────────────────────────

    function test_dispute_changesStatusToDisputed() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        r.dispute(DEC_A, "reason", CORR);
        assertEq(r.getDecision(DEC_A).status, "Disputed");
    }

    function test_dispute_emitsDisputedEvent() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        vm.expectEmit(true, true, false, true);
        emit AgentDecisionRegistryV2.DecisionDisputed(DEC_A, CORR, "reason");
        r.dispute(DEC_A, "reason", CORR);
    }

    /// @dev Cites `DisputeRequiresRecorded`.
    function test_DisputeRequiresRecorded_revertsForGhost() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.DecisionDoesNotExist.selector, DEC_A
            )
        );
        r.dispute(DEC_A, "reason", CORR);
    }

    function test_DisputeRequiresRecorded_revertsAfterRevoke() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        r.revoke(DEC_A, "revoking", CORR);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.DisputeRequiresRecorded.selector, DEC_A, "Revoked"
            )
        );
        r.dispute(DEC_A, "reason", CORR);
    }

    function test_DisputeRequiresRecorded_revertsAfterDispute() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        r.dispute(DEC_A, "first", CORR);
        vm.prank(recorder);
        vm.expectRevert();
        r.dispute(DEC_A, "second", CORR);
    }

    function test_dispute_acceptsPendingStatus() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "Pending");
        vm.prank(recorder);
        r.dispute(DEC_A, "reason", CORR);
        assertEq(r.getDecision(DEC_A).status, "Disputed");
    }

    function test_dispute_revertsForNonRecorder() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.NotRecorder.selector, stranger
            )
        );
        r.dispute(DEC_A, "reason", CORR);
    }

    // ── revoke ─────────────────────────────────────────────────────

    function test_revoke_changesStatusToRevoked() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        r.revoke(DEC_A, "reason", CORR);
        assertEq(r.getDecision(DEC_A).status, "Revoked");
    }

    function test_revoke_emitsRevokedEvent() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(recorder);
        vm.expectEmit(true, true, false, true);
        emit AgentDecisionRegistryV2.DecisionRevoked(DEC_A, CORR, "reason");
        r.revoke(DEC_A, "reason", CORR);
    }

    function test_revoke_revertsForGhost() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.DecisionDoesNotExist.selector, DEC_A
            )
        );
        r.revoke(DEC_A, "reason", CORR);
    }

    function test_revoke_revertsForNonRecorder() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.NotRecorder.selector, stranger
            )
        );
        r.revoke(DEC_A, "reason", CORR);
    }

    // ── Read views + LengthConsistent ──────────────────────────────

    /// @dev Cites `LengthConsistent`.
    function test_LengthConsistent_byUser() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        _record(DEC_B, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Audit, "y", "kba", "");
        _record(DEC_C, USER2, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Audit, "z", "kba", "");
        assertEq(r.byUser(USER).length, 2);
        assertEq(r.byUser(USER2).length, 1);
    }

    function test_NotRecordedNotInList() public view {
        assertEq(r.byUser(USER).length, 0);
        assertEq(r.byTenant(TENANT).length, 0);
        assertEq(r.byCorrId(CORR).length, 0);
        assertFalse(r.exists(DEC_A));
    }

    function test_RecordedInList_byCorrId() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "x", "kba", "");
        bytes32[] memory ids = r.byCorrId(CORR);
        bool found = false;
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == DEC_A) found = true;
        }
        assertTrue(found);
    }

    function test_getDecision_revertsForGhost() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentDecisionRegistryV2.DecisionDoesNotExist.selector, DEC_A
            )
        );
        r.getDecision(DEC_A);
    }

    function test_latestByTenant_returnsLatestN() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "a", "kba", "");
        _record(DEC_B, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Audit, "b", "kba", "");
        _record(DEC_C, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Verification, "c", "kba", "");
        bytes32[] memory ids = r.latestByTenant(TENANT, 2);
        assertEq(ids.length, 2);
        assertEq(ids[0], DEC_C);  // latest first
        assertEq(ids[1], DEC_B);
    }

    function test_latestByTenant_clampsToTotalSize() public {
        _record(DEC_A, USER, TENANT, CORR, AgentDecisionRegistryV2.EventClass.Provenance, "a", "kba", "");
        bytes32[] memory ids = r.latestByTenant(TENANT, 12);
        assertEq(ids.length, 1);
    }

    function test_latestByTenant_returnsEmptyForUnknown() public view {
        bytes32[] memory ids = r.latestByTenant(TENANT, 12);
        assertEq(ids.length, 0);
    }

    // ── Fuzz invariants ────────────────────────────────────────────

    /// @dev Fuzz `AppendOnly`: original state preserved across any
    ///      number of dispute/revoke status mutations.
    function testFuzz_AppendOnly_descriptionPreserved(bytes calldata desc) public {
        vm.assume(desc.length > 0 && desc.length < 200);
        vm.prank(recorder);
        r.record(
            DEC_A, USER, TENANT, CORR,
            AgentDecisionRegistryV2.EventClass.Provenance,
            string(desc), "kba", ART_ROOT, ""
        );
        AgentDecisionRegistryV2.Decision memory before_ = r.getDecision(DEC_A);
        vm.prank(recorder);
        r.dispute(DEC_A, "x", CORR);
        AgentDecisionRegistryV2.Decision memory after_ = r.getDecision(DEC_A);
        assertEq(after_.description, before_.description);
        assertEq(after_.user, before_.user);
    }

    /// @dev Fuzz `RecordedInList`: every recorded decision appears in
    ///      its byUser index.
    function testFuzz_RecordedInList(bytes32 user, bytes32 dec_id) public {
        vm.assume(user != bytes32(0) && dec_id != bytes32(0));
        vm.prank(recorder);
        r.record(
            dec_id, user, TENANT, CORR,
            AgentDecisionRegistryV2.EventClass.Provenance,
            "x", "kba", ART_ROOT, ""
        );
        bytes32[] memory ids = r.byUser(user);
        assertGt(ids.length, 0);
        assertEq(ids[ids.length - 1], dec_id);
    }

    /// @dev Fuzz `ListUnique`: same decision_id never re-recorded.
    function testFuzz_ListUnique(bytes32 dec_id) public {
        vm.prank(recorder);
        r.record(
            dec_id, USER, TENANT, CORR,
            AgentDecisionRegistryV2.EventClass.Provenance,
            "x", "kba", ART_ROOT, ""
        );
        vm.prank(recorder);
        vm.expectRevert();
        r.record(
            dec_id, USER, TENANT, CORR,
            AgentDecisionRegistryV2.EventClass.Audit,
            "y", "kba", ART_ROOT, ""
        );
    }

    // ── Helpers ────────────────────────────────────────────────────

    function _record(
        bytes32 dec_id,
        bytes32 user,
        bytes32 tenant,
        bytes32 corr_id,
        AgentDecisionRegistryV2.EventClass class,
        string memory desc,
        string memory auth_mode,
        string memory status
    ) internal {
        vm.prank(recorder);
        r.record(dec_id, user, tenant, corr_id, class, desc, auth_mode, ART_ROOT, status);
    }
}
