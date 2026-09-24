// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ComplianceRegistry} from "../../src/edu/ComplianceRegistry.sol";
import {InstitutionTreeV1} from "../../src/edu/InstitutionTreeV1.sol";

/// @notice Unit tests for ComplianceRegistry. Locks the state-machine and
///         access-control semantics for every (school × gate) lifecycle path.
contract ComplianceRegistryTest is Test {
    InstitutionTreeV1 internal tree;
    ComplianceRegistry internal reg;

    address internal governance = address(0xA11CE);
    address internal cmoAdmin = address(0xCEC0);
    address internal districtAdmin = address(0xD15);
    address internal caSchoolAdmin = address(0x5C0CA);
    address internal nySchoolAdmin = address(0x5C0DA);
    address internal stranger = address(0xBEEF);

    bytes32 internal constant CMO_HASH = keccak256("KIPP-EIN");
    bytes32 internal constant DIST_CA_HASH = keccak256("KIPP-CA-DIST");
    bytes32 internal constant DIST_NY_HASH = keccak256("KIPP-NY-DIST");
    bytes32 internal constant SCH_CA_HASH = keccak256("KIPP-CA-SCH-1");
    bytes32 internal constant SCH_NY_HASH = keccak256("KIPP-NY-SCH-1");
    bytes32 internal constant ENV_HASH_A = keccak256("envelope-a");
    bytes32 internal constant ENV_HASH_B = keccak256("envelope-b");
    bytes32 internal constant REASON_AUDIT = keccak256("reason:audit-finding-2026-Q2");

    uint8 internal constant STATE_CA = 0;
    uint8 internal constant STATE_NY = 1;
    uint8 internal constant STATE_OTHER = 255;

    // Gate indices — match ComplianceRegistry's enum ordering.
    uint8 internal constant G_DPA = 0;
    uint8 internal constant G_FERPA = 1;
    uint8 internal constant G_COPPA = 2;
    uint8 internal constant G_CIPA = 3;
    uint8 internal constant G_CA = 4;
    uint8 internal constant G_NY = 5;
    uint8 internal constant G_IL = 6;
    uint8 internal constant G_TX = 7;
    uint8 internal constant G_CO = 8;

    function setUp() public {
        tree = new InstitutionTreeV1(governance);
        reg = new ComplianceRegistry(governance, address(tree));

        // Build a CMO with one CA district + one NY district, each with a school.
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.startPrank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DIST_CA_HASH, districtAdmin, STATE_CA);
        tree.registerDistrict(CMO_HASH, DIST_NY_HASH, districtAdmin, STATE_NY);
        vm.stopPrank();
        vm.startPrank(districtAdmin);
        tree.registerSchool(DIST_CA_HASH, SCH_CA_HASH, caSchoolAdmin, STATE_CA);
        tree.registerSchool(DIST_NY_HASH, SCH_NY_HASH, nySchoolAdmin, STATE_NY);
        vm.stopPrank();

        // Pin time so timestamps are predictable.
        vm.warp(1_700_000_000); // 2023-11-14T22:13:20Z
    }

    // ──────────────────────────────────────────────────────────────
    // Construction
    // ──────────────────────────────────────────────────────────────

    function test_construction_setsGovernanceAndTree() public {
        assertEq(reg.governance(), governance);
        assertEq(address(reg.tree()), address(tree));
        assertEq(reg.totalSignings(), 0);
        assertEq(reg.totalRevocations(), 0);
        assertEq(reg.GATE_COUNT(), 9);
        assertEq(reg.FIRST_STATE_GATE(), 4);
        assertEq(reg.MAX_VALIDITY_WINDOW(), 365 days);
    }

    function test_construction_revertsOnZeroGovernance() public {
        vm.expectRevert(ComplianceRegistry.InvalidGovernanceTransfer.selector);
        new ComplianceRegistry(address(0), address(tree));
    }

    function test_construction_revertsOnZeroTree() public {
        vm.expectRevert(
            abi.encodeWithSelector(ComplianceRegistry.InvalidSchool.selector, bytes32(0))
        );
        new ComplianceRegistry(governance, address(0));
    }

    // ──────────────────────────────────────────────────────────────
    // Two-step governance transfer
    // ──────────────────────────────────────────────────────────────

    function test_governanceTransfer_twoStep() public {
        address newGov = address(0xC0FFEE);
        vm.prank(governance);
        reg.transferGovernance(newGov);
        assertEq(reg.pendingGovernance(), newGov);
        assertEq(reg.governance(), governance);

        vm.prank(newGov);
        reg.acceptGovernance();
        assertEq(reg.governance(), newGov);
        assertEq(reg.pendingGovernance(), address(0));
    }

    function test_governanceTransfer_canBeCancelled() public {
        vm.prank(governance);
        reg.transferGovernance(address(0xC0FFEE));
        vm.prank(governance);
        reg.cancelGovernanceTransfer();
        assertEq(reg.pendingGovernance(), address(0));
    }

    function test_governanceTransfer_revertsForRandomAcceptor() public {
        vm.prank(governance);
        reg.transferGovernance(address(0xC0FFEE));
        vm.prank(stranger);
        vm.expectRevert(ComplianceRegistry.InvalidGovernanceTransfer.selector);
        reg.acceptGovernance();
    }

    function test_governanceTransfer_revertsOnZeroNewGov() public {
        vm.prank(governance);
        vm.expectRevert(ComplianceRegistry.InvalidGovernanceTransfer.selector);
        reg.transferGovernance(address(0));
    }

    function test_transferGovernance_onlyGovernanceCanCall() public {
        vm.prank(stranger);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.transferGovernance(address(0xC0FFEE));
    }

    // ──────────────────────────────────────────────────────────────
    // recordSigned — happy paths
    // ──────────────────────────────────────────────────────────────

    function test_recordSigned_federalGate_byCaSchoolAdmin() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);

        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, ENV_HASH_A);
        assertEq(r.signer, caSchoolAdmin);
        assertEq(r.signedAt, uint64(block.timestamp));
        assertEq(r.expiresAt, expiresAt);
        assertEq(reg.totalSignings(), 1);
    }

    function test_recordSigned_stateGate_matchingState() public {
        uint64 expiresAt = uint64(block.timestamp + 365 days);
        // CA school can sign the CA-specific gate (gate 4)
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_CA, ENV_HASH_A, expiresAt);
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_CA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
    }

    function test_recordSigned_emitsEvent() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.expectEmit(true, true, true, true, address(reg));
        emit ComplianceRegistry.GateSigned(
            SCH_CA_HASH, G_DPA, caSchoolAdmin, ENV_HASH_A, uint64(block.timestamp), expiresAt
        );
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
    }

    function test_recordSigned_canResignAfterExpiry() public {
        uint64 firstExpires = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, firstExpires);

        // Walk past expiry, then expire
        vm.warp(firstExpires + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        // Re-sign with new envelope
        uint64 newExpires = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_B, newExpires);

        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, ENV_HASH_B);
        assertEq(reg.totalSignings(), 2);
    }

    function test_recordSigned_canResignAfterRevocation() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);

        // Re-sign post-revocation
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_B, expiresAt);

        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, ENV_HASH_B);
    }

    // ──────────────────────────────────────────────────────────────
    // recordSigned — revert paths
    // ──────────────────────────────────────────────────────────────

    function test_recordSigned_revertsOnInvalidGate() public {
        vm.prank(caSchoolAdmin);
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, uint8(9)));
        reg.recordSigned(SCH_CA_HASH, 9, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnZeroEnvelopeHash() public {
        vm.prank(caSchoolAdmin);
        vm.expectRevert(ComplianceRegistry.InvalidEnvelopeHash.selector);
        reg.recordSigned(SCH_CA_HASH, G_DPA, bytes32(0), uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnUnknownSchool() public {
        bytes32 ghost = keccak256("nonexistent");
        vm.prank(caSchoolAdmin);
        // Tree.getNode reverts with UnknownInstitution; that bubbles up
        vm.expectRevert(
            abi.encodeWithSelector(InstitutionTreeV1.UnknownInstitution.selector, ghost)
        );
        reg.recordSigned(ghost, G_DPA, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnNonSchoolNode() public {
        // CMO is level 1, not 3 → InvalidSchool
        vm.prank(cmoAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(ComplianceRegistry.InvalidSchool.selector, CMO_HASH)
        );
        reg.recordSigned(CMO_HASH, G_DPA, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnRevokedSchool() public {
        vm.prank(governance);
        tree.revokeInstitution(SCH_CA_HASH);

        vm.prank(caSchoolAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(ComplianceRegistry.SchoolRevoked.selector, SCH_CA_HASH)
        );
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnWrongAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsWhenSchoolAdminSignsOtherSchool() public {
        // CA school admin tries to sign the NY school's gate
        vm.prank(caSchoolAdmin);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCH_NY_HASH, G_DPA, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnStateMismatch_caSchoolNyGate() public {
        // CA school cannot sign the NY-specific gate
        vm.prank(caSchoolAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.GateNotApplicable.selector, SCH_CA_HASH, G_NY
            )
        );
        reg.recordSigned(SCH_CA_HASH, G_NY, ENV_HASH_A, uint64(block.timestamp + 30 days));
    }

    function test_recordSigned_revertsOnStateMismatch_otherStateAnyStateGate() public {
        // Register a school with state=Other (255), then verify it can't sign any state gate
        bytes32 schOtherHash = keccak256("KIPP-OTHER-SCH");
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_CA_HASH, schOtherHash, caSchoolAdmin, STATE_OTHER);

        // gate 4..8 — none should match state=255
        for (uint8 g = G_CA; g <= G_CO; g++) {
            vm.prank(caSchoolAdmin);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ComplianceRegistry.GateNotApplicable.selector, schOtherHash, g
                )
            );
            reg.recordSigned(schOtherHash, g, ENV_HASH_A, uint64(block.timestamp + 30 days));
        }
    }

    function test_recordSigned_revertsOnPastExpiry() public {
        vm.prank(caSchoolAdmin);
        vm.expectRevert(ComplianceRegistry.InvalidExpiry.selector);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, uint64(block.timestamp));
    }

    function test_recordSigned_revertsOnExpiryEqualsNow() public {
        vm.prank(caSchoolAdmin);
        vm.expectRevert(ComplianceRegistry.InvalidExpiry.selector);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, uint64(block.timestamp));
    }

    function test_recordSigned_revertsOnValidityWindowTooLong() public {
        uint64 beyondMax = uint64(block.timestamp) + reg.MAX_VALIDITY_WINDOW() + 1;
        vm.prank(caSchoolAdmin);
        vm.expectRevert(ComplianceRegistry.ValidityWindowTooLong.selector);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, beyondMax);
    }

    function test_recordSigned_acceptsExactlyMaxWindow() public {
        uint64 atMax = uint64(block.timestamp) + reg.MAX_VALIDITY_WINDOW();
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, atMax);
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(r.expiresAt, atMax);
    }

    function test_recordSigned_revertsOnReSignWithoutExpiryOrRevoke() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        // Try to re-sign while still currently Signed — must refuse
        vm.prank(caSchoolAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotRecordSigned.selector, ComplianceRegistry.Status.Signed
            )
        );
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_B, expiresAt);
    }

    // ──────────────────────────────────────────────────────────────
    // expireGate
    // ──────────────────────────────────────────────────────────────

    function test_expireGate_byAnyone() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        vm.warp(expiresAt + 1);

        // Stranger can call expire — permissionless keeper
        vm.prank(stranger);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Expired));
        // Other fields preserved (envelope, signer, signedAt, expiresAt)
        assertEq(r.envelopeIdHash, ENV_HASH_A);
        assertEq(r.signer, caSchoolAdmin);
    }

    function test_expireGate_emitsEvent() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.warp(expiresAt + 1);
        vm.expectEmit(true, true, false, true, address(reg));
        emit ComplianceRegistry.GateExpired(SCH_CA_HASH, G_DPA, uint64(block.timestamp));
        reg.expireGate(SCH_CA_HASH, G_DPA);
    }

    function test_expireGate_revertsOnInvalidGate() public {
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, uint8(9)));
        reg.expireGate(SCH_CA_HASH, 9);
    }

    function test_expireGate_revertsOnUntouched() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotExpire.selector, ComplianceRegistry.Status.Untouched
            )
        );
        reg.expireGate(SCH_CA_HASH, G_DPA);
    }

    function test_expireGate_revertsOnAlreadyExpired() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.warp(expiresAt + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotExpire.selector, ComplianceRegistry.Status.Expired
            )
        );
        reg.expireGate(SCH_CA_HASH, G_DPA);
    }

    function test_expireGate_revertsOnRevoked() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);

        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotExpire.selector, ComplianceRegistry.Status.Revoked
            )
        );
        reg.expireGate(SCH_CA_HASH, G_DPA);
    }

    function test_expireGate_revertsBeforeExpiry() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        // 1 second before expiry
        vm.warp(expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.NotYetExpired.selector, expiresAt, uint64(block.timestamp)
            )
        );
        reg.expireGate(SCH_CA_HASH, G_DPA);
    }

    function test_expireGate_atExactExpiryRevertsByOne() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        // At exactly expiresAt — still valid (boundary: > expiresAt required)
        vm.warp(expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.NotYetExpired.selector, expiresAt, uint64(block.timestamp)
            )
        );
        reg.expireGate(SCH_CA_HASH, G_DPA);

        // One second past expiry — succeeds
        vm.warp(expiresAt + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);
    }

    // ──────────────────────────────────────────────────────────────
    // revokeGate
    // ──────────────────────────────────────────────────────────────

    function test_revokeGate_byGovernance() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);

        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Revoked));
        assertEq(reg.totalRevocations(), 1);
    }

    function test_revokeGate_emitsEvent() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.expectEmit(true, true, true, true, address(reg));
        emit ComplianceRegistry.GateRevoked(
            SCH_CA_HASH, G_DPA, governance, REASON_AUDIT, uint64(block.timestamp)
        );
        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
    }

    function test_revokeGate_canRevokeExpired() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.warp(expiresAt + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        // Governance revokes the Expired record (e.g., for audit)
        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Revoked));
    }

    function test_revokeGate_revertsForNonGovernance() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        // Even the school admin cannot revoke their own record
        vm.prank(caSchoolAdmin);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
    }

    function test_revokeGate_revertsOnUntouched() public {
        vm.prank(governance);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotRevoke.selector, ComplianceRegistry.Status.Untouched
            )
        );
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
    }

    function test_revokeGate_revertsOnDoubleRevoke() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.startPrank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotRevoke.selector, ComplianceRegistry.Status.Revoked
            )
        );
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
        vm.stopPrank();
    }

    function test_revokeGate_revertsOnInvalidGate() public {
        vm.prank(governance);
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, uint8(9)));
        reg.revokeGate(SCH_CA_HASH, 9, REASON_AUDIT);
    }

    // ──────────────────────────────────────────────────────────────
    // Reads
    // ──────────────────────────────────────────────────────────────

    function test_getRecord_returnsUntouchedForNeverRecorded() public view {
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA_HASH, G_FERPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(r.envelopeIdHash, bytes32(0));
        assertEq(r.signer, address(0));
        assertEq(r.signedAt, 0);
        assertEq(r.expiresAt, 0);
    }

    function test_getRecord_revertsOnInvalidGate() public {
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, uint8(9)));
        reg.getRecord(SCH_CA_HASH, 9);
    }

    function test_getEffectiveStatus_returnsNotApplicableForStateMismatch() public view {
        // CA school: NY-specific gate is NotApplicable
        ComplianceRegistry.Status s = reg.getEffectiveStatus(SCH_CA_HASH, G_NY);
        assertEq(uint8(s), uint8(ComplianceRegistry.Status.NotApplicable));
    }

    function test_getEffectiveStatus_returnsActualStatusForApplicable() public {
        // CA school + federal gate: just returns whatever's recorded (Untouched at start)
        ComplianceRegistry.Status s = reg.getEffectiveStatus(SCH_CA_HASH, G_DPA);
        assertEq(uint8(s), uint8(ComplianceRegistry.Status.Untouched));

        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        s = reg.getEffectiveStatus(SCH_CA_HASH, G_DPA);
        assertEq(uint8(s), uint8(ComplianceRegistry.Status.Signed));
    }

    function test_getSchoolMatrix_returnsAll9CellsForCa() public {
        // Sign DPA + CA-specific for the CA school
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.startPrank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        reg.recordSigned(SCH_CA_HASH, G_CA, ENV_HASH_B, expiresAt);
        vm.stopPrank();

        ComplianceRegistry.Record[9] memory matrix = reg.getSchoolMatrix(SCH_CA_HASH);

        // Federal gates not yet signed → Untouched
        assertEq(uint8(matrix[G_DPA].status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(uint8(matrix[G_FERPA].status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(uint8(matrix[G_COPPA].status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(uint8(matrix[G_CIPA].status), uint8(ComplianceRegistry.Status.Untouched));

        // State gates: only CA matches; others are NotApplicable
        assertEq(uint8(matrix[G_CA].status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(uint8(matrix[G_NY].status), uint8(ComplianceRegistry.Status.NotApplicable));
        assertEq(uint8(matrix[G_IL].status), uint8(ComplianceRegistry.Status.NotApplicable));
        assertEq(uint8(matrix[G_TX].status), uint8(ComplianceRegistry.Status.NotApplicable));
        assertEq(uint8(matrix[G_CO].status), uint8(ComplianceRegistry.Status.NotApplicable));

        // Records' metadata preserved
        assertEq(matrix[G_DPA].envelopeIdHash, ENV_HASH_A);
        assertEq(matrix[G_CA].envelopeIdHash, ENV_HASH_B);
    }

    function test_getSchoolMatrix_returnsAllNotApplicableForOtherState() public {
        // Register a school in state=Other (255)
        bytes32 schOtherHash = keccak256("school-other");
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_CA_HASH, schOtherHash, caSchoolAdmin, STATE_OTHER);

        ComplianceRegistry.Record[9] memory matrix = reg.getSchoolMatrix(schOtherHash);

        // Federal gates: still applicable (Untouched)
        assertEq(uint8(matrix[G_DPA].status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(uint8(matrix[G_FERPA].status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(uint8(matrix[G_COPPA].status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(uint8(matrix[G_CIPA].status), uint8(ComplianceRegistry.Status.Untouched));
        // All 5 state gates: NotApplicable
        for (uint8 g = G_CA; g <= G_CO; g++) {
            assertEq(uint8(matrix[g].status), uint8(ComplianceRegistry.Status.NotApplicable));
        }
    }

    function test_isCompliant_trueWhenSignedAndCurrent() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        assertTrue(reg.isCompliant(SCH_CA_HASH, G_DPA));
    }

    function test_isCompliant_falseAfterExpiry_evenBeforeExpireGateCalled() public {
        uint64 expiresAt = uint64(block.timestamp + 30 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        // Walk past expiry — isCompliant computes based on timestamp,
        // even before the keeper has called expireGate
        vm.warp(expiresAt + 1);
        assertFalse(reg.isCompliant(SCH_CA_HASH, G_DPA));

        // Still false after the keeper sweep
        reg.expireGate(SCH_CA_HASH, G_DPA);
        assertFalse(reg.isCompliant(SCH_CA_HASH, G_DPA));
    }

    function test_isCompliant_falseForUnsignedGate() public view {
        assertFalse(reg.isCompliant(SCH_CA_HASH, G_DPA));
    }

    function test_isCompliant_falseForRevokedGate() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
        assertFalse(reg.isCompliant(SCH_CA_HASH, G_DPA));
    }

    function test_isCompliant_falseForRevokedSchool() public {
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

        vm.prank(governance);
        tree.revokeInstitution(SCH_CA_HASH);

        assertFalse(reg.isCompliant(SCH_CA_HASH, G_DPA));
    }

    function test_isCompliant_falseForStateMismatch() public {
        // Even with no signing, gate-not-applicable returns false
        assertFalse(reg.isCompliant(SCH_CA_HASH, G_NY));
    }

    function test_isCompliant_falseForOutOfRangeGate() public view {
        assertFalse(reg.isCompliant(SCH_CA_HASH, 9));
    }

    function test_isCompliant_falseForUnknownSchool() public {
        // Tree.getNode reverts internally; but isCompliant is a try-style
        // read, so we expect a revert (matches getRecord/getEffectiveStatus
        // semantics — unknown schools are programmer errors, not silent false)
        bytes32 ghost = keccak256("ghost");
        vm.expectRevert(
            abi.encodeWithSelector(InstitutionTreeV1.UnknownInstitution.selector, ghost)
        );
        reg.isCompliant(ghost, G_DPA);
    }

    // ──────────────────────────────────────────────────────────────
    // State machine — full lifecycle sequences
    // ──────────────────────────────────────────────────────────────

    function test_lifecycle_signExpireSignExpireSign() public {
        // Sign, expire, re-sign, re-expire, re-sign — should always work.
        //
        // NOTE on absolute timestamps: foundry.toml has `via_ir = true`,
        // which makes the compiler aggressively fold expressions like
        // `block.timestamp + 30 days` across `vm.warp` boundaries within
        // the same function (the IR optimizer assumes block.timestamp is
        // pure-by-call). Looped or repeated `block.timestamp + delta`
        // patterns produce the same value each iteration. To keep tests
        // robust, we use absolute timestamps via vm.warp + literal
        // expiries — defeats the IR caching by forcing distinct constant
        // expressions per call site.
        uint64 t0 = 1_700_000_000;     // setUp warps here
        uint64 e0 = t0 + 30 days;       // 1_702_592_000
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, e0);
        assertTrue(reg.isCompliant(SCH_CA_HASH, G_DPA));

        vm.warp(uint256(e0) + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        uint64 t1 = e0 + 1;
        uint64 e1 = t1 + 30 days;
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, e1);
        assertTrue(reg.isCompliant(SCH_CA_HASH, G_DPA));

        vm.warp(uint256(e1) + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        uint64 t2 = e1 + 1;
        uint64 e2 = t2 + 30 days;
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, e2);
        assertTrue(reg.isCompliant(SCH_CA_HASH, G_DPA));

        vm.warp(uint256(e2) + 1);
        reg.expireGate(SCH_CA_HASH, G_DPA);

        assertEq(reg.totalSignings(), 3);
    }

    function test_lifecycle_signRevokeSign() public {
        for (uint i = 0; i < 3; i++) {
            uint64 expiresAt = uint64(block.timestamp + 30 days);
            vm.prank(caSchoolAdmin);
            reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);

            vm.prank(governance);
            reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
        }
        assertEq(reg.totalSignings(), 3);
        assertEq(reg.totalRevocations(), 3);
    }

    function test_lifecycle_independentGatesDontInterfere() public {
        // Sign DPA only — FERPA stays Untouched
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        assertTrue(reg.isCompliant(SCH_CA_HASH, G_DPA));
        assertFalse(reg.isCompliant(SCH_CA_HASH, G_FERPA));

        // Revoking DPA doesn't touch FERPA
        vm.prank(governance);
        reg.revokeGate(SCH_CA_HASH, G_DPA, REASON_AUDIT);
        assertEq(
            uint8(reg.getRecord(SCH_CA_HASH, G_FERPA).status),
            uint8(ComplianceRegistry.Status.Untouched)
        );
    }

    function test_lifecycle_independentSchoolsDontInterfere() public {
        // CA school signs DPA; NY school's DPA stays Untouched
        uint64 expiresAt = uint64(block.timestamp + 180 days);
        vm.prank(caSchoolAdmin);
        reg.recordSigned(SCH_CA_HASH, G_DPA, ENV_HASH_A, expiresAt);
        assertTrue(reg.isCompliant(SCH_CA_HASH, G_DPA));
        assertFalse(reg.isCompliant(SCH_NY_HASH, G_DPA));

        // NY school signs its own DPA independently
        vm.prank(nySchoolAdmin);
        reg.recordSigned(SCH_NY_HASH, G_DPA, ENV_HASH_B, expiresAt);
        assertTrue(reg.isCompliant(SCH_NY_HASH, G_DPA));

        // Different envelopes
        assertEq(reg.getRecord(SCH_CA_HASH, G_DPA).envelopeIdHash, ENV_HASH_A);
        assertEq(reg.getRecord(SCH_NY_HASH, G_DPA).envelopeIdHash, ENV_HASH_B);
    }
}
