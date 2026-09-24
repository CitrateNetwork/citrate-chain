// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ContradictionLedger} from "../src/rbac/ContradictionLedger.sol";

/// @title ContradictionLedger.t — DPF-02-WP7 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/ContradictionStateMachine.tla`.
///      ≥35 tests covering every cited invariant + 3 fuzz targets.
contract ContradictionLedgerTest is Test {
    ContradictionLedger internal cl;

    bytes32 constant CON_A = keccak256("contradiction-a");
    bytes32 constant CON_B = keccak256("contradiction-b");
    bytes32 constant SUBJECT = keccak256("part-hash-1");
    bytes32 constant SUBJECT2 = keccak256("part-hash-2");
    bytes32 constant SOURCE_A = keccak256("tx-attestation-a");
    bytes32 constant SOURCE_B = keccak256("tx-attestation-b");
    bytes32 constant DETECTOR = keccak256("user-1");
    bytes32 constant CORR = keccak256("corr-1");
    bytes32 constant DECISION = keccak256("decision-resolution-1");

    address internal governance = address(0xA1);
    address internal resolver = address(0xB1);
    address internal stranger = address(0x5);

    function setUp() public {
        cl = new ContradictionLedger(governance);
        vm.prank(governance);
        cl.setResolver(resolver, true);
        // CHAIN-B-C023: `report` is now detector-gated. Authorize this test
        // contract (the default reporter for the happy-path cases below).
        vm.prank(governance);
        cl.setDetector(address(this), true);
    }

    // ── CHAIN-B-C023: report is detector-gated ─────────────────────

    /// RED (pre-fix): `report` was fully permissionless, so any address could
    /// push any subject to `Deny` via IncidentEscalation and grow the
    /// unbounded `_by_subject` array to grief the policy check on gas. GREEN:
    /// an unauthorized reporter is rejected.
    function test_C023_report_requires_detector() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(ContradictionLedger.NotDetector.selector, stranger));
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        assertFalse(cl.exists(CON_A));
    }

    function test_C023_setDetector_onlyGovernance() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(ContradictionLedger.NotGovernance.selector, stranger));
        cl.setDetector(stranger, true);

        // An authorized detector can file.
        vm.prank(governance);
        cl.setDetector(stranger, true);
        vm.prank(stranger);
        cl.report(CON_B, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        assertTrue(cl.exists(CON_B));
    }

    // ── Constructor + governance ───────────────────────────────────

    function test_constructor_setsGovernance() public view {
        assertEq(cl.governance(), governance);
    }

    function test_constructor_revertsOnZeroGovernance() public {
        vm.expectRevert(ContradictionLedger.ZeroGovernance.selector);
        new ContradictionLedger(address(0));
    }

    function test_setResolver_byGovernance() public {
        address resolver2 = address(0xB2);
        vm.prank(governance);
        cl.setResolver(resolver2, true);
        assertTrue(cl.is_resolver(resolver2));
    }

    function test_setResolver_emitsEvent() public {
        vm.prank(governance);
        vm.expectEmit(true, false, false, true);
        emit ContradictionLedger.ResolverSet(address(0xB2), true);
        cl.setResolver(address(0xB2), true);
    }

    function test_setResolver_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ContradictionLedger.NotGovernance.selector, stranger
            )
        );
        cl.setResolver(stranger, true);
    }

    // ── report happy path ──────────────────────────────────────────

    function test_report_basic() public {
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B,
            "1234", "5678", DETECTOR, CORR
        );
        ContradictionLedger.Contradiction memory c = cl.getContradiction(CON_A);
        assertEq(c.contradiction_id, CON_A);
        assertEq(c.subject, SUBJECT);
        assertEq(c.field, "lot_number");
        assertEq(c.value_a, "1234");
        assertEq(c.value_b, "5678");
    }

    /// @dev Cites OpenIsInitial.
    function test_OpenIsInitial() public {
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B,
            "1", "2", DETECTOR, CORR
        );
        assertEq(cl.getContradiction(CON_A).state, "Open");
    }

    function test_report_emitsReported() public {
        vm.expectEmit(true, true, false, true);
        emit ContradictionLedger.ContradictionReported(CON_A, SUBJECT, "lot_number");
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B,
            "1", "2", DETECTOR, CORR
        );
    }

    function test_report_storesTimestamp() public {
        vm.warp(1234567);
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B,
            "1", "2", DETECTOR, CORR
        );
        assertEq(cl.getContradiction(CON_A).ts, 1234567);
    }

    function test_report_indexesBySubject() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.report(CON_B, SUBJECT, "qty", SOURCE_A, SOURCE_B, "10", "20", DETECTOR, CORR);
        bytes32[] memory ids = cl.bySubject(SUBJECT);
        assertEq(ids.length, 2);
        assertEq(ids[0], CON_A);
        assertEq(ids[1], CON_B);
    }

    function test_report_independentSubjects() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.report(CON_B, SUBJECT2, "qty", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        assertEq(cl.bySubject(SUBJECT).length, 1);
        assertEq(cl.bySubject(SUBJECT2).length, 1);
    }

    // ── report invariants ──────────────────────────────────────────

    function test_report_revertsOnDuplicate() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.expectRevert(
            abi.encodeWithSelector(ContradictionLedger.AlreadyExists.selector, CON_A)
        );
        cl.report(CON_A, SUBJECT, "qty", SOURCE_A, SOURCE_B, "10", "20", DETECTOR, CORR);
    }

    function test_report_revertsOnZeroSubject() public {
        vm.expectRevert(ContradictionLedger.ZeroSubject.selector);
        cl.report(
            CON_A, bytes32(0), "lot_number", SOURCE_A, SOURCE_B,
            "1", "2", DETECTOR, CORR
        );
    }

    function test_report_revertsOnEmptyField() public {
        vm.expectRevert(ContradictionLedger.EmptyField.selector);
        cl.report(
            CON_A, SUBJECT, "", SOURCE_A, SOURCE_B,
            "1", "2", DETECTOR, CORR
        );
    }

    /// @dev Cites BelnapBImpliesTwoDistinctSources.
    function test_BelnapBImpliesTwoDistinctSources() public {
        vm.expectRevert(ContradictionLedger.EqualSources.selector);
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_A,
            "1", "2", DETECTOR, CORR
        );
    }

    /// @dev Cites ReportRequiresValueDifference.
    function test_ReportRequiresValueDifference() public {
        vm.expectRevert(ContradictionLedger.EqualValues.selector);
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B,
            "same", "same", DETECTOR, CORR
        );
    }

    // ── escalate ───────────────────────────────────────────────────

    function test_escalate_movesOpenToInvestigating() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.escalate(CON_A, CORR);
        assertEq(cl.getContradiction(CON_A).state, "Investigating");
    }

    function test_escalate_emitsEscalated() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.expectEmit(true, true, false, true);
        emit ContradictionLedger.ContradictionEscalated(CON_A, CORR);
        cl.escalate(CON_A, CORR);
    }

    function test_escalate_revertsForGhost() public {
        vm.expectRevert(
            abi.encodeWithSelector(ContradictionLedger.DoesNotExist.selector, CON_A)
        );
        cl.escalate(CON_A, CORR);
    }

    /// @dev Cites EscalateOnlyFromOpen.
    function test_EscalateOnlyFromOpen_revertsAfterEscalation() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.escalate(CON_A, CORR);
        vm.expectRevert(
            abi.encodeWithSelector(
                ContradictionLedger.InvalidStateForEscalate.selector, "Investigating"
            )
        );
        cl.escalate(CON_A, CORR);
    }

    function test_EscalateOnlyFromOpen_revertsAfterResolve() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        vm.expectRevert();
        cl.escalate(CON_A, CORR);
    }

    // ── resolve ────────────────────────────────────────────────────

    function test_resolve_fromOpenToResolvedA() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        assertEq(cl.getContradiction(CON_A).state, "Resolved-A");
        assertEq(cl.getContradiction(CON_A).resolution_decision, DECISION);
    }

    function test_resolve_fromInvestigatingToResolvedB() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.escalate(CON_A, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-B", DECISION, CORR);
        assertEq(cl.getContradiction(CON_A).state, "Resolved-B");
    }

    function test_resolve_resolvedOther() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-Other", DECISION, CORR);
        assertEq(cl.getContradiction(CON_A).state, "Resolved-Other");
    }

    function test_resolve_emitsResolved() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        vm.expectEmit(true, false, false, true);
        emit ContradictionLedger.ContradictionResolved(CON_A, "Resolved-A", DECISION);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
    }

    function test_resolve_revertsForNonResolver() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ContradictionLedger.NotResolver.selector, stranger
            )
        );
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
    }

    function test_resolve_revertsForGhost() public {
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(ContradictionLedger.DoesNotExist.selector, CON_A)
        );
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
    }

    /// @dev Cites ResolutionRequiresDecisionId.
    function test_ResolutionRequiresDecisionId() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        vm.expectRevert(ContradictionLedger.ZeroResolutionDecision.selector);
        cl.resolve(CON_A, "Resolved-A", bytes32(0), CORR);
    }

    function test_resolve_revertsOnInvalidState() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                ContradictionLedger.InvalidResolutionState.selector, "Bogus"
            )
        );
        cl.resolve(CON_A, "Bogus", DECISION, CORR);
    }

    function test_resolve_revertsAfterAlreadyResolved() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                ContradictionLedger.InvalidStateForResolve.selector, "Resolved-A"
            )
        );
        cl.resolve(CON_A, "Resolved-B", DECISION, CORR);
    }

    function test_resolve_revertsAfterWithdraw() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        vm.prank(resolver);
        vm.expectRevert();
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
    }

    // ── withdraw ───────────────────────────────────────────────────

    function test_withdraw_fromOpen() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        assertEq(cl.getContradiction(CON_A).state, "Withdrawn");
    }

    function test_withdraw_fromInvestigating() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.escalate(CON_A, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        assertEq(cl.getContradiction(CON_A).state, "Withdrawn");
    }

    /// @dev Cites WithdrawnHasNoResolution.
    function test_WithdrawnHasNoResolution() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        assertEq(cl.getContradiction(CON_A).resolution_decision, bytes32(0));
    }

    /// @dev Cites WithdrawnIsTerminal.
    function test_WithdrawnIsTerminal() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        vm.prank(resolver);
        vm.expectRevert();
        cl.withdraw(CON_A, CORR);
    }

    function test_withdraw_emitsWithdrawn() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        vm.expectEmit(true, true, false, true);
        emit ContradictionLedger.ContradictionWithdrawn(CON_A, CORR);
        cl.withdraw(CON_A, CORR);
    }

    function test_withdraw_revertsForNonResolver() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ContradictionLedger.NotResolver.selector, stranger
            )
        );
        cl.withdraw(CON_A, CORR);
    }

    function test_withdraw_revertsForGhost() public {
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(ContradictionLedger.DoesNotExist.selector, CON_A)
        );
        cl.withdraw(CON_A, CORR);
    }

    function test_withdraw_revertsAfterResolve() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        vm.prank(resolver);
        vm.expectRevert();
        cl.withdraw(CON_A, CORR);
    }

    // ── Read views ─────────────────────────────────────────────────

    function test_NotExistEmpty() public view {
        assertEq(cl.bySubject(SUBJECT).length, 0);
        assertFalse(cl.exists(CON_A));
        assertFalse(cl.hasOpenContradiction(SUBJECT));
    }

    function test_getContradiction_revertsForGhost() public {
        vm.expectRevert(
            abi.encodeWithSelector(ContradictionLedger.DoesNotExist.selector, CON_A)
        );
        cl.getContradiction(CON_A);
    }

    function test_hasOpenContradiction_trueForOpen() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        assertTrue(cl.hasOpenContradiction(SUBJECT));
    }

    function test_hasOpenContradiction_trueForInvestigating() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.escalate(CON_A, CORR);
        assertTrue(cl.hasOpenContradiction(SUBJECT));
    }

    function test_hasOpenContradiction_falseAfterResolve() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        assertFalse(cl.hasOpenContradiction(SUBJECT));
    }

    function test_hasOpenContradiction_falseAfterWithdraw() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        assertFalse(cl.hasOpenContradiction(SUBJECT));
    }

    function test_hasOpenContradiction_trueWhenAnyStillOpen() public {
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        cl.report(CON_B, SUBJECT, "qty", SOURCE_A, SOURCE_B, "10", "20", DETECTOR, CORR);
        vm.prank(resolver);
        cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        // CON_B still Open.
        assertTrue(cl.hasOpenContradiction(SUBJECT));
    }

    // ── Fuzz invariants ────────────────────────────────────────────

    /// @dev Fuzz BelnapBImpliesTwoDistinctSources: any equal pair reverts.
    function testFuzz_BelnapBImpliesTwoDistinctSources(bytes32 src) public {
        vm.expectRevert(ContradictionLedger.EqualSources.selector);
        cl.report(CON_A, SUBJECT, "lot_number", src, src, "1", "2", DETECTOR, CORR);
    }

    /// @dev Fuzz ReportRequiresValueDifference: any equal value pair reverts.
    function testFuzz_ReportRequiresValueDifference(string memory v) public {
        vm.expectRevert(ContradictionLedger.EqualValues.selector);
        cl.report(
            CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, v, v, DETECTOR, CORR
        );
    }

    /// @dev Fuzz WithdrawnIsTerminal: every other transition from
    ///      Withdrawn reverts.
    function testFuzz_WithdrawnIsTerminal(uint8 op) public {
        op = uint8(bound(op, 0, 2));
        cl.report(CON_A, SUBJECT, "lot_number", SOURCE_A, SOURCE_B, "1", "2", DETECTOR, CORR);
        vm.prank(resolver);
        cl.withdraw(CON_A, CORR);
        if (op == 0) {
            vm.expectRevert();
            cl.escalate(CON_A, CORR);
        } else if (op == 1) {
            vm.prank(resolver);
            vm.expectRevert();
            cl.resolve(CON_A, "Resolved-A", DECISION, CORR);
        } else {
            vm.prank(resolver);
            vm.expectRevert();
            cl.withdraw(CON_A, CORR);
        }
    }
}
