// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ClassificationRegistry} from "../src/rbac/ClassificationRegistry.sol";

/// @title ClassificationRegistry.t — DPF-02-WP4 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/ClassificationLadder.tla`.
///      ≥25 tests covering every cited invariant + 2 fuzz targets.
contract ClassificationRegistryTest is Test {
    ClassificationRegistry internal cr;

    bytes32 constant USER = keccak256("user-1");
    bytes32 constant USER2 = keccak256("user-2");

    address internal governance = address(0xA1);
    address internal oracle1 = address(0xB1);
    address internal oracle2 = address(0xB2);
    address internal stranger = address(0x5);

    function setUp() public {
        cr = new ClassificationRegistry(governance);
        vm.prank(governance);
        cr.addOracleSigner(oracle1);
    }

    // ── Constructor ─────────────────────────────────────────────────

    function test_constructor_setsGovernance() public view {
        assertEq(cr.governance(), governance);
    }

    function test_constructor_revertsOnZeroGovernance() public {
        vm.expectRevert(ClassificationRegistry.ZeroGovernance.selector);
        new ClassificationRegistry(address(0));
    }

    // ── Oracle set ──────────────────────────────────────────────────

    function test_addOracleSigner_byGovernance() public {
        vm.prank(governance);
        cr.addOracleSigner(oracle2);
        assertTrue(cr.hr_oracle_signers(oracle2));
    }

    function test_addOracleSigner_emitsEvent() public {
        vm.prank(governance);
        vm.expectEmit(true, false, false, true);
        emit ClassificationRegistry.OracleSignerSet(oracle2, true);
        cr.addOracleSigner(oracle2);
    }

    function test_addOracleSigner_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotGovernance.selector, stranger
            )
        );
        cr.addOracleSigner(oracle2);
    }

    function test_removeOracleSigner_byGovernance() public {
        vm.prank(governance);
        cr.removeOracleSigner(oracle1);
        assertFalse(cr.hr_oracle_signers(oracle1));
    }

    function test_removeOracleSigner_emitsEvent() public {
        vm.prank(governance);
        vm.expectEmit(true, false, false, true);
        emit ClassificationRegistry.OracleSignerSet(oracle1, false);
        cr.removeOracleSigner(oracle1);
    }

    function test_removeOracleSigner_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotGovernance.selector, stranger
            )
        );
        cr.removeOracleSigner(oracle1);
    }

    // ── setClearance happy path ─────────────────────────────────────

    function test_setClearance_initialPublic() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.Public, false, "sig");
        (ClassificationRegistry.ClassLevel max, bool fn) = cr.getClearance(USER);
        assertEq(uint8(max), 0);
        assertFalse(fn);
    }

    function test_setClearance_initialITAR() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig");
        (ClassificationRegistry.ClassLevel max, ) = cr.getClearance(USER);
        assertEq(uint8(max), 3);
    }

    function test_setClearance_emitsClearanceChanged() public {
        vm.prank(oracle1);
        vm.expectEmit(true, false, false, true);
        emit ClassificationRegistry.ClearanceChanged(
            USER,
            ClassificationRegistry.ClassLevel.Public,
            ClassificationRegistry.ClassLevel.CUI,
            false,
            false,
            oracle1
        );
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
    }

    function test_setClearance_increasesLevel() public {
        vm.prank(oracle1);
        cr.setClearance(
            USER, ClassificationRegistry.ClassLevel.Proprietary, false, "sig"
        );
        vm.warp(block.timestamp + 1);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig2");
        (ClassificationRegistry.ClassLevel max, ) = cr.getClearance(USER);
        assertEq(uint8(max), uint8(ClassificationRegistry.ClassLevel.CUI));
    }

    function test_setClearance_decreasesLevel() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig");
        vm.warp(block.timestamp + 1);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.Public, false, "sig2");
        (ClassificationRegistry.ClassLevel max, ) = cr.getClearance(USER);
        assertEq(uint8(max), 0);
    }

    function test_setClearance_recordStoresSigner() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        ClassificationRegistry.UserClass memory r = cr.getRecord(USER);
        assertEq(r.hr_oracle_signer, oracle1);
        assertTrue(r.exists);
    }

    function test_setClearance_independentUsers() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        vm.prank(oracle1);
        cr.setClearance(USER2, ClassificationRegistry.ClassLevel.ITAR, true, "sig");
        (ClassificationRegistry.ClassLevel m1, ) = cr.getClearance(USER);
        (ClassificationRegistry.ClassLevel m2, bool fn2) = cr.getClearance(USER2);
        assertEq(uint8(m1), 2);
        assertEq(uint8(m2), 3);
        assertTrue(fn2);
    }

    // ── SignerWasAuthorized invariant ───────────────────────────────

    function test_SignerWasAuthorized_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotOracleSigner.selector, stranger
            )
        );
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
    }

    function test_SignerWasAuthorized_revertsAfterRemoval() public {
        vm.prank(governance);
        cr.removeOracleSigner(oracle1);
        vm.prank(oracle1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotOracleSigner.selector, oracle1
            )
        );
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
    }

    // ── HistoryMonotonic invariant ──────────────────────────────────

    function test_HistoryMonotonic_revertsOnSameTimestamp() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        vm.prank(oracle1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.ClearanceNotFresher.selector,
                uint64(block.timestamp),
                uint64(block.timestamp)
            )
        );
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig2");
    }

    function test_HistoryMonotonic_acceptsLaterTimestamp() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        vm.warp(block.timestamp + 1);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig2");
        (ClassificationRegistry.ClassLevel max, ) = cr.getClearance(USER);
        assertEq(uint8(max), 3);
    }

    function test_HistoryMonotonic_lastUpdatedIncreases() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        uint64 t1 = cr.getRecord(USER).last_updated;
        vm.warp(block.timestamp + 100);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig2");
        uint64 t2 = cr.getRecord(USER).last_updated;
        assertGt(t2, t1);
    }

    // ── ForeignNationalChanged ──────────────────────────────────────

    function test_ForeignNational_emittedOnFlip() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        vm.warp(block.timestamp + 1);
        vm.prank(oracle1);
        vm.expectEmit(true, false, false, true);
        emit ClassificationRegistry.ForeignNationalChanged(USER, true);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, true, "sig2");
    }

    function test_ForeignNational_notEmittedWhenUnchanged() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        vm.warp(block.timestamp + 1);
        // Re-set with FN unchanged. We can't easily assert NO event,
        // but we assert the record state is correct.
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig2");
        (, bool fn) = cr.getClearance(USER);
        assertFalse(fn);
    }

    function test_ForeignNational_flipsBackToFalse() public {
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, true, "sig");
        vm.warp(block.timestamp + 1);
        vm.prank(oracle1);
        vm.expectEmit(true, false, false, true);
        emit ClassificationRegistry.ForeignNationalChanged(USER, false);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig2");
    }

    // ── ClearanceLadderIsTotal invariant ────────────────────────────

    function test_ClearanceLadder_allFourLevelsAccepted() public {
        vm.warp(100);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.Public, false, "sig");
        assertEq(cr.clearanceOrdinal(USER), 0);

        vm.warp(200);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.Proprietary, false, "sig");
        assertEq(cr.clearanceOrdinal(USER), 1);

        vm.warp(300);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
        assertEq(cr.clearanceOrdinal(USER), 2);

        vm.warp(400);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.ITAR, false, "sig");
        assertEq(cr.clearanceOrdinal(USER), 3);
    }

    function test_clearanceOrdinal_defaultsToZeroForUnset() public view {
        assertEq(cr.clearanceOrdinal(USER), 0);
    }

    function test_getClearance_defaultsToPublicForUnset() public view {
        (ClassificationRegistry.ClassLevel max, bool fn) = cr.getClearance(USER);
        assertEq(uint8(max), 0);
        assertFalse(fn);
    }

    function test_getRecord_defaultsToZeroForUnset() public view {
        ClassificationRegistry.UserClass memory r = cr.getRecord(USER);
        assertFalse(r.exists);
        assertEq(r.last_updated, 0);
    }

    // ── Fuzz invariants ─────────────────────────────────────────────

    /// @dev Fuzz HistoryMonotonic: any sequence of updates with
    ///      strictly increasing timestamps preserves the latest write.
    function testFuzz_HistoryMonotonic(uint8 lvl1, uint8 lvl2, uint32 gap) public {
        lvl1 = uint8(bound(lvl1, 0, 3));
        lvl2 = uint8(bound(lvl2, 0, 3));
        gap = uint32(bound(gap, 1, 365 days));

        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel(lvl1), false, "s1");
        vm.warp(block.timestamp + gap);
        vm.prank(oracle1);
        cr.setClearance(USER, ClassificationRegistry.ClassLevel(lvl2), false, "s2");
        assertEq(cr.clearanceOrdinal(USER), lvl2);
    }

    /// @dev Fuzz SignerWasAuthorized: random non-oracle senders revert.
    function testFuzz_SignerWasAuthorized(address random) public {
        vm.assume(random != oracle1 && random != address(0));
        vm.prank(random);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotOracleSigner.selector, random
            )
        );
        cr.setClearance(USER, ClassificationRegistry.ClassLevel.CUI, false, "sig");
    }

    // ── Governance transfer (two-step) ──────────────────────────────
    //
    // Added 2026-07-26. `governance` was assigned only in the constructor and
    // had no setter, so the address chosen at deploy time governed the
    // contract permanently — a staging deploy could never be handed to a
    // customer's multi-sig without redeploying and re-booking the address
    // across the federation.

    function test_transferGovernance_isTwoStep() public {
        address newGov = address(0xC1);

        vm.prank(governance);
        cr.transferGovernance(newGov);

        // Nominated, but NOT yet in force — this is the whole point.
        assertEq(cr.pendingGovernance(), newGov);
        assertEq(cr.governance(), governance);

        vm.prank(newGov);
        cr.acceptGovernance();

        assertEq(cr.governance(), newGov);
        assertEq(cr.pendingGovernance(), address(0));
    }

    function test_transferGovernance_onlyGovernanceMayNominate() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(ClassificationRegistry.NotGovernance.selector, stranger)
        );
        cr.transferGovernance(stranger);
    }

    function test_acceptGovernance_onlyNomineeMayAccept() public {
        vm.prank(governance);
        cr.transferGovernance(address(0xC1));

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotPendingGovernance.selector, stranger
            )
        );
        cr.acceptGovernance();
    }

    function test_newGovernanceCanAdminister_andOldCannot() public {
        address newGov = address(0xC1);
        vm.prank(governance);
        cr.transferGovernance(newGov);
        vm.prank(newGov);
        cr.acceptGovernance();

        // The new holder really governs.
        vm.prank(newGov);
        cr.addOracleSigner(oracle2);

        // And the old one is out.
        vm.prank(governance);
        vm.expectRevert(
            abi.encodeWithSelector(ClassificationRegistry.NotGovernance.selector, governance)
        );
        cr.addOracleSigner(stranger);
    }

    function test_pendingNominationCanBeCleared() public {
        vm.startPrank(governance);
        cr.transferGovernance(address(0xC1));
        cr.transferGovernance(address(0));
        vm.stopPrank();

        assertEq(cr.pendingGovernance(), address(0));

        // The dropped nominee cannot sneak in afterwards.
        vm.prank(address(0xC1));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotPendingGovernance.selector, address(0xC1)
            )
        );
        cr.acceptGovernance();
    }

    function test_nominationDoesNotWeakenTheCurrentHolder() public {
        // Between nomination and acceptance the incumbent still governs.
        vm.prank(governance);
        cr.transferGovernance(address(0xC1));

        vm.prank(governance);
        cr.addOracleSigner(oracle2);

        vm.prank(address(0xC1));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClassificationRegistry.NotGovernance.selector, address(0xC1)
            )
        );
        cr.addOracleSigner(stranger);
    }
}
