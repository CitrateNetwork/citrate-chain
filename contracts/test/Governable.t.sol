// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Governable} from "../src/lib/Governable.sol";

/// Concrete test harness exposing the mixin.
contract GovernableHarness is Governable {
    constructor(address gov) Governable(gov) {}

    function privilegedAction() external onlyGovernance returns (uint256) {
        return 42;
    }
}

/// @title GovernableTest — RM-D1 WP-D1.1 (audit SOL-21) acceptance
contract GovernableTest is Test {
    GovernableHarness internal target;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal carol = address(0xC4501);

    event GovernanceTransferProposed(address indexed currentGovernance, address indexed pendingGovernance);
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event GovernanceTransferCancelled(address indexed pendingGovernance);

    function setUp() public {
        target = new GovernableHarness(alice);
    }

    function test_constructor_rejects_zero_address() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        new GovernableHarness(address(0));
    }

    function test_constructor_emits_initial_transfer_event() public {
        vm.expectEmit(true, true, true, true);
        emit GovernanceTransferred(address(0), bob);
        new GovernableHarness(bob);
    }

    function test_initial_governor_can_call_privileged() public {
        vm.prank(alice);
        assertEq(target.privilegedAction(), 42);
    }

    function test_non_governor_cannot_call_privileged() public {
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        target.privilegedAction();
    }

    // ── Two-step transfer happy path ────────────────────────────────

    function test_transfer_governance_only_proposes() public {
        vm.expectEmit(true, true, true, true);
        emit GovernanceTransferProposed(alice, bob);
        vm.prank(alice);
        target.transferGovernance(bob);

        // Active governor unchanged until acceptance.
        assertEq(target.governance(), alice);
        assertEq(target.pendingGovernance(), bob);

        // Alice still controls privileged actions.
        vm.prank(alice);
        assertEq(target.privilegedAction(), 42);

        // Bob cannot yet act as governor.
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        target.privilegedAction();
    }

    function test_accept_governance_completes_handover() public {
        vm.prank(alice);
        target.transferGovernance(bob);

        vm.expectEmit(true, true, true, true);
        emit GovernanceTransferred(alice, bob);
        vm.prank(bob);
        target.acceptGovernance();

        assertEq(target.governance(), bob);
        assertEq(target.pendingGovernance(), address(0));

        // Alice no longer governor.
        vm.prank(alice);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        target.privilegedAction();

        // Bob now governor.
        vm.prank(bob);
        assertEq(target.privilegedAction(), 42);
    }

    // ── Authorization gates ─────────────────────────────────────────

    function test_transferGovernance_reverts_for_non_governor() public {
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        target.transferGovernance(carol);
    }

    function test_transferGovernance_rejects_zero_address() public {
        vm.prank(alice);
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        target.transferGovernance(address(0));
    }

    function test_acceptGovernance_reverts_for_random_caller() public {
        vm.prank(alice);
        target.transferGovernance(bob);

        vm.prank(carol);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        target.acceptGovernance();
    }

    function test_acceptGovernance_reverts_when_no_pending() public {
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        target.acceptGovernance();
    }

    /// SOL-21 core defense: the entire reason for two-step transfer
    /// is that a mistyped/lost successor key cannot strand the
    /// contract. Until the new account actually proves liveness
    /// via `acceptGovernance`, the original governor retains
    /// control AND can override the proposal.
    function test_sol21_mistyped_successor_does_not_strand_governance() public {
        // Alice proposes "bob" but it's actually carol's address that
        // controls the multisig. Bob's key is unreachable.
        vm.prank(alice);
        target.transferGovernance(bob);

        // Bob will never call acceptGovernance. Alice fixes by
        // pointing at the correct successor.
        vm.expectEmit(true, true, true, true);
        emit GovernanceTransferProposed(alice, carol);
        vm.prank(alice);
        target.transferGovernance(carol);

        assertEq(target.pendingGovernance(), carol);

        // Now carol accepts.
        vm.prank(carol);
        target.acceptGovernance();
        assertEq(target.governance(), carol);

        // Bob can no longer claim — pending was overwritten.
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        target.acceptGovernance();
    }

    // ── Cancellation ────────────────────────────────────────────────

    function test_cancelGovernanceTransfer_clears_pending() public {
        vm.prank(alice);
        target.transferGovernance(bob);

        vm.expectEmit(true, true, true, true);
        emit GovernanceTransferCancelled(bob);
        vm.prank(alice);
        target.cancelGovernanceTransfer();

        assertEq(target.pendingGovernance(), address(0));
        assertEq(target.governance(), alice);

        // Bob can no longer accept after cancel.
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        target.acceptGovernance();
    }

    function test_cancel_reverts_when_nothing_pending() public {
        vm.prank(alice);
        vm.expectRevert(Governable.Governable_NoPendingTransfer.selector);
        target.cancelGovernanceTransfer();
    }

    function test_cancel_reverts_for_non_governor() public {
        vm.prank(alice);
        target.transferGovernance(bob);

        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        target.cancelGovernanceTransfer();
    }
}
