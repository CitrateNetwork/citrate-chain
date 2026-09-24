// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {BudgetAllocation} from "../../src/edu/BudgetAllocation.sol";

/// @title RM-Q · CHAIN-B-C006 — permissionless spendFromBudget
/// @notice RED→GREEN tripwire. Before the fix, `spendFromBudget` carried
///         no access control, so any address could exhaust a classroom's
///         entire allocation. After the fix it is gated behind a
///         governance-managed spender allowlist.
contract RmQ_C006 is Test {
    BudgetAllocation internal budget;
    address internal governance = address(0x6006);
    address internal attacker = address(0xBAD);
    address internal spender = address(0x5AFE);

    function setUp() public {
        budget = new BudgetAllocation(governance);
        vm.prank(governance);
        budget.allocateBudget(1, 1000, 100);
    }

    /// RED: the exploit is that an unprivileged address exhausts the
    /// classroom budget. The failing assertion (pre-fix) is the
    /// expectRevert — pre-fix the call SUCCEEDS and no revert occurs.
    function test_C006_outsider_cannot_exhaust_budget() public {
        assertEq(budget.getRemaining(1), 1000);
        vm.prank(attacker);
        vm.expectRevert(BudgetAllocation.NotAuthorizedSpender.selector);
        budget.spendFromBudget(1, 1000);
        // GREEN: allocation untouched by the unauthorized caller.
        assertEq(budget.getRemaining(1), 1000);
    }

    /// The legitimate, governance-authorized spender path still works.
    function test_C006_authorized_spender_can_spend() public {
        vm.prank(governance);
        budget.setSpender(spender, true);
        vm.prank(spender);
        budget.spendFromBudget(1, 400);
        assertEq(budget.getRemaining(1), 600);
    }
}
