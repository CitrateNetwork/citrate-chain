// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {BudgetAllocation} from "../../src/edu/BudgetAllocation.sol";
import {CashoutRequest} from "../../src/edu/CashoutRequest.sol";
import {ICashoutRequest} from "../../src/edu/interfaces/ICashoutRequest.sol";

contract BudgetCashoutTest is Test {
    BudgetAllocation budget;
    CashoutRequest cashout;

    address governance = address(0x1000);
    address teacher = address(0x3);
    address nobody = address(0xBEEF);

    function setUp() public {
        budget = new BudgetAllocation(governance);
        cashout = new CashoutRequest(governance, 100); // $0.01 per SALT
    }

    // ===================================================================
    // BUDGET UNIT TESTS
    // ===================================================================

    function test_allocate_budget() public {
        vm.prank(governance);
        budget.allocateBudget(0, 1000, 500);
        assertEq(budget.getAllocated(0), 1000);
        assertEq(budget.getRemaining(0), 1000);
        assertEq(budget.getMonthlyLimit(0), 500);
    }

    function test_spend_from_budget() public {
        vm.prank(governance);
        budget.allocateBudget(0, 1000, 500);

        budget.spendFromBudget(0, 300);
        assertEq(budget.getRemaining(0), 700);
        assertEq(budget.getSpent(0), 300);
    }

    function test_spend_exceeds_budget_reverts() public {
        vm.prank(governance);
        budget.allocateBudget(0, 100, 100);

        vm.expectRevert(); // InsufficientBudget
        budget.spendFromBudget(0, 200);
    }

    function test_spend_exact_budget_exhausted() public {
        vm.prank(governance);
        budget.allocateBudget(0, 100, 100);

        budget.spendFromBudget(0, 100);
        assertEq(budget.getRemaining(0), 0);
    }

    function test_refill_budget() public {
        vm.prank(governance);
        budget.allocateBudget(0, 100, 100);

        budget.spendFromBudget(0, 80);

        vm.prank(governance);
        budget.refillBudget(0, 200);
        assertEq(budget.getRemaining(0), 220); // 100 - 80 + 200
    }

    function test_spend_inactive_budget_reverts() public {
        vm.expectRevert(); // BudgetNotActive
        budget.spendFromBudget(999, 100);
    }

    function test_non_governance_cannot_allocate() public {
        vm.prank(nobody);
        vm.expectRevert();
        budget.allocateBudget(0, 1000, 500);
    }

    function test_allocate_zero_reverts() public {
        vm.prank(governance);
        vm.expectRevert(); // ZeroAmount
        budget.allocateBudget(0, 0, 500);
    }

    // ===================================================================
    // CASHOUT UNIT TESTS
    // ===================================================================

    function test_request_cashout() public {
        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, 500, keccak256("supplies"));
        assertEq(id, 0);
        assertEq(uint256(cashout.getRequestStatus(id)), uint256(ICashoutRequest.RequestStatus.Pending));
        assertEq(cashout.getRequestTeacher(id), teacher);
        assertEq(cashout.getRequestAmount(id), 500);
    }

    function test_approve_cashout() public {
        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, 500, keccak256("supplies"));

        vm.prank(governance);
        cashout.approveCashout(id);
        assertEq(uint256(cashout.getRequestStatus(id)), uint256(ICashoutRequest.RequestStatus.Approved));
    }

    function test_reject_cashout() public {
        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, 500, keccak256("supplies"));

        vm.prank(governance);
        cashout.rejectCashout(id, keccak256("insufficient docs"));
        assertEq(uint256(cashout.getRequestStatus(id)), uint256(ICashoutRequest.RequestStatus.Rejected));
    }

    function test_self_approval_reverts() public {
        // If governance IS the teacher (edge case)
        vm.prank(governance);
        uint256 id = cashout.requestCashout(0, 500, keccak256("x"));

        vm.prank(governance);
        vm.expectRevert(); // SelfApproval
        cashout.approveCashout(id);
    }

    function test_approve_non_pending_reverts() public {
        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, 500, keccak256("x"));

        vm.prank(governance);
        cashout.rejectCashout(id, keccak256("no"));

        vm.prank(governance);
        vm.expectRevert(); // RequestNotPending
        cashout.approveCashout(id);
    }

    function test_set_salt_usd_rate() public {
        vm.prank(governance);
        cashout.setSaltUsdRate(200); // $0.02 per SALT
        assertEq(cashout.getSaltUsdRate(), 200);
    }

    function test_zero_cashout_reverts() public {
        vm.prank(teacher);
        vm.expectRevert(); // ZeroAmount
        cashout.requestCashout(0, 0, keccak256("x"));
    }

    function test_non_governance_cannot_approve() public {
        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, 500, keccak256("x"));

        vm.prank(nobody);
        vm.expectRevert();
        cashout.approveCashout(id);
    }

    // ===================================================================
    // INTEGRATION TESTS — Budget + Cashout
    // ===================================================================

    function test_integration_budget_spend_then_cashout() public {
        // Allocate budget
        vm.prank(governance);
        budget.allocateBudget(0, 1000, 500);

        // Spend some budget (simulating cycle gas costs)
        budget.spendFromBudget(0, 200);
        assertEq(budget.getRemaining(0), 800);

        // Teacher requests cashout of remaining
        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, 800, keccak256("end of semester"));

        // Admin approves
        vm.prank(governance);
        cashout.approveCashout(id);

        assertEq(uint256(cashout.getRequestStatus(id)), uint256(ICashoutRequest.RequestStatus.Approved));
    }

    function test_integration_multiple_classrooms_independent_budgets() public {
        vm.startPrank(governance);
        budget.allocateBudget(0, 1000, 500);
        budget.allocateBudget(1, 2000, 1000);
        vm.stopPrank();

        // Spend from classroom 0
        budget.spendFromBudget(0, 500);

        // Classroom 1 is unaffected
        assertEq(budget.getRemaining(0), 500);
        assertEq(budget.getRemaining(1), 2000);
    }

    // ===================================================================
    // FUZZ TESTS
    // ===================================================================

    function testFuzz_allocate_and_spend(uint256 allocated, uint256 spent) public {
        allocated = bound(allocated, 1, type(uint128).max);
        spent = bound(spent, 1, allocated);

        vm.prank(governance);
        budget.allocateBudget(0, allocated, allocated);

        budget.spendFromBudget(0, spent);
        assertEq(budget.getSpent(0), spent);
        assertEq(budget.getRemaining(0), allocated - spent);
    }

    function testFuzz_cashout_any_amount(uint256 amount) public {
        amount = bound(amount, 1, type(uint128).max);

        vm.prank(teacher);
        uint256 id = cashout.requestCashout(0, amount, keccak256("fuzz"));
        assertEq(cashout.getRequestAmount(id), amount);
    }

    function testFuzz_rate_change(uint256 rate) public {
        vm.prank(governance);
        cashout.setSaltUsdRate(rate);
        assertEq(cashout.getSaltUsdRate(), rate);
    }
}
