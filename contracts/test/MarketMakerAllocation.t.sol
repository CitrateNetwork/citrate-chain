// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/MarketMakerAllocation.sol";

contract MarketMakerAllocationTest is Test {
    MarketMakerAllocation public mma;

    address public governance = address(0x600);
    address public marketMaker = address(0xDEAD);
    address public newMaker = address(0xBEEF);

    function setUp() public {
        mma = new MarketMakerAllocation(marketMaker, governance);
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    function test_constructor_sets_initial_state() public view {
        assertEq(mma.marketMaker(), marketMaker);
        assertEq(mma.governance(), governance);
        assertEq(mma.allocationBps(), 1000); // 10%
        assertEq(mma.totalAllocated(), 0);
        assertEq(mma.totalWithdrawn(), 0);
    }

    function test_constructor_reverts_zero_market_maker() public {
        vm.expectRevert("Zero market maker address");
        new MarketMakerAllocation(address(0), governance);
    }

    function test_constructor_reverts_zero_governance() public {
        vm.expectRevert("Zero governance address");
        new MarketMakerAllocation(marketMaker, address(0));
    }

    // -----------------------------------------------------------------------
    // Receive (allocation)
    // -----------------------------------------------------------------------

    function test_receive_accepts_salt() public {
        vm.deal(address(this), 100 ether);
        (bool ok, ) = address(mma).call{value: 10 ether}("");
        assertTrue(ok);
        assertEq(mma.totalAllocated(), 10 ether);
        assertEq(address(mma).balance, 10 ether);
    }

    function test_receive_accumulates_multiple_allocations() public {
        vm.deal(address(this), 100 ether);
        (bool ok1, ) = address(mma).call{value: 5 ether}("");
        assertTrue(ok1);
        (bool ok2, ) = address(mma).call{value: 3 ether}("");
        assertTrue(ok2);
        assertEq(mma.totalAllocated(), 8 ether);
    }

    // -----------------------------------------------------------------------
    // Withdrawal
    // -----------------------------------------------------------------------

    function test_market_maker_can_withdraw() public {
        vm.deal(address(mma), 50 ether);
        uint256 balBefore = marketMaker.balance;

        vm.prank(marketMaker);
        mma.withdraw(20 ether);

        assertEq(marketMaker.balance, balBefore + 20 ether);
        assertEq(mma.totalWithdrawn(), 20 ether);
        assertEq(address(mma).balance, 30 ether);
    }

    function test_withdraw_all() public {
        vm.deal(address(mma), 50 ether);

        vm.prank(marketMaker);
        mma.withdrawAll();

        assertEq(mma.totalWithdrawn(), 50 ether);
        assertEq(address(mma).balance, 0);
    }

    function test_non_market_maker_cannot_withdraw() public {
        vm.deal(address(mma), 50 ether);
        vm.prank(address(0xBAD));
        vm.expectRevert("Only market maker");
        mma.withdraw(10 ether);
    }

    function test_withdraw_exceeding_balance_reverts() public {
        vm.deal(address(mma), 5 ether);
        vm.prank(marketMaker);
        vm.expectRevert("Insufficient balance");
        mma.withdraw(10 ether);
    }

    function test_withdraw_all_empty_reverts() public {
        vm.prank(marketMaker);
        vm.expectRevert("Nothing to withdraw");
        mma.withdrawAll();
    }

    // -----------------------------------------------------------------------
    // Calculate Allocation
    // -----------------------------------------------------------------------

    function test_calculate_allocation_10_percent() public view {
        (uint256 makerShare, uint256 remainder) = mma.calculateAllocation(1000 ether);
        assertEq(makerShare, 100 ether); // 10%
        assertEq(remainder, 900 ether);  // 90%
    }

    function test_calculate_allocation_zero_fees() public view {
        (uint256 makerShare, uint256 remainder) = mma.calculateAllocation(0);
        assertEq(makerShare, 0);
        assertEq(remainder, 0);
    }

    // -----------------------------------------------------------------------
    // Change Market Maker (Governance)
    // -----------------------------------------------------------------------

    function test_governance_can_change_market_maker() public {
        vm.prank(governance);
        mma.changeMarketMaker(newMaker, "Upgrading to new partner");

        assertEq(mma.marketMaker(), newMaker);
        assertEq(mma.changeHistoryCount(), 1);

        (address prev, address next, , ) = mma.changeHistory(0);
        assertEq(prev, marketMaker);
        assertEq(next, newMaker);
    }

    function test_non_governance_cannot_change_market_maker() public {
        vm.prank(address(0xBAD));
        vm.expectRevert("Only governance");
        mma.changeMarketMaker(newMaker, "Unauthorized");
    }

    function test_cannot_change_to_zero_address() public {
        vm.prank(governance);
        vm.expectRevert("Zero address");
        mma.changeMarketMaker(address(0), "Bad");
    }

    function test_cannot_change_to_same_address() public {
        vm.prank(governance);
        vm.expectRevert("Same address");
        mma.changeMarketMaker(marketMaker, "No change");
    }

    function test_new_market_maker_can_withdraw_after_change() public {
        vm.deal(address(mma), 100 ether);

        // Change market maker
        vm.prank(governance);
        mma.changeMarketMaker(newMaker, "New partner DLP");

        // Old maker cannot withdraw
        vm.prank(marketMaker);
        vm.expectRevert("Only market maker");
        mma.withdraw(10 ether);

        // New maker can withdraw
        vm.prank(newMaker);
        mma.withdraw(10 ether);
        assertEq(newMaker.balance, 10 ether);
    }

    // -----------------------------------------------------------------------
    // Change Allocation Rate (Governance)
    // -----------------------------------------------------------------------

    function test_governance_can_change_rate() public {
        // Move past cooldown
        vm.roll(block.number + 302_401);

        vm.prank(governance);
        mma.changeAllocationRate(500); // 5%

        assertEq(mma.allocationBps(), 500);
    }

    function test_rate_change_below_minimum_reverts() public {
        vm.roll(block.number + 302_401);
        vm.prank(governance);
        vm.expectRevert("Below minimum (1%)");
        mma.changeAllocationRate(50);
    }

    function test_rate_change_above_maximum_reverts() public {
        vm.roll(block.number + 302_401);
        vm.prank(governance);
        vm.expectRevert("Above maximum (15%)");
        mma.changeAllocationRate(2000);
    }

    function test_rate_change_cooldown_enforced() public {
        // First change (immediately after deploy)
        vm.roll(block.number + 302_401);
        vm.prank(governance);
        mma.changeAllocationRate(800);

        // Second change too soon
        vm.roll(block.number + 100);
        vm.prank(governance);
        vm.expectRevert("Rate change cooldown active");
        mma.changeAllocationRate(1200);
    }

    function test_rate_change_after_cooldown_succeeds() public {
        // First change: advance well past initial cooldown
        vm.roll(500_000);
        vm.prank(governance);
        mma.changeAllocationRate(800);

        // Second change: advance past another full cooldown
        vm.roll(500_000 + 302_401);
        vm.prank(governance);
        mma.changeAllocationRate(1200); // 12%
        assertEq(mma.allocationBps(), 1200);
    }

    function test_allocation_reflects_new_rate() public {
        vm.roll(block.number + 302_401);
        vm.prank(governance);
        mma.changeAllocationRate(500); // 5%

        (uint256 makerShare, uint256 remainder) = mma.calculateAllocation(1000 ether);
        assertEq(makerShare, 50 ether); // 5%
        assertEq(remainder, 950 ether);
    }

    // -----------------------------------------------------------------------
    // Governance Transfer
    // -----------------------------------------------------------------------

    function test_transfer_governance() public {
        address newGov = address(0x999);
        vm.prank(governance);
        mma.transferGovernance(newGov);
        assertEq(mma.governance(), newGov);
    }

    function test_transfer_governance_non_gov_reverts() public {
        vm.prank(address(0xBAD));
        vm.expectRevert("Only governance");
        mma.transferGovernance(address(0x999));
    }

    function test_transfer_governance_zero_reverts() public {
        vm.prank(governance);
        vm.expectRevert("Zero address");
        mma.transferGovernance(address(0));
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    function test_available_balance() public {
        vm.deal(address(mma), 42 ether);
        assertEq(mma.availableBalance(), 42 ether);
    }

    // -----------------------------------------------------------------------
    // Fuzz Tests
    // -----------------------------------------------------------------------

    function testFuzz_allocation_conservation(uint256 gasFees) public view {
        vm.assume(gasFees < type(uint256).max / 10000);
        (uint256 makerShare, uint256 remainder) = mma.calculateAllocation(gasFees);
        assertEq(makerShare + remainder, gasFees, "Allocation must be conserving");
    }

    function testFuzz_allocation_within_bounds(uint256 gasFees) public view {
        vm.assume(gasFees > 0 && gasFees < type(uint256).max / 10000);
        (uint256 makerShare, ) = mma.calculateAllocation(gasFees);
        // Market maker share should be <= 15% (max rate) of gas fees
        assertLe(makerShare, (gasFees * 1500) / 10000);
        // And >= 0
        assertGe(makerShare, 0);
    }
}
