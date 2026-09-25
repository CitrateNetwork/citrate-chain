// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";

/// @title RmQ_C018 — LiquidStakingPool reward reports were an unbacked mint
/// @notice CHAIN-B-C018 (HELD/reroll). Pre-fix `reportRewards` added to
///         `totalPooled` (a native-SALT liability) while moving no ETH, and
///         `donate()` added ETH without touching `totalPooled` — nothing
///         linked the two. A reward report was therefore a pure liability
///         mint, leaving `address(pool).balance < totalPooled` and bricking
///         later withdrawals. Fix: a report consumes donated backing.
contract RmQ_C018_LiquidStakingPool is Test {
    LiquidStakingPool internal pool;

    address internal alice = makeAddr("alice");
    address internal oracle1 = makeAddr("oracle1");

    function setUp() public {
        pool = new LiquidStakingPool(address(this)); // Governable(msg.sender) = this
        vm.deal(alice, 1000 ether);
        vm.deal(address(this), 1000 ether);
        pool.addOracle(oracle1); // oracleCount == 1 => votesNeeded == 1
    }

    /// GREEN: an unbacked reward report is rejected, keeping the pool solvent
    /// (`balance >= totalPooled`).
    /// RED (pre-fix): the single-oracle report finalizes and applies,
    /// `totalPooled` jumps to 300 ether while the balance is still 100 ether
    /// — an unbacked mint (no revert).
    function test_C018_unbacked_reward_report_reverts() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        assertEq(pool.totalPooled(), 100 ether);
        assertEq(address(pool).balance, 100 ether);

        // Report 2x totalPooled (within MAX_REWARD_RATE_BPS) with NO donation.
        vm.prank(oracle1);
        vm.expectRevert("Rewards exceed donated backing");
        pool.reportRewards(200 ether, 0);

        // Solvency invariant holds: the pool never owes more than it holds.
        assertEq(pool.totalPooled(), 100 ether, "liability not minted");
        assertGe(address(pool).balance, pool.totalPooled(), "pool solvent");
    }

    /// A reward report backed by a matching donation applies normally and the
    /// pool remains solvent afterwards.
    function test_C018_backed_reward_report_applies_and_stays_solvent() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        pool.donate{value: 200 ether}(); // real SALT backing enters the pool

        vm.prank(oracle1);
        pool.reportRewards(200 ether, 0);

        assertEq(pool.totalPooled(), 300 ether, "backed report applied");
        assertGe(address(pool).balance, pool.totalPooled(), "pool solvent");
    }

    receive() external payable {}
}
