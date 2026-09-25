// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";

/// Regression for PBA-L2-026 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_026_Regression is Test {
    /// PoC `test_F2_06_lsp_singleOracle_wedgesRewardReports`, inverted: one
    /// bogus first vote cannot stop an honest quorum from finalizing.
    function test_L2_026_singleOracleCannotWedgeReports() public {
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        address o1 = makeAddr("o1");
        address o2 = makeAddr("o2");
        address o3 = makeAddr("o3");
        pool.addOracle(o1);
        pool.addOracle(o2);
        pool.addOracle(o3);
        vm.deal(address(this), 100 ether);
        pool.deposit{value: 10 ether}();
        pool.donate{value: 1 ether}();
        vm.prank(o1);
        pool.reportRewards(0, 1); // bogus first vote
        pool.removeOracle(o1); // governance response
        vm.prank(o2);
        try pool.reportRewards(0.5 ether, 0) {} catch {}
        vm.prank(o3);
        try pool.reportRewards(0.5 ether, 0) {} catch {}
        assertEq(pool.rewardReportNonce(), 1, "honest quorum finalized the report");
    }

    receive() external payable {}
}
