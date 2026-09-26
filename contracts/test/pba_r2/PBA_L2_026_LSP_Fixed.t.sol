// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";

/// PBA-L2-026 tripwire: any single-oracle vote at nonce N cannot prevent an honest quorum.
contract PBA_L2_026_Fixed is Test {
    function testFuzz_L2_026_singleVoteNeverBlocksHonestQuorum(uint256 bogusRewards, uint256 bogusSlash) public {
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        address[4] memory o = [makeAddr("o1"), makeAddr("o2"), makeAddr("o3"), makeAddr("o4")];
        for (uint256 i = 0; i < 4; i++) pool.addOracle(o[i]);
        vm.deal(address(this), 100 ether);
        pool.deposit{value: 10 ether}();
        pool.donate{value: 1 ether}();
        bogusRewards = bound(bogusRewards, 0, 0.1 ether);
        bogusSlash = bound(bogusSlash, 0, 0.1 ether);
        vm.assume(!(bogusRewards == 0.05 ether && bogusSlash == 0));
        vm.prank(o[0]);
        pool.reportRewards(bogusRewards, bogusSlash);
        // votesNeeded(4) = 3: the three honest oracles finalize.
        for (uint256 i = 1; i < 4; i++) {
            vm.prank(o[i]);
            pool.reportRewards(0.05 ether, 0);
        }
        assertEq(pool.rewardReportNonce(), 1);
    }

    function test_L2_026_resetReportStartsAFreshRound() public {
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        address o1 = makeAddr("o1");
        address o2 = makeAddr("o2");
        pool.addOracle(o1);
        pool.addOracle(o2);
        vm.prank(o1);
        pool.reportRewards(0, 0);
        vm.prank(o2);
        pool.reportRewards(0, 1); // split vote: 1-1, needs 2
        assertEq(pool.rewardReportNonce(), 0);
        vm.prank(o1);
        vm.expectRevert();
        pool.resetReport();
        pool.resetReport();
        vm.prank(o1);
        pool.reportRewards(0, 0);
        vm.prank(o2);
        pool.reportRewards(0, 0);
        assertEq(pool.rewardReportNonce(), 1);
    }

    receive() external payable {}
}

/// PBA-L2-026: removing an oracle lowers the quorum, so the
/// open round restarts and only votes from the current set are counted.
contract PBA_L2_026_RemoveOracle is Test {
    function test_L2_026_removeOracle_startsFreshRound() public {
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        address o1 = makeAddr("o1");
        address o2 = makeAddr("o2");
        address o3 = makeAddr("o3");
        address o4 = makeAddr("o4");
        pool.addOracle(o1);
        pool.addOracle(o2);
        pool.addOracle(o3);
        pool.addOracle(o4);
        vm.deal(address(this), 100 ether);
        pool.deposit{value: 10 ether}();
        pool.donate{value: 1 ether}();
        assertEq(pool.votesRequired(), 3);
        vm.prank(o1);
        pool.reportRewards(0.5 ether, 0);
        uint256 roundBefore = pool.reportRound();
        pool.removeOracle(o1);
        assertEq(pool.votesRequired(), 2);
        assertEq(pool.reportRound(), roundBefore + 1, "removal starts a fresh round");
        vm.prank(o2);
        pool.reportRewards(0.5 ether, 0);
        assertEq(pool.rewardReportNonce(), 0, "the removed oracle's vote does not count");
        vm.prank(o3);
        pool.reportRewards(0.5 ether, 0);
        assertEq(pool.rewardReportNonce(), 1, "two current oracles finalize");
    }

    receive() external payable {}
}

/// PBA-L2-026: with exactly three oracles one dissenter must not
/// block (two thirds of 3 is 2, not unanimity).
contract PBA_L2_026_ThreeOracles is Test {
    function test_L2_026_threeOracles_oneDissenterDoesNotBlock() public {
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
        assertEq(pool.votesRequired(), 2);
        vm.prank(o1);
        pool.reportRewards(0, 1); // dissenter
        vm.prank(o2);
        pool.reportRewards(0.5 ether, 0);
        assertEq(pool.rewardReportNonce(), 0, "one honest vote is not a quorum");
        vm.prank(o3);
        pool.reportRewards(0.5 ether, 0);
        assertEq(pool.rewardReportNonce(), 1, "2 of 3 finalizes despite the dissenter");
    }

    function test_L2_026_votesRequiredIsCeilTwoThirds() public {
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        uint256[7] memory want = [uint256(0), 1, 2, 2, 3, 4, 4];
        for (uint256 n = 1; n <= 6; n++) {
            pool.addOracle(address(uint160(0x0A00 + n)));
            assertEq(pool.votesRequired(), want[n]);
        }
    }

    receive() external payable {}
}
