// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LearningPool} from "../../src/LearningPool.sol";

contract PBA_L2_029_Fixed is Test {
    function test_L2_029_anyoneEndsOverrunCycle_butNotBefore() public {
        LearningPool lp = new LearningPool();
        address creator = makeAddr("creator");
        address m = makeAddr("m");
        vm.deal(m, 1 ether);
        vm.prank(creator);
        uint256 pid = lp.createPool("p", "d", LearningPool.AccessType.Open, 0);
        vm.prank(m);
        lp.joinPool{value: 1 ether}(pid);
        vm.prank(creator);
        lp.whitelistModel(pid, keccak256("model"));
        vm.prank(creator);
        lp.startCycle(pid);
        vm.prank(m);
        vm.expectRevert("Not creator");
        lp.endCycle(pid);
        vm.prank(m);
        vm.expectRevert("Cannot leave during active cycle");
        lp.leavePool(pid);
        vm.warp(vm.getBlockTimestamp() + lp.MAX_CYCLE_DURATION());
        vm.prank(m);
        lp.endCycle(pid);
        assertEq(uint256(lp.getPool(pid).state), uint256(LearningPool.PoolState.Active));
    }
}
