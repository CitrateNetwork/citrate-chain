// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {NematocystSlashing} from "../../src/NematocystSlashing.sol";

/// PBA-L2-028 tripwire: stake with a pending unbond stays slashable; slashed SALT has a sink.
contract PBA_L2_028_Fixed is Test {
    function test_L2_028_withdrawAfterUnbondingAndSlashSink() public {
        NematocystSlashing ns = new NematocystSlashing(address(this));
        address p = makeAddr("p");
        vm.deal(p, 200 ether);
        vm.prank(p);
        ns.stake{value: 200 ether}();
        vm.prank(p);
        ns.unstake();
        vm.prank(p);
        vm.expectRevert("Still unbonding");
        ns.withdrawUnstaked();
        ns.slash(p, NematocystSlashing.SlashTier.Latency, hex"01"); // 5% of 200
        assertEq(ns.pendingUnstake(p), 190 ether);
        vm.roll(vm.getBlockNumber() + ns.UNBONDING_PERIOD());
        vm.prank(p);
        ns.withdrawUnstaked();
        assertEq(p.balance, 190 ether);
        // Slashed SALT has a governance sink now.
        address treasury = makeAddr("treasury");
        vm.expectRevert("Exceeds slashed balance");
        ns.withdrawSlashed(treasury, 11 ether);
        ns.withdrawSlashed(treasury, 10 ether);
        assertEq(treasury.balance, 10 ether);
        vm.prank(p);
        vm.expectRevert();
        ns.withdrawSlashed(p, 1);
    }

    function test_L2_028_byzantineReachesUnbondingStake() public {
        NematocystSlashing ns = new NematocystSlashing(address(this));
        address p = makeAddr("p");
        vm.deal(p, 150 ether);
        vm.prank(p);
        ns.stake{value: 150 ether}();
        vm.prank(p);
        ns.unstake();
        ns.slash(p, NematocystSlashing.SlashTier.Byzantine, hex"01");
        assertEq(ns.pendingUnstake(p), 0);
        assertTrue(ns.banned(p));
        assertEq(ns.totalProviders(), 0, "no double decrement");
        vm.roll(vm.getBlockNumber() + ns.UNBONDING_PERIOD());
        vm.prank(p);
        vm.expectRevert("Provider is banned");
        ns.withdrawUnstaked();
    }
}
