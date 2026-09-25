// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {NematocystSlashing} from "../../src/NematocystSlashing.sol";

/// Regression for PBA-L2-028 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_028_Regression is Test {
    /// Finding trace, inverted: a provider that sees `slash()` coming and
    /// calls `unstake()` first does not walk away with its stake.
    function test_L2_028_unstakeCannotEvadePendingSlash() public {
        NematocystSlashing ns = new NematocystSlashing(address(this));
        address p = makeAddr("provider");
        vm.deal(p, 200 ether);
        vm.prank(p);
        ns.stake{value: 200 ether}();
        vm.prank(p);
        ns.unstake(); // front-runs governance's slash
        try ns.slash(p, NematocystSlashing.SlashTier.Inconsistency, hex"01") {} catch {}
        assertEq(p.balance, 0, "stake was not paid out instantly");
        (bool ok, bytes memory ret) = address(ns).staticcall(abi.encodeWithSignature("pendingUnstake(address)", p));
        assertTrue(ok && ret.length == 32, "unbonding queue exists");
        assertEq(abi.decode(ret, (uint256)), 160 ether, "20% slash reached the unbonding stake");
    }
}

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
