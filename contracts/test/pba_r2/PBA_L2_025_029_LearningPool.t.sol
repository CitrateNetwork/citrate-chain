// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LearningPool} from "../../src/LearningPool.sol";

/// Regression for PBA-L2-025 / PBA-L2-029 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_025_029_Regression is Test {
    /// PoC `test_F2_05_learningPool_inviteHashIsTheCredential`, inverted: the
    /// registered (public) key is not a credential, and the invitee's raw
    /// code cannot be replayed by anyone else.
    function test_L2_025_publicInviteKeyIsNotACredential() public {
        LearningPool lp = new LearningPool();
        address creator = makeAddr("creator");
        address alice = makeAddr("alice");
        address outsider = makeAddr("outsider");
        vm.prank(creator);
        uint256 pid = lp.createPool("p", "d", LearningPool.AccessType.InviteOnly, 0);
        bytes32 code = keccak256("secret-invite-for-alice");
        bytes32 key = keccak256(abi.encode(pid, code, alice)); // == inviteKeyFor(pid, code, alice)
        vm.prank(creator);
        lp.addInviteCode(pid, key); // `key` is now public calldata + public mapping key

        vm.prank(outsider);
        try lp.joinWithInvite(pid, key) {} catch {}
        vm.prank(outsider);
        try lp.joinWithInvite(pid, code) {} catch {} // front-run of alice's raw code
        assertFalse(lp.isMember(pid, outsider), "outsider joined with a public value");

        vm.prank(alice);
        lp.joinWithInvite(pid, code);
        assertTrue(lp.isMember(pid, alice), "the intended invitee still gets in");
    }

    /// Finding trace, inverted: a creator who never ends the cycle cannot
    /// freeze member stakes past MAX_CYCLE_DURATION.
    function test_L2_029_perpetualCycleCannotFreezeStakes() public {
        LearningPool lp = new LearningPool();
        address creator = makeAddr("creator");
        address m = makeAddr("member");
        vm.deal(m, 5 ether);
        vm.prank(creator);
        uint256 pid = lp.createPool("p", "d", LearningPool.AccessType.Open, 0);
        vm.prank(m);
        lp.joinPool{value: 5 ether}(pid);
        vm.prank(creator);
        lp.whitelistModel(pid, keccak256("model"));
        vm.prank(creator);
        lp.startCycle(pid);
        vm.warp(vm.getBlockTimestamp() + 31 days);
        vm.prank(m);
        try lp.leavePool(pid) {} catch {}
        assertFalse(lp.isMember(pid, m), "member left an overrun cycle");
        assertEq(m.balance, 5 ether, "stake returned");
    }
}

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
