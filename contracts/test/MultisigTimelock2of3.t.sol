// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultisigTimelock2of3} from "../src/cit_agent/MultisigTimelock2of3.sol";

/// @title MultisigTimelock2of3.t — owner rotation (added 2026-07-26)
/// @dev `owners` was set in the constructor with no way to change it, so the
///      keys present at deploy time controlled the timelock — and everything
///      it owns — permanently. A staging deployment could never be handed to a
///      customer's signers. These cover the rotation path and, more
///      importantly, the ways it must NOT be reachable.
contract MultisigTimelock2of3RotationTest is Test {
    MultisigTimelock2of3 internal tl;

    address internal a = address(0xA1);
    address internal b = address(0xB2);
    address internal c = address(0xC3);
    address internal newOwner = address(0xD4);
    address internal stranger = address(0xE5);

    uint256 internal constant DELAY = 2 days;

    function setUp() public {
        tl = new MultisigTimelock2of3([a, b, c], DELAY);
    }

    /// Drive a payload through propose → 2 approvals → delay → execute.
    function _run(bytes memory payload) internal returns (bytes32 opId) {
        vm.prank(a);
        opId = tl.propose(address(tl), payload);
        // `propose` counts as the proposer's own approval, so one more owner
        // reaches 2-of-3.
        vm.prank(b);
        tl.approve(opId);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(a);
        tl.execute(opId);
    }

    function test_rotationRequiresTheFull2of3Flow() public {
        assertTrue(tl.isOwner(c));
        assertFalse(tl.isOwner(newOwner));

        _run(abi.encodeCall(MultisigTimelock2of3.replaceOwner, (2, newOwner)));

        assertFalse(tl.isOwner(c), "rotated-out owner still has power");
        assertTrue(tl.isOwner(newOwner));
        assertEq(tl.owners(2), newOwner);
    }

    function test_aSingleOwnerCannotReplaceAnother() public {
        // The attack this gate exists for: one key swapping the other two out
        // and seizing the multisig would make 2-of-3 decorative.
        vm.prank(a);
        vm.expectRevert(abi.encodeWithSelector(MultisigTimelock2of3.NotTimelock.selector, a));
        tl.replaceOwner(1, newOwner);
    }

    function test_aStrangerCannotReplaceAnOwner() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(MultisigTimelock2of3.NotTimelock.selector, stranger)
        );
        tl.replaceOwner(0, stranger);
    }

    function test_anOwnerCannotBeDuplicatedIntoTwoSlots() public {
        // Two slots holding one address would let that key satisfy two of the
        // three approvals — 2-of-3 collapses to 1-of-1.
        vm.prank(a);
        bytes32 opId = tl.propose(
            address(tl), abi.encodeCall(MultisigTimelock2of3.replaceOwner, (2, a))
        );
        vm.prank(b);
        tl.approve(opId);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(a);
        vm.expectRevert();          // ExecutionFailed wrapping DuplicateOwner
        tl.execute(opId);

        assertTrue(tl.isOwner(c), "c must still be an owner");
        assertEq(tl.owners(2), c);
    }

    function test_ownerCannotBeZeroed() public {
        vm.prank(a);
        bytes32 opId = tl.propose(
            address(tl), abi.encodeCall(MultisigTimelock2of3.replaceOwner, (0, address(0)))
        );
        vm.prank(b);
        tl.approve(opId);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(a);
        vm.expectRevert();
        tl.execute(opId);
        assertTrue(tl.isOwner(a));
    }

    function test_indexMustBeInRange() public {
        vm.prank(a);
        bytes32 opId = tl.propose(
            address(tl), abi.encodeCall(MultisigTimelock2of3.replaceOwner, (3, newOwner))
        );
        vm.prank(b);
        tl.approve(opId);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(a);
        vm.expectRevert();
        tl.execute(opId);
    }

    function test_theRotatedInOwnerCanImmediatelyGovern() public {
        _run(abi.encodeCall(MultisigTimelock2of3.replaceOwner, (2, newOwner)));

        // The new signer counts toward 2-of-3...
        vm.prank(newOwner);
        bytes32 opId = tl.propose(address(tl), abi.encodeCall(MultisigTimelock2of3.replaceOwner, (0, stranger)));
        vm.prank(b);
        tl.approve(opId);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(newOwner);
        tl.execute(opId);
        assertTrue(tl.isOwner(stranger));

        // ...and the one it replaced does not.
        vm.prank(c);
        vm.expectRevert(MultisigTimelock2of3.NotOwner.selector);
        tl.propose(address(tl), hex"00");
    }
}
