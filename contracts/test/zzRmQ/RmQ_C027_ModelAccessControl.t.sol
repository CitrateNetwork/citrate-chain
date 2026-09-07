// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ModelAccessControl} from "../../src/ModelAccessControl.sol";

/// @title RmQ_C027 — ModelAccessControl.emergencyWithdraw liability sweep
/// @notice CHAIN-B-C027 (HELD/reroll). Pre-fix `emergencyWithdraw` sent the
///         ENTIRE contract balance to the owner, but that balance also holds
///         per-user `userStakes` and `pendingWithdrawals`. One owner call
///         converted every stake into owner funds and bricked `unstake` /
///         `withdrawRevenue`. Fix: sweep only `balance - liabilities`.
contract RmQ_C027_ModelAccessControl is Test {
    ModelAccessControl internal mac;
    address internal owner = address(this); // Ownable(msg.sender)
    address internal userA = makeAddr("userA");

    bytes32 internal constant MODEL = bytes32(uint256(0xA1));

    function setUp() public {
        mac = new ModelAccessControl();
        vm.deal(userA, 100 ether);
    }

    /// GREEN: the owner cannot sweep user stake; `unstake` still pays out.
    /// RED (pre-fix): `emergencyWithdraw()` does NOT revert, sweeps 10 ether
    /// to the owner, and userA's `unstake(10 ether)` then reverts inside
    /// `Address.sendValue` ("insufficient balance").
    function test_C027_emergencyWithdraw_cannot_seize_user_stake() public {
        vm.prank(userA);
        mac.stakeForAccess{value: 10 ether}(MODEL);

        assertEq(address(mac).balance, 10 ether, "stake held by contract");
        assertEq(mac.totalUserStakes(), 10 ether, "liability tracked");

        // The whole balance is a user liability — nothing is the owner's.
        vm.prank(owner);
        vm.expectRevert("No surplus to withdraw");
        mac.emergencyWithdraw();

        // The stake is intact and still redeemable.
        assertEq(address(mac).balance, 10 ether, "balance preserved");
        uint256 before = userA.balance;
        vm.prank(userA);
        mac.unstake(MODEL, 10 ether);
        assertEq(userA.balance, before + 10 ether, "user recovered full stake");
    }

    /// The fix still lets the owner sweep genuine surplus (non-liability SALT
    /// sent to the contract), while leaving user liabilities untouched.
    function test_C027_emergencyWithdraw_takes_only_surplus() public {
        vm.prank(userA);
        mac.stakeForAccess{value: 10 ether}(MODEL);

        // 3 ether of unrelated surplus lands in the contract.
        vm.deal(address(this), 3 ether);
        (bool ok, ) = payable(address(mac)).call{value: 3 ether}("");
        require(ok, "seed surplus");

        uint256 ownerBefore = owner.balance;
        vm.prank(owner);
        mac.emergencyWithdraw();
        assertEq(owner.balance, ownerBefore + 3 ether, "owner takes only surplus");

        // User stake survives the sweep.
        vm.prank(userA);
        mac.unstake(MODEL, 10 ether);
    }

    receive() external payable {}
}
