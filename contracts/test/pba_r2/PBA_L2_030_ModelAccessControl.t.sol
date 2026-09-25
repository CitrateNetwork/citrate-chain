// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ModelAccessControl} from "../../src/ModelAccessControl.sol";

/// Regression for PBA-L2-030 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_030_Regression is Test {
    /// Finding trace, inverted: an unapproved request's payment is a
    /// liability (not sweepable) and refundable after the delay.
    function test_L2_030_unapprovedRequestEscrowIsProtectedAndRefundable() public {
        ModelAccessControl mac = ModelAccessControl(
            payable(_create(abi.encodePacked(type(ModelAccessControl).creationCode, abi.encode(address(this)))))
        );
        address modelOwner = makeAddr("modelOwner");
        address requester = makeAddr("requester");
        bytes32 mid = keccak256("m");
        vm.prank(modelOwner);
        mac.registerModel(mid, "cid", false, 1 ether);
        vm.deal(requester, 1 ether);
        vm.prank(requester);
        uint256 rid = mac.requestAccess{value: 1 ether}(mid, 1, "please");

        // The contract owner's surplus sweep must not take the escrow.
        try mac.emergencyWithdraw() {} catch {}
        assertEq(address(mac).balance, 1 ether, "request escrow was swept");

        vm.warp(vm.getBlockTimestamp() + 7 days);
        vm.prank(requester);
        (bool ok,) = address(mac).call(abi.encodeWithSignature("cancelAccessRequest(uint256)", rid));
        ok;
        assertEq(requester.balance, 1 ether, "ignored request refunded");
    }

    function _create(bytes memory initCode) internal returns (address a) {
        assembly {
            a := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(a != address(0), "create failed");
    }

    receive() external payable {}
}
