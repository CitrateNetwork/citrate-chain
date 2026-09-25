// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ModelAccessControl} from "../../src/ModelAccessControl.sol";

/// PBA-L2-030 tripwire: balance >= stakes + pending withdrawals + pending requests.
contract PBA_L2_030_Fixed is Test {
    function test_L2_030_cancelRules() public {
        ModelAccessControl mac = new ModelAccessControl(address(this));
        address mo = makeAddr("mo");
        address rq = makeAddr("rq");
        bytes32 mid = keccak256("m");
        vm.prank(mo);
        mac.registerModel(mid, "cid", false, 1 ether);
        vm.deal(rq, 3 ether);
        vm.prank(rq);
        uint256 rid = mac.requestAccess{value: 2 ether}(mid, 1, "r");
        assertEq(mac.totalPendingRequests(), 2 ether);
        vm.prank(rq);
        vm.expectRevert("Refund not yet available");
        mac.cancelAccessRequest(rid);
        vm.prank(makeAddr("other"));
        vm.warp(vm.getBlockTimestamp() + 7 days);
        vm.expectRevert("Not requester");
        mac.cancelAccessRequest(rid);
        vm.prank(rq);
        mac.cancelAccessRequest(rid);
        assertEq(mac.totalPendingRequests(), 0);
        vm.prank(mo);
        vm.expectRevert("Request cancelled");
        mac.approveAccessRequest(rid, 0, 0);

        vm.prank(rq);
        uint256 rid2 = mac.requestAccess{value: 1 ether}(mid, 1, "r2");
        vm.prank(mo);
        mac.approveAccessRequest(rid2, 0, 0);
        assertEq(mac.totalPendingRequests(), 0, "approval moves escrow to revenue");
        assertEq(mac.totalPendingWithdrawals(), 1 ether);
        assertGe(
            address(mac).balance,
            mac.totalUserStakes() + mac.totalPendingWithdrawals() + mac.totalPendingRequests()
        );
    }

    function test_L2_030_strayValueRefused() public {
        ModelAccessControl mac = new ModelAccessControl(address(this));
        address mo = makeAddr("mo");
        bytes32 mid = keccak256("free");
        vm.prank(mo);
        mac.registerModel(mid, "cid", false, 0);
        vm.deal(mo, 1 ether);
        vm.prank(mo);
        vm.expectRevert("No payment due");
        mac.executeInference{value: 1 ether}(mid, hex"00");
    }
}
