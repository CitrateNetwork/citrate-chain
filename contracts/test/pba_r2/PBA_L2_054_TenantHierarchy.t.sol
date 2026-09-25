// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TenantHierarchy} from "../../src/rbac/TenantHierarchy.sol";

/// Regression for PBA-L2-054 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_054_Regression is Test {
    function test_L2_054_removedTenantIdCannotBeRecreated() public {
        TenantHierarchy th = new TenantHierarchy();
        address rootAdmin = address(0xAD);
        address otherAdmin = address(0xBAD);
        address[] memory ra = new address[](1);
        ra[0] = rootAdmin;
        th.initRoot(keccak256("root"), "root", keccak256("s"), ra, 1, 3);
        bytes32 X = keccak256("X");
        bytes32 Y = keccak256("Y");
        vm.startPrank(rootAdmin);
        th.createNode(keccak256("root"), X, "X", 1, bytes32(0), ra, 1, 2);
        address[] memory oa = new address[](1);
        oa[0] = otherAdmin;
        th.createNode(keccak256("root"), Y, "Y", 1, bytes32(0), oa, 1, 2);
        bytes32 X2 = keccak256("X-child");
        th.createNode(X, X2, "X2", 2, bytes32(0), ra, 1, 1);
        th.removeNode(X2);
        vm.stopPrank();
        // An admin of a DIFFERENT subtree re-creates X2 under its own node.
        vm.prank(otherAdmin);
        try th.createNode(Y, X2, "X2", 2, bytes32(0), oa, 1, 1) {} catch {}
        assertFalse(th.exists(X2), "removed id was re-created under a foreign parent");
    }
}
