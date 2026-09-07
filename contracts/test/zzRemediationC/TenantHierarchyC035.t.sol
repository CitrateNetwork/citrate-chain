// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TenantHierarchy} from "../../src/rbac/TenantHierarchy.sol";

/// @title CHAIN-B-C035 — `setClassificationMax` must be monotone-down.
/// @notice The function is documented as "Lower a node's classification
///         ceiling", but pre-fix it only bounded against the PARENT's max, so a
///         node's own admins could RAISE their ceiling up to the parent's max
///         (clearing their scope above what the parent capped) and could LOWER
///         below an already-created child (leaving the child cleared above the
///         parent — the mirror hole).
contract TenantHierarchyC035Test is Test {
    TenantHierarchy th;

    bytes32 constant ROOT = keccak256("Boeing");
    bytes32 constant BU = keccak256("Boeing/BU");
    bytes32 constant SITE = keccak256("Boeing/BU/Site");

    address constant ADMIN = address(0xAD);

    function setUp() public {
        th = new TenantHierarchy();
        address[] memory admins = new address[](1);
        admins[0] = ADMIN;
        // root max = 3 (ITAR)
        th.initRoot(ROOT, "Boeing", keccak256("s0"), admins, 1, 3);
        // BU deliberately capped at 1 (Proprietary)
        vm.prank(ADMIN);
        th.createNode(ROOT, BU, "BU", 1, keccak256("s1"), admins, 1, 1);
    }

    /// RED (pre-fix): BU admin raises its own ceiling to 3 because the only
    /// check was against the parent (root max = 3). GREEN: reverts.
    function test_C035_cannotRaiseOwnCeiling() public {
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.ClassificationNotMonotoneDown.selector, uint8(3), uint8(1))
        );
        th.setClassificationMax(BU, 3);
    }

    /// Lowering still works.
    function test_C035_canStillLower() public {
        vm.prank(ADMIN);
        th.setClassificationMax(BU, 0);
        assertEq(th.getNode(BU).classification_max, 0, "lowering must still succeed");
    }

    /// RED (pre-fix): a node could be lowered below an existing child's ceiling,
    /// silently leaving the child cleared above the parent. GREEN: reverts.
    function test_C035_cannotLowerBelowChild() public {
        // Give BU headroom, create a SITE child at max 1, then try to drop BU
        // below the child.
        vm.startPrank(ADMIN);
        // SITE under BU at max 1 (== BU's max)
        th.createNode(BU, SITE, "Site", 2, keccak256("s2"), _admins(), 1, 1);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.ChildExceedsClassification.selector, SITE, uint8(1), uint8(0))
        );
        th.setClassificationMax(BU, 0);
        vm.stopPrank();
    }

    function _admins() internal pure returns (address[] memory a) {
        a = new address[](1);
        a[0] = ADMIN;
    }
}
