// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {RoleEscalation} from "../../src/rbac/RoleEscalation.sol";

/// The role-admin set can never be emptied: removing the last admin reverts,
/// while removing one of several still works and keeps the count in step.
contract RoleEscalationLastAdminTest is Test {
    RoleEscalation internal re;
    address internal constant ADMIN = address(0xAD);
    address internal constant OTHER = address(0xB0B);

    function setUp() public {
        re = new RoleEscalation(ADMIN);
    }

    function test_lastAdminCannotRemoveItself() public {
        vm.prank(ADMIN);
        vm.expectRevert(RoleEscalation.CannotRemoveLastAdmin.selector);
        re.setRoleAdmin(ADMIN, false);
        assertTrue(re.is_role_admin(ADMIN));
        assertEq(re.roleAdminCount(), 1);
    }

    function test_adminCannotStripTheSetDownToZero() public {
        vm.prank(ADMIN);
        re.setRoleAdmin(OTHER, true);
        assertEq(re.roleAdminCount(), 2);

        vm.prank(OTHER);
        re.setRoleAdmin(ADMIN, false); // one of two: allowed
        assertFalse(re.is_role_admin(ADMIN));
        assertEq(re.roleAdminCount(), 1);

        vm.prank(OTHER);
        vm.expectRevert(RoleEscalation.CannotRemoveLastAdmin.selector);
        re.setRoleAdmin(OTHER, false);
        assertTrue(re.is_role_admin(OTHER), "the set still has an admin");
    }

    function test_idempotentRemoveOfNonAdminDoesNotChangeCount() public {
        vm.prank(ADMIN);
        re.setRoleAdmin(OTHER, false); // OTHER was never an admin
        assertEq(re.roleAdminCount(), 1);
    }
}
