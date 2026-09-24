// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {RoleGrantTenantIndex} from "../../src/defense_prime/RoleGrantTenantIndex.sol";

contract RoleGrantTenantIndexTest is Test {
    RoleGrantTenantIndex internal idx;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant SCOPE_UNIT = keccak256("scope-unit");
    bytes32 internal constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 internal constant USER_1 = keccak256("user-1");
    bytes32 internal constant USER_2 = keccak256("user-2");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        idx = new RoleGrantTenantIndex(governance);
        vm.prank(governance);
        idx.setRecorder(recorder, true);
    }

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(RoleGrantTenantIndex.ZeroGovernance.selector);
        new RoleGrantTenantIndex(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(RoleGrantTenantIndex.NotGovernance.selector, nobody)
        );
        idx.setRecorder(nobody, true);
    }

    function test_record_emits_event_and_grows_byTenant() public {
        vm.expectEmit(true, true, false, true);
        emit RoleGrantTenantIndex.Indexed(SCOPE_UNIT, USER_1);
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, USER_1);

        bytes32[] memory list = idx.byTenant(SCOPE_UNIT);
        assertEq(list.length, 1);
        assertEq(list[0], USER_1);
        assertEq(idx.countByScope(SCOPE_UNIT), 1);
        assertTrue(idx.isIndexed(SCOPE_UNIT, USER_1));
    }

    function test_record_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(RoleGrantTenantIndex.NotRecorder.selector, nobody));
        idx.record(SCOPE_UNIT, USER_1);
    }

    function test_record_rejects_duplicate_pair() public {
        vm.startPrank(recorder);
        idx.record(SCOPE_UNIT, USER_1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleGrantTenantIndex.AlreadyIndexed.selector,
                SCOPE_UNIT,
                USER_1
            )
        );
        idx.record(SCOPE_UNIT, USER_1);
        vm.stopPrank();
    }

    function test_same_user_under_different_scopes_allowed() public {
        vm.startPrank(recorder);
        idx.record(SCOPE_UNIT, USER_1);
        idx.record(SCOPE_BDS, USER_1);
        vm.stopPrank();
        assertEq(idx.countByScope(SCOPE_UNIT), 1);
        assertEq(idx.countByScope(SCOPE_BDS), 1);
        assertTrue(idx.isIndexed(SCOPE_UNIT, USER_1));
        assertTrue(idx.isIndexed(SCOPE_BDS, USER_1));
    }

    function test_setRecorder_can_revoke() public {
        vm.prank(governance);
        idx.setRecorder(recorder, false);
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(RoleGrantTenantIndex.NotRecorder.selector, recorder));
        idx.record(SCOPE_UNIT, USER_1);
    }

    function test_empty_byTenant_returns_empty() public view {
        assertEq(idx.byTenant(SCOPE_UNIT).length, 0);
        assertEq(idx.countByScope(SCOPE_UNIT), 0);
        assertFalse(idx.isIndexed(SCOPE_UNIT, USER_1));
    }

    function test_multiple_users_under_same_scope() public {
        vm.startPrank(recorder);
        idx.record(SCOPE_UNIT, USER_1);
        idx.record(SCOPE_UNIT, USER_2);
        vm.stopPrank();
        bytes32[] memory list = idx.byTenant(SCOPE_UNIT);
        assertEq(list.length, 2);
        assertEq(list[0], USER_1);
        assertEq(list[1], USER_2);
    }

    function test_governance_is_set_correctly() public view {
        assertEq(idx.governance(), governance);
    }
}
