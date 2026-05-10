// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {DefensePrimeFLScopeIndex} from "../../src/defense_prime/DefensePrimeFLScopeIndex.sol";

contract DefensePrimeFLScopeIndexTest is Test {
    DefensePrimeFLScopeIndex internal r;

    address internal governance = address(0xA1);
    address internal recorder = address(0xB1);
    address internal stranger = address(0x5);

    bytes32 constant SCOPE_UNIT = keccak256("scope-unit");
    bytes32 constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 constant CORR = keccak256("corr-1");

    function setUp() public {
        r = new DefensePrimeFLScopeIndex(governance);
        vm.prank(governance);
        r.setRecorder(recorder, true);
    }

    // ── Constructor / governance ─────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(DefensePrimeFLScopeIndex.ZeroGovernance.selector);
        new DefensePrimeFLScopeIndex(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(DefensePrimeFLScopeIndex.NotGovernance.selector, stranger)
        );
        r.setRecorder(stranger, true);
    }

    // ── tag — happy + access ─────────────────────────────────────────

    function test_tag_basic_flow() public {
        vm.prank(recorder);
        r.tag(0, SCOPE_UNIT, CORR);
        assertEq(r.poolScope(0), SCOPE_UNIT);
        assertEq(r.poolsByScope(SCOPE_UNIT).length, 1);
        assertEq(r.poolsByScope(SCOPE_UNIT)[0], 0);
    }

    function test_tag_rejects_non_recorder() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(DefensePrimeFLScopeIndex.NotRecorder.selector, stranger)
        );
        r.tag(0, SCOPE_UNIT, CORR);
    }

    function test_tag_rejects_zero_scope() public {
        vm.prank(recorder);
        vm.expectRevert(DefensePrimeFLScopeIndex.ZeroScope.selector);
        r.tag(0, bytes32(0), CORR);
    }

    function test_tag_rejects_duplicate_pool() public {
        vm.prank(recorder);
        r.tag(0, SCOPE_UNIT, CORR);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefensePrimeFLScopeIndex.PoolAlreadyTagged.selector,
                0,
                SCOPE_UNIT
            )
        );
        r.tag(0, SCOPE_BDS, CORR);
    }

    function test_tag_emits_event() public {
        vm.prank(recorder);
        vm.expectEmit(true, true, false, true);
        emit DefensePrimeFLScopeIndex.PoolTagged(7, SCOPE_UNIT, CORR);
        r.tag(7, SCOPE_UNIT, CORR);
    }

    // ── poolsByScope / poolCount / isTagged ──────────────────────────

    function test_poolsByScope_multi_tag() public {
        vm.startPrank(recorder);
        r.tag(0, SCOPE_UNIT, CORR);
        r.tag(1, SCOPE_UNIT, CORR);
        r.tag(2, SCOPE_BDS, CORR);
        vm.stopPrank();
        assertEq(r.poolCount(SCOPE_UNIT), 2);
        assertEq(r.poolCount(SCOPE_BDS), 1);
    }

    function test_poolsByScope_empty_for_unknown() public view {
        assertEq(r.poolsByScope(keccak256("unknown")).length, 0);
    }

    function test_isTagged_false_for_untagged() public view {
        assertFalse(r.isTagged(99));
    }

    function test_isTagged_true_after_tag() public {
        vm.prank(recorder);
        r.tag(99, SCOPE_UNIT, CORR);
        assertTrue(r.isTagged(99));
    }

    // ── Fuzz ─────────────────────────────────────────────────────────

    function testFuzz_tag_appends_one_per_call(uint256 pool_id, bytes32 scope) public {
        vm.assume(scope != bytes32(0));
        uint256 before_ = r.poolsByScope(scope).length;
        vm.prank(recorder);
        r.tag(pool_id, scope, CORR);
        assertEq(r.poolsByScope(scope).length, before_ + 1);
    }
}
