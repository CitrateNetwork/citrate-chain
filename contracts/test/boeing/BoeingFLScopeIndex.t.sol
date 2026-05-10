// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {BoeingFLScopeIndex} from "../../src/boeing/BoeingFLScopeIndex.sol";

contract BoeingFLScopeIndexTest is Test {
    BoeingFLScopeIndex internal r;

    address internal governance = address(0xA1);
    address internal recorder = address(0xB1);
    address internal stranger = address(0x5);

    bytes32 constant SCOPE_BCA = keccak256("scope-bca");
    bytes32 constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 constant CORR = keccak256("corr-1");

    function setUp() public {
        r = new BoeingFLScopeIndex(governance);
        vm.prank(governance);
        r.setRecorder(recorder, true);
    }

    // ── Constructor / governance ─────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(BoeingFLScopeIndex.ZeroGovernance.selector);
        new BoeingFLScopeIndex(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(BoeingFLScopeIndex.NotGovernance.selector, stranger)
        );
        r.setRecorder(stranger, true);
    }

    // ── tag — happy + access ─────────────────────────────────────────

    function test_tag_basic_flow() public {
        vm.prank(recorder);
        r.tag(0, SCOPE_BCA, CORR);
        assertEq(r.poolScope(0), SCOPE_BCA);
        assertEq(r.poolsByScope(SCOPE_BCA).length, 1);
        assertEq(r.poolsByScope(SCOPE_BCA)[0], 0);
    }

    function test_tag_rejects_non_recorder() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(BoeingFLScopeIndex.NotRecorder.selector, stranger)
        );
        r.tag(0, SCOPE_BCA, CORR);
    }

    function test_tag_rejects_zero_scope() public {
        vm.prank(recorder);
        vm.expectRevert(BoeingFLScopeIndex.ZeroScope.selector);
        r.tag(0, bytes32(0), CORR);
    }

    function test_tag_rejects_duplicate_pool() public {
        vm.prank(recorder);
        r.tag(0, SCOPE_BCA, CORR);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                BoeingFLScopeIndex.PoolAlreadyTagged.selector,
                0,
                SCOPE_BCA
            )
        );
        r.tag(0, SCOPE_BDS, CORR);
    }

    function test_tag_emits_event() public {
        vm.prank(recorder);
        vm.expectEmit(true, true, false, true);
        emit BoeingFLScopeIndex.PoolTagged(7, SCOPE_BCA, CORR);
        r.tag(7, SCOPE_BCA, CORR);
    }

    // ── poolsByScope / poolCount / isTagged ──────────────────────────

    function test_poolsByScope_multi_tag() public {
        vm.startPrank(recorder);
        r.tag(0, SCOPE_BCA, CORR);
        r.tag(1, SCOPE_BCA, CORR);
        r.tag(2, SCOPE_BDS, CORR);
        vm.stopPrank();
        assertEq(r.poolCount(SCOPE_BCA), 2);
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
        r.tag(99, SCOPE_BCA, CORR);
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
