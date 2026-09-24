// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {CrossOrgIndex} from "../../src/defense_prime/CrossOrgIndex.sol";

contract CrossOrgIndexTest is Test {
    CrossOrgIndex internal idx;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant SCOPE_UNIT = keccak256("scope-unit");
    bytes32 internal constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 internal constant ENV_1 = keccak256("env-1");
    bytes32 internal constant ENV_2 = keccak256("env-2");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        idx = new CrossOrgIndex(governance);
        vm.prank(governance);
        idx.setRecorder(recorder, true);
    }

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(CrossOrgIndex.ZeroGovernance.selector);
        new CrossOrgIndex(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgIndex.NotGovernance.selector, nobody));
        idx.setRecorder(nobody, true);
    }

    function test_record_emits_event_and_grows_byScope() public {
        vm.expectEmit(true, true, false, true);
        emit CrossOrgIndex.Indexed(SCOPE_UNIT, ENV_1);
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, ENV_1);

        bytes32[] memory list = idx.byCrossOrg(SCOPE_UNIT);
        assertEq(list.length, 1);
        assertEq(list[0], ENV_1);
        assertEq(idx.envelopeScope(ENV_1), SCOPE_UNIT);
        assertTrue(idx.is_indexed(ENV_1));
        assertEq(idx.countByScope(SCOPE_UNIT), 1);
    }

    function test_record_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgIndex.NotRecorder.selector, nobody));
        idx.record(SCOPE_UNIT, ENV_1);
    }

    function test_record_rejects_duplicate_envelope() public {
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, ENV_1);
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgIndex.AlreadyIndexed.selector, ENV_1));
        idx.record(SCOPE_UNIT, ENV_1);
    }

    function test_record_rejects_duplicate_envelope_even_in_different_scope() public {
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, ENV_1);
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgIndex.AlreadyIndexed.selector, ENV_1));
        idx.record(SCOPE_BDS, ENV_1);
    }

    function test_multiple_scopes_are_isolated() public {
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, ENV_1);
        vm.prank(recorder);
        idx.record(SCOPE_BDS, ENV_2);
        assertEq(idx.byCrossOrg(SCOPE_UNIT).length, 1);
        assertEq(idx.byCrossOrg(SCOPE_BDS).length, 1);
        assertEq(idx.byCrossOrg(SCOPE_UNIT)[0], ENV_1);
        assertEq(idx.byCrossOrg(SCOPE_BDS)[0], ENV_2);
    }

    function test_record_appends_in_order() public {
        bytes32 e1 = keccak256("e1");
        bytes32 e2 = keccak256("e2");
        bytes32 e3 = keccak256("e3");
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, e1);
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, e2);
        vm.prank(recorder);
        idx.record(SCOPE_UNIT, e3);
        bytes32[] memory list = idx.byCrossOrg(SCOPE_UNIT);
        assertEq(list.length, 3);
        assertEq(list[0], e1);
        assertEq(list[1], e2);
        assertEq(list[2], e3);
    }

    function test_unindexed_envelope_returns_zero_scope() public view {
        assertEq(idx.envelopeScope(ENV_1), bytes32(0));
        assertFalse(idx.is_indexed(ENV_1));
    }
}
