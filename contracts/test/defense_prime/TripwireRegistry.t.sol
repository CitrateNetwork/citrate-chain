// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TripwireRegistry} from "../../src/defense_prime/TripwireRegistry.sol";

contract TripwireRegistryTest is Test {
    TripwireRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal resolver;
    address internal nobody;

    bytes32 internal constant F_1 = keccak256("firing-1");
    bytes32 internal constant F_2 = keccak256("firing-2");
    bytes32 internal constant TRIP_AC = keccak256("TRIP-AC-001");
    bytes32 internal constant TRIP_AU = keccak256("TRIP-AU-001");
    bytes32 internal constant SCOPE = keccak256("scope-unit");
    bytes32 internal constant CID = keccak256("ipfs-cid");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        resolver = makeAddr("resolver");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new TripwireRegistry(governance);
        vm.startPrank(governance);
        reg.setRecorder(recorder, true);
        reg.setResolver(resolver, true);
        vm.stopPrank();
    }

    // ── Constructor / governance ────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(TripwireRegistry.ZeroGovernance.selector);
        new TripwireRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotGovernance.selector, nobody)
        );
        reg.setRecorder(nobody, true);
    }

    function test_setResolver_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotGovernance.selector, nobody)
        );
        reg.setResolver(nobody, true);
    }

    // ── Fire validation ────────────────────────────────────────────

    function test_fire_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotRecorder.selector, nobody)
        );
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
    }

    function test_fire_rejects_zero_tripwire_id() public {
        vm.prank(recorder);
        vm.expectRevert(TripwireRegistry.ZeroTripwireId.selector);
        reg.fire(F_1, bytes32(0), SCOPE, 1, CID);
    }

    function test_fire_rejects_invalid_severity() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.InvalidSeverity.selector, 4)
        );
        reg.fire(F_1, TRIP_AC, SCOPE, 4, CID);
    }

    function test_fire_creates_record() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 2, CID);
        TripwireRegistry.Firing memory f = reg.getFiring(F_1);
        assertEq(f.state, 1);
        assertEq(f.severity, 2);
        assertEq(f.tripwire_id, TRIP_AC);
        assertEq(f.scope, SCOPE);
        assertEq(f.evidence_cid, CID);
        assertEq(f.fired_at_block, block.number);
    }

    function test_fire_rejects_duplicate_id() public {
        vm.startPrank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.expectRevert(abi.encodeWithSelector(TripwireRegistry.AlreadyFired.selector, F_1));
        reg.fire(F_1, TRIP_AU, SCOPE, 2, CID);
        vm.stopPrank();
    }

    function test_fire_records_severity_zero_low() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 0, CID);
        assertEq(reg.getFiring(F_1).severity, 0);
    }

    function test_fire_records_severity_three_critical() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 3, CID);
        assertEq(reg.getFiring(F_1).severity, 3);
    }

    // ── Acknowledge ────────────────────────────────────────────────

    function test_acknowledge_only_resolver() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotResolver.selector, nobody)
        );
        reg.acknowledge(F_1);
    }

    function test_acknowledge_only_from_fired() public {
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotInState.selector, F_1, 1, 0)
        );
        reg.acknowledge(F_1);
    }

    function test_acknowledge_transitions_to_state_2() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.roll(block.number + 5);
        vm.prank(resolver);
        reg.acknowledge(F_1);
        TripwireRegistry.Firing memory f = reg.getFiring(F_1);
        assertEq(f.state, 2);
        assertEq(f.acknowledged_at_block, block.number);
    }

    function test_acknowledge_idempotent_revert() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.prank(resolver);
        reg.acknowledge(F_1);
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotInState.selector, F_1, 1, 2)
        );
        reg.acknowledge(F_1);
    }

    // ── Resolve ────────────────────────────────────────────────────

    function test_resolve_only_resolver() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotResolver.selector, nobody)
        );
        reg.resolve(F_1);
    }

    function test_resolve_from_fired_fast_path() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.roll(block.number + 10);
        vm.prank(resolver);
        reg.resolve(F_1);
        assertEq(reg.getFiring(F_1).state, 3);
        assertEq(reg.getFiring(F_1).resolved_at_block, block.number);
    }

    function test_resolve_from_acknowledged() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.prank(resolver);
        reg.acknowledge(F_1);
        vm.prank(resolver);
        reg.resolve(F_1);
        assertEq(reg.getFiring(F_1).state, 3);
    }

    function test_resolve_already_resolved_reverts() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.startPrank(resolver);
        reg.resolve(F_1);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotInState.selector, F_1, 1, 3)
        );
        reg.resolve(F_1);
        vm.stopPrank();
    }

    function test_resolve_from_notfired_reverts() public {
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotInState.selector, F_1, 1, 0)
        );
        reg.resolve(F_1);
    }

    // ── Indices ─────────────────────────────────────────────────────

    function test_byTripwire_index_appends() public {
        vm.startPrank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        reg.fire(F_2, TRIP_AC, SCOPE, 2, CID);
        vm.stopPrank();
        bytes32[] memory list = reg.byTripwire(TRIP_AC);
        assertEq(list.length, 2);
        assertEq(list[0], F_1);
        assertEq(list[1], F_2);
    }

    function test_byScope_isolates() public {
        bytes32 scope2 = keccak256("scope-bds");
        vm.startPrank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        reg.fire(F_2, TRIP_AU, scope2, 1, CID);
        vm.stopPrank();
        assertEq(reg.countByScope(SCOPE), 1);
        assertEq(reg.countByScope(scope2), 1);
    }

    function test_bySeverity_groups() public {
        bytes32 f3 = keccak256("firing-3");
        vm.startPrank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 3, CID); // critical
        reg.fire(F_2, TRIP_AU, SCOPE, 1, CID); // medium
        reg.fire(f3, TRIP_AC, SCOPE, 3, CID);  // critical
        vm.stopPrank();
        assertEq(reg.countBySeverity(3), 2);
        assertEq(reg.countBySeverity(1), 1);
        assertEq(reg.countBySeverity(0), 0);
    }

    function test_allFirings_in_insertion_order() public {
        vm.startPrank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        reg.fire(F_2, TRIP_AU, SCOPE, 2, CID);
        vm.stopPrank();
        bytes32[] memory all = reg.allFirings();
        assertEq(all.length, 2);
        assertEq(all[0], F_1);
        assertEq(all[1], F_2);
        assertEq(reg.firingCount(), 2);
    }

    function test_fire_records_block_and_recorder() public {
        vm.roll(98765);
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        TripwireRegistry.Firing memory f = reg.getFiring(F_1);
        assertEq(f.fired_at_block, 98765);
        assertEq(f.fired_by, bytes32(uint256(uint160(recorder))));
    }

    function test_revoked_recorder_cannot_fire() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotRecorder.selector, recorder)
        );
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
    }

    function test_revoked_resolver_cannot_acknowledge() public {
        vm.prank(recorder);
        reg.fire(F_1, TRIP_AC, SCOPE, 1, CID);
        vm.prank(governance);
        reg.setResolver(resolver, false);
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(TripwireRegistry.NotResolver.selector, resolver)
        );
        reg.acknowledge(F_1);
    }
}
