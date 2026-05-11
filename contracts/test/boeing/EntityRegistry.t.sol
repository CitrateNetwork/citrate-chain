// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {EntityRegistry} from "../../src/boeing/EntityRegistry.sol";

contract EntityRegistryTest is Test {
    EntityRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant SCOPE_BCA = keccak256("scope-bca");
    bytes32 internal constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 internal constant CID_1 = keccak256("schema-v1");
    bytes32 internal constant CID_2 = keccak256("schema-v2");

    event RecorderSet(address indexed recorder, bool authorized);
    event TypeRegistered(
        bytes32 indexed type_id,
        bytes32 indexed scope,
        bytes32 schema_cid,
        string name
    );
    event SchemaBumped(bytes32 indexed type_id, bytes32 schema_cid, uint8 new_version);

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new EntityRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    // ── Constructor ─────────────────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(EntityRegistry.ZeroGovernance.selector);
        new EntityRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(EntityRegistry.NotGovernance.selector, nobody)
        );
        reg.setRecorder(nobody, true);
    }

    // ── registerType validation ────────────────────────────────────

    function test_register_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(EntityRegistry.NotRecorder.selector, nobody));
        reg.registerType(SCOPE_BCA, "Part", "Aircraft part", CID_1);
    }

    function test_register_rejects_zero_scope() public {
        vm.prank(recorder);
        vm.expectRevert(EntityRegistry.ZeroScope.selector);
        reg.registerType(bytes32(0), "Part", "Aircraft part", CID_1);
    }

    function test_register_rejects_zero_cid() public {
        vm.prank(recorder);
        vm.expectRevert(EntityRegistry.ZeroSchemaCid.selector);
        reg.registerType(SCOPE_BCA, "Part", "Aircraft part", bytes32(0));
    }

    function test_register_rejects_empty_name() public {
        vm.prank(recorder);
        vm.expectRevert(EntityRegistry.EmptyName.selector);
        reg.registerType(SCOPE_BCA, "", "x", CID_1);
    }

    function test_register_creates_type_at_version_1() public {
        vm.prank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "Aircraft part", CID_1);
        assertTrue(reg.exists(id));
        EntityRegistry.EntityType memory t = reg.getType(id);
        assertEq(t.version, 1);
        assertEq(t.scope, SCOPE_BCA);
        assertEq(t.schema_cid, CID_1);
        assertEq(t.name, "Part");
        assertEq(t.description, "Aircraft part");
    }

    function test_register_rejects_duplicate() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        vm.expectRevert(abi.encodeWithSelector(EntityRegistry.AlreadyRegistered.selector, id));
        reg.registerType(SCOPE_BCA, "Part", "y", CID_2);
        vm.stopPrank();
    }

    function test_register_emits_event() public {
        bytes32 expected = keccak256(abi.encode(SCOPE_BCA, "Part"));
        vm.expectEmit(true, true, false, true);
        emit TypeRegistered(expected, SCOPE_BCA, CID_1, "Part");
        vm.prank(recorder);
        reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
    }

    function test_register_records_block_and_creator() public {
        vm.roll(98765);
        vm.prank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        EntityRegistry.EntityType memory t = reg.getType(id);
        assertEq(t.created_at_block, 98765);
        assertEq(t.updated_at_block, 98765);
        assertEq(t.created_by, bytes32(uint256(uint160(recorder))));
    }

    // ── bumpSchema ─────────────────────────────────────────────────

    function test_bump_only_recorder() public {
        vm.prank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(EntityRegistry.NotRecorder.selector, nobody));
        reg.bumpSchema(id, CID_2);
    }

    function test_bump_rejects_unregistered() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(EntityRegistry.NotRegistered.selector, bytes32(uint256(99)))
        );
        reg.bumpSchema(bytes32(uint256(99)), CID_2);
    }

    function test_bump_rejects_zero_cid() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        vm.expectRevert(EntityRegistry.ZeroSchemaCid.selector);
        reg.bumpSchema(id, bytes32(0));
        vm.stopPrank();
    }

    function test_bump_increments_version_and_cid() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        vm.roll(99000);
        reg.bumpSchema(id, CID_2);
        vm.stopPrank();
        EntityRegistry.EntityType memory t = reg.getType(id);
        assertEq(t.version, 2);
        assertEq(t.schema_cid, CID_2);
        assertEq(t.updated_at_block, 99000);
    }

    function test_bump_emits_event() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        vm.expectEmit(true, false, false, true);
        emit SchemaBumped(id, CID_2, 2);
        reg.bumpSchema(id, CID_2);
        vm.stopPrank();
    }

    function test_bump_appends_to_allTypeIds() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        reg.bumpSchema(id, CID_2);
        reg.bumpSchema(id, keccak256("v3"));
        vm.stopPrank();
        assertEq(reg.totalEntries(), 3);
        assertEq(reg.allTypes()[0], id);
        assertEq(reg.allTypes()[1], id);
        assertEq(reg.allTypes()[2], id);
    }

    // ── Indices ─────────────────────────────────────────────────────

    function test_typesByScope_appends_once_per_register() public {
        vm.startPrank(recorder);
        reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        reg.registerType(SCOPE_BCA, "Tail", "y", CID_1);
        reg.registerType(SCOPE_BDS, "Supplier", "z", CID_1);
        vm.stopPrank();
        assertEq(reg.types(SCOPE_BCA).length, 2);
        assertEq(reg.types(SCOPE_BDS).length, 1);
        assertEq(reg.countByScope(SCOPE_BCA), 2);
    }

    function test_typesByScope_does_not_grow_on_bump() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        reg.bumpSchema(id, CID_2);
        vm.stopPrank();
        // typesByScope is APPEND-ONLY-PER-REGISTRATION; bumpSchema
        // doesn't push.
        assertEq(reg.types(SCOPE_BCA).length, 1);
    }

    function test_schema_returns_latest_cid() public {
        vm.startPrank(recorder);
        bytes32 id = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        assertEq(reg.schema(id), CID_1);
        reg.bumpSchema(id, CID_2);
        assertEq(reg.schema(id), CID_2);
        vm.stopPrank();
    }

    function test_exists_returns_false_for_unknown() public view {
        assertFalse(reg.exists(bytes32(uint256(99))));
    }

    function test_register_two_types_different_scopes_same_name() public {
        // Same name in different scopes produces distinct type_ids.
        vm.startPrank(recorder);
        bytes32 id1 = reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
        bytes32 id2 = reg.registerType(SCOPE_BDS, "Part", "y", CID_1);
        vm.stopPrank();
        assertTrue(id1 != id2);
        assertEq(reg.totalEntries(), 2);
    }

    function test_revoked_recorder_cannot_register() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(EntityRegistry.NotRecorder.selector, recorder)
        );
        reg.registerType(SCOPE_BCA, "Part", "x", CID_1);
    }
}
