// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AuditBundleRegistry} from "../../src/defense_prime/AuditBundleRegistry.sol";

contract AuditBundleRegistryTest is Test {
    AuditBundleRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal recorder2;
    address internal nobody;

    bytes32 internal constant SCOPE_UNIT = keccak256("scope-unit");
    bytes32 internal constant SCOPE_BDS = keccak256("scope-bds");

    bytes32 internal constant SESSION_1 = keccak256("session-1");
    bytes32 internal constant SESSION_2 = keccak256("session-2");

    bytes32 internal constant BUNDLE_1 = keccak256("bundle-1");
    bytes32 internal constant BUNDLE_2 = keccak256("bundle-2");
    bytes32 internal constant BUNDLE_3 = keccak256("bundle-3");

    bytes32 internal constant MROOT_1 = keccak256("merkle-1");
    bytes32 internal constant CID_1 = keccak256("ipfs-cid-1");

    event RecorderSet(address indexed recorder, bool authorized);
    event BundleAnchored(
        bytes32 indexed bundle_id,
        bytes32 indexed session_id,
        bytes32 indexed scope,
        uint8 kind,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint256 entry_count
    );

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        recorder2 = makeAddr("recorder2");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new AuditBundleRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    // ── Constructor ─────────────────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(AuditBundleRegistry.ZeroGovernance.selector);
        new AuditBundleRegistry(address(0));
    }

    function test_constructor_sets_governance() public {
        assertEq(reg.governance(), governance);
    }

    // ── Governance ──────────────────────────────────────────────────

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AuditBundleRegistry.NotGovernance.selector, nobody));
        reg.setRecorder(nobody, true);
    }

    function test_setRecorder_emits_event() public {
        vm.expectEmit(true, false, false, true);
        emit RecorderSet(recorder2, true);
        vm.prank(governance);
        reg.setRecorder(recorder2, true);
        assertTrue(reg.is_recorder(recorder2));
    }

    function test_setRecorder_can_revoke() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        assertFalse(reg.is_recorder(recorder));
    }

    // ── anchorSession ───────────────────────────────────────────────

    function test_anchorSession_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AuditBundleRegistry.NotRecorder.selector, nobody));
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    function test_anchorSession_rejects_zero_bundle_id() public {
        vm.prank(recorder);
        vm.expectRevert(AuditBundleRegistry.ZeroBundleId.selector);
        reg.anchorSession(bytes32(0), SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    function test_anchorSession_emits_event_with_kind_zero() public {
        vm.expectEmit(true, true, true, true);
        emit BundleAnchored(BUNDLE_1, SESSION_1, SCOPE_UNIT, 0, MROOT_1, CID_1, 12);
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    function test_anchorSession_populates_bundle_struct() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);

        AuditBundleRegistry.Bundle memory b = reg.getBundle(BUNDLE_1);
        assertEq(b.bundle_id, BUNDLE_1);
        assertEq(b.session_id, SESSION_1);
        assertEq(b.scope, SCOPE_UNIT);
        assertEq(b.merkle_root, MROOT_1);
        assertEq(b.ipfs_cid, CID_1);
        assertEq(b.kind, 0);
        assertEq(b.entry_count, 12);
        assertEq(b.anchored_at_block, block.number);
        assertEq(b.anchored_by, bytes32(uint256(uint160(recorder))));
    }

    function test_anchorSession_marks_is_anchored() public {
        assertFalse(reg.is_anchored(BUNDLE_1));
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        assertTrue(reg.is_anchored(BUNDLE_1));
    }

    function test_anchorSession_rejects_duplicate_bundle_id() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);

        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(AuditBundleRegistry.BundleAlreadyExists.selector, BUNDLE_1)
        );
        reg.anchorSession(BUNDLE_1, SESSION_2, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    // ── anchor (general) ────────────────────────────────────────────

    function test_anchor_export_kind() public {
        vm.prank(recorder);
        reg.anchor(1, BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        assertEq(reg.getBundle(BUNDLE_1).kind, 1);
    }

    function test_anchor_replay_kind() public {
        vm.prank(recorder);
        reg.anchor(2, BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        assertEq(reg.getBundle(BUNDLE_1).kind, 2);
    }

    function test_anchor_rejects_invalid_kind() public {
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(AuditBundleRegistry.InvalidKind.selector, 3));
        reg.anchor(3, BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    function test_anchor_kind_max_is_two() public {
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(AuditBundleRegistry.InvalidKind.selector, 255));
        reg.anchor(255, BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    function test_anchor_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AuditBundleRegistry.NotRecorder.selector, nobody));
        reg.anchor(1, BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }

    // ── Indexes ─────────────────────────────────────────────────────

    function test_bundlesByScope_index_grows() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_2, SESSION_2, SCOPE_UNIT, MROOT_1, CID_1, 5);

        bytes32[] memory list = reg.bundlesByScopeList(SCOPE_UNIT);
        assertEq(list.length, 2);
        assertEq(list[0], BUNDLE_1);
        assertEq(list[1], BUNDLE_2);
        assertEq(reg.bundleCountByScope(SCOPE_UNIT), 2);
    }

    function test_bundlesByScope_index_is_per_scope() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_2, SESSION_2, SCOPE_BDS, MROOT_1, CID_1, 5);

        assertEq(reg.bundlesByScopeList(SCOPE_UNIT).length, 1);
        assertEq(reg.bundlesByScopeList(SCOPE_BDS).length, 1);
        assertEq(reg.bundlesByScopeList(SCOPE_UNIT)[0], BUNDLE_1);
        assertEq(reg.bundlesByScopeList(SCOPE_BDS)[0], BUNDLE_2);
    }

    function test_allBundles_grows_in_insertion_order() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_2, SESSION_2, SCOPE_BDS, MROOT_1, CID_1, 5);
        vm.prank(recorder);
        reg.anchor(1, BUNDLE_3, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 20);

        bytes32[] memory all = reg.allBundles();
        assertEq(all.length, 3);
        assertEq(all[0], BUNDLE_1);
        assertEq(all[1], BUNDLE_2);
        assertEq(all[2], BUNDLE_3);
        assertEq(reg.bundleCount(), 3);
    }

    function test_latestSessionBundle_returns_latest() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        assertEq(reg.latestSessionBundle(SESSION_1), BUNDLE_1);

        vm.prank(recorder);
        reg.anchorSession(BUNDLE_2, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 18);
        assertEq(reg.latestSessionBundle(SESSION_1), BUNDLE_2);
    }

    function test_latestSessionBundle_returns_zero_when_absent() public {
        assertEq(reg.latestSessionBundle(SESSION_1), bytes32(0));
    }

    function test_getBundle_returns_zero_for_unknown() public {
        AuditBundleRegistry.Bundle memory b = reg.getBundle(BUNDLE_1);
        assertEq(b.bundle_id, bytes32(0));
        assertEq(b.kind, 0);
    }

    function test_is_anchored_remains_true_after_re_anchor_rejection() public {
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        assertTrue(reg.is_anchored(BUNDLE_1));

        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(AuditBundleRegistry.BundleAlreadyExists.selector, BUNDLE_1)
        );
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 99);
        assertTrue(reg.is_anchored(BUNDLE_1));
        assertEq(reg.getBundle(BUNDLE_1).entry_count, 12);
    }

    function test_anchorSession_records_anchored_by_msg_sender() public {
        vm.prank(governance);
        reg.setRecorder(recorder2, true);
        vm.prank(recorder2);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);

        assertEq(reg.getBundle(BUNDLE_1).anchored_by, bytes32(uint256(uint160(recorder2))));
    }

    function test_anchor_records_block_number() public {
        vm.roll(98765);
        vm.prank(recorder);
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
        assertEq(reg.getBundle(BUNDLE_1).anchored_at_block, 98765);
    }

    function test_revoked_recorder_cannot_anchor() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(AuditBundleRegistry.NotRecorder.selector, recorder));
        reg.anchorSession(BUNDLE_1, SESSION_1, SCOPE_UNIT, MROOT_1, CID_1, 12);
    }
}
