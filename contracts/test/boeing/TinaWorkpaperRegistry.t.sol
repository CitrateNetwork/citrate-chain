// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TinaWorkpaperRegistry} from "../../src/boeing/TinaWorkpaperRegistry.sol";

contract TinaWorkpaperRegistryTest is Test {
    TinaWorkpaperRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant WP_1 = keccak256("wp-1");
    bytes32 internal constant WP_2 = keccak256("wp-2");
    bytes32 internal constant PO_1 = keccak256("po-1");
    bytes32 internal constant SCOPE_BCA = keccak256("scope-bca");
    bytes32 internal constant ROOT = keccak256("merkle-root");
    bytes32 internal constant CID = keccak256("ipfs-cid");
    bytes32 internal constant SIG_A = keccak256("signer-a");
    bytes32 internal constant SIG_B = keccak256("signer-b");
    bytes32 internal constant SIG_C = keccak256("signer-c");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new TinaWorkpaperRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(TinaWorkpaperRegistry.ZeroGovernance.selector);
        new TinaWorkpaperRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.NotGovernance.selector, nobody)
        );
        reg.setRecorder(nobody, true);
    }

    // ── Draft validation ───────────────────────────────────────────

    function test_draft_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.NotRecorder.selector, nobody)
        );
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
    }

    function test_draft_rejects_zero_threshold() public {
        vm.prank(recorder);
        vm.expectRevert(TinaWorkpaperRegistry.ZeroThreshold.selector);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 0, block.number + 1000);
    }

    function test_draft_rejects_zero_po_hash() public {
        vm.prank(recorder);
        vm.expectRevert(TinaWorkpaperRegistry.ZeroPoHash.selector);
        reg.draftWorkpaper(WP_1, bytes32(0), ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
    }

    function test_draft_creates_pending_workpaper() public {
        vm.prank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        TinaWorkpaperRegistry.Workpaper memory w = reg.getWorkpaper(WP_1);
        assertEq(w.state, 1);
        assertEq(w.threshold, 2);
        assertEq(w.sig_count, 0);
        assertEq(w.po_hash, PO_1);
        assertEq(w.scope, SCOPE_BCA);
    }

    function test_draft_rejects_duplicate() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.AlreadyDrafted.selector, WP_1)
        );
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 3, block.number + 2000);
        vm.stopPrank();
    }

    // ── Signature flow ─────────────────────────────────────────────

    function test_addSignature_increments_count() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
        assertEq(reg.getWorkpaper(WP_1).sig_count, 1);
        assertTrue(reg.hasSigned(WP_1, SIG_A));
    }

    function test_addSignature_rejects_duplicate_signer() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.AlreadySigned.selector, WP_1, SIG_A)
        );
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
    }

    function test_addSignature_rejects_when_not_pending() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 1, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
        reg.signWorkpaper(WP_1);
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotPending.selector, WP_1));
        reg.addSignature(WP_1, SIG_B);
    }

    function test_signersList_records_order() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 3, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        reg.addSignature(WP_1, SIG_B);
        reg.addSignature(WP_1, SIG_C);
        vm.stopPrank();
        bytes32[] memory list = reg.signersList(WP_1);
        assertEq(list.length, 3);
        assertEq(list[0], SIG_A);
        assertEq(list[1], SIG_B);
        assertEq(list[2], SIG_C);
    }

    // ── Sign flow ──────────────────────────────────────────────────

    function test_sign_threshold_not_met_reverts() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.ThresholdNotMet.selector, 1, 2)
        );
        reg.signWorkpaper(WP_1);
    }

    function test_sign_threshold_met_transitions_to_signed() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        reg.addSignature(WP_1, SIG_B);
        vm.stopPrank();
        vm.roll(block.number + 5);
        reg.signWorkpaper(WP_1);
        TinaWorkpaperRegistry.Workpaper memory w = reg.getWorkpaper(WP_1);
        assertEq(w.state, 2);
        assertEq(w.signed_at_block, block.number);
    }

    function test_sign_idempotent_revert() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 1, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
        reg.signWorkpaper(WP_1);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotPending.selector, WP_1));
        reg.signWorkpaper(WP_1);
    }

    function test_sign_permissionless() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 1, block.number + 1000);
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
        // nobody calls signWorkpaper → succeeds.
        vm.prank(nobody);
        reg.signWorkpaper(WP_1);
        assertEq(reg.getWorkpaper(WP_1).state, 2);
    }

    // ── Expire flow ────────────────────────────────────────────────

    function test_expire_before_deadline_reverts() public {
        vm.prank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        vm.expectRevert(
            abi.encodeWithSelector(
                TinaWorkpaperRegistry.NotExpired.selector,
                block.number + 1000,
                block.number
            )
        );
        reg.expireWorkpaper(WP_1);
    }

    function test_expire_after_deadline_transitions_to_expired() public {
        vm.prank(recorder);
        uint256 deadline = block.number + 10;
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, deadline);
        vm.roll(deadline + 1);
        reg.expireWorkpaper(WP_1);
        assertEq(reg.getWorkpaper(WP_1).state, 3);
    }

    function test_expire_already_signed_reverts() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 1, block.number + 10);
        reg.addSignature(WP_1, SIG_A);
        vm.stopPrank();
        reg.signWorkpaper(WP_1);
        vm.roll(block.number + 100);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotPending.selector, WP_1));
        reg.expireWorkpaper(WP_1);
    }

    function test_expire_permissionless() public {
        vm.prank(recorder);
        uint256 deadline = block.number + 10;
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, deadline);
        vm.roll(deadline + 1);
        vm.prank(nobody);
        reg.expireWorkpaper(WP_1);
        assertEq(reg.getWorkpaper(WP_1).state, 3);
    }

    // ── Indices ─────────────────────────────────────────────────────

    function test_byScope_appends() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        reg.draftWorkpaper(WP_2, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        vm.stopPrank();
        assertEq(reg.byScope(SCOPE_BCA).length, 2);
        assertEq(reg.countByScope(SCOPE_BCA), 2);
    }

    function test_allWorkpapers_grows() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        reg.draftWorkpaper(WP_2, PO_1, ROOT, CID, SCOPE_BCA, 2, block.number + 1000);
        vm.stopPrank();
        assertEq(reg.allWorkpapers().length, 2);
        assertEq(reg.workpaperCount(), 2);
    }
}
