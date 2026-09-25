// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TinaWorkpaperRegistry} from "../../src/defense_prime/TinaWorkpaperRegistry.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";

contract TinaWorkpaperRegistryTest is Test {
    TinaWorkpaperRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant WP_1 = keccak256("wp-1");
    bytes32 internal constant WP_2 = keccak256("wp-2");
    bytes32 internal constant PO_1 = keccak256("po-1");
    bytes32 internal constant SCOPE_UNIT = keccak256("scope-unit");
    bytes32 internal constant ROOT = keccak256("merkle-root");
    bytes32 internal constant CID = keccak256("ipfs-cid");
    // PBA-L2-014: signer identities are the subject keys of real addresses,
    // and each signer signs for itself.
    address internal constant A = address(0x5A);
    address internal constant B = address(0x5B);
    address internal constant C = address(0x5C);
    bytes32 internal SIG_A;
    bytes32 internal SIG_B;
    bytes32 internal SIG_C;
    bytes32[] internal REQ;
    mapping(bytes32 => address) internal _addr;

    function setUp() public {
        SIG_A = QuorumIdentity.subjectKey(A);
        SIG_B = QuorumIdentity.subjectKey(B);
        SIG_C = QuorumIdentity.subjectKey(C);
        _addr[SIG_A] = A;
        _addr[SIG_B] = B;
        _addr[SIG_C] = C;
        REQ = new bytes32[](3);
        REQ[0] = SIG_A;
        REQ[1] = SIG_B;
        REQ[2] = SIG_C;
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new TinaWorkpaperRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    function _sign(bytes32 wp, bytes32 sig) internal {
        // PBA-L2-014: signers sign for themselves (not the recorder).
        vm.prank(_addr[sig]);
        reg.addSignature(wp, sig);
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
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
    }

    function test_draft_rejects_zero_threshold() public {
        vm.prank(recorder);
        vm.expectRevert(TinaWorkpaperRegistry.ZeroThreshold.selector);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 0, block.number + 1000, REQ);
    }

    function test_draft_rejects_zero_po_hash() public {
        vm.prank(recorder);
        vm.expectRevert(TinaWorkpaperRegistry.ZeroPoHash.selector);
        reg.draftWorkpaper(WP_1, bytes32(0), ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
    }

    function test_draft_creates_pending_workpaper() public {
        vm.prank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        TinaWorkpaperRegistry.Workpaper memory w = reg.getWorkpaper(WP_1);
        assertEq(w.state, 1);
        assertEq(w.threshold, 2);
        assertEq(w.sig_count, 0);
        assertEq(w.po_hash, PO_1);
        assertEq(w.scope, SCOPE_UNIT);
    }

    function test_draft_rejects_duplicate() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.AlreadyDrafted.selector, WP_1)
        );
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 3, block.number + 2000, REQ);
        vm.stopPrank();
    }

    // ── Signature flow ─────────────────────────────────────────────

    function test_addSignature_increments_count() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        assertEq(reg.getWorkpaper(WP_1).sig_count, 1);
        assertTrue(reg.hasSigned(WP_1, SIG_A));
    }

    function test_addSignature_rejects_duplicate_signer() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.AlreadySigned.selector, WP_1, SIG_A)
        );
        _sign(WP_1, SIG_A);
    }

    function test_addSignature_rejects_when_not_pending() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 1, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        reg.signWorkpaper(WP_1);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotPending.selector, WP_1));
        _sign(WP_1, SIG_B);
    }

    function test_signersList_records_order() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 3, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        _sign(WP_1, SIG_B);
        _sign(WP_1, SIG_C);
        bytes32[] memory list = reg.signersList(WP_1);
        assertEq(list.length, 3);
        assertEq(list[0], SIG_A);
        assertEq(list[1], SIG_B);
        assertEq(list[2], SIG_C);
    }

    // ── Sign flow ──────────────────────────────────────────────────

    function test_sign_threshold_not_met_reverts() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.ThresholdNotMet.selector, 1, 2)
        );
        reg.signWorkpaper(WP_1);
    }

    function test_sign_threshold_met_transitions_to_signed() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        _sign(WP_1, SIG_B);
        vm.roll(block.number + 5);
        reg.signWorkpaper(WP_1);
        TinaWorkpaperRegistry.Workpaper memory w = reg.getWorkpaper(WP_1);
        assertEq(w.state, 2);
        assertEq(w.signed_at_block, block.number);
    }

    function test_sign_idempotent_revert() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 1, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        reg.signWorkpaper(WP_1);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotPending.selector, WP_1));
        reg.signWorkpaper(WP_1);
    }

    function test_sign_permissionless() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 1, block.number + 1000, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        // nobody calls signWorkpaper → succeeds.
        vm.prank(nobody);
        reg.signWorkpaper(WP_1);
        assertEq(reg.getWorkpaper(WP_1).state, 2);
    }

    // ── Expire flow ────────────────────────────────────────────────

    function test_expire_before_deadline_reverts() public {
        vm.prank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
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
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, deadline, REQ);
        vm.roll(deadline + 1);
        reg.expireWorkpaper(WP_1);
        assertEq(reg.getWorkpaper(WP_1).state, 3);
    }

    function test_expire_already_signed_reverts() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 1, block.number + 10, REQ);
        vm.stopPrank();
        _sign(WP_1, SIG_A);
        reg.signWorkpaper(WP_1);
        vm.roll(block.number + 100);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotPending.selector, WP_1));
        reg.expireWorkpaper(WP_1);
    }

    function test_expire_permissionless() public {
        vm.prank(recorder);
        uint256 deadline = block.number + 10;
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, deadline, REQ);
        vm.roll(deadline + 1);
        vm.prank(nobody);
        reg.expireWorkpaper(WP_1);
        assertEq(reg.getWorkpaper(WP_1).state, 3);
    }

    // ── Indices ─────────────────────────────────────────────────────

    function test_byScope_appends() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        reg.draftWorkpaper(WP_2, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.stopPrank();
        assertEq(reg.byScope(SCOPE_UNIT).length, 2);
        assertEq(reg.countByScope(SCOPE_UNIT), 2);
    }

    function test_allWorkpapers_grows() public {
        vm.startPrank(recorder);
        reg.draftWorkpaper(WP_1, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        reg.draftWorkpaper(WP_2, PO_1, ROOT, CID, SCOPE_UNIT, 2, block.number + 1000, REQ);
        vm.stopPrank();
        assertEq(reg.allWorkpapers().length, 2);
        assertEq(reg.workpaperCount(), 2);
    }
}
