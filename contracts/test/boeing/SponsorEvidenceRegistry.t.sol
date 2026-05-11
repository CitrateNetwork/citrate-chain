// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {SponsorEvidenceRegistry} from "../../src/boeing/SponsorEvidenceRegistry.sol";

contract SponsorEvidenceRegistryTest is Test {
    SponsorEvidenceRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant B_1 = keccak256("bundle-1");
    bytes32 internal constant B_2 = keccak256("bundle-2");
    bytes32 internal constant ROOT = keccak256("merkle-root");
    bytes32 internal constant CID = keccak256("ipfs-cid");
    bytes32 internal constant SPONSOR_A = keccak256("sponsor-A");
    bytes32 internal constant SPONSOR_B = keccak256("sponsor-B");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new SponsorEvidenceRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(SponsorEvidenceRegistry.ZeroGovernance.selector);
        new SponsorEvidenceRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.NotGovernance.selector, nobody)
        );
        reg.setRecorder(nobody, true);
    }

    // ── Anchor validation ──────────────────────────────────────────

    function test_anchor_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.NotRecorder.selector, nobody)
        );
        reg.anchor(B_1, ROOT, CID, 0);
    }

    function test_anchor_rejects_zero_bundle_id() public {
        vm.prank(recorder);
        vm.expectRevert(SponsorEvidenceRegistry.ZeroBundleId.selector);
        reg.anchor(bytes32(0), ROOT, CID, 0);
    }

    function test_anchor_rejects_invalid_kind() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.InvalidSponsorKind.selector, 4)
        );
        reg.anchor(B_1, ROOT, CID, 4);
    }

    function test_anchor_accepts_all_valid_kinds() public {
        bytes32[4] memory ids = [
            keccak256("b-dod"),
            keccak256("b-afwerx"),
            keccak256("b-pmo"),
            keccak256("b-other")
        ];
        for (uint8 k = 0; k < 4; k++) {
            vm.prank(recorder);
            reg.anchor(ids[k], ROOT, CID, k);
        }
        assertEq(reg.bundleCount(), 4);
    }

    function test_anchor_records_full_struct() public {
        vm.roll(98765);
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 1); // AFWERX/SOFWERX
        SponsorEvidenceRegistry.EvidenceBundle memory b = reg.getBundle(B_1);
        assertEq(b.bundle_id, B_1);
        assertEq(b.merkle_root, ROOT);
        assertEq(b.ipfs_cid, CID);
        assertEq(b.sponsor_kind, 1);
        assertEq(b.anchored_at_block, 98765);
        assertEq(b.anchored_by, bytes32(uint256(uint160(recorder))));
        assertEq(b.sponsor_sig_count, 0);
    }

    function test_anchor_rejects_duplicate_id() public {
        vm.startPrank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.BundleAlreadyExists.selector, B_1)
        );
        reg.anchor(B_1, ROOT, CID, 1);
        vm.stopPrank();
    }

    function test_anchor_emits_event() public {
        vm.expectEmit(true, false, true, true);
        emit SponsorEvidenceRegistry.Anchored(B_1, ROOT, CID, 1);
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 1);
    }

    // ── Sponsor signatures ─────────────────────────────────────────

    function test_addSponsorSignature_rejects_unknown_bundle() public {
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.UnknownBundle.selector, B_1)
        );
        reg.addSponsorSignature(B_1, SPONSOR_A);
    }

    function test_addSponsorSignature_increments_count() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        reg.addSponsorSignature(B_1, SPONSOR_A);
        assertEq(reg.getBundle(B_1).sponsor_sig_count, 1);
        assertTrue(reg.sponsorHasSigned(B_1, SPONSOR_A));
    }

    function test_addSponsorSignature_rejects_duplicate() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        reg.addSponsorSignature(B_1, SPONSOR_A);
        vm.expectRevert(
            abi.encodeWithSelector(
                SponsorEvidenceRegistry.DuplicateSponsor.selector,
                B_1,
                SPONSOR_A
            )
        );
        reg.addSponsorSignature(B_1, SPONSOR_A);
    }

    function test_addSponsorSignature_multiple_distinct() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        reg.addSponsorSignature(B_1, SPONSOR_A);
        reg.addSponsorSignature(B_1, SPONSOR_B);
        assertEq(reg.getBundle(B_1).sponsor_sig_count, 2);
        bytes32[] memory signers = reg.signersOf(B_1);
        assertEq(signers.length, 2);
        assertEq(signers[0], SPONSOR_A);
        assertEq(signers[1], SPONSOR_B);
    }

    function test_addSponsorSignature_is_permissionless() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        // nobody can submit a sponsor signature (verification is off-chain).
        vm.prank(nobody);
        reg.addSponsorSignature(B_1, SPONSOR_A);
        assertEq(reg.getBundle(B_1).sponsor_sig_count, 1);
    }

    function test_addSponsorSignature_emits_event() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        vm.expectEmit(true, true, false, true);
        emit SponsorEvidenceRegistry.SponsorSigned(B_1, SPONSOR_A, 1);
        reg.addSponsorSignature(B_1, SPONSOR_A);
    }

    // ── Indices ─────────────────────────────────────────────────────

    function test_byKind_groups() public {
        bytes32 b_a = keccak256("b-a");
        bytes32 b_b = keccak256("b-b");
        bytes32 b_c = keccak256("b-c");
        vm.startPrank(recorder);
        reg.anchor(b_a, ROOT, CID, 0); // DOD
        reg.anchor(b_b, ROOT, CID, 0); // DOD
        reg.anchor(b_c, ROOT, CID, 2); // PMO
        vm.stopPrank();
        assertEq(reg.countByKind(0), 2);
        assertEq(reg.countByKind(2), 1);
        assertEq(reg.countByKind(1), 0);
    }

    function test_allBundles_in_insertion_order() public {
        vm.startPrank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        reg.anchor(B_2, ROOT, CID, 0);
        vm.stopPrank();
        bytes32[] memory all = reg.allBundles();
        assertEq(all.length, 2);
        assertEq(all[0], B_1);
        assertEq(all[1], B_2);
        assertEq(reg.bundleCount(), 2);
    }

    function test_revoked_recorder_cannot_anchor() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.NotRecorder.selector, recorder)
        );
        reg.anchor(B_1, ROOT, CID, 0);
    }

    function test_signersOf_empty_for_unsigned_bundle() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 0);
        assertEq(reg.signersOf(B_1).length, 0);
    }

    function test_max_kind_three_accepted() public {
        vm.prank(recorder);
        reg.anchor(B_1, ROOT, CID, 3); // Other
        assertEq(reg.getBundle(B_1).sponsor_kind, 3);
    }

    function test_kind_255_rejected() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.InvalidSponsorKind.selector, 255)
        );
        reg.anchor(B_1, ROOT, CID, 255);
    }
}
