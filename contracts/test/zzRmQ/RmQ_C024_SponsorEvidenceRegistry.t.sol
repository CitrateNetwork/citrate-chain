// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {SponsorEvidenceRegistry} from "../../src/boeing/SponsorEvidenceRegistry.sol";

/// @title RM-Q · CHAIN-B-C024 — permissionless addSponsorSignature
/// @notice RED→GREEN tripwire. Before the fix, `addSponsorSignature` was
///         fully permissionless: any anonymous account could fabricate a
///         federal-sponsor countersignature (e.g. keccak256("DOD")) on an
///         evidence bundle they never saw, and grow the signer array
///         without bound. After the fix it is recorder-gated.
contract RmQ_C024 is Test {
    SponsorEvidenceRegistry internal reg;
    address internal governance = address(0x6024);
    address internal recorder = address(0x8EC);
    address internal attacker = address(0xBAD);

    bytes32 internal constant BUNDLE = keccak256("evidence-bundle");
    bytes32 internal constant FAKE_DOD = keccak256("DOD");

    function setUp() public {
        reg = new SponsorEvidenceRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
        vm.prank(recorder);
        reg.anchor(BUNDLE, keccak256("root"), keccak256("cid"), 0);
    }

    /// RED: an anonymous account fabricates a sponsor countersignature.
    /// Pre-fix this SUCCEEDED and `signersOf` then showed a federal
    /// sponsor as having countersigned; post-fix it reverts NotRecorder.
    function test_C024_anon_cannot_forge_sponsor_signature() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(SponsorEvidenceRegistry.NotRecorder.selector, attacker)
        );
        reg.addSponsorSignature(BUNDLE, FAKE_DOD);
        // GREEN: no fabricated signer recorded.
        assertEq(reg.getBundle(BUNDLE).sponsor_sig_count, 0);
        assertFalse(reg.sponsorHasSigned(BUNDLE, FAKE_DOD));
    }

    /// The authorized recorder anchors a (off-chain-verified) sponsor sig.
    function test_C024_recorder_can_countersign() public {
        vm.prank(recorder);
        reg.addSponsorSignature(BUNDLE, FAKE_DOD);
        assertEq(reg.getBundle(BUNDLE).sponsor_sig_count, 1);
    }
}
