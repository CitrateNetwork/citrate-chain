// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {CrossOrgEnvelope} from "../../src/defense_prime/CrossOrgEnvelope.sol";

contract CrossOrgEnvelopeTest is Test {
    CrossOrgEnvelope internal env;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant ENV_1 = keccak256("env-1");
    bytes32 internal constant ART_ROOT = keccak256("artifact-root");
    bytes32 internal constant ART_CID = keccak256("ipfs-cid");
    bytes32 internal constant SCOPE = keccak256("scope-unit");
    bytes32 internal constant DEFENSE_PRIME = keccak256("defense_prime-root");
    bytes32 internal constant TIER1 = keccak256("tier1-root");
    bytes32 internal constant DOD = keccak256("dod-root");

    bytes32 internal constant SIG_B1 = keccak256("defense_prime-co");
    bytes32 internal constant SIG_B2 = keccak256("defense_prime-pm");
    bytes32 internal constant SIG_T1 = keccak256("tier1-sales");
    bytes32 internal constant SIG_T2 = keccak256("tier1-pm");
    bytes32 internal constant SIG_D1 = keccak256("dod-pm");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        env = new CrossOrgEnvelope(governance);
        vm.startPrank(governance);
        env.setRecorder(recorder, true);
        // CHAIN-B-C026 (a) RC-8: sign() is now per-org gated. Register the
        // shared test recorder for each org root used across these
        // fixtures so the existing single-recorder flows still exercise
        // the guarded path; cross-org forging is covered in the RmQ suite.
        env.setOrgRecorder(DEFENSE_PRIME, recorder, true);
        env.setOrgRecorder(TIER1, recorder, true);
        env.setOrgRecorder(DOD, recorder, true);
        vm.stopPrank();
    }

    function _draft_2org_2of2() internal {
        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = DEFENSE_PRIME;
        orgs[1] = TIER1;
        uint8[] memory ths = new uint8[](2);
        ths[0] = 2;
        ths[1] = 2;
        bytes32[][] memory signers = new bytes32[][](2);
        signers[0] = new bytes32[](2);
        signers[0][0] = SIG_B1;
        signers[0][1] = SIG_B2;
        signers[1] = new bytes32[](2);
        signers[1][0] = SIG_T1;
        signers[1][1] = SIG_T2;
        vm.prank(recorder);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
    }

    // ── Constructor / governance ────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(CrossOrgEnvelope.ZeroGovernance.selector);
        new CrossOrgEnvelope(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotGovernance.selector, nobody)
        );
        env.setRecorder(nobody, true);
    }

    // ── Draft validation ────────────────────────────────────────────

    function test_draft_only_recorder() public {
        bytes32[] memory orgs = new bytes32[](1);
        orgs[0] = DEFENSE_PRIME;
        uint8[] memory ths = new uint8[](1);
        ths[0] = 1;
        bytes32[][] memory signers = new bytes32[][](1);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotRecorder.selector, nobody)
        );
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
    }

    function test_draft_rejects_empty_orgs() public {
        bytes32[] memory orgs = new bytes32[](0);
        uint8[] memory ths = new uint8[](0);
        bytes32[][] memory signers = new bytes32[][](0);
        vm.prank(recorder);
        vm.expectRevert(CrossOrgEnvelope.EmptyOrgRoots.selector);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
    }

    function test_draft_rejects_length_mismatch() public {
        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = DEFENSE_PRIME;
        orgs[1] = TIER1;
        uint8[] memory ths = new uint8[](1); // wrong length
        ths[0] = 1;
        bytes32[][] memory signers = new bytes32[][](2);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        signers[1] = new bytes32[](1);
        signers[1][0] = SIG_T1;
        vm.prank(recorder);
        vm.expectRevert(CrossOrgEnvelope.MismatchedThresholdLength.selector);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
    }

    function test_draft_rejects_zero_threshold() public {
        bytes32[] memory orgs = new bytes32[](1);
        orgs[0] = DEFENSE_PRIME;
        uint8[] memory ths = new uint8[](1);
        ths[0] = 0; // zero
        bytes32[][] memory signers = new bytes32[][](1);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        vm.prank(recorder);
        vm.expectRevert(CrossOrgEnvelope.ZeroThreshold.selector);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
    }

    function test_draft_creates_envelope_in_drafted_state() public {
        _draft_2org_2of2();
        CrossOrgEnvelope.CrossOrgEnvelopeRecord memory e = env.getEnvelope(ENV_1);
        assertEq(e.state, 1);
        assertEq(env.orgRoots(ENV_1).length, 2);
        assertEq(env.requiredSigners(ENV_1, DEFENSE_PRIME).length, 2);
    }

    function test_draft_rejects_duplicate() public {
        _draft_2org_2of2();
        bytes32[] memory orgs = new bytes32[](1);
        orgs[0] = DEFENSE_PRIME;
        uint8[] memory ths = new uint8[](1);
        ths[0] = 1;
        bytes32[][] memory signers = new bytes32[][](1);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgEnvelope.AlreadyDrafted.selector, ENV_1));
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
    }

    // ── Signature flow ─────────────────────────────────────────────

    function test_first_signature_transitions_drafted_to_signing() public {
        _draft_2org_2of2();
        vm.prank(recorder);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        assertEq(env.getEnvelope(ENV_1).state, 2);
        assertEq(env.signedCountOf(ENV_1, DEFENSE_PRIME), 1);
    }

    function test_sign_rejects_non_required_signer() public {
        _draft_2org_2of2();
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossOrgEnvelope.NotRequiredSigner.selector,
                ENV_1,
                DEFENSE_PRIME,
                SIG_T1
            )
        );
        env.sign(ENV_1, DEFENSE_PRIME, SIG_T1);
    }

    function test_sign_rejects_unknown_org() public {
        _draft_2org_2of2();
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.UnknownOrg.selector, ENV_1, DOD)
        );
        env.sign(ENV_1, DOD, SIG_D1);
    }

    function test_sign_rejects_duplicate_signer() public {
        _draft_2org_2of2();
        vm.startPrank(recorder);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.AlreadySigned.selector, ENV_1, SIG_B1)
        );
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        vm.stopPrank();
    }

    function test_all_orgs_met_transitions_to_signed() public {
        _draft_2org_2of2();
        vm.startPrank(recorder);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B2);
        // DefensePrime threshold met, Tier-1 not yet; state stays Signing.
        assertEq(env.getEnvelope(ENV_1).state, 2);
        assertTrue(env.isOrgThresholdMet(ENV_1, DEFENSE_PRIME));
        assertFalse(env.isAllOrgsMet(ENV_1));

        env.sign(ENV_1, TIER1, SIG_T1);
        env.sign(ENV_1, TIER1, SIG_T2);
        vm.stopPrank();
        // Both orgs met → Signed.
        assertEq(env.getEnvelope(ENV_1).state, 3);
        assertTrue(env.isAllOrgsMet(ENV_1));
    }

    function test_sign_after_expiry_reverts() public {
        bytes32[] memory orgs = new bytes32[](1);
        orgs[0] = DEFENSE_PRIME;
        uint8[] memory ths = new uint8[](1);
        ths[0] = 1;
        bytes32[][] memory signers = new bytes32[][](1);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        uint256 deadline = block.number + 5;
        vm.prank(recorder);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, deadline, SCOPE, 0);
        vm.roll(deadline + 1);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.Expired.selector, deadline, deadline + 1)
        );
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
    }

    // ── Lifecycle progression ──────────────────────────────────────

    function _all_signed() internal {
        _draft_2org_2of2();
        vm.startPrank(recorder);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B2);
        env.sign(ENV_1, TIER1, SIG_T1);
        env.sign(ENV_1, TIER1, SIG_T2);
        vm.stopPrank();
    }

    function test_markDelivered_only_from_signed() public {
        _draft_2org_2of2();
        // From Drafted: rejected.
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotInState.selector, ENV_1, 3, 1)
        );
        env.markDelivered(ENV_1);
    }

    function test_full_happy_path() public {
        _all_signed();
        // CHAIN-B-C026 (b) RC-8: the delivery/accept/close transitions are
        // now recorder-gated (previously permissionless).
        vm.startPrank(recorder);
        env.markDelivered(ENV_1);
        assertEq(env.getEnvelope(ENV_1).state, 4);
        env.accept(ENV_1);
        assertEq(env.getEnvelope(ENV_1).state, 5);
        env.close(ENV_1);
        assertEq(env.getEnvelope(ENV_1).state, 7);
        vm.stopPrank();
    }

    function test_accept_only_from_delivered() public {
        _all_signed();
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotInState.selector, ENV_1, 4, 3)
        );
        env.accept(ENV_1);
    }

    function test_close_only_from_accepted() public {
        _all_signed();
        vm.prank(recorder);
        env.markDelivered(ENV_1);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotInState.selector, ENV_1, 5, 4)
        );
        env.close(ENV_1);
    }

    // ── Reject flow ────────────────────────────────────────────────

    function test_reject_from_drafted_is_terminal() public {
        _draft_2org_2of2();
        vm.prank(recorder);
        env.reject(ENV_1, DEFENSE_PRIME, "missing-evidence");
        assertEq(env.getEnvelope(ENV_1).state, 6);
        assertEq(env.getEnvelope(ENV_1).rejected_by_org, DEFENSE_PRIME);
    }

    function test_reject_from_signed_is_terminal() public {
        _all_signed();
        vm.prank(recorder);
        env.reject(ENV_1, TIER1, "withdrawing");
        assertEq(env.getEnvelope(ENV_1).state, 6);
    }

    function test_cannot_sign_after_reject() public {
        _draft_2org_2of2();
        vm.startPrank(recorder);
        env.reject(ENV_1, DEFENSE_PRIME, "x");
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotInState.selector, ENV_1, 1, 6)
        );
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        vm.stopPrank();
    }

    function test_cannot_reject_terminal() public {
        _all_signed();
        vm.startPrank(recorder);
        env.markDelivered(ENV_1);
        env.accept(ENV_1);
        env.close(ENV_1);
        vm.stopPrank();
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotInState.selector, ENV_1, 1, 7)
        );
        env.reject(ENV_1, DEFENSE_PRIME, "too-late");
    }

    function test_reject_only_recorder() public {
        _draft_2org_2of2();
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotRecorder.selector, nobody)
        );
        env.reject(ENV_1, DEFENSE_PRIME, "x");
    }

    function test_reject_unknown_org_reverts() public {
        _draft_2org_2of2();
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.UnknownOrg.selector, ENV_1, DOD)
        );
        env.reject(ENV_1, DOD, "x");
    }

    // ── Indices ─────────────────────────────────────────────────────

    function test_byScope_appends() public {
        _draft_2org_2of2();
        bytes32 env2 = keccak256("env-2");
        bytes32[] memory orgs = new bytes32[](1);
        orgs[0] = DEFENSE_PRIME;
        uint8[] memory ths = new uint8[](1);
        ths[0] = 1;
        bytes32[][] memory signers = new bytes32[][](1);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        vm.prank(recorder);
        env.draft(env2, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);

        assertEq(env.byScope(SCOPE).length, 2);
        assertEq(env.envelopeCount(), 2);
    }

    function test_3org_chain() public {
        // DefensePrime → Tier1 → DOD: 1/1/1 thresholds.
        bytes32[] memory orgs = new bytes32[](3);
        orgs[0] = DEFENSE_PRIME;
        orgs[1] = TIER1;
        orgs[2] = DOD;
        uint8[] memory ths = new uint8[](3);
        ths[0] = 1;
        ths[1] = 1;
        ths[2] = 1;
        bytes32[][] memory signers = new bytes32[][](3);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        signers[1] = new bytes32[](1);
        signers[1][0] = SIG_T1;
        signers[2] = new bytes32[](1);
        signers[2][0] = SIG_D1;
        vm.startPrank(recorder);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 0);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        env.sign(ENV_1, TIER1, SIG_T1);
        env.sign(ENV_1, DOD, SIG_D1);
        vm.stopPrank();
        assertEq(env.getEnvelope(ENV_1).state, 3); // Signed
    }

    // ── Classification-boundary gating (DPF-14b close) ──────────────

    function test_classification_gate_disabled_by_default() public {
        // No oracle wired → max_class=2 (CUI) should still draft even
        // though no clearance records exist (gate inactive).
        _draft_2org_2of2();
        assertEq(env.getEnvelope(ENV_1).state, 1);
        assertEq(env.artifactClassOf(ENV_1), 0);
    }

    function test_classification_gate_allows_when_signers_clear() public {
        MockClearance oracle = new MockClearance();
        oracle.set(SIG_B1, 2);
        oracle.set(SIG_B2, 2);
        oracle.set(SIG_T1, 2);
        oracle.set(SIG_T2, 2);
        vm.prank(governance);
        env.setClassificationOracle(address(oracle));

        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = DEFENSE_PRIME;
        orgs[1] = TIER1;
        uint8[] memory ths = new uint8[](2);
        ths[0] = 2;
        ths[1] = 2;
        bytes32[][] memory signers = new bytes32[][](2);
        signers[0] = new bytes32[](2);
        signers[0][0] = SIG_B1;
        signers[0][1] = SIG_B2;
        signers[1] = new bytes32[](2);
        signers[1][0] = SIG_T1;
        signers[1][1] = SIG_T2;
        vm.prank(recorder);
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 2);
        assertEq(env.getEnvelope(ENV_1).state, 1);
        assertEq(env.artifactClassOf(ENV_1), 2);
    }

    function test_classification_gate_rejects_under_cleared_signer() public {
        MockClearance oracle = new MockClearance();
        oracle.set(SIG_B1, 3);
        oracle.set(SIG_B2, 2);
        oracle.set(SIG_T1, 2);
        oracle.set(SIG_T2, 1); // under-cleared
        vm.prank(governance);
        env.setClassificationOracle(address(oracle));

        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = DEFENSE_PRIME;
        orgs[1] = TIER1;
        uint8[] memory ths = new uint8[](2);
        ths[0] = 2;
        ths[1] = 2;
        bytes32[][] memory signers = new bytes32[][](2);
        signers[0] = new bytes32[](2);
        signers[0][0] = SIG_B1;
        signers[0][1] = SIG_B2;
        signers[1] = new bytes32[](2);
        signers[1][0] = SIG_T1;
        signers[1][1] = SIG_T2;
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossOrgEnvelope.InsufficientClearance.selector,
                SIG_T2,
                uint8(2),
                uint8(1)
            )
        );
        env.draft(ENV_1, ART_ROOT, ART_CID, orgs, ths, signers, 0, SCOPE, 2);
    }

    function test_classification_gate_skipped_when_max_class_zero() public {
        // Oracle wired but artifact_max_class=0 → gate inactive, even
        // for signers with no clearance record.
        MockClearance oracle = new MockClearance();
        vm.prank(governance);
        env.setClassificationOracle(address(oracle));
        _draft_2org_2of2(); // passes 0 for max_class
        assertEq(env.getEnvelope(ENV_1).state, 1);
    }

    function test_setClassificationOracle_governance_only() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotGovernance.selector, nobody)
        );
        env.setClassificationOracle(address(0xdeadbeef));
    }
}

/// @notice Minimal IClassificationOracle test fixture. Returns the
///         ordinal that `set()` recorded for the queried user; 0 for
///         unset users (mirrors the production registry's default).
contract MockClearance {
    mapping(bytes32 => uint8) private _ord;
    function set(bytes32 user, uint8 ord) external {
        _ord[user] = ord;
    }
    function clearanceOrdinal(bytes32 user) external view returns (uint8) {
        return _ord[user];
    }
}
