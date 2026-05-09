// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";

/// @title MultiSigEnvelope.t — BFR-02-WP5 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/MultiSigEnvelopeFlow.tla`.
///      ≥50 tests covering every cited invariant + state machine
///      + 5 fuzz targets.
contract MultiSigEnvelopeTest is Test {
    MultiSigEnvelope internal env;

    bytes32 constant ID = keccak256("envelope-1");
    bytes32 constant ID2 = keccak256("envelope-2");
    bytes32 constant CORR = keccak256("corr-1");
    bytes32 constant INITIATOR = keccak256("user-init");
    bytes32 constant ART_ROOT = keccak256("artifact-root");
    bytes32 constant SIGNER_A = keccak256("signer-a");
    bytes32 constant SIGNER_B = keccak256("signer-b");
    bytes32 constant SIGNER_C = keccak256("signer-c");
    bytes32 constant SIGNER_D = keccak256("signer-d");
    bytes32 constant STRANGER = keccak256("stranger");

    function setUp() public {
        env = new MultiSigEnvelope();
    }

    // ── draft happy path ───────────────────────────────────────────

    function test_draft_setsDraftedState() public {
        _draft3of3(ID, 0);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Drafted));
    }

    function test_draft_storesAllFields() public {
        _draft3of3(ID, 0);
        MultiSigEnvelope.Envelope memory e = env.getEnvelope(ID);
        assertEq(e.envelope_id, ID);
        assertEq(e.initiator, INITIATOR);
        assertEq(e.artifact_root, ART_ROOT);
        assertEq(e.artifact_cid, "ipfs://Qm...");
        assertEq(e.threshold, 3);
        assertEq(e.required_signers.length, 3);
        assertEq(e.corr_id, CORR);
    }

    function test_draft_emitsEnvelopeDrafted() public {
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B; signers[2] = SIGNER_C;
        vm.expectEmit(true, true, true, true);
        emit MultiSigEnvelope.EnvelopeDrafted(ID, INITIATOR, CORR, 3, 0);
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 3, 0, CORR);
    }

    function test_draft_emitsStateChange() public {
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B; signers[2] = SIGNER_C;
        vm.expectEmit(true, false, false, true);
        emit MultiSigEnvelope.EnvelopeStateChanged(
            ID,
            MultiSigEnvelope.EnvelopeState.NotExist,
            MultiSigEnvelope.EnvelopeState.Drafted
        );
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 3, 0, CORR);
    }

    function test_draft_independentEnvelopes() public {
        _draft3of3(ID, 0);
        _draft3of3(ID2, 0);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Drafted));
        assertEq(uint8(env.getState(ID2)), uint8(MultiSigEnvelope.EnvelopeState.Drafted));
    }

    // ── draft revert paths ─────────────────────────────────────────

    function test_draft_revertsOnDuplicate() public {
        _draft3of3(ID, 0);
        bytes32[] memory signers = new bytes32[](1);
        signers[0] = SIGNER_A;
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.AlreadyExists.selector, ID)
        );
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 1, 0, CORR);
    }

    function test_draft_revertsOnEmptySigners() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(MultiSigEnvelope.EmptyRequiredSigners.selector);
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", empty, 1, 0, CORR);
    }

    function test_draft_revertsOnZeroThreshold() public {
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B;
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidThreshold.selector, 0, 2
            )
        );
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 0, 0, CORR);
    }

    function test_draft_revertsOnExcessThreshold() public {
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B;
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidThreshold.selector, 3, 2
            )
        );
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 3, 0, CORR);
    }

    function test_draft_revertsOnEmptyArtifactCid() public {
        bytes32[] memory signers = new bytes32[](1);
        signers[0] = SIGNER_A;
        vm.expectRevert(MultiSigEnvelope.EmptyArtifactCid.selector);
        env.draft(ID, INITIATOR, ART_ROOT, "", signers, 1, 0, CORR);
    }

    function test_draft_revertsOnPastExpiry() public {
        vm.warp(1000);
        bytes32[] memory signers = new bytes32[](1);
        signers[0] = SIGNER_A;
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.PastExpiry.selector, uint64(500), uint64(1000)
            )
        );
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 1, 500, CORR);
    }

    function test_draft_zeroExpiryAllowed() public {
        bytes32[] memory signers = new bytes32[](1);
        signers[0] = SIGNER_A;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 1, 0, CORR);
        assertEq(env.getEnvelope(ID).expires_at, 0);
    }

    // ── sign happy path ────────────────────────────────────────────

    function test_sign_firstSignerTransitionsToSigning() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signing));
    }

    function test_sign_emitsEnvelopeSigned() public {
        _draft3of3(ID, 0);
        vm.expectEmit(true, true, false, true);
        emit MultiSigEnvelope.EnvelopeSigned(ID, SIGNER_A, "kba");
        env.sign(ID, SIGNER_A, "sigA", "kba");
    }

    function test_sign_storesSignatureBytes() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "specific-bytes", "kba");
        assertEq(env.signatureOf(ID, SIGNER_A), bytes("specific-bytes"));
    }

    function test_sign_signedCountIncrements() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        env.sign(ID, SIGNER_B, "sigB", "kba");
        assertEq(env.signedCount(ID), 2);
    }

    function test_sign_thresholdMetMovesToSigned() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        env.sign(ID, SIGNER_B, "sigB", "kba");
        env.sign(ID, SIGNER_C, "sigC", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
        assertTrue(env.isSignedThresholdMet(ID));
    }

    function test_sign_signedAtRecorded() public {
        vm.warp(5000);
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        env.sign(ID, SIGNER_B, "sigB", "kba");
        env.sign(ID, SIGNER_C, "sigC", "kba");
        assertEq(env.getEnvelope(ID).signed_at, 5000);
    }

    function test_sign_2of3Configuration() public {
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B; signers[2] = SIGNER_C;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 2, 0, CORR);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        env.sign(ID, SIGNER_B, "sigB", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
    }

    // ── sign revert paths ──────────────────────────────────────────

    function test_sign_revertsOnNonExistent() public {
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.DoesNotExist.selector, ID)
        );
        env.sign(ID, SIGNER_A, "sigA", "kba");
    }

    /// @dev Cites `SignersUnique` invariant.
    function test_SignersUnique_revertsOnDoubleSign() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.AlreadySigned.selector, SIGNER_A)
        );
        env.sign(ID, SIGNER_A, "sigA-again", "kba");
    }

    function test_sign_revertsOnNonRequiredSigner() public {
        _draft3of3(ID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.NotRequiredSigner.selector, STRANGER
            )
        );
        env.sign(ID, STRANGER, "sigStranger", "kba");
    }

    function test_sign_revertsOnEmptyAuthMode() public {
        _draft3of3(ID, 0);
        vm.expectRevert(MultiSigEnvelope.EmptyAuthMode.selector);
        env.sign(ID, SIGNER_A, "sigA", "");
    }

    /// @dev Cites `ExpiredImpliesNoActiveSign`.
    function test_ExpiredImpliesNoActiveSign() public {
        vm.warp(1000);
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 2, 2000, CORR);
        vm.warp(2001);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.PastExpiry.selector, uint64(2000), uint64(2001)
            )
        );
        env.sign(ID, SIGNER_A, "sigA", "kba");
    }

    // ── State machine transitions ──────────────────────────────────

    function test_markDelivered_fromSigned() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Delivered));
    }

    function test_markDelivered_emitsStateChange() public {
        _draftAndFullySign(ID);
        vm.expectEmit(true, false, false, true);
        emit MultiSigEnvelope.EnvelopeStateChanged(
            ID,
            MultiSigEnvelope.EnvelopeState.Signed,
            MultiSigEnvelope.EnvelopeState.Delivered
        );
        env.markDelivered(ID);
    }

    function test_markDelivered_revertsFromDrafted() public {
        _draft3of3(ID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForDeliver.selector,
                MultiSigEnvelope.EnvelopeState.Drafted
            )
        );
        env.markDelivered(ID);
    }

    function test_markDelivered_revertsFromSigning() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForDeliver.selector,
                MultiSigEnvelope.EnvelopeState.Signing
            )
        );
        env.markDelivered(ID);
    }

    function test_accept_fromDelivered() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        env.accept(ID);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Accepted));
    }

    function test_accept_emitsAccepted() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        vm.expectEmit(true, true, false, true);
        emit MultiSigEnvelope.EnvelopeAccepted(ID, CORR);
        env.accept(ID);
    }

    function test_accept_revertsFromSigning() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForAcceptReject.selector,
                MultiSigEnvelope.EnvelopeState.Signing
            )
        );
        env.accept(ID);
    }

    function test_reject_fromDelivered() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        env.reject(ID, "MOQ contradicts attested capacity");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Rejected));
    }

    function test_reject_emitsRejectedWithReason() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        vm.expectEmit(true, true, false, true);
        emit MultiSigEnvelope.EnvelopeRejected(ID, CORR, "moq mismatch");
        env.reject(ID, "moq mismatch");
    }

    function test_close_fromDrafted() public {
        _draft3of3(ID, 0);
        env.close(ID, INITIATOR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    function test_close_fromSigning() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        env.close(ID, INITIATOR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    function test_close_fromSigned() public {
        _draftAndFullySign(ID);
        env.close(ID, INITIATOR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    function test_close_revertsForNonInitiator() public {
        _draft3of3(ID, 0);
        vm.expectRevert(bytes("MultiSigEnvelope: not initiator"));
        env.close(ID, SIGNER_A);
    }

    /// @dev Cites `ClosedIsTerminal`.
    function test_ClosedIsTerminal() public {
        _draft3of3(ID, 0);
        env.close(ID, INITIATOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Closed
            )
        );
        env.close(ID, INITIATOR);
    }

    function test_close_revertsAfterAccept() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        env.accept(ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Accepted
            )
        );
        env.close(ID, INITIATOR);
    }

    function test_close_revertsAfterReject() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        env.reject(ID, "no");
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Rejected
            )
        );
        env.close(ID, INITIATOR);
    }

    function test_close_revertsAfterDelivered() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Delivered
            )
        );
        env.close(ID, INITIATOR);
    }

    /// @dev Cites `AcceptOrRejectExclusive`.
    function test_AcceptOrRejectExclusive() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        env.accept(ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForAcceptReject.selector,
                MultiSigEnvelope.EnvelopeState.Accepted
            )
        );
        env.reject(ID, "too late");
    }

    function test_acceptOnlyOnce() public {
        _draftAndFullySign(ID);
        env.markDelivered(ID);
        env.accept(ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForAcceptReject.selector,
                MultiSigEnvelope.EnvelopeState.Accepted
            )
        );
        env.accept(ID);
    }

    // ── Invariants explicit ─────────────────────────────────────────

    /// @dev Cites `SignedCountLeRequired`.
    function test_SignedCountLeRequired() public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        env.sign(ID, SIGNER_B, "sigB", "kba");
        env.sign(ID, SIGNER_C, "sigC", "kba");
        assertLe(env.signedCount(ID), env.getEnvelope(ID).required_signers.length);
    }

    /// @dev Cites `DraftedHasNoSignatures`.
    function test_DraftedHasNoSignatures() public {
        _draft3of3(ID, 0);
        assertEq(env.signedCount(ID), 0);
    }

    /// @dev Cites `ThresholdSatisfiedImpliesSignedOrLater`.
    function test_ThresholdSatisfiedImpliesSignedOrLater() public {
        bytes32[] memory signers = new bytes32[](4);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B;
        signers[2] = SIGNER_C; signers[3] = SIGNER_D;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 2, 0, CORR);
        env.sign(ID, SIGNER_A, "sigA", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signing));
        env.sign(ID, SIGNER_B, "sigB", "kba");
        // Threshold (2) reached, state must advance.
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
        // But more signatures are still allowed — wait, sign() requires
        // Drafted/Signing. After Signed, sign() must revert.
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForSign.selector,
                MultiSigEnvelope.EnvelopeState.Signed
            )
        );
        env.sign(ID, SIGNER_C, "sigC", "kba");
    }

    function test_signNotAcceptedAfterClose() public {
        _draft3of3(ID, 0);
        env.close(ID, INITIATOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForSign.selector,
                MultiSigEnvelope.EnvelopeState.Closed
            )
        );
        env.sign(ID, SIGNER_A, "sigA", "kba");
    }

    // ── Read views ─────────────────────────────────────────────────

    function test_getState_notExistByDefault() public view {
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.NotExist));
    }

    function test_getEnvelope_revertsOnNotExist() public {
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.DoesNotExist.selector, ID)
        );
        env.getEnvelope(ID);
    }

    function test_signatureOf_emptyForUnsigned() public {
        _draft3of3(ID, 0);
        assertEq(env.signatureOf(ID, SIGNER_A), bytes(""));
    }

    function test_signedCount_zeroAfterDraft() public {
        _draft3of3(ID, 0);
        assertEq(env.signedCount(ID), 0);
    }

    function test_isSignedThresholdMet_falseDraft() public {
        _draft3of3(ID, 0);
        assertFalse(env.isSignedThresholdMet(ID));
    }

    function test_isSignedThresholdMet_falseNonExistent() public view {
        assertFalse(env.isSignedThresholdMet(ID));
    }

    // ── Fuzz invariants ─────────────────────────────────────────────

    /// @dev Fuzz `SignersUnique`: any second sign() by the same signer
    ///      reverts.
    function testFuzz_SignersUnique(bytes32 sig1, bytes32 sig2) public {
        _draft3of3(ID, 0);
        env.sign(ID, SIGNER_A, abi.encodePacked(sig1), "kba");
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.AlreadySigned.selector, SIGNER_A)
        );
        env.sign(ID, SIGNER_A, abi.encodePacked(sig2), "kba");
    }

    /// @dev Fuzz `SignedCountLeRequired`: count never exceeds required.
    function testFuzz_SignedCountLeRequired(uint8 nSigners, uint8 threshold) public {
        nSigners = uint8(bound(nSigners, 1, 4));
        threshold = uint8(bound(threshold, 1, nSigners));
        bytes32[] memory signers = new bytes32[](nSigners);
        for (uint256 i; i < nSigners; ++i) {
            signers[i] = keccak256(abi.encodePacked("signer-", i));
        }
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, threshold, 0, CORR);
        for (uint256 i; i < threshold; ++i) {
            env.sign(ID, signers[i], abi.encodePacked("sig-", i), "kba");
        }
        assertLe(env.signedCount(ID), nSigners);
        assertEq(env.signedCount(ID), threshold);
    }

    /// @dev Fuzz `ThresholdSatisfiedImpliesSignedOrLater`: state advances.
    function testFuzz_ThresholdReached(uint8 threshold) public {
        threshold = uint8(bound(threshold, 1, 3));
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B; signers[2] = SIGNER_C;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, threshold, 0, CORR);
        for (uint256 i; i < threshold; ++i) {
            env.sign(ID, signers[i], abi.encodePacked("sig-", i), "kba");
        }
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
    }

    /// @dev Fuzz `ExpiredImpliesNoActiveSign`: any expired envelope rejects sign.
    function testFuzz_ExpiredBlocksSign(uint64 expiry) public {
        // Bound expiry strictly above the warped "now" so draft() accepts it.
        expiry = uint64(bound(expiry, 100, 1_000_000));
        vm.warp(10);
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 2, expiry, CORR);
        vm.warp(uint256(expiry) + 1);
        vm.expectRevert();
        env.sign(ID, SIGNER_A, "sigA", "kba");
    }

    /// @dev Fuzz `ClosedIsTerminal`: any state transition from Closed reverts.
    function testFuzz_ClosedIsTerminal_AllTransitionsRevert(uint8 op) public {
        op = uint8(bound(op, 0, 3));
        _draft3of3(ID, 0);
        env.close(ID, INITIATOR);
        if (op == 0) {
            vm.expectRevert();
            env.sign(ID, SIGNER_A, "sigA", "kba");
        } else if (op == 1) {
            vm.expectRevert();
            env.markDelivered(ID);
        } else if (op == 2) {
            vm.expectRevert();
            env.accept(ID);
        } else {
            vm.expectRevert();
            env.reject(ID, "x");
        }
    }

    // ── Helpers ────────────────────────────────────────────────────

    function _draft3of3(bytes32 envId, uint64 expiresAt) internal {
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A;
        signers[1] = SIGNER_B;
        signers[2] = SIGNER_C;
        env.draft(envId, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 3, expiresAt, CORR);
    }

    function _draftAndFullySign(bytes32 envId) internal {
        _draft3of3(envId, 0);
        env.sign(envId, SIGNER_A, "sigA", "kba");
        env.sign(envId, SIGNER_B, "sigB", "kba");
        env.sign(envId, SIGNER_C, "sigC", "kba");
    }
}
