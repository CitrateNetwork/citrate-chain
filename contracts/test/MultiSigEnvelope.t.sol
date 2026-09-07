// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../src/quorum/QuorumIdentity.sol";

/// @title MultiSigEnvelope.t — BFR-02-WP5 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/MultiSigEnvelopeFlow.tla`.
///      ≥50 tests covering every cited invariant + state machine
///      + 5 fuzz targets.
///
/// CHAIN-B-C008 (audit 2026-09-02): `sign`/`close`/`markDelivered` now bind
/// the named identity to `QuorumIdentity.subjectKey(msg.sender)`, so this
/// suite signs/closes/delivers through pranked helpers keyed to real
/// addresses. The pre-fix suite had ZERO `vm.prank` calls — it could not
/// distinguish "the signer signed" from "anyone signed on the signer's
/// behalf", which was the vulnerability. The `test_C008_*` tests are the
/// RED/GREEN tripwires for the forgery + close-hijack exploits.
contract MultiSigEnvelopeTest is Test {
    MultiSigEnvelope internal env;

    bytes32 constant ID = keccak256("envelope-1");
    bytes32 constant ID2 = keccak256("envelope-2");
    bytes32 constant CORR = keccak256("corr-1");
    bytes32 constant ART_ROOT = keccak256("artifact-root");

    // Real addresses behind each identity; the on-chain key is their subjectKey.
    address internal INIT_ADDR = address(0x1117);
    address internal A_ADDR = address(0xA1);
    address internal B_ADDR = address(0xB2);
    address internal C_ADDR = address(0xC3);
    address internal D_ADDR = address(0xD4);
    address internal STRANGER_ADDR = address(0x57A);

    bytes32 internal INITIATOR;
    bytes32 internal SIGNER_A;
    bytes32 internal SIGNER_B;
    bytes32 internal SIGNER_C;
    bytes32 internal SIGNER_D;
    bytes32 internal STRANGER;

    function setUp() public {
        env = new MultiSigEnvelope();
        INITIATOR = QuorumIdentity.subjectKey(INIT_ADDR);
        SIGNER_A = QuorumIdentity.subjectKey(A_ADDR);
        SIGNER_B = QuorumIdentity.subjectKey(B_ADDR);
        SIGNER_C = QuorumIdentity.subjectKey(C_ADDR);
        SIGNER_D = QuorumIdentity.subjectKey(D_ADDR);
        STRANGER = QuorumIdentity.subjectKey(STRANGER_ADDR);
    }

    // ── pranked helpers (CHAIN-B-C008) ─────────────────────────────

    function _sign(bytes32 id, address who, bytes memory sig, string memory mode) internal {
        vm.prank(who);
        env.sign(id, QuorumIdentity.subjectKey(who), sig, mode);
    }

    function _close(bytes32 id, address who) internal {
        vm.prank(who);
        env.close(id, QuorumIdentity.subjectKey(who));
    }

    function _markDelivered(bytes32 id, address who) internal {
        vm.prank(who);
        env.markDelivered(id);
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
        _sign(ID, A_ADDR, "sigA", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signing));
    }

    function test_sign_emitsEnvelopeSigned() public {
        _draft3of3(ID, 0);
        vm.expectEmit(true, true, false, true);
        emit MultiSigEnvelope.EnvelopeSigned(ID, SIGNER_A, "kba");
        _sign(ID, A_ADDR, "sigA", "kba");
    }

    function test_sign_storesSignatureBytes() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "specific-bytes", "kba");
        assertEq(env.signatureOf(ID, SIGNER_A), bytes("specific-bytes"));
    }

    function test_sign_signedCountIncrements() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        _sign(ID, B_ADDR, "sigB", "kba");
        assertEq(env.signedCount(ID), 2);
    }

    function test_sign_thresholdMetMovesToSigned() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        _sign(ID, B_ADDR, "sigB", "kba");
        _sign(ID, C_ADDR, "sigC", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
        assertTrue(env.isSignedThresholdMet(ID));
    }

    function test_sign_signedAtRecorded() public {
        vm.warp(5000);
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        _sign(ID, B_ADDR, "sigB", "kba");
        _sign(ID, C_ADDR, "sigC", "kba");
        assertEq(env.getEnvelope(ID).signed_at, 5000);
    }

    function test_sign_2of3Configuration() public {
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B; signers[2] = SIGNER_C;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 2, 0, CORR);
        _sign(ID, A_ADDR, "sigA", "kba");
        _sign(ID, B_ADDR, "sigB", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
    }

    // ── sign revert paths ──────────────────────────────────────────

    function test_sign_revertsOnNonExistent() public {
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.DoesNotExist.selector, ID)
        );
        _sign(ID, A_ADDR, "sigA", "kba");
    }

    /// @dev Cites `SignersUnique` invariant.
    function test_SignersUnique_revertsOnDoubleSign() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.AlreadySigned.selector, SIGNER_A)
        );
        _sign(ID, A_ADDR, "sigA-again", "kba");
    }

    function test_sign_revertsOnNonRequiredSigner() public {
        _draft3of3(ID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.NotRequiredSigner.selector, STRANGER
            )
        );
        _sign(ID, STRANGER_ADDR, "sigStranger", "kba");
    }

    function test_sign_revertsOnEmptyAuthMode() public {
        _draft3of3(ID, 0);
        vm.expectRevert(MultiSigEnvelope.EmptyAuthMode.selector);
        _sign(ID, A_ADDR, "sigA", "");
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
        _sign(ID, A_ADDR, "sigA", "kba");
    }

    // ── State machine transitions ──────────────────────────────────

    function test_markDelivered_fromSigned() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
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
        _markDelivered(ID, INIT_ADDR);
    }

    function test_markDelivered_revertsFromDrafted() public {
        _draft3of3(ID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForDeliver.selector,
                MultiSigEnvelope.EnvelopeState.Drafted
            )
        );
        _markDelivered(ID, INIT_ADDR);
    }

    function test_markDelivered_revertsFromSigning() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForDeliver.selector,
                MultiSigEnvelope.EnvelopeState.Signing
            )
        );
        _markDelivered(ID, INIT_ADDR);
    }

    function test_accept_fromDelivered() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
        env.accept(ID);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Accepted));
    }

    function test_accept_emitsAccepted() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
        vm.expectEmit(true, true, false, true);
        emit MultiSigEnvelope.EnvelopeAccepted(ID, CORR);
        env.accept(ID);
    }

    function test_accept_revertsFromSigning() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
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
        _markDelivered(ID, INIT_ADDR);
        env.reject(ID, "MOQ contradicts attested capacity");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Rejected));
    }

    function test_reject_emitsRejectedWithReason() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
        vm.expectEmit(true, true, false, true);
        emit MultiSigEnvelope.EnvelopeRejected(ID, CORR, "moq mismatch");
        env.reject(ID, "moq mismatch");
    }

    function test_close_fromDrafted() public {
        _draft3of3(ID, 0);
        _close(ID, INIT_ADDR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    function test_close_fromSigning() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        _close(ID, INIT_ADDR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    function test_close_fromSigned() public {
        _draftAndFullySign(ID);
        _close(ID, INIT_ADDR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    function test_close_revertsForNonInitiator() public {
        _draft3of3(ID, 0);
        // Caller supplies a non-initiator identity → NotInitiator.
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.NotInitiator.selector, INITIATOR, address(this))
        );
        env.close(ID, SIGNER_A);
    }

    /// @dev Cites `ClosedIsTerminal`.
    function test_ClosedIsTerminal() public {
        _draft3of3(ID, 0);
        _close(ID, INIT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Closed
            )
        );
        _close(ID, INIT_ADDR);
    }

    function test_close_revertsAfterAccept() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
        env.accept(ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Accepted
            )
        );
        _close(ID, INIT_ADDR);
    }

    function test_close_revertsAfterReject() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
        env.reject(ID, "no");
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Rejected
            )
        );
        _close(ID, INIT_ADDR);
    }

    function test_close_revertsAfterDelivered() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForClose.selector,
                MultiSigEnvelope.EnvelopeState.Delivered
            )
        );
        _close(ID, INIT_ADDR);
    }

    /// @dev Cites `AcceptOrRejectExclusive`.
    function test_AcceptOrRejectExclusive() public {
        _draftAndFullySign(ID);
        _markDelivered(ID, INIT_ADDR);
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
        _markDelivered(ID, INIT_ADDR);
        env.accept(ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForAcceptReject.selector,
                MultiSigEnvelope.EnvelopeState.Accepted
            )
        );
        env.accept(ID);
    }

    // ── CHAIN-B-C008: authentication tripwires ─────────────────────

    /// RED (pre-fix): one EOA drove any envelope to `Signed` by naming each
    /// required signer in turn — `sign` never read `msg.sender`. GREEN: the
    /// named signer must equal the caller's own subject key, so an attacker
    /// who controls none of the signer addresses cannot forge the multisig.
    function test_C008_one_address_cannot_forge_full_envelope() public {
        _draft3of3(ID, 0);
        address attacker = address(0xBAD);
        // The attacker tries to sign as SIGNER_A while being neither A nor
        // the owner of that identity.
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.SignerNotCaller.selector, SIGNER_A, attacker)
        );
        env.sign(ID, SIGNER_A, hex"01", "x");

        // And it cannot walk the whole required set from one address.
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.SignerNotCaller.selector, SIGNER_B, attacker)
        );
        env.sign(ID, SIGNER_B, hex"01", "x");

        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Drafted));
        assertFalse(env.isSignedThresholdMet(ID));
    }

    /// RED (pre-fix): `close` "authenticated" by comparing a caller-supplied
    /// `initiator` against the public stored value, so anyone could read the
    /// initiator off the getter and permanently kill any pending approval.
    /// GREEN: close is bound to the caller's subject key.
    function test_C008_outsider_cannot_close_someone_elses_envelope() public {
        _draft3of3(ID, 0);
        address attacker = address(0xBAD);
        // Attacker reads the public initiator and replays it — still rejected
        // because it does not match the attacker's own subject key.
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.NotInitiator.selector, INITIATOR, attacker)
        );
        env.close(ID, INITIATOR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Drafted));

        // The real initiator can still close it.
        _close(ID, INIT_ADDR);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Closed));
    }

    /// GREEN: `markDelivered` is now initiator-gated (was uncontrolled).
    function test_C008_outsider_cannot_markDelivered() public {
        _draftAndFullySign(ID);
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.NotInitiator.selector, INITIATOR, attacker)
        );
        env.markDelivered(ID);
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
    }

    // ── Invariants explicit ─────────────────────────────────────────

    /// @dev Cites `SignedCountLeRequired`.
    function test_SignedCountLeRequired() public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, "sigA", "kba");
        _sign(ID, B_ADDR, "sigB", "kba");
        _sign(ID, C_ADDR, "sigC", "kba");
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
        _sign(ID, A_ADDR, "sigA", "kba");
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signing));
        _sign(ID, B_ADDR, "sigB", "kba");
        // Threshold (2) reached, state must advance.
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
        // After Signed, sign() must revert.
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForSign.selector,
                MultiSigEnvelope.EnvelopeState.Signed
            )
        );
        _sign(ID, C_ADDR, "sigC", "kba");
    }

    function test_signNotAcceptedAfterClose() public {
        _draft3of3(ID, 0);
        _close(ID, INIT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigEnvelope.InvalidStateForSign.selector,
                MultiSigEnvelope.EnvelopeState.Closed
            )
        );
        _sign(ID, A_ADDR, "sigA", "kba");
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

    /// @dev Fuzz `SignersUnique`: any second sign() by the same signer reverts.
    function testFuzz_SignersUnique(bytes32 sig1, bytes32 sig2) public {
        _draft3of3(ID, 0);
        _sign(ID, A_ADDR, abi.encodePacked(sig1), "kba");
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.AlreadySigned.selector, SIGNER_A)
        );
        _sign(ID, A_ADDR, abi.encodePacked(sig2), "kba");
    }

    /// @dev Fuzz `SignedCountLeRequired`: count never exceeds required.
    function testFuzz_SignedCountLeRequired(uint8 nSigners, uint8 threshold) public {
        nSigners = uint8(bound(nSigners, 1, 4));
        threshold = uint8(bound(threshold, 1, nSigners));
        address[] memory addrs = new address[](nSigners);
        bytes32[] memory signers = new bytes32[](nSigners);
        for (uint256 i; i < nSigners; ++i) {
            addrs[i] = address(uint160(0x2000 + i));
            signers[i] = QuorumIdentity.subjectKey(addrs[i]);
        }
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, threshold, 0, CORR);
        for (uint256 i; i < threshold; ++i) {
            _sign(ID, addrs[i], abi.encodePacked("sig-", i), "kba");
        }
        assertLe(env.signedCount(ID), nSigners);
        assertEq(env.signedCount(ID), threshold);
    }

    /// @dev Fuzz `ThresholdSatisfiedImpliesSignedOrLater`: state advances.
    function testFuzz_ThresholdReached(uint8 threshold) public {
        threshold = uint8(bound(threshold, 1, 3));
        address[3] memory addrs = [A_ADDR, B_ADDR, C_ADDR];
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B; signers[2] = SIGNER_C;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, threshold, 0, CORR);
        for (uint256 i; i < threshold; ++i) {
            _sign(ID, addrs[i], abi.encodePacked("sig-", i), "kba");
        }
        assertEq(uint8(env.getState(ID)), uint8(MultiSigEnvelope.EnvelopeState.Signed));
    }

    /// @dev Fuzz `ExpiredImpliesNoActiveSign`: any expired envelope rejects sign.
    function testFuzz_ExpiredBlocksSign(uint64 expiry) public {
        expiry = uint64(bound(expiry, 100, 1_000_000));
        vm.warp(10);
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = SIGNER_A; signers[1] = SIGNER_B;
        env.draft(ID, INITIATOR, ART_ROOT, "ipfs://Qm...", signers, 2, expiry, CORR);
        vm.warp(uint256(expiry) + 1);
        vm.expectRevert();
        _sign(ID, A_ADDR, "sigA", "kba");
    }

    /// @dev Fuzz `ClosedIsTerminal`: any state transition from Closed reverts.
    function testFuzz_ClosedIsTerminal_AllTransitionsRevert(uint8 op) public {
        op = uint8(bound(op, 0, 3));
        _draft3of3(ID, 0);
        _close(ID, INIT_ADDR);
        if (op == 0) {
            vm.expectRevert();
            _sign(ID, A_ADDR, "sigA", "kba");
        } else if (op == 1) {
            vm.expectRevert();
            _markDelivered(ID, INIT_ADDR);
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
        _sign(envId, A_ADDR, "sigA", "kba");
        _sign(envId, B_ADDR, "sigB", "kba");
        _sign(envId, C_ADDR, "sigC", "kba");
    }
}
