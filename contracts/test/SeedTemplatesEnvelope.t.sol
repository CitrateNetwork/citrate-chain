// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IGovernanceProtocol} from "../src/quorum/IGovernanceProtocol.sol";
import {SegregationOfDuties} from "../src/quorum/SegregationOfDuties.sol";
import {ChangeControlBoard} from "../src/quorum/ChangeControlBoard.sol";
import {SupplierAdmission} from "../src/quorum/SupplierAdmission.sol";
import {QuorumIdentity} from "../src/quorum/QuorumIdentity.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";

/// @title The three envelope-reading seed templates — invariant tests (QRM-S6.7)
///
/// `SegregationOfDuties`, `ChangeControlBoard` and `SupplierAdmission` all read
/// the real deployed `MultiSigEnvelope`. Nothing here is stubbed: the whole
/// claim is that these read that contract's state correctly.
contract SeedTemplatesEnvelopeTest is Test {
    MultiSigEnvelope envelopes;
    SegregationOfDuties sod;
    ChangeControlBoard ccb;
    SupplierAdmission sa;

    bytes32 constant TENANT = keccak256("Citrate");
    bytes32 constant OTHER = keccak256("Elsewhere");
    bytes32 constant ACTION = keccak256("change.deploy");
    bytes32 constant PARAMS = keccak256("params");
    bytes32 constant CORR = keccak256("corr");
    bytes32 constant SPEC_HASH = keccak256("spec");
    string constant SPEC_CID = "bafySpec";

    address constant PROPOSER_ADDR = address(0xA11CE);
    address constant EXECUTOR_ADDR = address(0xB0B);
    address constant THIRD_ADDR = address(0xC0FFEE);

    address constant BOARD_A_ADDR = address(0xB0A2DA);
    address constant BOARD_B_ADDR = address(0xB0A2DB);
    bytes32 PROPOSER;
    bytes32 EXECUTOR;
    bytes32 THIRD;
    // CHAIN-B-C008: board identities must be the subjectKey of a real address we
    // prank as when signing for them (assigned in setUp, before the constructors).
    bytes32 BOARD_A;
    bytes32 BOARD_B;
    mapping(bytes32 => address) internal _idAddr;

    uint64 constant START = 1_700_000_000;
    uint64 constant REVIEW = 2 days;
    uint64 constant TIMELOCK = 1 days;

    function setUp() public {
        vm.warp(START);
        envelopes = new MultiSigEnvelope();
        PROPOSER = QuorumIdentity.subjectKey(PROPOSER_ADDR);
        EXECUTOR = QuorumIdentity.subjectKey(EXECUTOR_ADDR);
        THIRD = QuorumIdentity.subjectKey(THIRD_ADDR);
        BOARD_A = QuorumIdentity.subjectKey(BOARD_A_ADDR);
        BOARD_B = QuorumIdentity.subjectKey(BOARD_B_ADDR);
        _idAddr[PROPOSER] = PROPOSER_ADDR;
        _idAddr[EXECUTOR] = EXECUTOR_ADDR;
        _idAddr[THIRD] = THIRD_ADDR;
        _idAddr[BOARD_A] = BOARD_A_ADDR;
        _idAddr[BOARD_B] = BOARD_B_ADDR;

        // PBA-L2-013: SoD counts only roster members as proposer/approvers.
        bytes32[] memory roster = new bytes32[](5);
        roster[0] = PROPOSER;
        roster[1] = EXECUTOR;
        roster[2] = THIRD;
        roster[3] = BOARD_A;
        roster[4] = BOARD_B;
        sod = new SegregationOfDuties(
            TENANT, keccak256("sod"), 1, SPEC_HASH, SPEC_CID, address(envelopes), 1, roster
        );

        bytes32[] memory board = new bytes32[](2);
        board[0] = BOARD_A;
        board[1] = BOARD_B;
        ccb = new ChangeControlBoard(
            TENANT, keccak256("ccb"), 1, SPEC_HASH, SPEC_CID, address(envelopes), board, 2, REVIEW, TIMELOCK
        );
        sa = new SupplierAdmission(
            TENANT, keccak256("sa"), 1, SPEC_HASH, SPEC_CID, address(envelopes), board, 2
        );
    }

    function _ctx(address principal) internal pure returns (IGovernanceProtocol.ActionContext memory) {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 0,
            principal: principal,
            classification: 0,
            cost: 0,
            paramsHash: PARAMS,
            correlationId: CORR
        });
    }

    function _draft(bytes32 id, bytes32 initiator, bytes32[] memory required, uint8 threshold, bytes32 root, string memory cid)
        internal
    {
        vm.prank(_idAddr[initiator]); // PBA-L2-013: draft binds initiator to the caller
        envelopes.draft(id, initiator, root, cid, required, threshold, 0, CORR);
    }

    function _two(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](2);
        r[0] = a;
        r[1] = b;
    }

    // ── pranked envelope helpers (CHAIN-B-C008) ─────────────────────
    // sign/markDelivered/close bind to `subjectKey(msg.sender)`; act as the
    // address behind the identity. (PBA-L2-035: reject/accept now need a required signer.)

    function _sign(bytes32 id, bytes32 who, bytes memory sig, string memory mode) internal {
        vm.prank(_idAddr[who]);
        envelopes.sign(id, who, sig, mode);
    }

    function _markDelivered(bytes32 id, bytes32 initiator) internal {
        vm.prank(_idAddr[initiator]);
        envelopes.markDelivered(id);
    }

    // ══ SegregationOfDuties ═════════════════════════════════════════

    function _sodCheck(address actor)
        internal
        view
        returns (IGovernanceProtocol.Verdict v, bytes32 reason)
    {
        (v, reason,) = sod.check(TENANT, ACTION, _ctx(actor));
    }

    /// The proposer approving their own change is a **control failure**, not a
    /// queue. Answering it with "get more approvals" would invite the wrong fix:
    /// one more signature on top of a tainted approval, rather than a different
    /// approver.
    function test_SOD_proposerApprovingTheirOwnChangeIsDeniedNotQueued() public {
        bytes32 id = sod.approvalEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(PROPOSER, THIRD), 1, keccak256("a"), "bafyA");
        _sign(id, PROPOSER, hex"ab", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _sodCheck(EXECUTOR_ADDR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, sod.REASON_PROPOSER_APPROVED());
    }

    /// The executor cannot have approved it either.
    function test_SOD_executorMayNotHaveApproved() public {
        bytes32 id = sod.approvalEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(EXECUTOR, THIRD), 1, keccak256("a"), "bafyA");
        _sign(id, EXECUTOR, hex"ab", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _sodCheck(EXECUTOR_ADDR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, sod.REASON_EXECUTOR_APPROVED());
    }

    /// …nor proposed it.
    function test_SOD_executorMayNotHaveProposed() public {
        bytes32 id = sod.approvalEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, EXECUTOR, _two(PROPOSER, THIRD), 1, keccak256("a"), "bafyA");
        _sign(id, THIRD, hex"ab", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _sodCheck(EXECUTOR_ADDR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, sod.REASON_EXECUTOR_PROPOSED());
    }

    /// Three distinct people: proposed by one, approved by another, executed by
    /// a third. This is the only shape that passes.
    function test_SOD_threeDistinctPeopleIsTheOnlyShapeThatPasses() public {
        bytes32 id = sod.approvalEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(THIRD, BOARD_A), 1, keccak256("a"), "bafyA");

        (IGovernanceProtocol.Verdict pending, bytes32 r1) = _sodCheck(EXECUTOR_ADDR);
        assertEq(uint8(pending), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, sod.REASON_PENDING(), "a shortfall is a queue, and says so");

        _sign(id, THIRD, hex"ab", "ceremony");
        (IGovernanceProtocol.Verdict v, bytes32 r2) = _sodCheck(EXECUTOR_ADDR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r2, sod.REASON_SATISFIED());
    }

    /// The identity encoding is the load-bearing precondition: a deployment that
    /// keys envelopes differently gets a disjointness check that always passes,
    /// because nobody ever matches anybody. `executorIdentity` is public so an
    /// integrator can check it against a real envelope first.
    function test_SOD_executorIdentityIsTheSharedDerivation() public view {
        assertEq(sod.executorIdentity(PROPOSER_ADDR), QuorumIdentity.subjectKey(PROPOSER_ADDR));
        assertEq(sod.executorIdentity(PROPOSER_ADDR), PROPOSER);
        assertTrue(sod.executorIdentity(PROPOSER_ADDR) != sod.executorIdentity(EXECUTOR_ADDR));
    }

    function test_SOD_wrongTenantIsDenied() public view {
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = sod.check(OTHER, ACTION, _ctx(EXECUTOR_ADDR));
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, sod.REASON_WRONG_TENANT());
    }

    // ══ ChangeControlBoard ══════════════════════════════════════════

    function _ccbCheck() internal view returns (IGovernanceProtocol.Verdict v, bytes32 reason) {
        // PBA-L2-035: CCB only reads an envelope drafted by a board member or by
        // the acting principal; here the principal is the change's proposer.
        (v, reason,) = ccb.check(TENANT, ACTION, _ctx(PROPOSER_ADDR));
    }

    /// The full ceremony, in order, with each stage naming itself. A single
    /// combined "not yet" would leave an operator unable to tell a two-day wait
    /// from a missing signature.
    function test_CCB_theWholeCeremonyInOrder() public {
        bytes32 id = ccb.approvalEnvelopeId(ACTION, PARAMS, CORR);

        (IGovernanceProtocol.Verdict v0, bytes32 r0) = _ccbCheck();
        assertEq(uint8(v0), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r0, ccb.REASON_NOT_PROPOSED());

        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, keccak256("a"), "bafyA");

        (IGovernanceProtocol.Verdict v1, bytes32 r1) = _ccbCheck();
        assertEq(uint8(v1), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, ccb.REASON_IN_REVIEW(), "filed, and inside its review period");

        // Signing during the review window is allowed; what the window gates is
        // the verdict, not the signing. Here the board signs after it, so the
        // three stages appear separately.
        vm.warp(START + REVIEW);
        _sign(id, BOARD_A, hex"ab", "ceremony");

        (IGovernanceProtocol.Verdict v2, bytes32 r2) = _ccbCheck();
        assertEq(uint8(v2), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r2, ccb.REASON_PENDING_BOARD());

        _sign(id, BOARD_B, hex"cd", "ceremony");
        (IGovernanceProtocol.Verdict v3, bytes32 r3) = _ccbCheck();
        assertEq(uint8(v3), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r3, ccb.REASON_IN_TIMELOCK());

        vm.warp(START + REVIEW + TIMELOCK);
        (IGovernanceProtocol.Verdict v4, bytes32 r4) = _ccbCheck();
        assertEq(uint8(v4), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r4, ccb.REASON_APPROVED());
    }

    /// **The two waits overlap; they do not stack.** The timelock runs from
    /// `signed_at`, so a board that approves on the day of filing has served
    /// most of its cooling-off period inside the review window, and the change
    /// is executable at `max(review end, approval + timelock)` rather than at
    /// the sum.
    ///
    /// That is deliberate — the delay is a property of the decision, not of when
    /// someone got round to executing it — but it is surprising enough that a
    /// deployment choosing `timelock` should see it pinned. A board wanting a
    /// full post-approval cooling-off sets `timelock` to that period AND does
    /// not approve early; a board wanting a hard floor sets `reviewWindow` to it.
    function test_CCB_theTimelockRunsFromApprovalNotFromTheEndOfReview() public {
        bytes32 id = ccb.approvalEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, keccak256("a"), "bafyA");
        _sign(id, BOARD_A, hex"ab", "ceremony");
        _sign(id, BOARD_B, hex"cd", "ceremony");

        // TIMELOCK (1 day) elapses well inside REVIEW (2 days).
        vm.warp(START + REVIEW - 1);
        (IGovernanceProtocol.Verdict early, bytes32 r1) = _ccbCheck();
        assertEq(uint8(early), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, ccb.REASON_IN_REVIEW(), "the review window is still the binding constraint");

        vm.warp(START + REVIEW);
        (IGovernanceProtocol.Verdict v, bytes32 r2) = _ccbCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r2, ccb.REASON_APPROVED(), "max(review, approval+timelock), not the sum");
    }

    /// A board shortfall is distinct from a timing gate, and outlives the review
    /// window.
    function test_CCB_aBoardShortfallIsNotATimingProblem() public {
        bytes32 id = ccb.approvalEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, keccak256("a"), "bafyA");
        _sign(id, BOARD_A, hex"ab", "ceremony");

        vm.warp(START + REVIEW + TIMELOCK * 10);
        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ccbCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, ccb.REASON_PENDING_BOARD(), "no amount of waiting is a second signature");
    }

    /// Signatures from outside the board do not count toward it — otherwise the
    /// board would be advisory to its own control.
    function test_CCB_nonBoardSignaturesDoNotCount() public {
        bytes32 id = ccb.approvalEnvelopeId(ACTION, PARAMS, CORR);
        bytes32[] memory required = new bytes32[](3);
        required[0] = BOARD_A;
        required[1] = THIRD;
        required[2] = PROPOSER;
        _draft(id, PROPOSER, required, 3, keccak256("a"), "bafyA");
        _sign(id, BOARD_A, hex"ab", "ceremony");
        _sign(id, THIRD, hex"cd", "ceremony");
        _sign(id, PROPOSER, hex"ef", "ceremony");

        vm.warp(START + REVIEW + TIMELOCK * 2);
        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ccbCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, ccb.REASON_PENDING_BOARD(), "two outsiders are not the second board member");
    }

    /// `signed_at` is 0 until the ENVELOPE's own threshold is met. Treating that
    /// as "long ago" would let a change execute with no delay at all — the exact
    /// failure a timelock exists to prevent.
    function test_CCB_anUnstampedEnvelopeIsNotAnExpiredTimelock() public {
        bytes32 id = ccb.approvalEnvelopeId(ACTION, PARAMS, CORR);
        // Envelope threshold 3, board threshold 2: the board is satisfied while
        // the envelope is not, so `signed_at` stays 0.
        bytes32[] memory required = new bytes32[](3);
        required[0] = BOARD_A;
        required[1] = BOARD_B;
        required[2] = THIRD;
        _draft(id, PROPOSER, required, 3, keccak256("a"), "bafyA");
        _sign(id, BOARD_A, hex"ab", "ceremony");
        _sign(id, BOARD_B, hex"cd", "ceremony");

        vm.warp(START + REVIEW + TIMELOCK * 5);
        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ccbCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, ccb.REASON_IN_TIMELOCK(), "an unstamped envelope has not started its clock");
    }

    // ══ SupplierAdmission ═══════════════════════════════════════════

    function _saCheck() internal view returns (IGovernanceProtocol.Verdict v, bytes32 reason) {
        // PBA-L2-035: SA only reads an envelope drafted by a committee member or
        // by the acting principal; here the principal is the filing proposer.
        (v, reason,) = sa.check(TENANT, ACTION, _ctx(PROPOSER_ADDR));
    }

    /// A committee can approve an admission it never had documents for. That is
    /// not hypothetical; it is how admissions go wrong under time pressure. So
    /// the evidence is checked BEFORE the votes, and a full committee approval
    /// with no attestation bundle is still a refusal.
    function test_SA_approvalWithoutEvidenceIsStillARefusal() public {
        bytes32 id = sa.admissionEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, bytes32(0), "bafyDocs");
        _sign(id, BOARD_A, hex"ab", "ceremony");
        _sign(id, BOARD_B, hex"cd", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _saCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, sa.REASON_NO_ATTESTATION(), "a fully-approved admission with no commitment");
    }

    /// The two halves fail separately because they are fixed by different
    /// people: a root with no CID is evidence nobody can read, a CID with no
    /// root is evidence nobody can prove was the one reviewed.
    function test_SA_aCommitmentWithNothingToFetchIsItsOwnFailure() public {
        bytes32 id = sa.admissionEnvelopeId(ACTION, PARAMS, CORR);
        // `MultiSigEnvelope.draft` refuses an empty CID outright, which is the
        // first line of this defence; the protocol's own check is the second,
        // for a deployment pointed at a laxer envelope contract.
        vm.expectRevert(MultiSigEnvelope.EmptyArtifactCid.selector);
        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, keccak256("root"), "");
    }

    function test_SA_evidencePlusCommitteeAdmits() public {
        bytes32 id = sa.admissionEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, keccak256("root"), "bafyDocs");

        (IGovernanceProtocol.Verdict pending, bytes32 r1) = _saCheck();
        assertEq(uint8(pending), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, sa.REASON_PENDING());

        _sign(id, BOARD_A, hex"ab", "ceremony");
        _sign(id, BOARD_B, hex"cd", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 r2) = _saCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r2, sa.REASON_ADMITTED());
    }

    function test_SA_aRefusedAdmissionStaysRefused() public {
        bytes32 id = sa.admissionEnvelopeId(ACTION, PARAMS, CORR);
        _draft(id, PROPOSER, _two(BOARD_A, BOARD_B), 2, keccak256("root"), "bafyDocs");
        _sign(id, BOARD_A, hex"ab", "ceremony");
        _sign(id, BOARD_B, hex"cd", "ceremony");
        _markDelivered(id, PROPOSER);
        vm.prank(BOARD_A_ADDR); // PBA-L2-035: a counterparty (required signer) rejects
        envelopes.reject(id, "failed diligence");

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _saCheck();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, sa.REASON_REFUSED());
    }

    // ══ Shared ══════════════════════════════════════════════════════

    /// Each protocol derives its own envelope id, so binding two of them to one
    /// action class does not make them share an approval record.
    function test_eachProtocolReadsItsOwnEnvelope() public view {
        assertTrue(
            sod.approvalEnvelopeId(ACTION, PARAMS, CORR) != ccb.approvalEnvelopeId(ACTION, PARAMS, CORR)
        );
        assertTrue(
            ccb.approvalEnvelopeId(ACTION, PARAMS, CORR) != sa.admissionEnvelopeId(ACTION, PARAMS, CORR)
        );
    }

    function test_constructorsRefuseAPolicyThatCouldNeverBind() public {
        bytes32[] memory board = _two(BOARD_A, BOARD_B);

        vm.expectRevert(SegregationOfDuties.MinApproversTooLow.selector);
        new SegregationOfDuties(TENANT, keccak256("x"), 1, SPEC_HASH, SPEC_CID, address(envelopes), 0, board);

        vm.expectRevert(abi.encodeWithSelector(ChangeControlBoard.BadThreshold.selector, uint8(3), uint256(2)));
        new ChangeControlBoard(
            TENANT, keccak256("x"), 1, SPEC_HASH, SPEC_CID, address(envelopes), board, 3, REVIEW, TIMELOCK
        );

        bytes32[] memory dupes = _two(BOARD_A, BOARD_A);
        vm.expectRevert(abi.encodeWithSelector(SupplierAdmission.DuplicateCommitteeMember.selector, BOARD_A));
        new SupplierAdmission(TENANT, keccak256("x"), 1, SPEC_HASH, SPEC_CID, address(envelopes), dupes, 1);
    }
}
