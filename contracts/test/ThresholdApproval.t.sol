// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ThresholdApproval, IMultiSigEnvelope} from "../src/quorum/ThresholdApproval.sol";
import {IGovernanceProtocol} from "../src/quorum/IGovernanceProtocol.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../src/quorum/QuorumIdentity.sol";

/// @title ThresholdApproval — invariant tests (QRM-S6.3)
///
/// Run against the **real deployed `MultiSigEnvelope`**, not a stand-in. Two
/// reasons: the protocol's whole job is reading that contract's state correctly,
/// and `IMultiSigEnvelope`'s mirrored struct would drift silently against a
/// stub — here a layout change breaks these tests, which is where it should
/// break.
contract ThresholdApprovalTest is Test {
    MultiSigEnvelope envelopes;
    ThresholdApproval protocol;

    bytes32 constant TENANT = keccak256("Citrate");
    bytes32 constant OTHER_TENANT = keccak256("SomeoneElse");
    bytes32 constant TEMPLATE_ID = keccak256(abi.encode("ThresholdApproval", uint32(1)));
    bytes32 constant SPEC_HASH = keccak256("the spec text");
    string constant SPEC_CID = "bafyThresholdApprovalSpecV1";

    // CHAIN-B-C008: MultiSigEnvelope binds sign/close/deliver to the caller's
    // own subjectKey, so each identity must be the subjectKey of a REAL address
    // that we prank as when acting for it. The identities are assigned in setUp.
    address constant ALICE_ADDR = address(0xA11CE);
    address constant BOB_ADDR = address(0xB0B);
    address constant CAROL_ADDR = address(0xCAB01);
    address constant MALLORY_ADDR = address(0x1A11005);
    bytes32 ALICE;
    bytes32 BOB;
    bytes32 CAROL;
    bytes32 MALLORY;
    mapping(bytes32 => address) internal _idAddr;

    bytes32 constant ACTION = keccak256("repo.write");
    bytes32 constant PARAMS = keccak256("the exact call parameters");
    bytes32 constant CORR = keccak256("meeting-42");

    function setUp() public {
        envelopes = new MultiSigEnvelope();
        ALICE = QuorumIdentity.subjectKey(ALICE_ADDR);
        BOB = QuorumIdentity.subjectKey(BOB_ADDR);
        CAROL = QuorumIdentity.subjectKey(CAROL_ADDR);
        MALLORY = QuorumIdentity.subjectKey(MALLORY_ADDR);
        _idAddr[ALICE] = ALICE_ADDR;
        _idAddr[BOB] = BOB_ADDR;
        _idAddr[CAROL] = CAROL_ADDR;
        _idAddr[MALLORY] = MALLORY_ADDR;
        protocol = _deploy(2);
    }

    // ── pranked envelope helpers (CHAIN-B-C008) ─────────────────────
    // sign/close/markDelivered are bound to `subjectKey(msg.sender)`, so each is
    // called while pranking as the address behind the acting identity.

    function _sign(bytes32 id, bytes32 who, bytes memory sig, string memory mode) internal {
        vm.prank(_idAddr[who]);
        envelopes.sign(id, who, sig, mode);
    }

    function _close(bytes32 id, bytes32 initiator) internal {
        vm.prank(_idAddr[initiator]);
        envelopes.close(id, initiator);
    }

    function _markDelivered(bytes32 id, bytes32 initiator) internal {
        vm.prank(_idAddr[initiator]);
        envelopes.markDelivered(id);
    }

    function _deploy(uint8 threshold) internal returns (ThresholdApproval) {
        bytes32[] memory approvers = new bytes32[](3);
        approvers[0] = ALICE;
        approvers[1] = BOB;
        approvers[2] = CAROL;
        return new ThresholdApproval(
            TENANT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(envelopes), approvers, threshold
        );
    }

    function _ctx() internal pure returns (IGovernanceProtocol.ActionContext memory) {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 7,
            principal: address(0xA11CE),
            classification: 1,
            cost: 0,
            paramsHash: PARAMS,
            correlationId: CORR
        });
    }

    /// Draft the envelope the protocol will actually look at.
    function _draft(bytes32[] memory required, uint8 envThreshold, uint64 expiresAt) internal returns (bytes32 id) {
        id = protocol.approvalEnvelopeId(ACTION, PARAMS, CORR);
        envelopes.draft(id, ALICE, keccak256("artifact"), "bafyArtifact", required, envThreshold, expiresAt, CORR);
    }

    function _requiredAll() internal view returns (bytes32[] memory r) {
        r = new bytes32[](3);
        r[0] = ALICE;
        r[1] = BOB;
        r[2] = CAROL;
    }

    function _check() internal view returns (IGovernanceProtocol.Verdict, bytes32, bytes32[] memory) {
        return protocol.check(TENANT, ACTION, _ctx());
    }

    // ── The verdict ladder ──────────────────────────────────────────

    /// Nothing proposed yet is `RequireApproval` with the full approver set —
    /// not `Deny`. The difference matters to the operator: one is "get these
    /// people to sign", the other is "give up".
    function test_unproposedActionRequiresApprovalAndNamesWho() public view {
        (IGovernanceProtocol.Verdict v, bytes32 reason, bytes32[] memory signers) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, protocol.REASON_NOT_PROPOSED());
        assertEq(signers.length, 3, "all three approvers are outstanding");
    }

    /// Below threshold, the outstanding set shrinks to who has NOT signed. An
    /// app that re-listed everyone would keep asking people who already acted.
    function test_partialApprovalListsOnlyWhoStillHasToSign() public {
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _sign(id, ALICE, hex"ab", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason, bytes32[] memory signers) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, protocol.REASON_PENDING());
        assertEq(signers.length, 2);
        assertEq(signers[0], BOB);
        assertEq(signers[1], CAROL);
    }

    function test_thresholdMetAllows() public {
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _sign(id, ALICE, hex"ab", "ceremony");
        _sign(id, BOB, hex"cd", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason, bytes32[] memory signers) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, protocol.REASON_SATISFIED());
        assertEq(signers.length, 0, "nobody else has to act");
    }

    // ── The forgery this design exists to refuse ────────────────────

    /// **The invariant this whole template turns on.** `MultiSigEnvelope.draft`
    /// is permissionless: anyone may create an envelope at any id, with a
    /// threshold of 1 and themselves as the only required signer. If the
    /// protocol trusted `isSignedThresholdMet`, forging an approval would cost
    /// one transaction.
    ///
    /// So it counts against its OWN approver set. Here the attacker builds a
    /// perfectly valid, fully-signed envelope at exactly the right id — and it
    /// buys nothing.
    function test_selfDraftedEnvelopeWithOutsideSignersCountsZero() public {
        bytes32[] memory attackerSet = new bytes32[](1);
        attackerSet[0] = MALLORY;
        bytes32 id = _draft(attackerSet, 1, 0);
        _sign(id, MALLORY, hex"ff", "self");

        // The envelope itself is satisfied, by its own rules.
        assertTrue(envelopes.isSignedThresholdMet(id), "the envelope believes it is signed");
        assertEq(uint8(envelopes.getState(id)), uint8(MultiSigEnvelope.EnvelopeState.Signed));

        // The protocol is not.
        (IGovernanceProtocol.Verdict v, bytes32 reason, bytes32[] memory signers) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval), "forged approval must not Allow");
        assertEq(reason, protocol.REASON_PENDING());
        assertEq(signers.length, 3, "none of the real approvers has signed");
    }

    /// A signature entry with no signature bytes is not evidence. The envelope
    /// contract accepts an empty blob; this protocol does not count it.
    function test_signatureWithNoMaterialIsNotCounted() public {
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _sign(id, ALICE, hex"", "ceremony");
        _sign(id, BOB, hex"cd", "ceremony");

        (IGovernanceProtocol.Verdict v,, bytes32[] memory signers) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval), "one real signature is not two");
        assertEq(signers.length, 2);
        assertEq(signers[0], ALICE, "alice is still outstanding: her entry carries nothing");
    }

    // ── The approval is bound to THIS action ────────────────────────

    /// An approval for one action cannot be spent on another. Each field of the
    /// derivation is varied independently, because a derivation that dropped any
    /// one of them would still pass a test that varied only the others.
    function test_approvalDoesNotTransferToAnotherAction() public {
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _sign(id, ALICE, hex"ab", "ceremony");
        _sign(id, BOB, hex"cd", "ceremony");
        (IGovernanceProtocol.Verdict ok,,) = _check();
        assertEq(uint8(ok), uint8(IGovernanceProtocol.Verdict.Allow));

        IGovernanceProtocol.ActionContext memory ctx = _ctx();

        // different action class
        (IGovernanceProtocol.Verdict v1, bytes32 r1,) = protocol.check(TENANT, keccak256("repo.delete"), ctx);
        assertEq(uint8(v1), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, protocol.REASON_NOT_PROPOSED());

        // same action, different parameters
        ctx.paramsHash = keccak256("different parameters entirely");
        (IGovernanceProtocol.Verdict v2, bytes32 r2,) = protocol.check(TENANT, ACTION, ctx);
        assertEq(uint8(v2), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r2, protocol.REASON_NOT_PROPOSED());

        // same action and parameters, different attempt
        ctx.paramsHash = PARAMS;
        ctx.correlationId = keccak256("meeting-43");
        (IGovernanceProtocol.Verdict v3, bytes32 r3,) = protocol.check(TENANT, ACTION, ctx);
        assertEq(uint8(v3), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r3, protocol.REASON_NOT_PROPOSED());
    }

    /// The id is also bound to the protocol instance, so two protocols in one
    /// tenant cannot share an approval.
    function test_envelopeIdIsBoundToTheProtocolInstance() public {
        ThresholdApproval twin = _deploy(2);
        assertTrue(
            protocol.approvalEnvelopeId(ACTION, PARAMS, CORR) != twin.approvalEnvelopeId(ACTION, PARAMS, CORR),
            "a second protocol must not read the first one's approvals"
        );
    }

    /// Pins the derivation itself, so the app can compute it without
    /// reimplementing — and so a change to it is a deliberate act.
    function test_envelopeIdDerivationIsPinned() public view {
        assertEq(
            protocol.approvalEnvelopeId(ACTION, PARAMS, CORR),
            keccak256(abi.encode(address(protocol), TENANT, ACTION, PARAMS, CORR))
        );
    }

    // ── Tenant scoping ──────────────────────────────────────────────

    /// A protocol deployed for one tenant never answers for another, even when
    /// the approvals would satisfy it.
    function test_wrongTenantIsDeniedEvenWhenFullySigned() public {
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _sign(id, ALICE, hex"ab", "ceremony");
        _sign(id, BOB, hex"cd", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = protocol.check(OTHER_TENANT, ACTION, _ctx());
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, protocol.REASON_WRONG_TENANT());
    }

    // ── Terminal states and expiry ──────────────────────────────────

    function test_rejectedEnvelopeDenies() public {
        bytes32 id = _draft(_requiredAll(), 2, 0);
        _sign(id, ALICE, hex"ab", "ceremony");
        _sign(id, BOB, hex"cd", "ceremony");
        _markDelivered(id, ALICE);
        envelopes.reject(id, "not this quarter");

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, protocol.REASON_REJECTED());
    }

    function test_withdrawnEnvelopeDenies() public {
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _close(id, ALICE);

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, protocol.REASON_WITHDRAWN());
    }

    /// An expiry outranks a completed approval. The deadline is on the
    /// authorization, not merely on collecting signatures — "approved, but that
    /// authorization lapsed" is a refusal, not a technicality.
    function test_expiryOutranksACompletedApproval() public {
        uint64 deadline = uint64(block.timestamp + 1 days);
        bytes32 id = _draft(_requiredAll(), 3, deadline);
        _sign(id, ALICE, hex"ab", "ceremony");
        _sign(id, BOB, hex"cd", "ceremony");

        (IGovernanceProtocol.Verdict live,,) = _check();
        assertEq(uint8(live), uint8(IGovernanceProtocol.Verdict.Allow), "valid before the deadline");

        // Exactly at the deadline — the instant `MultiSigEnvelope.sign` starts
        // refusing. The gate must agree with it, not lag a second behind.
        vm.warp(deadline);
        (IGovernanceProtocol.Verdict v, bytes32 reason, bytes32[] memory signers) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, protocol.REASON_EXPIRED());
        assertEq(signers.length, 3, "a lapsed authorization needs the whole set again");
    }

    // ── Construction ────────────────────────────────────────────────

    /// The rules are immutable after deployment. A protocol whose approver set
    /// or threshold could be edited after the ceremony approved it would make
    /// the ceremony meaningless — this asserts the absence of any setter, which
    /// is where a future edit gets told what it just changed.
    function test_thereIsNoSetterForTheRules() public view {
        (uint8 required, bytes32[] memory approvers) = protocol.policy();
        assertEq(required, 2);
        assertEq(approvers.length, 3);
        // `threshold` and `tenant` are `immutable`; `_approvers` is written only
        // in the constructor. The public surface is check/template/spec/policy/
        // approverCount/isApprover/approvalEnvelopeId — all views.
        assertTrue(protocol.isApprover(ALICE));
        assertFalse(protocol.isApprover(MALLORY));
    }

    function test_constructorRefusesAnUnsatisfiableOrAmbiguousPolicy() public {
        bytes32[] memory three = _requiredAll();
        bytes32[] memory empty = new bytes32[](0);

        vm.expectRevert(ThresholdApproval.EmptyApproverSet.selector);
        new ThresholdApproval(TENANT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(envelopes), empty, 1);

        // A threshold nobody can reach is a rule that reads like governance and
        // functions as a permanent block.
        vm.expectRevert(abi.encodeWithSelector(ThresholdApproval.BadThreshold.selector, uint8(4), uint256(3)));
        new ThresholdApproval(TENANT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(envelopes), three, 4);

        vm.expectRevert(abi.encodeWithSelector(ThresholdApproval.BadThreshold.selector, uint8(0), uint256(3)));
        new ThresholdApproval(TENANT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(envelopes), three, 0);

        // A duplicate makes "2 of 3" a lie about how many distinct people can
        // satisfy the rule.
        bytes32[] memory dupes = new bytes32[](3);
        dupes[0] = ALICE;
        dupes[1] = BOB;
        dupes[2] = ALICE;
        vm.expectRevert(abi.encodeWithSelector(ThresholdApproval.DuplicateApprover.selector, ALICE));
        new ThresholdApproval(TENANT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(envelopes), dupes, 2);

        vm.expectRevert(ThresholdApproval.ZeroTenant.selector);
        new ThresholdApproval(bytes32(0), TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(envelopes), three, 2);

        vm.expectRevert(ThresholdApproval.EmptySpec.selector);
        new ThresholdApproval(TENANT, TEMPLATE_ID, 1, SPEC_HASH, "", address(envelopes), three, 2);
    }

    /// GF-3's other half: from a live protocol address a verifier can reach both
    /// the audited template and the plain-English spec it claims to implement.
    function test_provenanceIsReadableFromTheProtocolItself() public view {
        (bytes32 templateId, uint32 version) = protocol.template();
        assertEq(templateId, TEMPLATE_ID);
        assertEq(version, 1);

        (bytes32 specHash, string memory cid) = protocol.spec();
        assertEq(specHash, SPEC_HASH);
        assertEq(cid, SPEC_CID);
    }

    /// A 1-of-3 is a real configuration, not a degenerate one — it is how "any
    /// duty manager may authorise this" is expressed.
    function test_oneOfThreeIsSatisfiedByAnySingleApprover() public {
        protocol = _deploy(1);
        bytes32 id = _draft(_requiredAll(), 3, 0);
        _sign(id, CAROL, hex"ee", "ceremony");

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check();
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, protocol.REASON_SATISFIED());
    }
}
