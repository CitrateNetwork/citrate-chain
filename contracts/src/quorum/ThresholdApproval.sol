// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";

/// Minimal view of the deployed `MultiSigEnvelope` (DPF-02, `rbac/`).
///
/// Declared here rather than imported so a protocol can be pointed at a
/// customer's own envelope contract. The struct MUST stay layout-identical to
/// the real one — the test suite exercises this interface against the actual
/// `MultiSigEnvelope` contract precisely so that a drift breaks a test rather
/// than silently mis-decoding in production.
interface IMultiSigEnvelope {
    enum EnvelopeState {
        NotExist,
        Drafted,
        Signing,
        Signed,
        Delivered,
        Accepted,
        Rejected,
        Closed
    }

    struct Envelope {
        bytes32 envelope_id;
        bytes32 artifact_root;
        string artifact_cid;
        bytes32[] required_signers;
        bytes32[] signed_by;
        uint8 threshold;
        EnvelopeState state;
        bytes32 corr_id;
        uint64 created_at;
        uint64 signed_at;
        uint64 expires_at;
        bytes32 initiator;
    }

    function getState(bytes32 envelope_id) external view returns (EnvelopeState);
    function getEnvelope(bytes32 envelope_id) external view returns (Envelope memory);
    function signatureOf(bytes32 envelope_id, bytes32 signer) external view returns (bytes memory);
}

/// @title ThresholdApproval — N-of-M from a named approver set
/// @notice citrate-quorum QRM-S6.3. Seed template 1 of 8. Planset
/// `03_GOVERNANCE_CONTRACTS.md` §1 ("action class X requires N-of-M signers
/// from role set R").
///
/// One of the two verdict shapes the seed set has to exercise: this one moves
/// `RequireApproval` → `Allow` as approvals arrive. `ClassificationGate` is the
/// `Deny` shape.
///
/// ## How an approval is located
///
/// The envelope id is DERIVED, not supplied:
///
/// ```
/// envelopeId = keccak256(abi.encode(address(this), tenant, actionClass, ctx.paramsHash, ctx.correlationId))
/// ```
///
/// If a caller could name the envelope, "is this approved?" would become "can
/// you find me any approved envelope?", and every action in the tenant could be
/// waved through by pointing at one unrelated signed envelope. Deriving it binds
/// the approval to *this protocol, this tenant, this action class, these exact
/// parameters, and this correlation*. [`approvalEnvelopeId`] exposes the
/// derivation so the app drafts the envelope the protocol will actually look at.
///
/// ## What this counts, and what it refuses to count
///
/// **The envelope's own `threshold` and `required_signers` are ignored.**
/// `MultiSigEnvelope.draft` is permissionless: anyone may create an envelope at
/// any id with a threshold of 1 and themselves as the only required signer. If
/// this protocol trusted `isSignedThresholdMet`, forging an approval would cost
/// one transaction. So it counts against ITS OWN policy instead — how many
/// distinct identities **from this protocol's approver set** are recorded as
/// having signed, with signature material attached — and a self-drafted envelope
/// signed by identities outside the set counts zero.
///
/// ## The trust boundary, stated plainly
///
/// `MultiSigEnvelope.sign` does not authenticate the signer cryptographically:
/// its own NatSpec delegates that to the caller ("the orchestrator's HSM
/// verifies the cryptographic proof before invoking this method"). Anyone able
/// to send a transaction can record a signature for any identity in an
/// envelope's `required_signers`.
///
/// Therefore `Allow` from this protocol means: *an envelope exists in which at
/// least N identities from the approver set are recorded as having signed, with
/// signature bytes attached.* It does NOT mean the chain verified those
/// signatures. Binding that record to real humans is citrate-quorum's
/// SignatureCeremony, off chain, and the signature bytes in the envelope are the
/// evidence a verifier re-checks.
///
/// In the interface's own terms (`IGovernanceProtocol`), this template is
/// **attested** — provable after the fact — and is **binding** only to the
/// extent that whoever may write to the envelope contract is trusted. Making it
/// binding on its own would require `MultiSigEnvelope` to verify signatures,
/// which is a change to a deployed DPF-02 contract and is not this sprint's to
/// make. It is written here rather than left for a reader to infer, because the
/// gap between "N people approved" and "N signatures are recorded" is exactly
/// the kind of thing that gets flattened in a board slide.
///
/// ## Expiry is deliberate, and has a consequence worth knowing
///
/// An expired envelope is not an approval. Because the id is derived and
/// `draft` is one-shot per id, a lapsed approval cannot be re-drafted at the
/// same id — the action must be re-proposed under a new `correlationId`, which
/// is what a correlation is for (it threads one attempt: meeting → grant →
/// action). A retried action is a new attempt, not a second run at the old one.
contract ThresholdApproval is IGovernanceProtocol {
    /// Reason codes. Short strings so an operator reading a raw log sees words,
    /// and the app maps them to sentences.
    bytes32 public constant REASON_WRONG_TENANT = bytes32("TA_WRONG_TENANT");
    bytes32 public constant REASON_NOT_PROPOSED = bytes32("TA_NOT_PROPOSED");
    bytes32 public constant REASON_PENDING = bytes32("TA_PENDING");
    bytes32 public constant REASON_SATISFIED = bytes32("TA_SATISFIED");
    bytes32 public constant REASON_REJECTED = bytes32("TA_REJECTED");
    bytes32 public constant REASON_WITHDRAWN = bytes32("TA_WITHDRAWN");
    bytes32 public constant REASON_EXPIRED = bytes32("TA_EXPIRED");

    /// The one tenant this protocol answers for.
    bytes32 public immutable tenant;
    /// Where approvals are collected.
    IMultiSigEnvelope public immutable envelopes;
    /// How many of the approver set must sign.
    uint8 public immutable threshold;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;
    /// The approver set. Hashed identities (`keccak256(user_id)`), matching
    /// `MultiSigEnvelope`'s signer encoding — never names.
    bytes32[] private _approvers;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroEnvelopes();
    error EmptySpec();
    error EmptyApproverSet();
    error ApproverSetTooLarge(uint256 size);
    error DuplicateApprover(bytes32 approver);
    error BadThreshold(uint8 threshold, uint256 approvers);

    /// Bound at construction and never changeable. A governance protocol whose
    /// rules could be edited after the ceremony approved it would make the
    /// ceremony meaningless — a version change is a new deployment with a new
    /// address (GF-5), which is what the factory's salt lineage is for.
    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address envelopes_,
        bytes32[] memory approvers_,
        uint8 threshold_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (envelopes_ == address(0)) revert ZeroEnvelopes();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        if (approvers_.length == 0) revert EmptyApproverSet();
        // `check` is a view called on every gated action; an unbounded approver
        // set would make it unaffordable for an on-chain (binding) caller.
        if (approvers_.length > 64) revert ApproverSetTooLarge(approvers_.length);
        if (threshold_ == 0 || threshold_ > approvers_.length) {
            revert BadThreshold(threshold_, approvers_.length);
        }
        // A duplicate cannot inflate the count (membership is a set test), but it
        // makes `threshold <= approvers.length` a lie about how many distinct
        // people can satisfy this rule. Refuse it at construction, where it is
        // still cheap to fix.
        for (uint256 i = 0; i < approvers_.length; ++i) {
            for (uint256 j = i + 1; j < approvers_.length; ++j) {
                if (approvers_[i] == approvers_[j]) revert DuplicateApprover(approvers_[i]);
            }
        }

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        envelopes = IMultiSigEnvelope(envelopes_);
        threshold = threshold_;
        _approvers = approvers_;
    }

    /// The envelope this protocol will look at for a given action.
    ///
    /// `public pure`-adjacent (it reads only `tenant` and `address(this)`) so the
    /// app computes the same id the protocol does rather than reimplementing it.
    function approvalEnvelopeId(bytes32 actionClass, bytes32 paramsHash, bytes32 correlationId)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(address(this), tenant, actionClass, paramsHash, correlationId));
    }

    /// @inheritdoc IGovernanceProtocol
    function check(bytes32 tenantId, bytes32 actionClass, ActionContext calldata ctx)
        external
        view
        override
        returns (Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners)
    {
        // A protocol deployed for one tenant must never answer for another. The
        // caller is `PolicyBinding`, which is itself tenant-keyed, but a protocol
        // that trusted its caller's framing would be one misrouted binding away
        // from applying tenant A's approvers to tenant B's actions.
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, new bytes32[](0));
        }

        bytes32 envelopeId = approvalEnvelopeId(actionClass, ctx.paramsHash, ctx.correlationId);
        IMultiSigEnvelope.EnvelopeState state = envelopes.getState(envelopeId);

        // Nothing proposed yet: say who has to act, so the app can draft the
        // envelope rather than telling the operator "denied".
        if (state == IMultiSigEnvelope.EnvelopeState.NotExist) {
            return (Verdict.RequireApproval, REASON_NOT_PROPOSED, _approvers);
        }
        // Terminal-fail states are answers, not waiting rooms. Re-proposing needs
        // a new correlation id.
        if (state == IMultiSigEnvelope.EnvelopeState.Rejected) {
            return (Verdict.Deny, REASON_REJECTED, new bytes32[](0));
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Closed) {
            return (Verdict.Deny, REASON_WITHDRAWN, new bytes32[](0));
        }

        IMultiSigEnvelope.Envelope memory e = envelopes.getEnvelope(envelopeId);
        // `>=`, matching `MultiSigEnvelope.sign`, which refuses at exactly
        // `expires_at`. A gate that considered an envelope live one second after
        // it stopped being signable would answer for a state that cannot exist.
        //
        // Checked BEFORE the tally, so an expiry outranks a completed approval:
        // the deadline is on the AUTHORIZATION, not merely on collecting
        // signatures. "Approved, but that authorization lapsed on Friday" is a
        // refusal, not a technicality.
        if (e.expires_at != 0 && block.timestamp >= e.expires_at) {
            return (Verdict.RequireApproval, REASON_EXPIRED, _approvers);
        }

        (uint256 counted, bytes32[] memory outstanding) = _tally(envelopeId, e.signed_by);
        if (counted >= threshold) {
            return (Verdict.Allow, REASON_SATISFIED, new bytes32[](0));
        }
        return (Verdict.RequireApproval, REASON_PENDING, outstanding);
    }

    /// How many approvers from THIS protocol's set have signed, and which have
    /// not. The envelope's own threshold and required-signer list are not
    /// consulted — see the contract header for why.
    function _tally(bytes32 envelopeId, bytes32[] memory signedBy)
        private
        view
        returns (uint256 counted, bytes32[] memory outstanding)
    {
        bytes32[] memory pending = new bytes32[](_approvers.length);
        uint256 pendingCount;

        for (uint256 i = 0; i < _approvers.length; ++i) {
            bool signed;
            for (uint256 j = 0; j < signedBy.length; ++j) {
                if (signedBy[j] != _approvers[i]) continue;
                // Recorded as a signer AND carrying signature material. An empty
                // blob is not evidence of anything, and the envelope contract
                // does not require one.
                if (envelopes.signatureOf(envelopeId, _approvers[i]).length != 0) {
                    signed = true;
                }
                break;
            }
            if (signed) {
                ++counted;
            } else {
                pending[pendingCount++] = _approvers[i];
            }
        }

        outstanding = new bytes32[](pendingCount);
        for (uint256 i = 0; i < pendingCount; ++i) {
            outstanding[i] = pending[i];
        }
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }

    /// The rule in force, for the app to render next to the spec.
    function policy() external view returns (uint8 required, bytes32[] memory approvers) {
        return (threshold, _approvers);
    }

    function approverCount() external view returns (uint256) {
        return _approvers.length;
    }

    function isApprover(bytes32 identity) external view returns (bool) {
        for (uint256 i = 0; i < _approvers.length; ++i) {
            if (_approvers[i] == identity) return true;
        }
        return false;
    }
}
