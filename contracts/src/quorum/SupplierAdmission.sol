// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";
import {IMultiSigEnvelope} from "./ThresholdApproval.sol";

/// @title SupplierAdmission — nobody joins on a promise
/// @notice citrate-quorum QRM-S6.7. Seed template 7 of 8.
///
/// Admitting an external organisation — a supplier, a partner, a subcontractor —
/// through a committee approval that is inseparable from the evidence it was
/// based on.
///
/// ## The rule this template exists for
///
/// A committee can approve an admission it never had documents for. That is not
/// a hypothetical failure; it is the normal way admissions go wrong under time
/// pressure. So an approval here does not count unless the envelope carries
/// **both** halves of the attestation bundle:
///
/// - `artifact_root != 0` — a commitment to the documents, so what was reviewed
///   is fixed and later-provable;
/// - a non-empty `artifact_cid` — a pointer to fetch them, so it is *retrievable*
///   and not merely hashed into a void.
///
/// One without the other is the failure worth naming separately: a root with no
/// CID is evidence nobody can read, a CID with no root is evidence nobody can
/// prove was the one reviewed. They get distinct reason codes because they are
/// fixed by different people.
///
/// This is the same shape as the factory's GF-3 (`specHash` + `specCID`
/// together, never one) — for the same reason, at a different layer.
///
/// ## What is deliberately not checked
///
/// **The contents of the attestations.** This contract cannot open a document,
/// and a check that pretended to would be theatre. What it enforces is that a
/// committee's approval is bound to a specific, fetchable, tamper-evident
/// bundle. Judging whether an ISO certificate is genuine is the committee's job,
/// and this makes it impossible for them to later be unclear about which
/// document they judged.
contract SupplierAdmission is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("SA_WRONG_TENANT");
    bytes32 public constant REASON_NOT_PROPOSED = bytes32("SA_NOT_PROPOSED");
    bytes32 public constant REASON_NO_ATTESTATION = bytes32("SA_NO_ATTESTATION");
    bytes32 public constant REASON_UNFETCHABLE = bytes32("SA_UNFETCHABLE");
    bytes32 public constant REASON_PENDING = bytes32("SA_PENDING");
    bytes32 public constant REASON_ADMITTED = bytes32("SA_ADMITTED");
    bytes32 public constant REASON_REFUSED = bytes32("SA_REFUSED");
    bytes32 public constant REASON_WITHDRAWN = bytes32("SA_WITHDRAWN");

    bytes32 public immutable tenant;
    IMultiSigEnvelope public immutable envelopes;
    uint8 public immutable committeeThreshold;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;
    bytes32[] private _committee;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroEnvelopes();
    error EmptySpec();
    error EmptyCommittee();
    error CommitteeTooLarge(uint256 size);
    error DuplicateCommitteeMember(bytes32 member);
    error BadThreshold(uint8 threshold, uint256 committee);

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address envelopes_,
        bytes32[] memory committee_,
        uint8 committeeThreshold_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (envelopes_ == address(0)) revert ZeroEnvelopes();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        if (committee_.length == 0) revert EmptyCommittee();
        if (committee_.length > 64) revert CommitteeTooLarge(committee_.length);
        for (uint256 i = 0; i < committee_.length; ++i) {
            for (uint256 j = i + 1; j < committee_.length; ++j) {
                if (committee_[i] == committee_[j]) revert DuplicateCommitteeMember(committee_[i]);
            }
        }
        if (committeeThreshold_ == 0 || committeeThreshold_ > committee_.length) {
            revert BadThreshold(committeeThreshold_, committee_.length);
        }

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        envelopes = IMultiSigEnvelope(envelopes_);
        _committee = committee_;
        committeeThreshold = committeeThreshold_;
    }

    function admissionEnvelopeId(bytes32 actionClass, bytes32 paramsHash, bytes32 correlationId)
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
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, new bytes32[](0));
        }

        bytes32 envelopeId = admissionEnvelopeId(actionClass, ctx.paramsHash, ctx.correlationId);
        IMultiSigEnvelope.EnvelopeState state = envelopes.getState(envelopeId);
        if (state == IMultiSigEnvelope.EnvelopeState.NotExist) {
            return (Verdict.RequireApproval, REASON_NOT_PROPOSED, _committee);
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Rejected) {
            return (Verdict.Deny, REASON_REFUSED, new bytes32[](0));
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Closed) {
            return (Verdict.Deny, REASON_WITHDRAWN, new bytes32[](0));
        }

        IMultiSigEnvelope.Envelope memory e = envelopes.getEnvelope(envelopeId);

        // Evidence before votes. Checked first so a committee is never told
        // "approved, now attach the documents" — the documents are what they
        // were supposed to be approving.
        if (e.artifact_root == bytes32(0)) {
            return (Verdict.Deny, REASON_NO_ATTESTATION, new bytes32[](0));
        }
        if (bytes(e.artifact_cid).length == 0) {
            return (Verdict.Deny, REASON_UNFETCHABLE, new bytes32[](0));
        }

        uint256 approvals;
        for (uint256 i = 0; i < _committee.length; ++i) {
            for (uint256 j = 0; j < e.signed_by.length; ++j) {
                if (e.signed_by[j] == _committee[i]) {
                    ++approvals;
                    break;
                }
            }
        }
        if (approvals < committeeThreshold) {
            return (Verdict.RequireApproval, REASON_PENDING, _committee);
        }

        return (Verdict.Allow, REASON_ADMITTED, new bytes32[](0));
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }

    function committee() external view returns (bytes32[] memory) {
        return _committee;
    }
}
