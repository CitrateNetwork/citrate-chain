// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";
import {IMultiSigEnvelope} from "./ThresholdApproval.sol";
import {QuorumIdentity} from "./QuorumIdentity.sol";

/// @title SegregationOfDuties — proposer ≠ approver ≠ executor
/// @notice citrate-quorum QRM-S6.7. Seed template 4 of 8.
///
/// The oldest control in the book, and the one an auditor asks about first: the
/// person who proposed a change may not be the person who approved it, and
/// neither may be the person who carried it out.
///
/// ## Where each of the three roles is read from
///
/// | Role | Source |
/// |---|---|
/// | Proposer | the envelope's `initiator` |
/// | Approver | the envelope's `signed_by` |
/// | Executor | `QuorumIdentity.subjectKey(ctx.principal)` — whoever is acting now |
///
/// The envelope is located exactly as `ThresholdApproval` locates it, from the
/// same derivation, so one action has one approval record rather than one per
/// protocol that wants to look at it.
///
/// **Deployment precondition, stated because it is load-bearing:** the envelope's
/// identities must be written with the same encoding this reads —
/// `QuorumIdentity.subjectKey` of the acting address. A deployment that drafts
/// envelopes keyed some other way does not fail loudly here; it produces a
/// disjointness check that always passes, because nobody ever matches anybody.
/// That is the failure mode this NatSpec exists to prevent, and
/// [`executorIdentity`] is exposed so an integrator can verify the encoding
/// against a real envelope before trusting a single verdict.
///
/// ## Why a self-approval is `Deny` and a shortfall is `RequireApproval`
///
/// They are different situations and need different sentences. "Not enough
/// people have approved yet" is a queue; "the person who proposed this also
/// approved it" is a control failure, and answering it with "get more
/// approvals" would invite exactly the wrong fix — one more signature on top of
/// a tainted approval, rather than a different approver.
contract SegregationOfDuties is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("SOD_WRONG_TENANT");
    bytes32 public constant REASON_NOT_PROPOSED = bytes32("SOD_NOT_PROPOSED");
    bytes32 public constant REASON_PENDING = bytes32("SOD_PENDING");
    bytes32 public constant REASON_SATISFIED = bytes32("SOD_SATISFIED");
    bytes32 public constant REASON_PROPOSER_APPROVED = bytes32("SOD_PROPOSER_APPROVED");
    bytes32 public constant REASON_EXECUTOR_APPROVED = bytes32("SOD_EXECUTOR_APPROVED");
    bytes32 public constant REASON_EXECUTOR_PROPOSED = bytes32("SOD_EXECUTOR_PROPOSED");
    bytes32 public constant REASON_WITHDRAWN = bytes32("SOD_WITHDRAWN");
    bytes32 public constant REASON_REJECTED = bytes32("SOD_REJECTED");

    bytes32 public immutable tenant;
    IMultiSigEnvelope public immutable envelopes;
    /// How many distinct approvers, none of them the proposer or the executor.
    uint8 public immutable minApprovers;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroEnvelopes();
    error EmptySpec();
    /// One approver who is neither proposer nor executor is the minimum that
    /// means anything; zero would make this protocol a no-op that reads like a
    /// control.
    error MinApproversTooLow();

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address envelopes_,
        uint8 minApprovers_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (envelopes_ == address(0)) revert ZeroEnvelopes();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        if (minApprovers_ == 0) revert MinApproversTooLow();

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        envelopes = IMultiSigEnvelope(envelopes_);
        minApprovers = minApprovers_;
    }

    /// The envelope this protocol reads. Same derivation as
    /// `ThresholdApproval.approvalEnvelopeId`, so one action has one approval
    /// record however many protocols consult it.
    function approvalEnvelopeId(bytes32 actionClass, bytes32 paramsHash, bytes32 correlationId)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(address(this), tenant, actionClass, paramsHash, correlationId));
    }

    /// The identity an acting address has inside the envelope contract. Exposed
    /// so an integrator can check the encoding against a real envelope rather
    /// than assume it — see the header on why a mismatch is silent.
    function executorIdentity(address who) public pure returns (bytes32) {
        return QuorumIdentity.subjectKey(who);
    }

    /// @inheritdoc IGovernanceProtocol
    function check(bytes32 tenantId, bytes32 actionClass, ActionContext calldata ctx)
        external
        view
        override
        returns (Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners)
    {
        requiredSigners = new bytes32[](0);
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, requiredSigners);
        }

        bytes32 envelopeId = approvalEnvelopeId(actionClass, ctx.paramsHash, ctx.correlationId);
        IMultiSigEnvelope.EnvelopeState state = envelopes.getState(envelopeId);
        if (state == IMultiSigEnvelope.EnvelopeState.NotExist) {
            return (Verdict.RequireApproval, REASON_NOT_PROPOSED, requiredSigners);
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Rejected) {
            return (Verdict.Deny, REASON_REJECTED, requiredSigners);
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Closed) {
            return (Verdict.Deny, REASON_WITHDRAWN, requiredSigners);
        }

        IMultiSigEnvelope.Envelope memory e = envelopes.getEnvelope(envelopeId);
        bytes32 executor = executorIdentity(ctx.principal);

        // A control failure, not a queue. Each one is named separately because
        // the remedy differs: find another approver, hand the action to someone
        // else, or find another proposer.
        if (e.initiator == executor) {
            return (Verdict.Deny, REASON_EXECUTOR_PROPOSED, requiredSigners);
        }
        uint256 eligible;
        for (uint256 i = 0; i < e.signed_by.length; ++i) {
            if (e.signed_by[i] == e.initiator) {
                return (Verdict.Deny, REASON_PROPOSER_APPROVED, requiredSigners);
            }
            if (e.signed_by[i] == executor) {
                return (Verdict.Deny, REASON_EXECUTOR_APPROVED, requiredSigners);
            }
            ++eligible;
        }

        if (eligible < minApprovers) {
            return (Verdict.RequireApproval, REASON_PENDING, requiredSigners);
        }
        return (Verdict.Allow, REASON_SATISFIED, requiredSigners);
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }
}
