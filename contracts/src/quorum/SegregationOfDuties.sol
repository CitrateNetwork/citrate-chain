// SPDX-License-Identifier: Apache-2.0
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
/// | Proposer | the envelope's `initiator` (bound to the drafting address, and a roster member) |
/// | Approver | the envelope's `signed_by`, counted only for roster members (PBA-L2-013) |
/// | Executor | `QuorumIdentity.subjectKey(ctx.principal)` — whoever is acting now |
///
/// The envelope id is derived the same WAY as `ThresholdApproval`'s, but the
/// derivation includes `address(this)`, so each protocol reads its OWN envelope
/// (PBA-L2-013 corrected the earlier claim that one action has one record).
/// Binding SoD next to ThresholdApproval therefore needs both envelopes.
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
    /// PBA-L2-035: an envelope at the derived id exists but was drafted by a
    /// party this protocol does not recognise; it is ignored (it can neither
    /// approve nor deny), and the action must be re-proposed under a new
    /// correlation id by a recognised proposer.
    bytes32 public constant REASON_FOREIGN_PROPOSER = bytes32("SOD_FOREIGN_PROPOSER");
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
    /// PBA-L2-013: the roster whose members may propose and approve. Hashed
    /// identities (`QuorumIdentity.subjectKey`). Before this, every `signed_by`
    /// entry counted, so an executor satisfied SoD with sybil addresses.
    bytes32[] private _roster;

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
    error EmptyRoster();
    error RosterTooLarge(uint256 size);
    error DuplicateRosterMember(bytes32 member);
    /// A roster that cannot seat a proposer, `minApprovers` approvers and an
    /// executor who are all distinct can never Allow.
    error RosterTooSmall(uint256 size, uint8 minApprovers);

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address envelopes_,
        uint8 minApprovers_,
        bytes32[] memory roster_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (envelopes_ == address(0)) revert ZeroEnvelopes();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        if (minApprovers_ == 0) revert MinApproversTooLow();
        if (roster_.length == 0) revert EmptyRoster();
        if (roster_.length > 64) revert RosterTooLarge(roster_.length);
        // proposer + approvers (the executor may be outside the roster)
        if (roster_.length < uint256(minApprovers_) + 1) revert RosterTooSmall(roster_.length, minApprovers_);
        for (uint256 i = 0; i < roster_.length; ++i) {
            for (uint256 j = i + 1; j < roster_.length; ++j) {
                if (roster_[i] == roster_[j]) revert DuplicateRosterMember(roster_[i]);
            }
        }
        _roster = roster_;

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        envelopes = IMultiSigEnvelope(envelopes_);
        minApprovers = minApprovers_;
    }

    /// The envelope this protocol reads. Same shape as
    /// `ThresholdApproval.approvalEnvelopeId`, but keyed by this contract's
    /// address, so it is this protocol's own record (PBA-L2-013).
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

        IMultiSigEnvelope.Envelope memory e = envelopes.getEnvelope(envelopeId);
        // PBA-L2-013/-035: the proposer must be a roster member. `initiator` is
        // now bound to the drafting address, so it cannot be a fake identity;
        // an envelope drafted by anyone else is ignored for every verdict.
        if (!_inRoster(e.initiator)) {
            return (Verdict.RequireApproval, REASON_FOREIGN_PROPOSER, requiredSigners);
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Rejected) {
            return (Verdict.Deny, REASON_REJECTED, requiredSigners);
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Closed) {
            return (Verdict.Deny, REASON_WITHDRAWN, requiredSigners);
        }

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
            // PBA-L2-013: only roster members are approvers. A sybil address
            // outside the roster signs nothing that counts here.
            if (_inRoster(e.signed_by[i])) ++eligible;
        }

        if (eligible < minApprovers) {
            return (Verdict.RequireApproval, REASON_PENDING, requiredSigners);
        }
        return (Verdict.Allow, REASON_SATISFIED, requiredSigners);
    }

    /// The roster in force (PBA-L2-013).
    function roster() external view returns (bytes32[] memory) {
        return _roster;
    }

    function _inRoster(bytes32 who) private view returns (bool) {
        for (uint256 i = 0; i < _roster.length; ++i) {
            if (_roster[i] == who) return true;
        }
        return false;
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
