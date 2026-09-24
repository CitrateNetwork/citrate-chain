// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";
import {IMultiSigEnvelope} from "./ThresholdApproval.sol";

/// @title ChangeControlBoard — review window, board approval, timelock
/// @notice citrate-quorum QRM-S6.7. Seed template 6 of 8.
///
/// The ceremony a regulated change goes through: proposed → **visible for a
/// review window** → approved by the board → **held for a timelock** →
/// executable. Every stage is read from the timestamps the deployed
/// `MultiSigEnvelope` already records, so nothing here keeps a second clock.
///
/// | Stage | Read from |
/// |---|---|
/// | Proposed | the envelope exists |
/// | Review window elapsed | `created_at + reviewWindow` |
/// | Board approved | `signed_by` ∩ board ≥ `threshold` |
/// | Timelock elapsed | `signed_at + timelock` |
///
/// ## Why the review window is checked before the approvals
///
/// A board that can approve the instant a change is filed has not reviewed it,
/// and if this checked approvals first, an operator would see "approved, now
/// wait" — which reads as bureaucracy. Checking the window first produces the
/// true sentence: "this is still in its review period", which is what the
/// control is actually for. Signatures collected during the window still count;
/// what the window gates is the *verdict*, not the signing.
///
/// ## Why the timelock runs from `signed_at` and not from now
///
/// `MultiSigEnvelope` stamps `signed_at` when the threshold is reached. Running
/// the timelock from that instant means the delay is a property of the decision,
/// not of when someone got round to executing it — so a change approved on
/// Friday is executable on Monday whether or not anyone tried in between.
///
/// A caveat worth stating: `signed_at` is set against the envelope's OWN
/// threshold, which is not this protocol's board threshold. Where the two
/// differ, the timelock starts when the envelope considered itself signed. A
/// deployment that wants them to coincide drafts the envelope with the board's
/// threshold — [`boardThreshold`] is public so it can.
///
/// ## What "vote" means here
///
/// The board's signatures are the vote. A weighted tally is a different
/// mechanism with an unresolved basis (planset Q7) and lives in `VoteAllowance`
/// plus whatever governor consumes it; building one in here would quietly decide
/// Q7 by implementing it.
contract ChangeControlBoard is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("CCB_WRONG_TENANT");
    bytes32 public constant REASON_NOT_PROPOSED = bytes32("CCB_NOT_PROPOSED");
    bytes32 public constant REASON_IN_REVIEW = bytes32("CCB_IN_REVIEW");
    bytes32 public constant REASON_PENDING_BOARD = bytes32("CCB_PENDING_BOARD");
    bytes32 public constant REASON_IN_TIMELOCK = bytes32("CCB_IN_TIMELOCK");
    bytes32 public constant REASON_APPROVED = bytes32("CCB_APPROVED");
    bytes32 public constant REASON_REJECTED = bytes32("CCB_REJECTED");
    bytes32 public constant REASON_WITHDRAWN = bytes32("CCB_WITHDRAWN");

    bytes32 public immutable tenant;
    IMultiSigEnvelope public immutable envelopes;
    uint64 public immutable reviewWindow;
    uint64 public immutable timelock;
    uint8 public immutable boardThreshold;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;
    bytes32[] private _board;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroEnvelopes();
    error EmptySpec();
    error EmptyBoard();
    error BoardTooLarge(uint256 size);
    error DuplicateBoardMember(bytes32 member);
    error BadThreshold(uint8 threshold, uint256 board);

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address envelopes_,
        bytes32[] memory board_,
        uint8 boardThreshold_,
        uint64 reviewWindow_,
        uint64 timelock_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (envelopes_ == address(0)) revert ZeroEnvelopes();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        if (board_.length == 0) revert EmptyBoard();
        if (board_.length > 64) revert BoardTooLarge(board_.length);
        for (uint256 i = 0; i < board_.length; ++i) {
            for (uint256 j = i + 1; j < board_.length; ++j) {
                if (board_[i] == board_[j]) revert DuplicateBoardMember(board_[i]);
            }
        }
        if (boardThreshold_ == 0 || boardThreshold_ > board_.length) {
            revert BadThreshold(boardThreshold_, board_.length);
        }

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        envelopes = IMultiSigEnvelope(envelopes_);
        _board = board_;
        boardThreshold = boardThreshold_;
        reviewWindow = reviewWindow_;
        timelock = timelock_;
    }

    /// Same derivation as the other envelope-reading templates, so one change
    /// has one record however many protocols consult it.
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
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, new bytes32[](0));
        }

        bytes32 envelopeId = approvalEnvelopeId(actionClass, ctx.paramsHash, ctx.correlationId);
        IMultiSigEnvelope.EnvelopeState state = envelopes.getState(envelopeId);
        if (state == IMultiSigEnvelope.EnvelopeState.NotExist) {
            return (Verdict.RequireApproval, REASON_NOT_PROPOSED, _board);
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Rejected) {
            return (Verdict.Deny, REASON_REJECTED, new bytes32[](0));
        }
        if (state == IMultiSigEnvelope.EnvelopeState.Closed) {
            return (Verdict.Deny, REASON_WITHDRAWN, new bytes32[](0));
        }

        IMultiSigEnvelope.Envelope memory e = envelopes.getEnvelope(envelopeId);

        // The window first — see the header. Signing during it still counts.
        if (block.timestamp < e.created_at + reviewWindow) {
            return (Verdict.RequireApproval, REASON_IN_REVIEW, _board);
        }

        uint256 approvals;
        for (uint256 i = 0; i < _board.length; ++i) {
            for (uint256 j = 0; j < e.signed_by.length; ++j) {
                if (e.signed_by[j] == _board[i]) {
                    ++approvals;
                    break;
                }
            }
        }
        if (approvals < boardThreshold) {
            return (Verdict.RequireApproval, REASON_PENDING_BOARD, _board);
        }

        // `signed_at` is 0 until the ENVELOPE's own threshold is met. If the
        // board is satisfied but the envelope is not, the timelock has not
        // started — treating 0 as "long ago" would let a change execute with no
        // delay at all, which is the failure this control exists to prevent.
        if (e.signed_at == 0 || block.timestamp < e.signed_at + timelock) {
            return (Verdict.RequireApproval, REASON_IN_TIMELOCK, new bytes32[](0));
        }

        return (Verdict.Allow, REASON_APPROVED, new bytes32[](0));
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }

    function board() external view returns (bytes32[] memory) {
        return _board;
    }
}
