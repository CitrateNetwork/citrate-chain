// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";

/// Minimal view of the deployed `ContradictionLedger` (DPF-02, `rbac/`).
interface IContradictionLedger {
    struct Contradiction {
        bytes32 contradiction_id;
        bytes32 subject;
        string field;
        bytes32 source_a;
        bytes32 source_b;
        string value_a;
        string value_b;
        bytes32 detected_by;
        bytes32 corr_id;
        uint64 ts;
        string state;
        bytes32 resolution_decision;
        bool exists;
    }

    function hasOpenContradiction(bytes32 subject) external view returns (bool);
    function bySubject(bytes32 subject) external view returns (bytes32[] memory);
    function getContradiction(bytes32 contradiction_id) external view returns (Contradiction memory);
}

/// @title IncidentEscalation — an agent under an open contradiction slows down
/// @notice citrate-quorum QRM-S6.7. Seed template 8 of 8.
///
/// While an agent has an unresolved contradiction recorded against it, its
/// actions stop being routine. First they need a human. Past the SLA, they stop
/// entirely.
///
/// | State | Verdict |
/// |---|---|
/// | No open contradiction | `Allow` |
/// | Open, within SLA | `RequireApproval` — a human takes this one |
/// | Open, past SLA | `Deny` — the ladder has run out |
///
/// ## Why the SLA ends in `Deny` rather than another escalation
///
/// An escalation ladder whose last rung is "escalate harder" never terminates,
/// and in practice it degrades into everything sitting at the top rung being
/// approved by whoever is available. A breached SLA is a decision that something
/// is wrong enough to stop, and stopping is the only rung that cannot be
/// absorbed by a busy approver. Resolving the contradiction in
/// `ContradictionLedger` is what lifts it — the remedy is fixing the underlying
/// disagreement, not obtaining a bigger signature.
///
/// ## The subject is the agent
///
/// `ContradictionLedger` is keyed by an opaque `subject`. Here that is
/// `bytes32(ctx.agentSbtId)`: the contradiction is about the agent whose outputs
/// disagree. A human acting directly (`agentSbtId == 0`) is not gated by this
/// protocol at all, which is deliberate — a human is already the escalation
/// target, and gating them would make the ladder circular.
///
/// [`subjectOf`] is public so an integrator can confirm the encoding against a
/// real ledger entry, because a mismatch here fails open: the ledger simply
/// reports no contradictions for a subject nobody ever files under.
///
/// ## What it costs to read
///
/// `hasOpenContradiction` answers the common case in one call. Only when
/// something IS open does this walk `bySubject` to find the oldest one still
/// open, and that walk is bounded by [`maxScan`] — an agent with a very long
/// contradiction history must not make its own actions un-checkable, which
/// would be a slow-motion fail-open. When the scan is truncated it says so with
/// its own reason code instead of quietly returning the best it managed.
contract IncidentEscalation is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("IE_WRONG_TENANT");
    bytes32 public constant REASON_CLEAR = bytes32("IE_CLEAR");
    bytes32 public constant REASON_HUMAN_ACTING = bytes32("IE_HUMAN_ACTING");
    bytes32 public constant REASON_OPEN_INCIDENT = bytes32("IE_OPEN_INCIDENT");
    bytes32 public constant REASON_SLA_BREACHED = bytes32("IE_SLA_BREACHED");
    bytes32 public constant REASON_SCAN_TRUNCATED = bytes32("IE_SCAN_TRUNCATED");

    /// Lifecycle states that count as still open. Mirrors
    /// `ContradictionLedger`'s string states; anything else is resolved,
    /// withdrawn, or unknown-and-therefore-not-our-problem.
    bytes32 private constant STATE_OPEN = keccak256(bytes("Open"));
    bytes32 private constant STATE_INVESTIGATING = keccak256(bytes("Investigating"));

    bytes32 public immutable tenant;
    IContradictionLedger public immutable contradictions;
    /// Seconds an open contradiction may stand before actions stop.
    uint64 public immutable slaSeconds;
    /// Bound on the per-check history walk.
    uint256 public immutable maxScan;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;
    bytes32[] private _responders;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroLedger();
    error EmptySpec();
    error EmptyResponders();
    error ZeroSla();
    error ZeroMaxScan();

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address contradictions_,
        bytes32[] memory responders_,
        uint64 slaSeconds_,
        uint256 maxScan_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (contradictions_ == address(0)) revert ZeroLedger();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        if (responders_.length == 0) revert EmptyResponders();
        // A zero SLA would make every open contradiction an instant hard stop,
        // skipping the human rung entirely — that is a different control, and it
        // should be configured as one rather than arrived at by leaving a field
        // unset.
        if (slaSeconds_ == 0) revert ZeroSla();
        if (maxScan_ == 0) revert ZeroMaxScan();

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        contradictions = IContradictionLedger(contradictions_);
        _responders = responders_;
        slaSeconds = slaSeconds_;
        maxScan = maxScan_;
    }

    /// The `ContradictionLedger` subject key for an agent.
    function subjectOf(uint256 agentSbtId) public pure returns (bytes32) {
        return bytes32(agentSbtId);
    }

    /// @inheritdoc IGovernanceProtocol
    function check(bytes32 tenantId, bytes32, ActionContext calldata ctx)
        external
        view
        override
        returns (Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners)
    {
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, new bytes32[](0));
        }
        // A human acting directly is already the escalation target. Gating them
        // would make the ladder circular.
        if (ctx.agentSbtId == 0) {
            return (Verdict.Allow, REASON_HUMAN_ACTING, new bytes32[](0));
        }

        bytes32 subject = subjectOf(ctx.agentSbtId);
        if (!contradictions.hasOpenContradiction(subject)) {
            return (Verdict.Allow, REASON_CLEAR, new bytes32[](0));
        }

        bytes32[] memory ids = contradictions.bySubject(subject);
        uint256 scanned = ids.length > maxScan ? maxScan : ids.length;
        uint64 oldestOpen = type(uint64).max;
        for (uint256 i = 0; i < scanned; ++i) {
            IContradictionLedger.Contradiction memory c = contradictions.getContradiction(ids[i]);
            if (!_isOpen(c.state)) continue;
            if (c.ts < oldestOpen) oldestOpen = c.ts;
        }

        if (oldestOpen == type(uint64).max) {
            // The ledger says something is open but the scanned window did not
            // reach it. Saying so is the point: silently reporting "within SLA"
            // would turn a truncated read into a permissive answer.
            if (ids.length > maxScan) {
                return (Verdict.Deny, REASON_SCAN_TRUNCATED, _responders);
            }
            return (Verdict.Allow, REASON_CLEAR, new bytes32[](0));
        }

        if (block.timestamp > oldestOpen + slaSeconds) {
            return (Verdict.Deny, REASON_SLA_BREACHED, _responders);
        }
        return (Verdict.RequireApproval, REASON_OPEN_INCIDENT, _responders);
    }

    function _isOpen(string memory state) private pure returns (bool) {
        bytes32 h = keccak256(bytes(state));
        return h == STATE_OPEN || h == STATE_INVESTIGATING;
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }

    function responders() external view returns (bytes32[] memory) {
        return _responders;
    }
}
