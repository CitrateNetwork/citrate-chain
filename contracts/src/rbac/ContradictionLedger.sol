// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title ContradictionLedger — Belnap 4-valued state ledger
/// @notice Records contradictions (Belnap "B" state) preserved in the
///         system. The demo-distinctive moment: when two attested
///         sources disagree, the system does NOT silently reconcile —
///         it records the contradiction explicitly, surfacing it for
///         human investigation.
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/ContradictionStateMachine.tla`
/// @dev Cited invariants:
///   - `BelnapBImpliesTwoDistinctSources` — every recorded
///     contradiction has two distinct source attestations.
///   - `ReportRequiresValueDifference` — `report()` reverts when
///     `value_a == value_b` (same value is not a contradiction).
///   - `ResolutionRequiresDecisionId` — `resolve()` reverts unless
///     a non-zero `decision_id` is provided (referencing
///     AgentDecisionRegistry).
///   - `NotExistEmpty` — non-existent contradiction_ids return zero
///     records and don't appear in any index.
///   - `OpenIsInitial` — `report()` always lands in Open.
///   - `EscalateOnlyFromOpen` — `escalate()` reverts unless current
///     state is Open.
///   - `WithdrawnIsTerminal` / `WithdrawnHasNoResolution` — Withdrawn
///     is a sink without a resolution_decision link.
///
/// @dev Per `03_RBAC_CONTRACTS.md` § 6. DPF-02 deliverable.
contract ContradictionLedger {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice Contradiction lifecycle state. Stored as a string for
    ///         forward compatibility (matches the V2 AgentDecisionRegistry
    ///         pattern of tagged-string status fields).
    string internal constant STATE_OPEN = "Open";
    string internal constant STATE_INVESTIGATING = "Investigating";
    string internal constant STATE_RESOLVED_A = "Resolved-A";
    string internal constant STATE_RESOLVED_B = "Resolved-B";
    string internal constant STATE_RESOLVED_OTHER = "Resolved-Other";
    string internal constant STATE_WITHDRAWN = "Withdrawn";

    struct Contradiction {
        bytes32 contradiction_id;
        bytes32 subject;
        string  field;
        bytes32 source_a;
        bytes32 source_b;
        string  value_a;
        string  value_b;
        bytes32 detected_by;
        bytes32 corr_id;
        uint64  ts;
        string  state;
        bytes32 resolution_decision;
        bool    exists;
    }

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 contradiction_id => Contradiction) private _contradictions;
    mapping(bytes32 subject => bytes32[]) private _by_subject;

    /// @notice Authorized resolvers (admin set; report() is open-permission).
    mapping(address => bool) public is_resolver;

    /// @notice Authorized contradiction detectors. CHAIN-B-C023: `report`
    ///         USED to be fully permissionless, letting anyone push any
    ///         subject to `Deny` through `IncidentEscalation.check` and, by
    ///         filing thousands of reports, grow the unbounded `_by_subject`
    ///         array until the policy check runs out of gas permanently. Only
    ///         governance-authorized detectors may now file.
    mapping(address => bool) public is_detector;

    /// @notice Governance admin (root-tenant multi-sig executor).
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    event ContradictionReported(
        bytes32 indexed contradiction_id,
        bytes32 indexed subject,
        string field
    );
    event ContradictionEscalated(
        bytes32 indexed contradiction_id,
        bytes32 indexed corr_id
    );
    event ContradictionResolved(
        bytes32 indexed contradiction_id,
        string state,
        bytes32 resolution_decision
    );
    event ContradictionWithdrawn(
        bytes32 indexed contradiction_id,
        bytes32 indexed corr_id
    );
    event ResolverSet(address indexed resolver, bool authorized);
    event DetectorSet(address indexed detector, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotResolver(address caller);
    /// CHAIN-B-C023: caller is not an authorized contradiction detector.
    error NotDetector(address caller);
    error ZeroGovernance();
    error AlreadyExists(bytes32 contradiction_id);
    error DoesNotExist(bytes32 contradiction_id);
    error EqualValues();
    error EqualSources();
    error EmptyField();
    error InvalidStateForEscalate(string current_state);
    error InvalidStateForResolve(string current_state);
    error InvalidStateForWithdraw(string current_state);
    error InvalidResolutionState(string state);
    error ZeroResolutionDecision();
    error ZeroSubject();

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = InitialAdmin.check(initialGovernance); // PBA-L2-002: never the CREATE2 factory
    }

    // ── Governance transfer (two-step) ──────────────────────────────

    /// @notice Governance nominated to take over, pending its own
    ///         acceptance. Zero when no transfer is in flight.
    address public pendingGovernance;

    /// @notice Emitted when a transfer is proposed.
    event GovernanceTransferStarted(address indexed from, address indexed to);
    /// @notice Emitted when the nominee accepts and governance moves.
    event GovernanceTransferred(address indexed from, address indexed to);

    error NotPendingGovernance(address caller);

    /// @notice Nominate `newGovernance`. It does not take effect until the
    ///         nominee calls {acceptGovernance}.
    ///
    /// @dev Two-step on purpose. `governance` gates every admin operation on
    ///      this contract and there is no recovery path: a one-step setter
    ///      pointed at a typo, an address on the wrong chain, or a contract
    ///      that cannot call back would brick administration permanently and
    ///      the only remedy would be redeploying and re-booking the address
    ///      across the federation. Requiring the nominee to prove it can
    ///      transact makes that unreachable.
    ///
    ///      Passing `address(0)` clears a pending nomination.
    function transferGovernance(address newGovernance) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        pendingGovernance = newGovernance;
        emit GovernanceTransferStarted(governance, newGovernance);
    }

    /// @notice Accept a pending nomination. Only the nominee may call this.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) {
            revert NotPendingGovernance(msg.sender);
        }
        address previous = governance;
        governance = msg.sender;
        pendingGovernance = address(0);
        emit GovernanceTransferred(previous, msg.sender);
    }

    // ── Governance ──────────────────────────────────────────────────

    function setResolver(address resolver, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_resolver[resolver] = authorized;
        emit ResolverSet(resolver, authorized);
    }

    /// @notice Authorize or de-authorize a contradiction detector.
    ///         CHAIN-B-C023: gates `report` so open-contradiction griefing
    ///         and unbounded-array gas exhaustion require an authorized key.
    function setDetector(address detector, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_detector[detector] = authorized;
        emit DetectorSet(detector, authorized);
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Open-permission report. Any attested source can report
    ///         a contradiction.
    /// @dev Cites BelnapBImpliesTwoDistinctSources +
    ///      ReportRequiresValueDifference. Both invariants enforced
    ///      in the revert paths below.
    function report(
        bytes32 contradiction_id,
        bytes32 subject,
        string calldata field_,
        bytes32 source_a,
        bytes32 source_b,
        string calldata value_a,
        string calldata value_b,
        bytes32 detected_by,
        bytes32 corr_id
    ) external {
        // CHAIN-B-C023: only authorized detectors may file. Closes the
        // permissionless forced-`Deny` grief and the unbounded `_by_subject`
        // growth that could brick `IncidentEscalation.check` on gas.
        if (!is_detector[msg.sender]) revert NotDetector(msg.sender);
        if (_contradictions[contradiction_id].exists) {
            revert AlreadyExists(contradiction_id);
        }
        if (subject == bytes32(0)) revert ZeroSubject();
        if (bytes(field_).length == 0) revert EmptyField();
        // BelnapBImpliesTwoDistinctSources
        if (source_a == source_b) revert EqualSources();
        // ReportRequiresValueDifference
        if (keccak256(bytes(value_a)) == keccak256(bytes(value_b))) {
            revert EqualValues();
        }

        _contradictions[contradiction_id] = Contradiction({
            contradiction_id: contradiction_id,
            subject: subject,
            field: field_,
            source_a: source_a,
            source_b: source_b,
            value_a: value_a,
            value_b: value_b,
            detected_by: detected_by,
            corr_id: corr_id,
            ts: uint64(block.timestamp),
            state: STATE_OPEN,
            resolution_decision: bytes32(0),
            exists: true
        });
        _by_subject[subject].push(contradiction_id);
        emit ContradictionReported(contradiction_id, subject, field_);
    }

    /// @notice Move Open → Investigating. Anyone may escalate (the
    ///         action records who via the corr_id).
    /// @dev Cites EscalateOnlyFromOpen.
    function escalate(bytes32 contradiction_id, bytes32 corr_id) external {
        Contradiction storage c = _contradictions[contradiction_id];
        if (!c.exists) revert DoesNotExist(contradiction_id);
        if (keccak256(bytes(c.state)) != keccak256(bytes(STATE_OPEN))) {
            revert InvalidStateForEscalate(c.state);
        }
        c.state = STATE_INVESTIGATING;
        emit ContradictionEscalated(contradiction_id, corr_id);
    }

    /// @notice Admin-gated resolution. Must reference a non-zero
    ///         decision_id from AgentDecisionRegistry.
    /// @dev Cites ResolutionRequiresDecisionId.
    /// @param resolution_state One of "Resolved-A", "Resolved-B",
    ///        "Resolved-Other".
    function resolve(
        bytes32 contradiction_id,
        string calldata resolution_state,
        bytes32 decision_id,
        bytes32 corr_id
    ) external {
        if (!is_resolver[msg.sender]) revert NotResolver(msg.sender);
        Contradiction storage c = _contradictions[contradiction_id];
        if (!c.exists) revert DoesNotExist(contradiction_id);
        if (
            keccak256(bytes(c.state)) != keccak256(bytes(STATE_OPEN)) &&
            keccak256(bytes(c.state)) != keccak256(bytes(STATE_INVESTIGATING))
        ) {
            revert InvalidStateForResolve(c.state);
        }
        if (decision_id == bytes32(0)) revert ZeroResolutionDecision();

        bytes32 stateHash = keccak256(bytes(resolution_state));
        if (
            stateHash != keccak256(bytes(STATE_RESOLVED_A)) &&
            stateHash != keccak256(bytes(STATE_RESOLVED_B)) &&
            stateHash != keccak256(bytes(STATE_RESOLVED_OTHER))
        ) {
            revert InvalidResolutionState(resolution_state);
        }

        c.state = resolution_state;
        c.resolution_decision = decision_id;
        emit ContradictionResolved(contradiction_id, resolution_state, decision_id);
        // Suppress unused warning for corr_id while keeping the audit-
        // trail intent — it is referenced by the resolver's off-chain
        // workflow that emits a parallel AgentDecisionRegistry record
        // tagged with this same corr_id.
        corr_id;
    }

    /// @notice Withdraw a contradiction (no resolution decision).
    ///         Used when the report itself was incorrect.
    /// @dev Cites WithdrawnIsTerminal / WithdrawnHasNoResolution —
    ///      Withdrawn never has a resolution_decision attached.
    function withdraw(bytes32 contradiction_id, bytes32 corr_id) external {
        if (!is_resolver[msg.sender]) revert NotResolver(msg.sender);
        Contradiction storage c = _contradictions[contradiction_id];
        if (!c.exists) revert DoesNotExist(contradiction_id);
        if (
            keccak256(bytes(c.state)) != keccak256(bytes(STATE_OPEN)) &&
            keccak256(bytes(c.state)) != keccak256(bytes(STATE_INVESTIGATING))
        ) {
            revert InvalidStateForWithdraw(c.state);
        }
        c.state = STATE_WITHDRAWN;
        // resolution_decision stays bytes32(0) by invariant.
        emit ContradictionWithdrawn(contradiction_id, corr_id);
    }

    // ── Read views ──────────────────────────────────────────────────

    function getContradiction(bytes32 contradiction_id)
        external view returns (Contradiction memory)
    {
        Contradiction storage c = _contradictions[contradiction_id];
        if (!c.exists) revert DoesNotExist(contradiction_id);
        return c;
    }

    function exists(bytes32 contradiction_id) external view returns (bool) {
        return _contradictions[contradiction_id].exists;
    }

    function bySubject(bytes32 subject) external view returns (bytes32[] memory) {
        return _by_subject[subject];
    }

    /// @notice Whether a subject currently has any open or investigating
    ///         contradictions. Used by the kit's BelnapBadge "B" state.
    function hasOpenContradiction(bytes32 subject) external view returns (bool) {
        bytes32[] storage ids = _by_subject[subject];
        for (uint256 i; i < ids.length; ++i) {
            Contradiction storage c = _contradictions[ids[i]];
            bytes32 sh = keccak256(bytes(c.state));
            if (
                sh == keccak256(bytes(STATE_OPEN)) ||
                sh == keccak256(bytes(STATE_INVESTIGATING))
            ) {
                return true;
            }
        }
        return false;
    }
}
