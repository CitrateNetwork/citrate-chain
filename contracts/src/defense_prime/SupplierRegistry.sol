// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title SupplierRegistry — DefensePrime supplier lifecycle + qualification
/// @notice On-chain backing for the DPF-06 Suppliers panel. Tracks
///         each supplier's state through the planset state machine:
///
///           Pending → InReview → ReQualified → InReview → ...
///                                ├→ Probationary
///                                ├→ Suspended (governance-gated)
///                                └→ Rejected (governance-gated)
///
///         ReQualified can re-enter InReview when a re-qualification
///         is requested. Probationary is reversible; Suspended +
///         Rejected are terminal.
///
/// @dev Cited specs (composition):
///   - `formal/specs/contracts/ProcurementCronTick.tla` —
///     HumanGateBlocksProgression ratified by terminal-state
///     governance gate.
///   - `formal/specs/contracts/AgentDecisionLog.tla` — AppendOnly
///     ratified for the per-supplier history log (state changes
///     append a record; never mutate prior history).
///
/// @dev Cited invariants:
///   - **StateTransitionsMonotonic** — `setState` reverts on
///     transitions outside the allowed graph.
///   - **TerminalStatesGovernance** — `setState(Suspended)` and
///     `setState(Rejected)` revert unless caller is governance.
///   - **AppendOnlyHistory** — every state change appends to
///     `_history[supplier]`; existing entries never mutate.
///   - **ScopeIndexConsistent** — every registered supplier is
///     retrievable via `byScope(scope)`.
contract SupplierRegistry {
    // ── Types ───────────────────────────────────────────────────────

    enum State {
        Pending,        // 0 — newly registered, awaiting first review
        InReview,       // 1 — qualification dossier under review
        ReQualified,    // 2 — passed; cleared for full procurement
        Probationary,   // 3 — passed with restrictions
        Suspended,      // 4 — terminal-but-recoverable; governance-gated
        Rejected        // 5 — terminal; governance-gated
    }

    /// @notice One historical state-change record. Append-only.
    struct StateRecord {
        State state;
        uint64 ts;
        bytes32 corr_id;
        bytes32 signer;       // hashed user/agent who effected the change
        string  reason;
    }

    struct Supplier {
        bytes32 supplier_id;
        bytes32 scope;        // tenant scope
        State   state;
        uint64  registered_at;
        uint64  qualification_period_days; // planset default 365
        bool    exists;
    }

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 supplier_id => Supplier) private _suppliers;
    mapping(bytes32 supplier_id => StateRecord[]) private _history;
    mapping(bytes32 scope => bytes32[]) private _by_scope;
    mapping(uint8 state_idx => bytes32[]) private _by_state_global;

    address public governance;
    mapping(address => bool) public is_recorder;

    // ── Events ──────────────────────────────────────────────────────

    event SupplierRegistered(
        bytes32 indexed supplier_id,
        bytes32 indexed scope,
        uint64 qualification_period_days
    );
    event StateChanged(
        bytes32 indexed supplier_id,
        State indexed from_state,
        State indexed to_state,
        bytes32 corr_id
    );
    event RequalificationRequested(
        bytes32 indexed supplier_id,
        bytes32 indexed corr_id
    );
    event RecorderSet(address indexed recorder, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error ZeroGovernance();
    error SupplierAlreadyExists(bytes32 supplier_id);
    error SupplierDoesNotExist(bytes32 supplier_id);
    error InvalidTransition(State from_state, State to_state);
    error TerminalStateRequiresGovernance(State to_state);
    error EmptyReason();

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = InitialAdmin.check(initialGovernance); // PBA-L2-002: never the CREATE2 factory
    }

    // ── Governance ──────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Register a new supplier. Initial state is Pending.
    function register(
        bytes32 supplier_id,
        bytes32 scope,
        uint64 qualification_period_days,
        bytes32 corr_id,
        bytes32 signer
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (_suppliers[supplier_id].exists) {
            revert SupplierAlreadyExists(supplier_id);
        }

        _suppliers[supplier_id] = Supplier({
            supplier_id: supplier_id,
            scope: scope,
            state: State.Pending,
            registered_at: uint64(block.timestamp),
            qualification_period_days: qualification_period_days,
            exists: true
        });

        _history[supplier_id].push(StateRecord({
            state: State.Pending,
            ts: uint64(block.timestamp),
            corr_id: corr_id,
            signer: signer,
            reason: "registered"
        }));
        _by_scope[scope].push(supplier_id);
        _by_state_global[uint8(State.Pending)].push(supplier_id);

        emit SupplierRegistered(supplier_id, scope, qualification_period_days);
    }

    /// @notice Transition a supplier's state. Cited invariant:
    ///         StateTransitionsMonotonic + TerminalStatesGovernance.
    function setState(
        bytes32 supplier_id,
        State to_state,
        bytes32 corr_id,
        bytes32 signer,
        string calldata reason
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Supplier storage s = _suppliers[supplier_id];
        if (!s.exists) revert SupplierDoesNotExist(supplier_id);
        if (bytes(reason).length == 0) revert EmptyReason();
        if (!_isValidTransition(s.state, to_state)) {
            revert InvalidTransition(s.state, to_state);
        }
        // Terminal states require governance directly.
        if ((to_state == State.Suspended || to_state == State.Rejected) &&
            msg.sender != governance) {
            revert TerminalStateRequiresGovernance(to_state);
        }

        State from_state = s.state;
        s.state = to_state;
        _history[supplier_id].push(StateRecord({
            state: to_state,
            ts: uint64(block.timestamp),
            corr_id: corr_id,
            signer: signer,
            reason: reason
        }));
        _by_state_global[uint8(to_state)].push(supplier_id);

        emit StateChanged(supplier_id, from_state, to_state, corr_id);
    }

    /// @notice Request re-qualification — moves a ReQualified supplier
    ///         back into InReview. Convenience mutator.
    function requestRequalification(
        bytes32 supplier_id,
        bytes32 corr_id,
        bytes32 signer
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Supplier storage s = _suppliers[supplier_id];
        if (!s.exists) revert SupplierDoesNotExist(supplier_id);
        if (s.state != State.ReQualified && s.state != State.Probationary) {
            revert InvalidTransition(s.state, State.InReview);
        }
        s.state = State.InReview;
        _history[supplier_id].push(StateRecord({
            state: State.InReview,
            ts: uint64(block.timestamp),
            corr_id: corr_id,
            signer: signer,
            reason: "re-qualification requested"
        }));
        _by_state_global[uint8(State.InReview)].push(supplier_id);

        emit RequalificationRequested(supplier_id, corr_id);
        emit StateChanged(supplier_id, s.state, State.InReview, corr_id);
    }

    // ── Read views ──────────────────────────────────────────────────

    function get(bytes32 supplier_id) external view returns (Supplier memory) {
        Supplier storage s = _suppliers[supplier_id];
        if (!s.exists) revert SupplierDoesNotExist(supplier_id);
        return s;
    }

    function history(bytes32 supplier_id) external view returns (StateRecord[] memory) {
        return _history[supplier_id];
    }

    function byScope(bytes32 scope) external view returns (bytes32[] memory) {
        return _by_scope[scope];
    }

    function byState(State state) external view returns (bytes32[] memory) {
        return _by_state_global[uint8(state)];
    }

    function exists(bytes32 supplier_id) external view returns (bool) {
        return _suppliers[supplier_id].exists;
    }

    function historyLength(bytes32 supplier_id) external view returns (uint256) {
        return _history[supplier_id].length;
    }

    // ── Internal ────────────────────────────────────────────────────

    /// @dev State machine per planset 02_PROCUREMENT_AUTOMATION.md § 2:
    ///   Pending → InReview
    ///   InReview → {ReQualified, Probationary, Suspended, Rejected}
    ///   ReQualified → InReview (via requestRequalification)
    ///   Probationary → InReview (via requestRequalification)
    ///   Probationary → {Suspended, Rejected}
    ///   Suspended/Rejected: terminal (no outbound transitions)
    function _isValidTransition(State from_state, State to_state) internal pure returns (bool) {
        if (from_state == State.Pending) {
            return to_state == State.InReview;
        }
        if (from_state == State.InReview) {
            return to_state == State.ReQualified
                || to_state == State.Probationary
                || to_state == State.Suspended
                || to_state == State.Rejected;
        }
        if (from_state == State.ReQualified) {
            return to_state == State.InReview;
        }
        if (from_state == State.Probationary) {
            return to_state == State.InReview
                || to_state == State.Suspended
                || to_state == State.Rejected;
        }
        // Suspended + Rejected are terminal.
        return false;
    }
}
