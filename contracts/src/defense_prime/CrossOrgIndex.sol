// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title CrossOrgIndex — Scope-to-envelope index sidecar (DPF-09)
/// @notice Maintains `mapping(bytes32 scope => bytes32[] envelope_ids)`
///         observed at envelope-draft time. Pairs with the existing
///         `MultiSigEnvelope` (DPF-02 at `0x05825775...`) which doesn't
///         carry a scope field in its events; off-chain orchestrators
///         call `record(scope, envelope_id)` immediately after the
///         envelope's `draft(...)` tx to populate the index.
///
/// @dev Append-only. Records cannot be removed; an envelope appears
///      in `byCrossOrg(scope)` for the lifetime of the chain.
///
/// @dev Per `07_DATA_SOURCES.md` Panel 7 IPC
///      `defense_prime-iot-list(scope) → MultiSigEnvelope.byCrossOrg(scope)`.
///      The planset's wording mapped to a method that doesn't exist
///      on the deployed MultiSigEnvelope; this sidecar provides the
///      same surface without modifying the existing contract.
///
///      See DPF-09 SPRINT.md decision D-3 for the option-B rationale.
contract CrossOrgIndex {
    // ── Errors ─────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error AlreadyIndexed(bytes32 envelope_id);

    // ── Storage ────────────────────────────────────────────────────

    address public governance;

    /// @notice Recorder allowlist (write-gate for `record`).
    mapping(address => bool) public is_recorder;

    /// @notice scope → envelope_ids (append-only).
    mapping(bytes32 => bytes32[]) public byScopeList;

    /// @notice envelope_id → scope it was indexed under (for sanity
    ///         + dedupe).
    mapping(bytes32 => bytes32) public envelopeScope;

    /// @notice envelope_id → first-seen flag.
    mapping(bytes32 => bool) public is_indexed;

    // ── Events ─────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event Indexed(bytes32 indexed scope, bytes32 indexed envelope_id);

    // ── Constructor ────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = InitialAdmin.check(initialGovernance); // PBA-L2-002: never the CREATE2 factory
    }

    // ── Governance ─────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────

    /// @notice Record an envelope under a tenant scope. Idempotent
    ///         per envelope_id (reverts if already indexed).
    function record(bytes32 scope, bytes32 envelope_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (is_indexed[envelope_id]) revert AlreadyIndexed(envelope_id);
        byScopeList[scope].push(envelope_id);
        envelopeScope[envelope_id] = scope;
        is_indexed[envelope_id] = true;
        emit Indexed(scope, envelope_id);
    }

    // ── Views ──────────────────────────────────────────────────────

    /// @notice All envelope_ids recorded under a scope. Maps to IPC
    ///         `defense_prime-iot-list(scope)`.
    function byCrossOrg(bytes32 scope) external view returns (bytes32[] memory) {
        return byScopeList[scope];
    }

    /// @notice Number of envelopes indexed under a scope.
    function countByScope(bytes32 scope) external view returns (uint256) {
        return byScopeList[scope].length;
    }
}
