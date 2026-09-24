// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title RoleGrantTenantIndex — Scope→user index sidecar (DPF-11)
/// @notice Maintains `mapping(bytes32 scope => bytes32[] user_ids)`
///         observed at grant time. Pairs with the existing
///         `RoleEscalation` (DPF-02 at `0x3130B9...`) which doesn't
///         expose a `byTenant(scope)` accessor; the off-chain
///         orchestrator calls `record(scope, user)` immediately after
///         the `RoleEscalation.setBaseRole(...)` /
///         `requestElevation(...)` tx.
///
/// @dev Append-only. Records cannot be removed; a user appears in
///      `byTenant(scope)` for the lifetime of the chain.
///
/// @dev Per `07_DATA_SOURCES.md` Panel 9 IPC
///      `defense_prime-gov-roles(scope) → RoleEscalation.byTenant(scope) + ...`.
///      The planset's wording maps to a method that doesn't exist on
///      the deployed RoleEscalation; this sidecar provides the same
///      surface without modifying the existing contract.
///
/// @dev Same pattern as DPF-09's CrossOrgIndex (scope→envelopes).
///      Tests, governance gating, and storage layout intentionally
///      mirror it for consistency.
///
/// Source: .agentile/sprints/active/2026-05-11-dpf-11-governance-panel/SPRINT.md D-1
contract RoleGrantTenantIndex {
    // ── Errors ─────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error AlreadyIndexed(bytes32 scope, bytes32 user);

    // ── Storage ────────────────────────────────────────────────────

    address public governance;

    /// @notice Recorder allowlist (write-gate for `record`).
    mapping(address => bool) public is_recorder;

    /// @notice scope → user_ids (append-only; each (scope, user) pair
    ///         is recorded once via the `is_indexed` dedup mapping).
    mapping(bytes32 => bytes32[]) public byScopeList;

    /// @notice `keccak256(scope || user) → bool` — first-seen flag.
    mapping(bytes32 => bool) public is_indexed;

    // ── Events ─────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event Indexed(bytes32 indexed scope, bytes32 indexed user);

    // ── Constructor ────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance ─────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────

    /// @notice Record a user under a scope. Idempotent per (scope,
    ///         user) pair (reverts if already indexed).
    function record(bytes32 scope, bytes32 user) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        bytes32 key = keccak256(abi.encode(scope, user));
        if (is_indexed[key]) revert AlreadyIndexed(scope, user);
        byScopeList[scope].push(user);
        is_indexed[key] = true;
        emit Indexed(scope, user);
    }

    // ── Views ──────────────────────────────────────────────────────

    /// @notice All user_ids recorded under a scope. Maps to IPC
    ///         `defense_prime-gov-roles(scope)`.
    function byTenant(bytes32 scope) external view returns (bytes32[] memory) {
        return byScopeList[scope];
    }

    /// @notice Number of users indexed under a scope.
    function countByScope(bytes32 scope) external view returns (uint256) {
        return byScopeList[scope].length;
    }

    /// @notice Is (scope, user) already indexed?
    function isIndexed(bytes32 scope, bytes32 user) external view returns (bool) {
        return is_indexed[keccak256(abi.encode(scope, user))];
    }
}
