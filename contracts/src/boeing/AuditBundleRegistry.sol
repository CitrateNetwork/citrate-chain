// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title AuditBundleRegistry — Session-bundle anchoring for the BFR-10
///        Assistant pane.
/// @notice Append-only registry of "audit bundles" — Merkle-root anchors
///         over a contiguous range of `AgentDecisionRegistryV2` entries,
///         pinned to an IPFS CID for replay.
///
/// @dev Three bundle kinds:
///        0 = Session  — `anchorSession(session_id, ...)`; the assistant
///                       pane's "Save conversation" path
///        1 = Export   — `anchor(kind=1, ...)`; a governance/audit-log
///                       export for FedRAMP evidence
///        2 = Replay   — `anchor(kind=2, ...)`; a "replay this
///                       conversation" reproducibility anchor
///
/// @dev Append-only: a `bundle_id` is recorded exactly once and never
///      rewritten. The (scope → bundle_ids) index is also append-only.
///
/// @dev Cites TLA+ specs:
///        - contracts/AgentDecisionLog.tla::AppendOnly — bundles
///          follow the same append-only pattern as decisions
///        - contracts/AgentDecisionLog.tla::ByTenantDeterministic —
///          bundlesByScope read-back parity
///        - gui/AssistantPaneFlow.tla — caller-side state machine
///          (the assistant pane anchors on close-with-save)
///
/// @dev Recorder authorization mirrors AgentDecisionRegistryV2 (BFR-02).
///      The off-chain orchestrator (typically a Citrate node operator
///      or the assistant pane's host) holds the recorder grant.
///
/// Source: .agentile/sprints/active/2026-05-11-bfr-10-assistant-pane/SPRINT.md D-2
contract AuditBundleRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error BundleAlreadyExists(bytes32 bundle_id);
    error ZeroBundleId();
    error InvalidKind(uint8 kind);

    // ── Types ──────────────────────────────────────────────────────────

    /// @notice Bundle storage record. Mirrors the
    ///         `apps_contracts::BundleView` Rust struct in
    ///         citrate-rbac-bindings.
    struct Bundle {
        bytes32 bundle_id;
        bytes32 session_id;
        bytes32 scope;
        bytes32 merkle_root;
        bytes32 ipfs_cid;
        bytes32 anchored_by;
        uint8 kind;
        uint256 anchored_at_block;
        uint256 entry_count;
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;

    /// @notice Recorder allowlist (write-gate for `anchorSession` /
    ///         `anchor`). Set by governance.
    mapping(address => bool) public is_recorder;

    /// @notice bundle_id → Bundle (append-only; never overwritten).
    mapping(bytes32 => Bundle) public bundles;

    /// @notice bundle_id → exists flag (cheap O(1) check that doesn't
    ///         require loading the full struct).
    mapping(bytes32 => bool) public is_anchored;

    /// @notice session_id → latest bundle_id anchored for that session.
    ///         Overwrites are permitted (latest-wins semantics) so the
    ///         pane's "save again" path works; the full history is
    ///         still recoverable via `byScope` + filter.
    mapping(bytes32 => bytes32) public latestBundleBySession;

    /// @notice scope → all bundle_ids anchored under that scope
    ///         (append-only).
    mapping(bytes32 => bytes32[]) public bundlesByScope;

    /// @notice All bundle_ids ever anchored, in insertion order.
    bytes32[] public allBundleIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);

    event BundleAnchored(
        bytes32 indexed bundle_id,
        bytes32 indexed session_id,
        bytes32 indexed scope,
        uint8 kind,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint256 entry_count
    );

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance ─────────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Anchor a session bundle. Convenience wrapper around
    ///         `anchor(kind=0, ...)` for the assistant pane's
    ///         common path.
    function anchorSession(
        bytes32 bundle_id,
        bytes32 session_id,
        bytes32 scope,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint256 entry_count
    ) external {
        _anchor(bundle_id, session_id, scope, merkle_root, ipfs_cid, entry_count, 0);
    }

    /// @notice General-purpose anchor for Export / Replay bundles. The
    ///         pane uses `anchorSession`; the governance panel
    ///         (BFR-11) and the replay flow (BFR-10b) use this.
    function anchor(
        uint8 kind,
        bytes32 bundle_id,
        bytes32 session_id,
        bytes32 scope,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint256 entry_count
    ) external {
        if (kind > 2) revert InvalidKind(kind);
        _anchor(bundle_id, session_id, scope, merkle_root, ipfs_cid, entry_count, kind);
    }

    function _anchor(
        bytes32 bundle_id,
        bytes32 session_id,
        bytes32 scope,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint256 entry_count,
        uint8 kind
    ) internal {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (bundle_id == bytes32(0)) revert ZeroBundleId();
        if (is_anchored[bundle_id]) revert BundleAlreadyExists(bundle_id);

        bundles[bundle_id] = Bundle({
            bundle_id: bundle_id,
            session_id: session_id,
            scope: scope,
            merkle_root: merkle_root,
            ipfs_cid: ipfs_cid,
            anchored_by: bytes32(uint256(uint160(msg.sender))),
            kind: kind,
            anchored_at_block: block.number,
            entry_count: entry_count
        });
        is_anchored[bundle_id] = true;
        latestBundleBySession[session_id] = bundle_id;
        bundlesByScope[scope].push(bundle_id);
        allBundleIds.push(bundle_id);

        emit BundleAnchored(
            bundle_id,
            session_id,
            scope,
            kind,
            merkle_root,
            ipfs_cid,
            entry_count
        );
    }

    // ── Views ──────────────────────────────────────────────────────────

    /// @notice Full bundle record by id. Reverts implicitly with the
    ///         zero struct if not present — callers should check
    ///         `is_anchored[bundle_id]` first.
    function getBundle(bytes32 bundle_id) external view returns (Bundle memory) {
        return bundles[bundle_id];
    }

    /// @notice All bundle_ids anchored under a scope.
    function bundlesByScopeList(bytes32 scope) external view returns (bytes32[] memory) {
        return bundlesByScope[scope];
    }

    /// @notice Latest bundle_id for a session (latest-wins).
    function latestSessionBundle(bytes32 session_id) external view returns (bytes32) {
        return latestBundleBySession[session_id];
    }

    /// @notice All bundle_ids ever anchored.
    function allBundles() external view returns (bytes32[] memory) {
        return allBundleIds;
    }

    /// @notice Cheap O(1) count.
    function bundleCount() external view returns (uint256) {
        return allBundleIds.length;
    }

    /// @notice Cheap O(1) count per scope.
    function bundleCountByScope(bytes32 scope) external view returns (uint256) {
        return bundlesByScope[scope].length;
    }
}
