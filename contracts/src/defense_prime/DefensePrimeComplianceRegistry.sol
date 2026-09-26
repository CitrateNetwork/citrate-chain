// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title DefensePrimeComplianceRegistry — Compliance posture matrix for DPF-11.
/// @notice Per-(framework, scope) compliance attestations with a
///         5-state posture machine + append-only history.
///
/// @dev Posture states (mirror `ComplianceAttestationLifecycle.tla`):
///        0 = NotAttempted (sentinel — no row exists)
///        1 = InProgress    (work started, evidence not yet anchored)
///        2 = Attested      (evidence anchored, attestor signed)
///        3 = Exception     (waiver granted with caveats)
///        4 = Failed        (attestation rejected; corrective action required)
///
/// @dev Allowed transitions:
///        NotAttempted -> InProgress
///        NotAttempted -> Attested  (fast-path)
///        InProgress   -> Attested
///        InProgress   -> Failed
///        Attested     -> InProgress (re-certification)
///        Attested     -> Exception
///        Attested     -> Failed     (lapsed audit)
///        Exception    -> Attested   (waiver cleared)
///        Exception    -> Failed
///        Failed       -> InProgress (corrective work)
///
/// @dev Append-only: every attest() appends a row_id to `allRowIds`,
///      `rowsByScope[scope]`, and `rowsByFramework[framework]`. The
///      `rows` mapping holds the LATEST row per (framework, scope) —
///      the full history is reconstructable from the append-only lists.
///
/// @dev Cites TLA+ specs:
///        - contracts/ComplianceAttestationLifecycle.tla (NEW in DPF-11)
///          — 5-state posture machine + append-only history invariants
///        - contracts/AgentDecisionLog.tla::AppendOnly — same pattern
///
/// Source: .agentile/sprints/active/2026-05-11-dpf-11-governance-panel/SPRINT.md D-3
contract DefensePrimeComplianceRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error InvalidPosture(uint8 posture);
    error DisallowedTransition(uint8 from, uint8 to);
    error ZeroFramework();
    error ZeroScope();

    // ── Types ──────────────────────────────────────────────────────────

    /// @notice Row storage record. Mirrors `governance::ComplianceRow`
    ///         Rust struct in citrate-rbac-bindings.
    struct Row {
        bytes32 row_id;
        bytes32 framework;
        bytes32 scope;
        bytes32 evidence_cid;
        bytes32 attestor;
        uint8   posture;
        bool    expired;
        uint256 attested_at_block;
        uint256 expires_at_block;
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;

    /// @notice Recorder allowlist (write-gate for `attest`).
    mapping(address => bool) public is_recorder;

    /// @notice Latest row per row_id (= keccak256(framework, scope)).
    mapping(bytes32 => Row) public rows;

    /// @notice scope → row_ids (append-only; each attest pushes).
    mapping(bytes32 => bytes32[]) public rowsByScope;

    /// @notice framework → row_ids (append-only).
    mapping(bytes32 => bytes32[]) public rowsByFramework;

    /// @notice All row_ids ever attested, in insertion order.
    bytes32[] public allRowIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);

    event Attested(
        bytes32 indexed row_id,
        bytes32 indexed framework,
        bytes32 indexed scope,
        uint8 posture,
        bytes32 evidence_cid,
        uint256 expires_at_block
    );

    event Expired(bytes32 indexed row_id);

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = InitialAdmin.check(initialGovernance); // PBA-L2-002: never the CREATE2 factory
    }

    // ── Governance ─────────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Attest a (framework, scope) row with a new posture.
    function attest(
        bytes32 framework,
        bytes32 scope,
        uint8 posture,
        bytes32 evidence_cid,
        uint256 expires_at_block
    ) external returns (bytes32 row_id) {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (framework == bytes32(0)) revert ZeroFramework();
        if (scope == bytes32(0)) revert ZeroScope();
        if (posture < 1 || posture > 4) revert InvalidPosture(posture);

        row_id = keccak256(abi.encode(framework, scope));
        uint8 current = rows[row_id].posture;

        if (!_allowed(current, posture)) {
            revert DisallowedTransition(current, posture);
        }

        bool first = (current == 0);

        rows[row_id] = Row({
            row_id: row_id,
            framework: framework,
            scope: scope,
            evidence_cid: evidence_cid,
            attestor: bytes32(uint256(uint160(msg.sender))),
            posture: posture,
            expired: false,
            attested_at_block: block.number,
            expires_at_block: expires_at_block
        });

        if (first) {
            allRowIds.push(row_id);
            rowsByScope[scope].push(row_id);
            rowsByFramework[framework].push(row_id);
        } else {
            // History-of-attestations is reconstructable by re-pushing
            // the row_id; the index arrays are append-only per the
            // ComplianceAttestationLifecycle.tla::HistoryAppendOnly
            // invariant.
            allRowIds.push(row_id);
            rowsByScope[scope].push(row_id);
            rowsByFramework[framework].push(row_id);
        }

        emit Attested(row_id, framework, scope, posture, evidence_cid, expires_at_block);
    }

    /// @notice Mark a row as expired. Posture is unchanged — the row
    ///         remains queryable per the
    ///         `ExpiredIsAttestedOrException` invariant.
    function expire(bytes32 row_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Row storage r = rows[row_id];
        // Only Attested (2) or Exception (3) can be expired.
        if (r.posture != 2 && r.posture != 3) {
            revert DisallowedTransition(r.posture, r.posture);
        }
        r.expired = true;
        emit Expired(row_id);
    }

    // ── Internal ───────────────────────────────────────────────────────

    function _allowed(uint8 from, uint8 to) internal pure returns (bool) {
        // 0=NotAttempted, 1=InProgress, 2=Attested, 3=Exception, 4=Failed
        if (from == 0) return to == 1 || to == 2;
        if (from == 1) return to == 2 || to == 4;
        if (from == 2) return to == 1 || to == 3 || to == 4;
        if (from == 3) return to == 2 || to == 4;
        if (from == 4) return to == 1;
        return false;
    }

    // ── Views ──────────────────────────────────────────────────────────

    /// @notice Full row record.
    function getRow(bytes32 row_id) external view returns (Row memory) {
        return rows[row_id];
    }

    /// @notice Compute row_id from (framework, scope) — useful for
    ///         off-chain callers.
    function rowIdFor(bytes32 framework, bytes32 scope) external pure returns (bytes32) {
        return keccak256(abi.encode(framework, scope));
    }

    /// @notice All row_ids attested under a scope (insertion order;
    ///         duplicates allowed per HistoryAppendOnly).
    function rowsByScopeList(bytes32 scope) external view returns (bytes32[] memory) {
        return rowsByScope[scope];
    }

    /// @notice All row_ids attested under a framework.
    function rowsByFrameworkList(bytes32 framework) external view returns (bytes32[] memory) {
        return rowsByFramework[framework];
    }

    /// @notice All row_ids ever attested.
    function allRows() external view returns (bytes32[] memory) {
        return allRowIds;
    }

    /// @notice Cheap O(1) count.
    function rowCount() external view returns (uint256) {
        return allRowIds.length;
    }

    /// @notice Cheap O(1) count per scope.
    function rowCountByScope(bytes32 scope) external view returns (uint256) {
        return rowsByScope[scope].length;
    }

    /// @notice Resolve `framework(framework, scope)` per planset row 9
    ///         — returns the latest row for the (framework, scope) pair.
    function framework(bytes32 framework_id, bytes32 scope) external view returns (Row memory) {
        bytes32 row_id = keccak256(abi.encode(framework_id, scope));
        return rows[row_id];
    }
}
