// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title TripwireRegistry — FedRAMP AU-9 tripwire firing anchor (DPF-15).
/// @notice Per planset 04_FEDRAMP_COMPLIANCE.md § Tripwires, this
///         contract anchors tripwire firings as immutable on-chain
///         records. The 9 named FedRAMP tripwires
///         (TRIP-AC-001..TRIP-SI-001) fire into this registry; the
///         on-chain record is the load-bearing AU-9 evidence.
///
/// @dev 4-state firing lifecycle (mirrors TripwireFiringLifecycle.tla):
///        0 = NotFired      (sentinel)
///        1 = Fired         (immutable record on-chain)
///        2 = Acknowledged  (operator received the alert)
///        3 = Resolved      (incident closed)
///
/// @dev Severity is {0=Low, 1=Medium, 2=High, 3=Critical}.
///
/// @dev Once fired, severity + evidence_cid + tripwire_id + fired_by
///      are immutable. Only state transitions are permitted.
///
/// Source: .agentile/sprints/active/2026-05-11-dpf-15-fedramp-hardening/SPRINT.md D-1
contract TripwireRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error NotResolver(address caller);
    error AlreadyFired(bytes32 firing_id);
    error NotInState(bytes32 firing_id, uint8 expected, uint8 actual);
    error ZeroTripwireId();
    error InvalidSeverity(uint8 severity);

    // ── Types ──────────────────────────────────────────────────────────

    struct Firing {
        bytes32 firing_id;
        bytes32 tripwire_id;        // e.g., keccak("TRIP-AC-001")
        bytes32 scope;              // tenant scope
        bytes32 evidence_cid;       // IPFS CID for the evidence bundle
        bytes32 fired_by;           // recorder identity
        uint8   severity;           // 0..3
        uint8   state;              // 1=Fired, 2=Acknowledged, 3=Resolved
        uint256 fired_at_block;
        uint256 acknowledged_at_block;
        uint256 resolved_at_block;
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;
    mapping(address => bool) public is_recorder;
    /// @notice Resolvers can acknowledge + resolve firings. Separate
    ///         from recorders (recorders fire; resolvers close).
    mapping(address => bool) public is_resolver;

    mapping(bytes32 => Firing) public firings;
    mapping(bytes32 => bool) public exists;

    /// @notice tripwire_id → firing_ids (append-only).
    mapping(bytes32 => bytes32[]) public firingsByTripwire;
    /// @notice scope → firing_ids (append-only).
    mapping(bytes32 => bytes32[]) public firingsByScope;
    /// @notice severity → firing_ids (append-only).
    mapping(uint8 => bytes32[]) public firingsBySeverity;
    /// @notice All firing_ids ever recorded.
    bytes32[] public allFiringIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event ResolverSet(address indexed resolver, bool authorized);
    event Fired(
        bytes32 indexed firing_id,
        bytes32 indexed tripwire_id,
        bytes32 indexed scope,
        uint8 severity,
        bytes32 evidence_cid
    );
    event Acknowledged(bytes32 indexed firing_id, uint256 block_number);
    event Resolved(bytes32 indexed firing_id, uint256 block_number);

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = InitialAdmin.check(initialGovernance); // PBA-L2-002: never the CREATE2 factory
    }

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    function setResolver(address resolver, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_resolver[resolver] = authorized;
        emit ResolverSet(resolver, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Fire a tripwire. NotFired → Fired (state=1).
    function fire(
        bytes32 firing_id,
        bytes32 tripwire_id,
        bytes32 scope,
        uint8 severity,
        bytes32 evidence_cid
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (tripwire_id == bytes32(0)) revert ZeroTripwireId();
        if (severity > 3) revert InvalidSeverity(severity);
        if (exists[firing_id]) revert AlreadyFired(firing_id);

        firings[firing_id] = Firing({
            firing_id: firing_id,
            tripwire_id: tripwire_id,
            scope: scope,
            evidence_cid: evidence_cid,
            fired_by: bytes32(uint256(uint160(msg.sender))),
            severity: severity,
            state: 1,
            fired_at_block: block.number,
            acknowledged_at_block: 0,
            resolved_at_block: 0
        });
        exists[firing_id] = true;
        firingsByTripwire[tripwire_id].push(firing_id);
        firingsByScope[scope].push(firing_id);
        firingsBySeverity[severity].push(firing_id);
        allFiringIds.push(firing_id);

        emit Fired(firing_id, tripwire_id, scope, severity, evidence_cid);
    }

    /// @notice Acknowledge a firing. Fired (1) → Acknowledged (2).
    function acknowledge(bytes32 firing_id) external {
        if (!is_resolver[msg.sender]) revert NotResolver(msg.sender);
        Firing storage f = firings[firing_id];
        if (f.state != 1) revert NotInState(firing_id, 1, f.state);
        f.state = 2;
        f.acknowledged_at_block = block.number;
        emit Acknowledged(firing_id, block.number);
    }

    /// @notice Resolve a firing. Fired (1) | Acknowledged (2) → Resolved (3).
    function resolve(bytes32 firing_id) external {
        if (!is_resolver[msg.sender]) revert NotResolver(msg.sender);
        Firing storage f = firings[firing_id];
        if (f.state != 1 && f.state != 2) revert NotInState(firing_id, 1, f.state);
        f.state = 3;
        f.resolved_at_block = block.number;
        emit Resolved(firing_id, block.number);
    }

    // ── Views ──────────────────────────────────────────────────────────

    function getFiring(bytes32 firing_id) external view returns (Firing memory) {
        return firings[firing_id];
    }

    function byTripwire(bytes32 tripwire_id) external view returns (bytes32[] memory) {
        return firingsByTripwire[tripwire_id];
    }

    function byScope(bytes32 scope) external view returns (bytes32[] memory) {
        return firingsByScope[scope];
    }

    function bySeverity(uint8 severity) external view returns (bytes32[] memory) {
        return firingsBySeverity[severity];
    }

    function allFirings() external view returns (bytes32[] memory) {
        return allFiringIds;
    }

    function firingCount() external view returns (uint256) {
        return allFiringIds.length;
    }

    function countByScope(bytes32 scope) external view returns (uint256) {
        return firingsByScope[scope].length;
    }

    function countBySeverity(uint8 severity) external view returns (uint256) {
        return firingsBySeverity[severity].length;
    }
}
