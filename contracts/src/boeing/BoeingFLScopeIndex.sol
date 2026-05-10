// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title BoeingFLScopeIndex — tenant-scope tagging for RM-FL pools
/// @notice Lightweight join contract under `boeing/`. Tags existing
///         `LearningPool.sol` pool ids with a Boeing tenant scope so
///         the BFR-07 Federated Learning panel can scope-filter
///         pools by tenant without modifying the RM-FL track's
///         contract surface.
///
///         The actual pool detail / participants / reward-split reads
///         go to LearningPool + ContributionAccounting directly via
///         their existing methods. This contract only answers
///         "which pool ids belong to a Boeing scope?".
///
/// @dev Cited specs (composition):
///   - `formal/specs/contracts/AgentDecisionLog.tla` — AppendOnly
///     ratified for the scope→pool tagging history.
///
/// @dev Cited invariants:
///   - **PoolTaggedOnce** — `tag(pool_id, scope)` reverts on
///     duplicate (a pool can be tagged to at most one scope).
///   - **ScopeIndexConsistent** — every tagged pool is retrievable
///     via `poolsByScope(scope)`.
///   - **TagAuthGated** — only governance-authorized recorders can
///     tag (no permissionless tagging — Boeing operations team
///     decides which pools are part of Boeing's FL program).
///
/// @dev BFR-07 deliverable. Companion to RM-FL track's
///      `LearningPool.sol` + `ContributionAccounting.sol`. The Boeing
///      panel adapter (`citrate-boeing-fl`) is responsible for the
///      `poolId → pool detail` and `poolId → reward split` joins.
contract BoeingFLScopeIndex {
    // ── State ───────────────────────────────────────────────────────

    /// @notice Pool id → Boeing scope (zero = untagged).
    mapping(uint256 pool_id => bytes32) public poolScope;

    /// @notice Boeing scope → list of pool ids.
    mapping(bytes32 scope => uint256[]) private _pools_by_scope;

    /// @notice Authorized taggers (Boeing ops team).
    mapping(address => bool) public is_recorder;

    /// @notice Admin authority.
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    event PoolTagged(
        uint256 indexed pool_id,
        bytes32 indexed scope,
        bytes32 corr_id
    );
    event RecorderSet(address indexed recorder, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error ZeroGovernance();
    error PoolAlreadyTagged(uint256 pool_id, bytes32 existing_scope);
    error ZeroScope();

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance ──────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Tag a pool with a Boeing scope. One-shot per pool.
    /// @dev Cited invariant: PoolTaggedOnce.
    function tag(uint256 pool_id, bytes32 scope, bytes32 corr_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (scope == bytes32(0)) revert ZeroScope();
        bytes32 existing = poolScope[pool_id];
        if (existing != bytes32(0)) {
            revert PoolAlreadyTagged(pool_id, existing);
        }
        poolScope[pool_id] = scope;
        _pools_by_scope[scope].push(pool_id);
        emit PoolTagged(pool_id, scope, corr_id);
    }

    // ── Read views ──────────────────────────────────────────────────

    /// @notice Pool ids tagged with `scope`.
    /// @dev Cited invariant: ScopeIndexConsistent.
    function poolsByScope(bytes32 scope) external view returns (uint256[] memory) {
        return _pools_by_scope[scope];
    }

    /// @notice Number of pools tagged with `scope`. O(1).
    function poolCount(bytes32 scope) external view returns (uint256) {
        return _pools_by_scope[scope].length;
    }

    /// @notice Whether a pool is tagged at all.
    function isTagged(uint256 pool_id) external view returns (bool) {
        return poolScope[pool_id] != bytes32(0);
    }
}
