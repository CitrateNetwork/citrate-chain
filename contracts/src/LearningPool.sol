// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";

/// @title LearningPool — Federated Learning Pool Management
/// @notice Create, join, leave learning pools. Each pool has a model whitelist,
///         minimum stake requirement, and access control (open/invite/application).
///         Satisfies LearningPool.tla invariants INV-1 through INV-8.
/// @dev WP-LC.1.3 — backbone for the Learning Center "Network" screen.
contract LearningPool is ReentrancyGuard {
    // ============================================================
    // Types
    // ============================================================

    enum AccessType { Open, InviteOnly, ApplicationRequired }
    enum PoolState { Active, Closed, ActiveCycle }

    struct Pool {
        uint256 id;
        string name;
        string description;
        address creator;
        PoolState state;
        AccessType access;
        uint256 minStake;           // Minimum SALT to join
        uint256 memberCount;
        uint256 createdAt;
    }

    // ============================================================
    // State
    // ============================================================

    uint256 public nextPoolId;
    mapping(uint256 => Pool) public pools;
    mapping(uint256 => mapping(address => bool)) public isMember;
    mapping(uint256 => mapping(address => uint256)) public stakes;
    mapping(uint256 => mapping(bytes32 => bool)) public whitelistedModels;
    mapping(uint256 => mapping(bytes32 => bool)) public validInviteCodes;

    /// @notice Per-(pool, code) expiry timestamp for invite codes.
    /// 0 means "no expiry recorded" — pre-WP-E3.2 codes are
    /// transitionally allowed via `_isInviteValid` but the
    /// `addInviteCode` path now always populates this.
    /// RM-B1 / WP-E3.2 (audit GUI-L-03).
    mapping(uint256 => mapping(bytes32 => uint64)) public inviteExpiresAt;

    /// @notice Default invite-code TTL when the creator doesn't pass
    /// an explicit value. 7 days matches the planset's default.
    uint64 public constant DEFAULT_INVITE_TTL = 7 days;
    /// Maximum TTL a creator can request.
    uint64 public constant MAX_INVITE_TTL = 90 days;

    // ============================================================
    // Events
    // ============================================================

    event PoolCreated(uint256 indexed poolId, address indexed creator, string name, AccessType access);
    event MemberJoined(uint256 indexed poolId, address indexed member, uint256 stake);
    event MemberLeft(uint256 indexed poolId, address indexed member, uint256 stakeReturned);
    event PoolClosed(uint256 indexed poolId);
    event PoolReopened(uint256 indexed poolId);
    event CycleStarted(uint256 indexed poolId);
    event CycleEnded(uint256 indexed poolId);
    event ModelWhitelisted(uint256 indexed poolId, bytes32 modelHash);
    event ModelRemoved(uint256 indexed poolId, bytes32 modelHash);
    event InviteCodeAdded(uint256 indexed poolId, bytes32 codeHash);
    /// RM-B1 / WP-E3.2 (audit GUI-L-03).
    event InviteCodeTtlSet(uint256 indexed poolId, bytes32 indexed codeHash, uint64 expiresAt);

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyCreator(uint256 poolId) {
        require(pools[poolId].creator == msg.sender, "Not creator");
        _;
    }

    modifier poolExists(uint256 poolId) {
        require(poolId < nextPoolId, "Pool does not exist");
        _;
    }

    // ============================================================
    // Constructor — Genesis Pool
    // ============================================================

    /// @dev Deploy-time genesis pool #0. Creator is `address(0)` so the pool
    ///      is permanent — no one can call `closePool`, `startCycle`,
    ///      `whitelistModel`, or `leavePool` against it as creator. Anyone
    ///      can join with zero minimum stake. This guarantees the Learning
    ///      Center always has at least one pool a newcomer can enter.
    constructor() {
        uint256 poolId = nextPoolId++;
        pools[poolId] = Pool({
            id: poolId,
            name: "Genesis",
            description: "The default federated learning pool. Open to everyone, no minimum stake.",
            creator: address(0),
            state: PoolState.Active,
            access: AccessType.Open,
            minStake: 0,
            memberCount: 0,
            createdAt: block.timestamp
        });
        emit PoolCreated(poolId, address(0), "Genesis", AccessType.Open);
    }

    // ============================================================
    // Core: Pool Creation
    // ============================================================

    /// @notice Create a new learning pool. Creator becomes first member.
    /// @dev Satisfies TLA+ CreatePool: creator ∈ Members, creator ∈ poolMembers,
    ///      stakes[pool][creator] > 0, poolState = "Open".
    /// @param name Pool display name (non-empty)
    /// @param description Pool description
    /// @param access Access control type (Open, InviteOnly, ApplicationRequired)
    /// @param minStake Minimum SALT required to join
    /// @return poolId The new pool's ID
    function createPool(
        string calldata name,
        string calldata description,
        AccessType access,
        uint256 minStake
    ) external payable returns (uint256 poolId) {
        require(bytes(name).length > 0, "Empty name");
        require(msg.value >= minStake, "Creator must meet min stake");

        poolId = nextPoolId++;
        pools[poolId] = Pool({
            id: poolId,
            name: name,
            description: description,
            creator: msg.sender,
            state: PoolState.Active,
            access: access,
            minStake: minStake,
            memberCount: 1,
            createdAt: block.timestamp
        });

        isMember[poolId][msg.sender] = true;
        stakes[poolId][msg.sender] = msg.value;

        emit PoolCreated(poolId, msg.sender, name, access);
        emit MemberJoined(poolId, msg.sender, msg.value);
    }

    // ============================================================
    // Core: Join Pool
    // ============================================================

    /// @notice Join an open pool by staking SALT.
    /// @dev Satisfies TLA+ JoinPool: poolState = "Open", member ∉ poolMembers,
    ///      stake = msg.value >= minStake.
    /// @param poolId The pool to join
    function joinPool(uint256 poolId) external payable poolExists(poolId) {
        Pool storage pool = pools[poolId];
        require(pool.state == PoolState.Active, "Pool not active");
        require(!isMember[poolId][msg.sender], "Already member");
        require(msg.value >= pool.minStake, "Below min stake");
        require(pool.access == AccessType.Open, "Not open pool");

        _addMember(poolId, msg.sender, msg.value);
    }

    /// @notice Join an invite-only pool with a valid invite code hash.
    /// @param poolId The pool to join
    /// @param codeHash keccak256 of the invite code
    function joinWithInvite(uint256 poolId, bytes32 codeHash) external payable poolExists(poolId) {
        Pool storage pool = pools[poolId];
        require(pool.state == PoolState.Active, "Pool not active");
        require(!isMember[poolId][msg.sender], "Already member");
        require(msg.value >= pool.minStake, "Below min stake");
        require(pool.access == AccessType.InviteOnly, "Not invite pool");
        require(validInviteCodes[poolId][codeHash], "Invalid invite code");

        // RM-B1 / WP-E3.2 (audit GUI-L-03): expired invites stop
        // enrolling new members. The creator must mint a fresh code.
        uint64 expiresAt = inviteExpiresAt[poolId][codeHash];
        require(expiresAt != 0, "Invite code has no TTL recorded");
        require(block.timestamp <= uint256(expiresAt), "Invite code expired");

        _addMember(poolId, msg.sender, msg.value);
    }

    // ============================================================
    // Core: Leave Pool
    // ============================================================

    /// @notice Leave a pool and reclaim staked SALT.
    /// @dev Satisfies TLA+ LeavePool: member ∈ poolMembers, member ≠ creator,
    ///      poolState ≠ "ActiveCycle". Stakes zeroed, membership removed.
    ///      INV-6 (NonMemberNoStake) maintained.
    /// @param poolId The pool to leave
    function leavePool(uint256 poolId) external nonReentrant poolExists(poolId) {
        require(isMember[poolId][msg.sender], "Not member");
        require(pools[poolId].creator != msg.sender, "Creator cannot leave");
        require(pools[poolId].state != PoolState.ActiveCycle, "Cannot leave during active cycle");

        uint256 stakeReturn = stakes[poolId][msg.sender];
        isMember[poolId][msg.sender] = false;
        stakes[poolId][msg.sender] = 0;
        pools[poolId].memberCount--;

        if (stakeReturn > 0) {
            (bool success, ) = payable(msg.sender).call{value: stakeReturn}("");
            require(success, "Stake transfer failed");
        }

        emit MemberLeft(poolId, msg.sender, stakeReturn);
    }

    // ============================================================
    // Pool State Management
    // ============================================================

    /// @notice Close a pool (creator only). Rejects new members.
    /// @dev Satisfies TLA+ ClosePool: poolState = "Open" → "Closed", caller = creator.
    /// @param poolId The pool to close
    function closePool(uint256 poolId) external poolExists(poolId) onlyCreator(poolId) {
        require(pools[poolId].state == PoolState.Active, "Not active");
        pools[poolId].state = PoolState.Closed;
        emit PoolClosed(poolId);
    }

    /// @notice Reopen a closed pool (creator only).
    /// @dev Satisfies TLA+ ReopenPool: poolState = "Closed" → "Open", caller = creator.
    /// @param poolId The pool to reopen
    function reopenPool(uint256 poolId) external poolExists(poolId) onlyCreator(poolId) {
        require(pools[poolId].state == PoolState.Closed, "Not closed");
        pools[poolId].state = PoolState.Active;
        emit PoolReopened(poolId);
    }

    /// @notice Start a learning cycle (creator only, pool must have ≥2 members).
    /// @dev Satisfies TLA+ StartCycle: poolState = "Open" → "ActiveCycle",
    ///      Cardinality(poolMembers) ≥ 2, caller = creator.
    /// @param poolId The pool to start a cycle in
    function startCycle(uint256 poolId) external poolExists(poolId) onlyCreator(poolId) {
        require(pools[poolId].state == PoolState.Active, "Not active");
        require(pools[poolId].memberCount >= 2, "Need at least 2 members");
        pools[poolId].state = PoolState.ActiveCycle;
        emit CycleStarted(poolId);
    }

    /// @notice End an active learning cycle (creator only).
    /// @dev Satisfies TLA+ EndCycle: poolState = "ActiveCycle" → "Open", caller = creator.
    /// @param poolId The pool to end the cycle in
    function endCycle(uint256 poolId) external poolExists(poolId) onlyCreator(poolId) {
        require(pools[poolId].state == PoolState.ActiveCycle, "No active cycle");
        pools[poolId].state = PoolState.Active;
        emit CycleEnded(poolId);
    }

    // ============================================================
    // Model Whitelist Management
    // ============================================================

    /// @notice Whitelist a model for this pool (creator only).
    /// @dev Satisfies TLA+ AddModel: caller = creator, model added to poolModels.
    /// @param poolId The pool ID
    /// @param modelHash Hash identifying the model
    function whitelistModel(uint256 poolId, bytes32 modelHash) external poolExists(poolId) onlyCreator(poolId) {
        whitelistedModels[poolId][modelHash] = true;
        emit ModelWhitelisted(poolId, modelHash);
    }

    /// @notice Remove a model from the whitelist (creator only).
    /// @dev Satisfies TLA+ RemoveModel: caller = creator, model removed from poolModels.
    /// @param poolId The pool ID
    /// @param modelHash Hash identifying the model
    function removeModel(uint256 poolId, bytes32 modelHash) external poolExists(poolId) onlyCreator(poolId) {
        whitelistedModels[poolId][modelHash] = false;
        emit ModelRemoved(poolId, modelHash);
    }

    // ============================================================
    // Invite Code Management
    // ============================================================

    /// @notice Add an invite code hash (creator only) with the
    /// default TTL (`DEFAULT_INVITE_TTL`).
    /// @param poolId The pool ID
    /// @param codeHash keccak256 of the invite code
    function addInviteCode(uint256 poolId, bytes32 codeHash) external poolExists(poolId) onlyCreator(poolId) {
        addInviteCodeWithTtl(poolId, codeHash, DEFAULT_INVITE_TTL);
    }

    /// @notice Add an invite code hash with an explicit TTL.
    /// RM-B1 / WP-E3.2 (audit GUI-L-03).
    /// @param poolId The pool ID
    /// @param codeHash keccak256 of the invite code
    /// @param ttlSeconds TTL in seconds. `0` means "use the default";
    ///        capped at `MAX_INVITE_TTL`.
    function addInviteCodeWithTtl(uint256 poolId, bytes32 codeHash, uint64 ttlSeconds)
        public
        poolExists(poolId)
        onlyCreator(poolId)
    {
        uint64 ttl = ttlSeconds == 0 ? DEFAULT_INVITE_TTL : ttlSeconds;
        require(ttl <= MAX_INVITE_TTL, "TTL exceeds MAX_INVITE_TTL");
        validInviteCodes[poolId][codeHash] = true;
        uint64 expiresAt = uint64(block.timestamp) + ttl;
        inviteExpiresAt[poolId][codeHash] = expiresAt;
        emit InviteCodeAdded(poolId, codeHash);
        emit InviteCodeTtlSet(poolId, codeHash, expiresAt);
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get full pool info.
    /// @param poolId The pool ID
    /// @return Pool struct
    function getPool(uint256 poolId) external view returns (Pool memory) {
        return pools[poolId];
    }

    /// @notice Get a member's stake in a pool.
    /// @param poolId The pool ID
    /// @param member The member address
    /// @return Staked amount
    function getMemberStake(uint256 poolId, address member) external view returns (uint256) {
        return stakes[poolId][member];
    }

    /// @notice Check if a model is whitelisted for a pool.
    /// @param poolId The pool ID
    /// @param modelHash The model hash
    /// @return True if whitelisted
    function isModelWhitelisted(uint256 poolId, bytes32 modelHash) external view returns (bool) {
        return whitelistedModels[poolId][modelHash];
    }

    // ============================================================
    // Internal
    // ============================================================

    /// @dev Add a member to a pool with stake. Emits MemberJoined.
    function _addMember(uint256 poolId, address member, uint256 stake) internal {
        isMember[poolId][member] = true;
        stakes[poolId][member] = stake;
        pools[poolId].memberCount++;
        emit MemberJoined(poolId, member, stake);
    }
}
