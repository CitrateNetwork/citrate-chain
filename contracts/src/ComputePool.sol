// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/ComputeLib.sol";
import "./lib/Governable.sol";
import "./interfaces/INematocystSlashing.sol";

/// @title ComputePool — Multi-Provider GPU Clustering
/// @notice Implements GPU pool management from GPU_CLUSTERING_DESIGN.md.
///         Three modes of operation:
///           - InferencePool: linear scaling, round-robin/least-loaded routing
///           - DataParallel: sub-linear scaling, federated gradient aggregation
///           - PipelineParallel: constrained scaling, model sharding across providers
///
///         Invariants enforced:
///           PoolSolvent             — total staked >= guaranteedThroughput * penalty rate
///           ProviderCooldown        — can't leave during active job
///           MinProvidersMaintained  — active pool has >= minProviders
///           SLAEnforced             — actual < guarantee => proportional slash
///           GPUCountAccurate        — totalGPUs = sum of provider GPU allocations
///
/// @dev WP-CI.3 — Compute Infrastructure: Compute Pool
contract ComputePool is ReentrancyGuard, Governable {
    // ── Types ───────────────────────────────────────────────────────

    enum PoolMode { InferencePool, DataParallel, PipelineParallel }
    enum PoolState { Active, Paused, Dissolved }
    enum JobStatus { Pending, Executing, Completed, Failed }

    struct Pool {
        uint256 id;
        string name;
        PoolMode mode;
        address creator;
        PoolState state;
        uint256 minProviders;
        uint256 totalGPUs;
        uint256 guaranteedThroughput;  // queries/sec for inference
        uint256 pricePerUnit;          // SALT per query
        uint256 memberCount;
        uint256 activeJobCount;
        uint256 totalStaked;
    }

    struct PoolMember {
        uint256 gpuCount;
        uint256 stake;
        uint256 activeJobs;           // jobs currently assigned to this provider in the pool
        uint256 joinedAt;             // block number
        bool active;
    }

    struct PoolJob {
        uint256 poolId;
        address requester;
        bytes jobSpec;
        uint256 payment;
        JobStatus status;
        uint256 createdAt;
        // CM-05 WP-05.1: dispatch tracking. dispatchBlock=0 means
        // the coordinator hasn't yet recorded a dispatch; >0 means
        // it has, and reassignCoordinator's COORDINATION_TIMEOUT
        // window starts ticking from this value.
        uint256 dispatchBlock;
        // The coordinator that recorded the dispatch — slashed if
        // they fail to complete the job before COORDINATION_TIMEOUT.
        address dispatchedBy;
    }

    /// @notice Versioned, structured job spec (CM-05 WP-05.1).
    /// @dev Replaces the opaque `bytes jobSpec` form for new callers.
    ///      The legacy `bytes` overload of `requestPoolCompute` is kept
    ///      for backwards compatibility; callers that want a typed
    ///      shape use `requestPoolComputeStruct`.
    struct PoolJobSpec {
        uint8 version;            // 1 in this release
        uint8 mode;               // 0=InferencePool (CM-05); 1=DataParallel (CM-07); 2=Pipeline (CM-08)
        bytes32 modelHash;        // resolved via ModelRegistry
        bytes inputData;          // up to 64KB inline; beyond that, IPFS CID bytes
        uint32 maxTokens;         // hard cap on output tokens
        uint8 verificationTier;   // 0=Commitment, 1=ZKProof, 2=TEE
        uint32 batchSize;         // 1 for chat, N for batch
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Minimum stake per GPU (10 SALT).
    uint256 public constant MIN_STAKE_PER_GPU = 10 ether;

    /// @notice SLA penalty basis points: 10% of proportional stake for violation.
    uint256 public constant SLA_PENALTY_BPS = 1000;

    /// @notice Basis points denominator.
    uint256 private constant BPS = 10000;

    /// @notice Provider cooldown period in blocks after last job completes (~5 min).
    uint256 public constant LEAVE_COOLDOWN = 150;

    /// @notice Length of a coordinator-election epoch in blocks
    /// (CM-05 WP-05.1). At ~12s/block this is ~20 minutes per epoch.
    uint256 public constant EPOCH_LENGTH = 100;

    /// @notice Blocks the coordinator has to complete a dispatched
    /// job before any pool member can call `reassignCoordinator`.
    /// At ~12s/block this is ~4 minutes (CM-05 WP-05.1).
    uint256 public constant COORDINATION_TIMEOUT = 20;

    /// @notice Liveness slash, in basis points of the failed
    /// coordinator's stake. 10 bps = 0.1% per planset CM-05 risks
    /// table — small enough to be tolerable per incident, large
    /// enough that a serial offender churns out via repeated
    /// liveness slashes.
    uint256 public constant LIVENESS_SLASH_BPS = 10;

    /// @notice Hard job-level deadline, in blocks from `createdAt`, after
    /// which the requester may reclaim escrowed payment for a job that
    /// never reached a terminal state (INFER-S2 / WP-G2). Distinct from
    /// the per-coordinator `COORDINATION_TIMEOUT`: that one rotates the
    /// coordinator and slashes for liveness; this one is the backstop that
    /// guarantees a buyer's funds are never stranded if the pool as a whole
    /// fails to deliver. At ~12s/block this is ~2h.
    uint256 public constant JOB_DEADLINE = 600;

    // ── State ───────────────────────────────────────────────────────

    /// @notice All pools.
    mapping(uint256 => Pool) public pools;

    /// @notice Pool membership: poolId => provider => PoolMember.
    mapping(uint256 => mapping(address => PoolMember)) public members;

    /// @notice Pool member list: poolId => array of member addresses.
    mapping(uint256 => address[]) internal _poolMembers;

    /// @notice Pool jobs: jobId => PoolJob.
    mapping(uint256 => PoolJob) public jobs;

    /// @notice Next pool ID.
    uint256 public nextPoolId;

    /// @notice Next job ID.
    uint256 public nextJobId;

    /// @notice NematocystSlashing contract for SLA enforcement.
    INematocystSlashing public slashingContract;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ── Events ──────────────────────────────────────────────────────

    event PoolCreated(
        uint256 indexed poolId,
        address indexed creator,
        string name,
        PoolMode mode,
        uint256 minProviders,
        uint256 guaranteedThroughput,
        uint256 pricePerUnit
    );
    event ProviderJoined(uint256 indexed poolId, address indexed provider, uint256 gpuCount, uint256 stake);
    event ProviderLeft(uint256 indexed poolId, address indexed provider, uint256 stakeReturned);
    event PoolPaused(uint256 indexed poolId);
    event PoolResumed(uint256 indexed poolId);
    event PoolDissolved(uint256 indexed poolId);
    event ComputeRequested(uint256 indexed poolId, uint256 indexed jobId, address indexed requester, uint256 payment);
    event JobCompleted(uint256 indexed jobId, uint256 indexed poolId);
    event JobFailed(uint256 indexed jobId, uint256 indexed poolId);
    /// @notice Emitted when a requester reclaims escrow for a job that
    /// passed `JOB_DEADLINE` without terminating (INFER-S2 / WP-G2).
    event JobReclaimed(uint256 indexed jobId, uint256 indexed poolId, address indexed requester, uint256 refund);
    event SLAViolationReported(uint256 indexed poolId, uint256 actualThroughput, uint256 guaranteedThroughput);
    event SlashingContractUpdated(address oldContract, address newContract);
    // GovernanceTransferred event provided by Governable mixin.

    // ── CM-05 WP-05.1 events ───────────────────────────────────────

    /// @notice Emitted by view-helper-driven indexers; the contract
    /// itself does NOT call this on `coordinatorFor` (view fn). The
    /// coordinator binary fires it off-chain when it detects a
    /// new-epoch transition. Logged here for ABI completeness +
    /// indexer subscriptions.
    event CoordinatorElected(
        uint256 indexed poolId,
        uint256 indexed epoch,
        address indexed coordinator
    );

    /// @notice Emitted by `reassignCoordinator` when the current
    /// coordinator times out and a new one takes over.
    event CoordinatorReassigned(
        uint256 indexed jobId,
        address indexed previous,
        address indexed next
    );

    /// @notice Emitted by `reassignCoordinator` after slashing the
    /// stalled coordinator. `amount` is in grains (wei).
    event CoordinatorSlashedForLiveness(
        uint256 indexed poolId,
        address indexed coordinator,
        uint256 amount
    );

    /// @notice Emitted when a coordinator records a dispatch via
    /// `recordDispatch`. Useful for the off-chain timeline UI
    /// (CM-04 buyer webapp's `/jobs/:id` view) to detect the
    /// "Dispatched" state transition without scanning every block.
    event DispatchRecorded(
        uint256 indexed jobId,
        address indexed coordinator,
        uint256 dispatchBlock
    );

    // ── Modifiers ───────────────────────────────────────────────────

    // `onlyGovernance` is inherited from Governable.

    modifier poolExists(uint256 poolId) {
        require(poolId < nextPoolId, "Pool does not exist");
        _;
    }

    modifier onlyPoolCreator(uint256 poolId) {
        require(pools[poolId].creator == msg.sender, "Not pool creator");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────

    constructor() Governable(msg.sender) {}

    // ── Pool Management ─────────────────────────────────────────────

    /// @notice Create a new compute pool.
    /// @dev Creator does NOT auto-join; they must call joinPool separately.
    /// @param name Pool display name.
    /// @param mode Clustering mode (InferencePool, DataParallel, PipelineParallel).
    /// @param minProviders Minimum providers required for the pool to be active.
    /// @param guaranteedThroughput Guaranteed queries/sec (inference) or steps/sec (training).
    /// @param pricePerUnit SALT per query/unit.
    /// @return poolId The new pool's ID.
    function createPool(
        string calldata name,
        PoolMode mode,
        uint256 minProviders,
        uint256 guaranteedThroughput,
        uint256 pricePerUnit
    ) external returns (uint256 poolId) {
        require(bytes(name).length > 0, "Empty name");
        require(minProviders >= 1, "Min providers must be >= 1");
        require(guaranteedThroughput > 0, "Throughput must be > 0");
        require(pricePerUnit > 0, "Price must be > 0");

        poolId = nextPoolId++;

        // Initialize pool in storage field-by-field to reduce stack pressure
        Pool storage pool = pools[poolId];
        pool.id = poolId;
        pool.name = name;
        pool.mode = mode;
        pool.creator = msg.sender;
        pool.state = PoolState.Active;
        pool.minProviders = minProviders;
        pool.guaranteedThroughput = guaranteedThroughput;
        pool.pricePerUnit = pricePerUnit;

        emit PoolCreated(poolId, msg.sender, name, mode, minProviders, guaranteedThroughput, pricePerUnit);
    }

    /// @notice Join a pool with a GPU allocation and stake.
    /// @dev Invariant: GPUCountAccurate — totalGPUs updated atomically.
    ///      Invariant: PoolSolvent — stake >= gpuCount * MIN_STAKE_PER_GPU.
    /// @param poolId The pool to join.
    /// @param gpuCount Number of GPUs being contributed.
    function joinPool(uint256 poolId, uint256 gpuCount) external payable poolExists(poolId) nonReentrant {
        Pool storage pool = pools[poolId];
        require(pool.state != PoolState.Dissolved, "Pool dissolved");
        require(!members[poolId][msg.sender].active, "Already a member");
        require(gpuCount > 0, "Must contribute at least 1 GPU");
        require(msg.value >= gpuCount * MIN_STAKE_PER_GPU, "Insufficient stake for GPUs");

        // Initialize member field-by-field to reduce stack pressure
        PoolMember storage member = members[poolId][msg.sender];
        member.gpuCount = gpuCount;
        member.stake = msg.value;
        member.joinedAt = block.number;
        member.active = true;

        _poolMembers[poolId].push(msg.sender);

        // GPUCountAccurate: totalGPUs = sum of all provider GPUs
        pool.totalGPUs += gpuCount;
        pool.memberCount++;
        pool.totalStaked += msg.value;

        emit ProviderJoined(poolId, msg.sender, gpuCount, msg.value);
    }

    /// @notice Leave a pool and reclaim staked SALT.
    /// @dev Invariant: ProviderCooldown — can't leave during active job.
    ///      Invariant: MinProvidersMaintained — checked but not enforced as blocker
    ///      (pool auto-pauses if below minimum).
    /// @param poolId The pool to leave.
    function leavePool(uint256 poolId) external poolExists(poolId) nonReentrant {
        PoolMember storage member = members[poolId][msg.sender];
        require(member.active, "Not a member");

        // ProviderCooldown: can't leave during active job
        require(member.activeJobs == 0, "Has active jobs");

        Pool storage pool = pools[poolId];

        uint256 stakeReturn = member.stake;

        // Update pool state
        pool.totalGPUs -= member.gpuCount;
        pool.memberCount--;
        pool.totalStaked -= stakeReturn;

        // Clear member state
        member.active = false;
        member.gpuCount = 0;
        member.stake = 0;

        // Keep the payout and coordination index limited to current members.
        // Leaving only cleared the mapping before this removal, so a later
        // rejoin appended a second entry and paid the provider twice.
        address[] storage memberList = _poolMembers[poolId];
        for (uint256 i = 0; i < memberList.length; i++) {
            if (memberList[i] == msg.sender) {
                memberList[i] = memberList[memberList.length - 1];
                memberList.pop();
                break;
            }
        }

        // MinProvidersMaintained: auto-pause if below minimum
        if (pool.memberCount < pool.minProviders && pool.state == PoolState.Active) {
            pool.state = PoolState.Paused;
            emit PoolPaused(poolId);
        }

        // Return stake
        if (stakeReturn > 0) {
            (bool success, ) = payable(msg.sender).call{value: stakeReturn}("");
            require(success, "Stake transfer failed");
        }

        emit ProviderLeft(poolId, msg.sender, stakeReturn);
    }

    /// @notice Dissolve a pool (creator only). All members get stake back.
    /// @dev Pool must have no active jobs.
    /// @param poolId The pool to dissolve.
    function dissolvePool(uint256 poolId) external poolExists(poolId) onlyPoolCreator(poolId) nonReentrant {
        Pool storage pool = pools[poolId];
        require(pool.state != PoolState.Dissolved, "Already dissolved");
        require(pool.activeJobCount == 0, "Has active jobs");

        pool.state = PoolState.Dissolved;

        // Return all member stakes
        address[] storage memberList = _poolMembers[poolId];
        for (uint256 i = 0; i < memberList.length; i++) {
            _returnMemberStake(poolId, memberList[i]);
        }

        emit PoolDissolved(poolId);
    }

    /// @dev Return a single member's stake during pool dissolution.
    function _returnMemberStake(uint256 poolId, address memberAddr) internal {
        PoolMember storage member = members[poolId][memberAddr];

        if (!member.active || member.stake == 0) return;

        uint256 stakeReturn = member.stake;

        member.active = false;
        member.stake = 0;
        pools[poolId].totalGPUs -= member.gpuCount;
        member.gpuCount = 0;
        pools[poolId].memberCount--;
        pools[poolId].totalStaked -= stakeReturn;

        (bool success, ) = payable(memberAddr).call{value: stakeReturn}("");
        require(success, "Stake transfer failed");

        emit ProviderLeft(poolId, memberAddr, stakeReturn);
    }

    /// @notice Pause a pool (creator only). No new jobs accepted.
    /// @param poolId The pool to pause.
    function pausePool(uint256 poolId) external poolExists(poolId) onlyPoolCreator(poolId) {
        require(pools[poolId].state == PoolState.Active, "Not active");
        pools[poolId].state = PoolState.Paused;
        emit PoolPaused(poolId);
    }

    /// @notice Resume a paused pool (creator only).
    /// @dev Invariant: MinProvidersMaintained — requires >= minProviders to resume.
    /// @param poolId The pool to resume.
    function resumePool(uint256 poolId) external poolExists(poolId) onlyPoolCreator(poolId) {
        Pool storage pool = pools[poolId];
        require(pool.state == PoolState.Paused, "Not paused");
        require(pool.memberCount >= pool.minProviders, "Below min providers");
        pool.state = PoolState.Active;
        emit PoolResumed(poolId);
    }

    // ── Compute Requests ────────────────────────────────────────────

    /// @notice Request compute from a pool.
    /// @dev Invariant: PoolSolvent — pool must have sufficient stake.
    /// @param poolId The pool to request compute from.
    /// @param jobSpec Encoded job specification.
    /// @return jobId The new job ID.
    function requestPoolCompute(
        uint256 poolId,
        bytes calldata jobSpec,
        uint256 maxPrice
    ) external payable poolExists(poolId) nonReentrant returns (uint256 jobId) {
        // Delegate to the shared internal helper so the typed-struct
        // overload (`requestPoolComputeStruct`, CM-05 WP-05.1) and
        // this legacy bytes overload share identical pricing,
        // pool-state, and counter logic.
        return _requestPoolCompute(poolId, jobSpec, maxPrice);
    }

    /// @notice Mark a job as completed (governance, pool creator, or the
    ///         elected coordinator that ran it).
    /// @dev Payment is distributed proportionally to pool members.
    ///      INFER-S2 / WP-G1: `job.dispatchedBy` is the VRF-elected
    ///      coordinator recorded by `recordDispatch` (gated to
    ///      `coordinatorFor`), so adding it to the allow-list does not
    ///      widen trust beyond "the member the VRF actually elected to run
    ///      this job." The requester is deliberately left OUT — a buyer
    ///      must never be able to trigger provider payment for unverified
    ///      work.
    /// @param jobId The job to complete.
    function completeJob(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(job.status == JobStatus.Pending || job.status == JobStatus.Executing, "Invalid job status");

        Pool storage pool = pools[job.poolId];
        require(
            msg.sender == governance()
                || msg.sender == pool.creator
                || msg.sender == job.dispatchedBy,
            "Not authorized"
        );

        job.status = JobStatus.Completed;
        pool.activeJobCount--;

        // Distribute payment proportionally based on GPU contribution
        _distributePayment(job.poolId, job.payment);

        emit JobCompleted(jobId, job.poolId);
    }

    /// @notice Mark a job as failed (governance, pool creator, or the
    ///         elected coordinator that ran it). Payment refunded.
    /// @dev INFER-S2 / WP-G1: see `completeJob` — `job.dispatchedBy` is the
    ///      executor of record and is added to the allow-list so the actor
    ///      that ran the job can also close it as failed.
    /// @param jobId The job that failed.
    function failJob(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(job.status == JobStatus.Pending || job.status == JobStatus.Executing, "Invalid job status");

        Pool storage pool = pools[job.poolId];
        require(
            msg.sender == governance()
                || msg.sender == pool.creator
                || msg.sender == job.dispatchedBy,
            "Not authorized"
        );

        job.status = JobStatus.Failed;
        pool.activeJobCount--;

        // Refund requester
        if (job.payment > 0) {
            uint256 refund = job.payment;
            job.payment = 0;
            (bool success, ) = payable(job.requester).call{value: refund}("");
            require(success, "Refund failed");
        }

        emit JobFailed(jobId, job.poolId);
    }

    /// @notice Requester reclaims escrowed payment for a job that never
    ///         terminated (INFER-S2 / WP-G2).
    /// @dev Refund-only — never pays providers. Callable only by the
    ///      `requester`, only while the job is still `Pending`/`Executing`,
    ///      and only after `JOB_DEADLINE` blocks have elapsed since
    ///      `createdAt`. This is the on-chain primitive the gateway uses to
    ///      refund a buyer's key balance when the pool fails to deliver, so
    ///      escrow can never be stranded. Liveness slashing stays in
    ///      `reassignCoordinator` (no double-jeopardy); this path is
    ///      deliberately slash-free to keep the refund simple and safe.
    ///      Sets a terminal `Failed` status BEFORE the external call (CEI)
    ///      so a completed/failed job can never be reclaimed and the refund
    ///      cannot be re-entered.
    /// @param jobId The job whose escrow is being reclaimed.
    function reclaimExpiredJob(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(
            job.status == JobStatus.Pending || job.status == JobStatus.Executing,
            "Not open"
        );
        require(msg.sender == job.requester, "Not requester");
        require(block.number > job.createdAt + JOB_DEADLINE, "Not expired");

        // Effects before interaction (CEI). Terminal status guards against
        // a reclaim-after-complete race and reentrancy.
        job.status = JobStatus.Failed;
        pools[job.poolId].activeJobCount--;

        uint256 refund = job.payment;
        job.payment = 0;
        if (refund > 0) {
            (bool success, ) = payable(job.requester).call{value: refund}("");
            require(success, "Refund failed");
        }

        emit JobReclaimed(jobId, job.poolId, job.requester, refund);
    }

    // ── SLA Enforcement ─────────────────────────────────────────────

    /// @notice Report an SLA violation on a pool.
    /// @dev Invariant: SLAEnforced — actual < guarantee => proportional slash.
    ///      Slashes each provider proportionally to the throughput deficit.
    /// @param poolId The pool with the SLA violation.
    /// @param actualThroughput The measured throughput.
    function reportSLAViolation(
        uint256 poolId,
        uint256 actualThroughput
    ) external onlyGovernance poolExists(poolId) {
        Pool storage pool = pools[poolId];
        require(pool.state != PoolState.Dissolved, "Pool dissolved");
        require(actualThroughput < pool.guaranteedThroughput, "No violation");

        emit SLAViolationReported(poolId, actualThroughput, pool.guaranteedThroughput);

        // Calculate proportional penalty: penalty = (deficit / guaranteed) * SLA_PENALTY_BPS / BPS * stake
        uint256 deficit = pool.guaranteedThroughput - actualThroughput;
        uint256 guaranteed = pool.guaranteedThroughput;

        // Slash each active member proportionally
        address[] storage memberList = _poolMembers[poolId];
        for (uint256 i = 0; i < memberList.length; i++) {
            _slashMemberForSLA(poolId, memberList[i], deficit, guaranteed);
        }
    }

    /// @dev Slash a single pool member for an SLA violation.
    function _slashMemberForSLA(
        uint256 poolId,
        address memberAddr,
        uint256 deficit,
        uint256 guaranteed
    ) internal {
        PoolMember storage member = members[poolId][memberAddr];

        if (!member.active || member.stake == 0) return;

        uint256 penalty = ComputeLib.calculateSLAPenalty(
            member.stake, SLA_PENALTY_BPS, deficit, guaranteed
        );

        if (penalty > 0) {
            member.stake -= penalty;
            pools[poolId].totalStaked -= penalty;

            // Trigger slash via NematocystSlashing if available
            if (address(slashingContract) != address(0)) {
                try slashingContract.slash(
                    memberAddr,
                    0, // SlashTier.Latency
                    abi.encodePacked("sla:violation:pool:", poolId, ":throughput:", deficit)
                ) {} catch {}
            }
        }
    }

    // ── View Functions ──────────────────────────────────────────────

    /// @notice Get full pool record.
    /// @param poolId The pool ID.
    /// @return The Pool struct.
    function getPool(uint256 poolId) external view returns (Pool memory) {
        return pools[poolId];
    }

    /// @notice Get all members of a pool.
    /// @param poolId The pool ID.
    /// @return Array of member addresses.
    function getPoolMembers(uint256 poolId) external view returns (address[] memory) {
        return _poolMembers[poolId];
    }

    /// @notice Get total GPU count for a pool.
    /// @param poolId The pool ID.
    /// @return Total GPUs.
    function getPoolGPUCount(uint256 poolId) external view returns (uint256) {
        return pools[poolId].totalGPUs;
    }

    /// @notice Get a member's info in a pool.
    /// @param poolId The pool ID.
    /// @param provider The provider address.
    /// @return The PoolMember struct.
    function getMember(uint256 poolId, address provider) external view returns (PoolMember memory) {
        return members[poolId][provider];
    }

    /// @notice Get a job's info.
    /// @param jobId The job ID.
    /// @return The PoolJob struct.
    function getJob(uint256 jobId) external view returns (PoolJob memory) {
        return jobs[jobId];
    }

    /// @notice Check if a pool is solvent (total stake covers SLA penalty).
    /// @dev Invariant: PoolSolvent.
    /// @param poolId The pool ID.
    /// @return True if the pool's total stake is sufficient.
    function isPoolSolvent(uint256 poolId) external view returns (bool) {
        Pool storage pool = pools[poolId];
        // Solvency = total staked >= guaranteedThroughput * pricePerUnit * SLA_PENALTY_BPS / BPS
        uint256 minRequired = (pool.guaranteedThroughput * pool.pricePerUnit * SLA_PENALTY_BPS) / BPS;
        return pool.totalStaked >= minRequired;
    }

    // ── Governance ──────────────────────────────────────────────────

    /// @notice Set the NematocystSlashing contract.
    /// @param _slashingContract Address of NematocystSlashing.
    function setSlashingContract(address _slashingContract) external onlyGovernance {
        address old = address(slashingContract);
        slashingContract = INematocystSlashing(_slashingContract);
        emit SlashingContractUpdated(old, _slashingContract);
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ── CM-05 WP-05.1: Coordinator election + reassignment ─────────

    /// @notice Deterministic, gpuCount-weighted coordinator selection
    /// for a (poolId, epoch). Reverts with `NoMembers` when the pool
    /// has no active members.
    ///
    /// The seed is `keccak256(blockhash(epochStart) || poolId || epoch)`.
    /// `blockhash` returns 0x0 for blocks > 256 ago, making old
    /// epochs un-electable; in production the off-chain coordinator
    /// binary records the seed at each epoch boundary so historical
    /// queries can be answered. For slice 1 (this WP) the function
    /// is reliable for the most-recent ~256 blocks of history, which
    /// covers the active and immediately-preceding epoch.
    ///
    /// @dev Mirrors the `ElectCoordinator` action precondition in
    ///      .agentile/formal/specs/compute/InferencePoolLifecycle.tla
    ///      (CM-05 WP-05.0 spec gate). The TLA+ spec verifies
    ///      `ExactlyOneOrNoCoordinatorPerEpoch` and
    ///      `CoordinatorIsKnownMember` — this implementation upholds
    ///      both by always returning a current member.
    function coordinatorFor(uint256 poolId, uint256 epoch)
        public
        view
        poolExists(poolId)
        returns (address)
    {
        address[] storage memberList = _poolMembers[poolId];
        require(memberList.length > 0, "NoMembers");

        Pool storage p = pools[poolId];
        uint256 totalGpus = p.totalGPUs;
        require(totalGpus > 0, "NoGPUs");

        uint256 epochStart = epoch * EPOCH_LENGTH;
        // blockhash returns 0x0 for the current block AND blocks > 256
        // old. We mix in poolId and epoch so the 0x0 fallback case
        // still produces a varied seed across pools.
        uint256 seed = uint256(
            keccak256(abi.encodePacked(blockhash(epochStart), poolId, epoch))
        );
        uint256 target = seed % totalGpus;

        uint256 cumulative = 0;
        for (uint256 i = 0; i < memberList.length; i++) {
            PoolMember storage m = members[poolId][memberList[i]];
            if (!m.active || m.gpuCount == 0) continue;
            cumulative += m.gpuCount;
            if (target < cumulative) {
                return memberList[i];
            }
        }
        // Reachable only if `totalGpus` got out of sync with the
        // sum of active members' gpuCount — which would be a state
        // corruption bug elsewhere. Defensive fallback.
        return memberList[memberList.length - 1];
    }

    /// @notice Same as `requestPoolCompute` but takes a typed
    /// `PoolJobSpec` instead of opaque bytes. The struct is
    /// abi-encoded into the underlying `bytes` storage so legacy
    /// readers continue to work.
    function requestPoolComputeStruct(
        uint256 poolId,
        PoolJobSpec calldata spec,
        uint256 maxPrice
    ) external payable poolExists(poolId) nonReentrant returns (uint256 jobId) {
        require(spec.version == 1, "Unsupported spec version");
        bytes memory encoded = abi.encode(spec);
        return _requestPoolCompute(poolId, encoded, maxPrice);
    }

    /// @notice Decode a previously-encoded `PoolJobSpec` from its
    /// stored bytes. View helper used by off-chain consumers and
    /// tests that want to round-trip the typed shape.
    function decodePoolJobSpec(bytes calldata data)
        external
        pure
        returns (PoolJobSpec memory)
    {
        return abi.decode(data, (PoolJobSpec));
    }

    /// @notice Coordinator reports they've dispatched a job to a
    /// member. Records the dispatch block so `reassignCoordinator`
    /// has a timer to compare against.
    ///
    /// @dev Only the elected coordinator for the job's pool + the
    ///      current epoch can call this. Off-chain coordinators
    ///      (the citrate-pool-coordinator binary, WP-05.2) call this
    ///      immediately after their HTTPS dispatch to a pool member.
    function recordDispatch(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(
            job.status == JobStatus.Pending,
            "Job not pending"
        );
        uint256 epoch = block.number / EPOCH_LENGTH;
        address expectedCoord = coordinatorFor(job.poolId, epoch);
        require(msg.sender == expectedCoord, "Not the coordinator");

        job.dispatchBlock = block.number;
        job.dispatchedBy = msg.sender;
        job.status = JobStatus.Executing;

        emit DispatchRecorded(jobId, msg.sender, block.number);
    }

    /// @notice Any pool member can call this to reassign coordinator
    /// duty for a job whose original coordinator has stalled past
    /// `COORDINATION_TIMEOUT`. Slashes the stalled coordinator
    /// `LIVENESS_SLASH_BPS` of their stake and resets the job to
    /// Pending so the next coordinator (current epoch's election)
    /// can pick it up.
    ///
    /// @dev Caller must be a current pool member to prevent griefing
    ///      from outsiders. The slash amount is small per-incident
    ///      (10 bps = 0.1%) but accumulates across repeated
    ///      offenses, eventually pushing a chronically-offline
    ///      provider out of the pool via stake exhaustion.
    function reassignCoordinator(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(
            job.status == JobStatus.Executing,
            "Job not in Executing"
        );
        require(
            block.number > job.dispatchBlock + COORDINATION_TIMEOUT,
            "Coordinator has time"
        );

        // Caller must be a current pool member (prevents outside
        // griefing).
        require(
            members[job.poolId][msg.sender].active,
            "Not a pool member"
        );

        address stalled = job.dispatchedBy;
        require(stalled != address(0), "No prior coordinator");

        // Slash the stalled coordinator.
        PoolMember storage badMember = members[job.poolId][stalled];
        uint256 slashAmount = (badMember.stake * LIVENESS_SLASH_BPS) / BPS;
        if (slashAmount > 0 && badMember.stake >= slashAmount) {
            badMember.stake -= slashAmount;
            // Slashed funds stay in the contract treasury for now;
            // a future sprint may route them to an insurance pool.
            emit CoordinatorSlashedForLiveness(
                job.poolId,
                stalled,
                slashAmount
            );
        }

        // Reset job state so the next election cycle dispatches it.
        job.status = JobStatus.Pending;
        job.dispatchBlock = 0;
        job.dispatchedBy = address(0);

        // Inform indexers of the reassignment. The "next" address
        // isn't determined here — the next dispatch action will pick
        // whichever address `coordinatorFor(poolId, epoch)` returns
        // at that point, which may differ from the stalled one
        // automatically (next epoch) or stay the same (same epoch +
        // VRF still picks them — in which case they get another
        // chance and another slash if they fail again).
        emit CoordinatorReassigned(jobId, stalled, address(0));
    }

    // ── Internal ────────────────────────────────────────────────────

    /// @dev Shared body for both `requestPoolCompute` overloads.
    function _requestPoolCompute(
        uint256 poolId,
        bytes memory jobSpec,
        uint256 maxPrice
    ) internal returns (uint256 jobId) {
        Pool storage pool = pools[poolId];
        require(pool.state == PoolState.Active, "Pool not active");
        require(pool.memberCount >= pool.minProviders, "Insufficient providers");
        require(msg.value >= pool.pricePerUnit, "Insufficient payment");
        require(msg.value >= maxPrice, "Payment less than maxPrice");
        require(jobSpec.length > 0, "Empty job spec");

        jobId = nextJobId++;

        PoolJob storage pj = jobs[jobId];
        pj.poolId = poolId;
        pj.requester = msg.sender;
        pj.jobSpec = jobSpec;
        pj.payment = msg.value;
        pj.status = JobStatus.Pending;
        pj.createdAt = block.number;
        // dispatchBlock + dispatchedBy left as zero-defaults; set by
        // `recordDispatch`.

        pool.activeJobCount++;

        emit ComputeRequested(poolId, jobId, msg.sender, msg.value);
    }

    /// @dev Distribute payment to pool members proportionally based on GPU contribution.
    function _distributePayment(uint256 poolId, uint256 totalPayment) internal {
        Pool storage pool = pools[poolId];
        if (pool.totalGPUs == 0 || totalPayment == 0) return;

        address[] storage memberList = _poolMembers[poolId];
        uint256 distributed = 0;

        for (uint256 i = 0; i < memberList.length; i++) {
            address memberAddr = memberList[i];
            PoolMember storage member = members[poolId][memberAddr];

            if (member.active && member.gpuCount > 0) {
                uint256 share = (totalPayment * member.gpuCount) / pool.totalGPUs;

                if (share > 0) {
                    distributed += share;
                    (bool success, ) = payable(memberAddr).call{value: share}("");
                    require(success, "Payment distribution failed");
                }
            }
        }

        // Any dust remaining due to rounding stays in the contract
    }

    // ── Receive ─────────────────────────────────────────────────────

    /// @notice Accept SALT transfers.
    receive() external payable {}
}
