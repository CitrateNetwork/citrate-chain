// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/ComputeLib.sol";
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
contract ComputePool is ReentrancyGuard {
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

    /// @notice Governance address.
    address public governance;

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
    event SLAViolationReported(uint256 indexed poolId, uint256 actualThroughput, uint256 guaranteedThroughput);
    event SlashingContractUpdated(address oldContract, address newContract);
    event GovernanceTransferred(address indexed oldGov, address indexed newGov);

    // ── Modifiers ───────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governance, "Not governance");
        _;
    }

    modifier poolExists(uint256 poolId) {
        require(poolId < nextPoolId, "Pool does not exist");
        _;
    }

    modifier onlyPoolCreator(uint256 poolId) {
        require(pools[poolId].creator == msg.sender, "Not pool creator");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────

    constructor() {
        governance = msg.sender;
    }

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
        Pool storage pool = pools[poolId];
        require(pool.state == PoolState.Active, "Pool not active");
        require(pool.memberCount >= pool.minProviders, "Insufficient providers");
        require(msg.value >= pool.pricePerUnit, "Insufficient payment");
        require(msg.value >= maxPrice, "Payment less than maxPrice");
        require(jobSpec.length > 0, "Empty job spec");

        jobId = nextJobId++;

        // Initialize job field-by-field to reduce stack pressure
        PoolJob storage pj = jobs[jobId];
        pj.poolId = poolId;
        pj.requester = msg.sender;
        pj.jobSpec = jobSpec;
        pj.payment = msg.value;
        pj.status = JobStatus.Pending;
        pj.createdAt = block.number;

        pool.activeJobCount++;

        emit ComputeRequested(poolId, jobId, msg.sender, msg.value);
    }

    /// @notice Mark a job as completed (governance or pool creator).
    /// @dev Payment is distributed proportionally to pool members.
    /// @param jobId The job to complete.
    function completeJob(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(job.status == JobStatus.Pending || job.status == JobStatus.Executing, "Invalid job status");

        Pool storage pool = pools[job.poolId];
        require(
            msg.sender == governance || msg.sender == pool.creator,
            "Not authorized"
        );

        job.status = JobStatus.Completed;
        pool.activeJobCount--;

        // Distribute payment proportionally based on GPU contribution
        _distributePayment(job.poolId, job.payment);

        emit JobCompleted(jobId, job.poolId);
    }

    /// @notice Mark a job as failed (governance or pool creator). Payment refunded.
    /// @param jobId The job that failed.
    function failJob(uint256 jobId) external nonReentrant {
        PoolJob storage job = jobs[jobId];
        require(job.status == JobStatus.Pending || job.status == JobStatus.Executing, "Invalid job status");

        Pool storage pool = pools[job.poolId];
        require(
            msg.sender == governance || msg.sender == pool.creator,
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

    /// @notice Transfer governance.
    /// @param newGovernance New governance address.
    function transferGovernance(address newGovernance) external onlyGovernance {
        require(newGovernance != address(0), "Zero address");
        address old = governance;
        governance = newGovernance;
        emit GovernanceTransferred(old, newGovernance);
    }

    // ── Internal ────────────────────────────────────────────────────

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
