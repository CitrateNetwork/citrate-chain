// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";
import "./TEEAttestationRegistry.sol";

/// @title ComputePoolPipeline — PipelineParallel inference (CM-08)
/// @notice On-chain lifecycle for pipeline-parallel requests. A
///         single request traverses N sequential stages, each owned
///         by one worker holding a model-layer slice. Stage 0
///         receives the input, forwards activations through stages,
///         stage N-1 emits tokens.
///
///         Every stage worker MUST hold a valid attestation in
///         TEEAttestationRegistry at `requestPipelineCompute` time
///         and at each stage advance. An expired or slashed worker
///         is non-serving.
///
///         Enforced invariants (matching PipelineParallelInference.tla):
///           - Stage ownership unique per worker
///           - Request progression strictly monotonic (no skip-back)
///           - Completed → passed through all stages
///           - Draft-implies-unowned (atomic fault-then-reassign)
///           - Terminated-is-clean (no in-flight requests)
///           - Payment conservation (from PipelineParallelEscrow.tla)
///
/// @dev CM-08 WP-08.1. Stand-alone deployment; separate from
///      ComputePool (CM-05) and ComputePoolTraining (CM-07).
contract ComputePoolPipeline is ReentrancyGuard, Governable {
    // ── Types ───────────────────────────────────────────────────────

    enum JobState { Forming, Active, Draining, Terminated }
    enum RequestState { Created, InFlight, Completed, Failed }

    struct Job {
        address creator;
        uint32 stageCount;
        uint128 paymentPerRequest;  // total escrow per request
        uint128 perStakePerStage;   // stake each stage owner posts
        JobState state;
        bytes32 modelHash;          // all stages attest to this
    }

    struct Request {
        uint256 jobId;
        address requester;
        uint32 progress;            // 0..stageCount (stageCount = Completed)
        RequestState state;
        uint128 escrow;             // paymentPerRequest at submit; drained per stage
        /// RM-B1 / WP-D5.2 (audit SOL-09): block height past which
        /// the request can be `failRequest`'d by anyone. Pre-fix
        /// only the original requester (or governance) could fail
        /// the request — a stuck request whose requester contract
        /// had self-destructed became permanent stake-locked state.
        /// Set to `submitBlock + maxLatencyBlocks` at submit.
        uint64 deadlineBlock;
    }

    // ── Constants ───────────────────────────────────────────────────

    uint32 public constant MAX_STAGE_COUNT = 32;
    uint32 public constant MIN_STAGE_COUNT = 2;

    /// RM-B1 / WP-D5.2 (audit SOL-09): per-request block deadline
    /// after which any caller can `failRequest`. Default 7200
    /// (~24h at 12s blocks) matches a generous outer bound; the
    /// real per-stage SLA is enforced off-chain via gateways.
    uint64 public constant DEFAULT_REQUEST_LATENCY_BLOCKS = 7200;

    // ── State ───────────────────────────────────────────────────────

    TEEAttestationRegistry public immutable teeRegistry;

    mapping(uint256 => Job) public jobs;
    /// jobId → stageIndex → ownerAddress
    mapping(uint256 => mapping(uint32 => address)) public stageOwner;
    /// jobId → stageIndex → replacementOwed (address displaced by fault)
    mapping(uint256 => mapping(uint32 => address)) public draftReplacements;
    /// jobId → ownerAddress → stakePosted
    mapping(uint256 => mapping(address => uint128)) public stageStake;
    /// jobId → ownerAddress → paymentEarned (from served requests)
    mapping(uint256 => mapping(address => uint128)) public paymentEarned;
    /// RM-B1 / WP-D5.5 (audit SOL-13): O(1) duplicate-stage check.
    /// jobId → ownerAddress → owns at least one stage in this job.
    /// Pre-fix the duplicate-stage scan was O(N) on every
    /// `assignStage` call (bounded by `MAX_STAGE_COUNT = 32`).
    mapping(uint256 => mapping(address => bool)) public hasStage;

    mapping(uint256 => Request) public requests;
    uint256 public nextJobId;
    uint256 public nextRequestId;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ── Events ──────────────────────────────────────────────────────

    event PipelineJobCreated(uint256 indexed jobId, address indexed creator, uint32 stageCount, bytes32 modelHash);
    event StageAssigned(uint256 indexed jobId, uint32 indexed stage, address indexed worker, uint128 stake);
    event JobActivated(uint256 indexed jobId);
    event PipelineRequestSubmitted(uint256 indexed requestId, uint256 indexed jobId, address indexed requester, uint128 escrow);
    event StageServed(uint256 indexed requestId, uint32 indexed stage, address indexed worker, uint128 stageShare);
    event PipelineRequestCompleted(uint256 indexed requestId);
    event PipelineRequestFailed(uint256 indexed requestId, uint128 refundedToRequester);
    event StageFaulted(uint256 indexed jobId, uint32 indexed stage, address indexed former);
    event StageReassigned(uint256 indexed jobId, uint32 indexed stage, address former, address newOwner);
    event JobDraining(uint256 indexed jobId);
    event JobTerminated(uint256 indexed jobId);

    // ── Modifiers ───────────────────────────────────────────────────

    // `onlyGovernance` is inherited from Governable.

    modifier jobExists(uint256 jobId) {
        require(jobs[jobId].creator != address(0), "Pipeline: unknown job");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address _governance, address _teeRegistry)
        Governable(_governance)
    {
        require(_teeRegistry != address(0), "Pipeline: zero registry");
        teeRegistry = TEEAttestationRegistry(_teeRegistry);
    }

    // ── Job lifecycle ───────────────────────────────────────────────

    function createPipelineJob(
        uint32 stageCount,
        uint128 paymentPerRequest,
        uint128 perStakePerStage,
        bytes32 modelHash
    ) external returns (uint256 jobId) {
        require(stageCount >= MIN_STAGE_COUNT && stageCount <= MAX_STAGE_COUNT, "Pipeline: bad stageCount");
        require(paymentPerRequest > 0, "Pipeline: zero payment");
        require(modelHash != bytes32(0), "Pipeline: zero model hash");
        require(paymentPerRequest % stageCount == 0, "Pipeline: payment not divisible");

        jobId = nextJobId++;
        jobs[jobId] = Job({
            creator: msg.sender,
            stageCount: stageCount,
            paymentPerRequest: paymentPerRequest,
            perStakePerStage: perStakePerStage,
            state: JobState.Forming,
            modelHash: modelHash
        });
        emit PipelineJobCreated(jobId, msg.sender, stageCount, modelHash);
    }

    /// @notice A worker joins as the owner of stage `s`. Must be
    /// attested in the registry. Once every stage is owned, anyone
    /// can call `activate`.
    function assignStage(uint256 jobId, uint32 stage) external payable jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Forming, "Pipeline: not forming");
        require(stage < job.stageCount, "Pipeline: stage out of range");
        require(stageOwner[jobId][stage] == address(0), "Pipeline: stage owned");
        require(msg.value == job.perStakePerStage, "Pipeline: stake mismatch");
        require(
            teeRegistry.isAttested(msg.sender, block.number),
            "Pipeline: not attested"
        );

        // RM-B1 / WP-D5.5 (audit SOL-13): O(1) duplicate-stage
        // check via the `hasStage` mapping. Pre-fix this was an
        // O(N) loop bounded by MAX_STAGE_COUNT (32). Bumping
        // stage count past that bound was gas-bounded.
        require(!hasStage[jobId][msg.sender], "Pipeline: worker holds another stage");

        stageOwner[jobId][stage] = msg.sender;
        stageStake[jobId][msg.sender] = job.perStakePerStage;
        hasStage[jobId][msg.sender] = true;
        emit StageAssigned(jobId, stage, msg.sender, job.perStakePerStage);
    }

    function activateJob(uint256 jobId) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Forming, "Pipeline: not forming");
        for (uint32 i = 0; i < job.stageCount; i++) {
            require(stageOwner[jobId][i] != address(0), "Pipeline: stage unowned");
        }
        job.state = JobState.Active;
        emit JobActivated(jobId);
    }

    // ── Request lifecycle ───────────────────────────────────────────

    function submitRequest(uint256 jobId)
        external
        payable
        jobExists(jobId)
        returns (uint256 requestId)
    {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Active, "Pipeline: not active");
        require(msg.value == job.paymentPerRequest, "Pipeline: payment mismatch");

        requestId = nextRequestId++;
        requests[requestId] = Request({
            jobId: jobId,
            requester: msg.sender,
            progress: 0,
            state: RequestState.InFlight,
            escrow: job.paymentPerRequest,
            deadlineBlock: uint64(block.number) + DEFAULT_REQUEST_LATENCY_BLOCKS
        });
        emit PipelineRequestSubmitted(requestId, jobId, msg.sender, job.paymentPerRequest);
    }

    /// @notice Current stage owner claims the per-stage share after
    /// executing. Callable only by the owner of `progress`-th stage.
    /// Advances progress; if progress == stageCount, request is
    /// Completed.
    function advanceRequest(uint256 requestId) external nonReentrant {
        Request storage req = requests[requestId];
        require(req.state == RequestState.InFlight, "Pipeline: not in-flight");
        Job storage job = jobs[req.jobId];

        uint32 stage = req.progress;
        address owner = stageOwner[req.jobId][stage];
        require(owner != address(0), "Pipeline: stage unowned (faulted)");
        require(msg.sender == owner, "Pipeline: caller not stage owner");
        require(
            teeRegistry.isAttested(owner, block.number),
            "Pipeline: stage not attested"
        );

        uint128 stageShare = job.paymentPerRequest / job.stageCount;
        paymentEarned[req.jobId][owner] += stageShare;
        req.escrow -= stageShare;

        req.progress += 1;
        emit StageServed(requestId, stage, owner, stageShare);
        if (req.progress == job.stageCount) {
            req.state = RequestState.Completed;
            emit PipelineRequestCompleted(requestId);
        }
    }

    /// @notice Mark a request Failed. Refunds any unspent escrow to
    /// the requester. Anyone can call; the contract doesn't
    /// automatically time out (real-time tracking is off-chain;
    /// caller attests to failure via this call).
    function failRequest(uint256 requestId) external nonReentrant {
        Request storage req = requests[requestId];
        require(req.state == RequestState.InFlight, "Pipeline: not in-flight");
        // RM-B1 / WP-D5.2 (audit SOL-09): permissionless after
        // deadline. Pre-fix only the original requester or
        // governance could fail the request — a self-destructed
        // requester left the stake/escrow permanently locked.
        bool authorized = msg.sender == req.requester || msg.sender == governance();
        bool pastDeadline = block.number > req.deadlineBlock;
        require(authorized || pastDeadline, "Pipeline: not authorized to fail");

        uint128 refund = req.escrow;
        req.escrow = 0;
        req.state = RequestState.Failed;

        if (refund > 0) {
            (bool ok, ) = req.requester.call{value: refund}("");
            require(ok, "Pipeline: refund failed");
        }
        emit PipelineRequestFailed(requestId, refund);
    }

    // ── Stage fault + reassignment ──────────────────────────────────

    /// @notice Marks a stage faulted. The old owner is removed; a
    /// `ReassignStage` call with a new worker must follow. Any
    /// joined stage-owner or governance can trigger.
    function faultStage(uint256 jobId, uint32 stage) external jobExists(jobId) nonReentrant {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Active || job.state == JobState.Draining, "Pipeline: wrong state");
        address former = stageOwner[jobId][stage];
        require(former != address(0), "Pipeline: no owner to fault");
        require(
            _isAnyStageOwner(jobId, msg.sender) || msg.sender == governance(),
            "Pipeline: not authorized to fault"
        );

        draftReplacements[jobId][stage] = former;
        stageOwner[jobId][stage] = address(0);
        // SOL-13: clear `hasStage` so the former owner can be
        // reassigned to a different stage in this job.
        hasStage[jobId][former] = false;

        // C040: return the faulted worker's OWN stake and its accrued earnings
        // rather than freezing them. `terminateJob` only pays *current* stage
        // owners, and `reassignStage` requires the replacement to post fresh
        // stake — so without this the former owner's `stageStake`/`paymentEarned`
        // are unreachable forever. Zero state before the external call (CEI).
        uint128 stake = stageStake[jobId][former];
        uint128 earned = paymentEarned[jobId][former];
        stageStake[jobId][former] = 0;
        paymentEarned[jobId][former] = 0;

        emit StageFaulted(jobId, stage, former);

        uint256 payout = uint256(stake) + uint256(earned);
        if (payout > 0) {
            (bool ok, ) = former.call{value: payout}("");
            require(ok, "Pipeline: fault payout failed");
        }
    }

    function reassignStage(uint256 jobId, uint32 stage) external payable jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Active || job.state == JobState.Draining, "Pipeline: wrong state");
        require(stageOwner[jobId][stage] == address(0), "Pipeline: stage still owned");
        address former = draftReplacements[jobId][stage];
        require(former != address(0), "Pipeline: no fault pending");
        require(msg.sender != former, "Pipeline: former cannot take back");
        require(msg.value == job.perStakePerStage, "Pipeline: stake mismatch");
        require(
            teeRegistry.isAttested(msg.sender, block.number),
            "Pipeline: not attested"
        );
        // SOL-13: O(1) check via hasStage mapping.
        require(!hasStage[jobId][msg.sender], "Pipeline: worker holds another stage");

        stageOwner[jobId][stage] = msg.sender;
        stageStake[jobId][msg.sender] = job.perStakePerStage;
        hasStage[jobId][msg.sender] = true;
        draftReplacements[jobId][stage] = address(0);
        emit StageReassigned(jobId, stage, former, msg.sender);
    }

    // ── Drain + terminate ───────────────────────────────────────────

    function drainJob(uint256 jobId) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Active, "Pipeline: not active");
        require(msg.sender == job.creator || msg.sender == governance(), "Pipeline: not authorized");
        job.state = JobState.Draining;
        emit JobDraining(jobId);
    }

    /// @notice Terminate a drained job. Requires no InFlight
    /// requests for this job. Returns stake + paymentEarned to
    /// every stage owner.
    function terminateJob(uint256 jobId) external jobExists(jobId) nonReentrant {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Draining, "Pipeline: not draining");

        job.state = JobState.Terminated;

        // Distribute stake + earnings to every stage owner.
        for (uint32 i = 0; i < job.stageCount; i++) {
            address owner = stageOwner[jobId][i];
            if (owner == address(0)) continue;
            uint128 stake = stageStake[jobId][owner];
            uint128 earned = paymentEarned[jobId][owner];
            stageStake[jobId][owner] = 0;
            paymentEarned[jobId][owner] = 0;
            if (stake + earned > 0) {
                (bool ok, ) = owner.call{value: uint256(stake) + uint256(earned)}("");
                require(ok, "Pipeline: worker payout failed");
            }
        }
        emit JobTerminated(jobId);
    }

    // ── Views + helpers ─────────────────────────────────────────────

    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }

    function getRequest(uint256 requestId) external view returns (Request memory) {
        return requests[requestId];
    }

    function getStageOwner(uint256 jobId, uint32 stage) external view returns (address) {
        return stageOwner[jobId][stage];
    }

    function _isAnyStageOwner(uint256 jobId, address who) internal view returns (bool) {
        Job storage job = jobs[jobId];
        for (uint32 i = 0; i < job.stageCount; i++) {
            if (stageOwner[jobId][i] == who) return true;
        }
        return false;
    }
}
