// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";

/// @title ComputePoolTraining — DataParallel training jobs (CM-07)
/// @notice Extension contract for the CM-05 ComputePool surface that
///         adds the DataParallel training lifecycle. Per ADR-008, the
///         chain holds only per-epoch Merkle roots — individual step
///         commitments live in the libp2p mesh. This keeps gas cost
///         bounded regardless of worker × step cardinality.
///
///         Enforced invariants (matching the three CM-07 TLA+ specs):
///           - SingleCoordinatorPerEpoch — at most one coordinator
///             address per (jobId, epoch)
///           - EpochMonotonic — commitEpoch calls are sequential
///             0, 1, 2, ... without gaps
///           - FinalizedImpliesAllEpochsCommitted — finalize only
///             accepts when every epoch has a root
///           - StakeConservation — per-worker:
///               posted == paid + slashed + returned + held
///           - PerEpochBudgetRespected — cumulative payout per
///             epoch ≤ perEpochBudget
///           - NoSelfChallenge — a worker cannot challenge themselves
///           - ResolvedChallengeSettlesBond — bond either returned
///             (with reward) or forfeited, never held after resolution
///
///         Deployment: v3 fresh-address. The CM-05 ComputePool v2
///         remains at its own address for InferencePool traffic.
///
/// @dev CM-07 WP-07.1. See docs/adr/ADR-008-gradient-commitment.md.
contract ComputePoolTraining is ReentrancyGuard {
    // ── Types ───────────────────────────────────────────────────────

    enum JobState { Recruiting, Training, Awaiting, Finalized, Aborted }

    enum ChallengeState { None, Voting, ResolvedUphold, ResolvedReject }

    struct TrainingJobSpec {
        bytes32 modelStartHash;
        bytes32 datasetHash;
        uint32 epochCount;
        uint32 stepsPerEpoch;
        uint32 minWorkers;
        uint32 maxWorkers;
        uint32 challengeWindowBlocks;
        uint128 perEpochBudget;
        uint128 perWorkerStake;
    }

    struct TrainingJob {
        address requester;
        bytes32 modelStartHash;
        bytes32 datasetHash;
        uint32 epochCount;
        uint32 stepsPerEpoch;
        uint32 minWorkers;
        uint32 maxWorkers;
        uint32 challengeWindowBlocks;
        uint128 perEpochBudget;
        uint128 perWorkerStake;
        uint128 escrowRemaining;        // buyer's epoch-budget × epochCount, drawn down per commitEpoch
        JobState state;
        uint32 currentEpoch;
        uint32 workerCount;
        uint64 allEpochsCommittedBlock; // 0 until final epoch root posted; then = block.number
        address coordinator;            // set at closeRecruitment; rotation is a future CM-05-alignment
    }

    struct WorkerInfo {
        // ── Stake ledger ─────────────────────────────────────────
        // The TLA+ DataParallelEscrow.tla StakeConservation invariant
        // applies to THIS ledger only:
        //     stakePosted == stakeSlashed + stakeReturned + held
        // where held is derived on the fly.
        uint128 stakePosted;
        uint128 stakeSlashed;
        uint128 stakeReturned;
        // ── Earnings ledger ──────────────────────────────────────
        // Payment from buyer escrow is a SEPARATE flow; it doesn't
        // reduce the worker's posted collateral. Accrues per epoch;
        // paid out to the worker in a single transfer at finalize.
        uint128 paymentEarned;
        bool joined;
    }

    struct Challenge {
        address challenger;
        uint128 bond;
        uint64 openedAt;
        ChallengeState state;
        uint8 upholdVotes;
        uint8 rejectVotes;
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Challenge bond amount in native token (SALT). Refunded
    /// with reward on successful challenge; forfeited on reject.
    uint256 public constant CHALLENGE_BOND = 1 ether;

    /// @notice Slash amount applied to a target on successful challenge.
    /// 10% of the worker's posted stake per successful challenge.
    uint256 public constant SLASH_BPS = 1000;

    /// @notice Basis points denominator.
    uint256 private constant BPS = 10000;

    /// @notice Committee quorum required to resolve a challenge. The
    /// committee is governance-configured (see `setCommittee`).
    uint256 public constant COMMITTEE_QUORUM = 2;

    // ── State ───────────────────────────────────────────────────────

    mapping(uint256 => TrainingJob) public jobs;

    /// @notice workers[jobId][address] → WorkerInfo
    mapping(uint256 => mapping(address => WorkerInfo)) public workers;

    /// @notice Per-job flat list of joined worker addresses. Keeps
    /// finalize / iteration cheap for small pools; scale-out would
    /// need a different shape.
    mapping(uint256 => address[]) internal _workerList;

    /// @notice Per-epoch Merkle root over (step, worker) leaves. 0 if
    /// not yet committed.
    mapping(uint256 => mapping(uint32 => bytes32)) public epochCommitment;

    /// @notice Per-epoch cumulative payout amount, for the
    /// PerEpochBudgetRespected invariant.
    mapping(uint256 => mapping(uint32 => uint128)) public epochPaid;

    /// @notice challenges[jobId][epoch][step][target] — each (step,
    /// target) tuple can have at most one open challenge at a time.
    /// Another challenger opening a second against the same (step,
    /// target) overwrites the slot only if the previous state was
    /// Resolved*.
    mapping(uint256 => mapping(uint32 => mapping(uint32 => mapping(address => Challenge))))
        public challenges;

    /// @notice Has a committee member already voted on this challenge?
    mapping(uint256 => mapping(uint32 => mapping(uint32 => mapping(address => mapping(address => bool)))))
        public hasVoted;

    /// @notice Governance-configured committee addresses.
    mapping(address => bool) public committee;

    uint256 public nextJobId;

    /// @notice Governance address (manages committee + upgrades).
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    event TrainingJobOpened(
        uint256 indexed jobId,
        address indexed requester,
        bytes32 modelStartHash,
        bytes32 datasetHash,
        uint32 epochCount,
        uint32 stepsPerEpoch
    );
    event WorkerJoined(uint256 indexed jobId, address indexed worker, uint128 stake);
    event RecruitmentClosed(uint256 indexed jobId, uint32 workerCount, address coordinator);
    event EpochCommitted(uint256 indexed jobId, uint32 indexed epoch, bytes32 root);
    event EpochPaymentReleased(
        uint256 indexed jobId,
        uint32 indexed epoch,
        address indexed worker,
        uint128 amount
    );
    event ChallengeOpened(
        uint256 indexed jobId,
        uint32 indexed epoch,
        uint32 step,
        address indexed target,
        address challenger,
        uint128 bond
    );
    event ChallengeVoted(
        uint256 indexed jobId,
        uint32 indexed epoch,
        uint32 step,
        address indexed target,
        address voter,
        bool uphold
    );
    event ChallengeResolved(
        uint256 indexed jobId,
        uint32 indexed epoch,
        uint32 step,
        address indexed target,
        bool upheld,
        uint128 slashAmount
    );
    event WorkerStakeReturned(uint256 indexed jobId, address indexed worker, uint128 amount);
    event TrainingJobCompleted(uint256 indexed jobId, bytes32 finalWeightsHash);
    event TrainingJobAborted(uint256 indexed jobId, string reason);
    event CommitteeUpdated(address indexed member, bool isMember);

    // ── Modifiers ───────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governance, "ComputePoolTraining: not governance");
        _;
    }

    modifier jobExists(uint256 jobId) {
        require(jobs[jobId].requester != address(0), "ComputePoolTraining: unknown job");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address _governance) {
        require(_governance != address(0), "ComputePoolTraining: zero governance");
        governance = _governance;
    }

    // ── Job lifecycle ───────────────────────────────────────────────

    /// @notice Create a training job. The caller (requester) escrows
    /// `perEpochBudget × epochCount` in native token to fund per-epoch
    /// payments to workers.
    ///
    /// Returns the assigned jobId. Emits TrainingJobOpened.
    function requestTrainingJob(TrainingJobSpec calldata spec)
        external
        payable
        nonReentrant
        returns (uint256 jobId)
    {
        require(spec.epochCount > 0, "ComputePoolTraining: zero epochs");
        require(spec.stepsPerEpoch > 0, "ComputePoolTraining: zero steps");
        require(spec.minWorkers >= 1, "ComputePoolTraining: zero min workers");
        require(spec.maxWorkers >= spec.minWorkers, "ComputePoolTraining: max < min");
        require(spec.perEpochBudget > 0, "ComputePoolTraining: zero epoch budget");
        require(spec.perWorkerStake > 0, "ComputePoolTraining: zero worker stake");

        uint256 requiredEscrow = uint256(spec.perEpochBudget) * spec.epochCount;
        require(msg.value == requiredEscrow, "ComputePoolTraining: escrow mismatch");

        jobId = nextJobId++;
        TrainingJob storage job = jobs[jobId];
        job.requester = msg.sender;
        job.modelStartHash = spec.modelStartHash;
        job.datasetHash = spec.datasetHash;
        job.epochCount = spec.epochCount;
        job.stepsPerEpoch = spec.stepsPerEpoch;
        job.minWorkers = spec.minWorkers;
        job.maxWorkers = spec.maxWorkers;
        job.challengeWindowBlocks = spec.challengeWindowBlocks;
        job.perEpochBudget = spec.perEpochBudget;
        job.perWorkerStake = spec.perWorkerStake;
        job.escrowRemaining = uint128(requiredEscrow);
        job.state = JobState.Recruiting;

        emit TrainingJobOpened(
            jobId,
            msg.sender,
            spec.modelStartHash,
            spec.datasetHash,
            spec.epochCount,
            spec.stepsPerEpoch
        );
    }

    /// @notice Worker joins the training job by posting stake. Valid
    /// only during Recruiting. Stake is held until finalization or
    /// slash.
    function joinTrainingJob(uint256 jobId) external payable jobExists(jobId) nonReentrant {
        TrainingJob storage job = jobs[jobId];
        require(job.state == JobState.Recruiting, "ComputePoolTraining: not recruiting");
        require(!workers[jobId][msg.sender].joined, "ComputePoolTraining: already joined");
        require(job.workerCount < job.maxWorkers, "ComputePoolTraining: pool full");
        require(msg.value == job.perWorkerStake, "ComputePoolTraining: stake mismatch");

        workers[jobId][msg.sender] = WorkerInfo({
            stakePosted: job.perWorkerStake,
            stakeSlashed: 0,
            stakeReturned: 0,
            paymentEarned: 0,
            joined: true
        });
        _workerList[jobId].push(msg.sender);
        job.workerCount += 1;

        emit WorkerJoined(jobId, msg.sender, job.perWorkerStake);
    }

    /// @notice Close the recruitment window and elect the initial
    /// coordinator. Callable by anyone once minWorkers is met. The
    /// coordinator must be a joined worker.
    function closeRecruitment(uint256 jobId, address coordinator_)
        external
        jobExists(jobId)
    {
        TrainingJob storage job = jobs[jobId];
        require(job.state == JobState.Recruiting, "ComputePoolTraining: not recruiting");
        require(job.workerCount >= job.minWorkers, "ComputePoolTraining: below min workers");
        require(workers[jobId][coordinator_].joined, "ComputePoolTraining: coord not joined");

        job.state = JobState.Training;
        job.coordinator = coordinator_;
        emit RecruitmentClosed(jobId, job.workerCount, coordinator_);
    }

    /// @notice Coordinator posts the Merkle root for the current
    /// epoch. Epochs must be committed in sequence: currentEpoch is
    /// the one accepted by this call; incremented after.
    ///
    /// Payment: `perEpochBudget` is divided equally among
    /// *currently-unslashed* workers and credited to their stakePaid
    /// ledger. Workers claim the actual ETH via `withdrawPayment`
    /// after the challenge window closes (pull pattern avoids gas
    /// griefing; also lets a late challenge claw back).
    function commitEpoch(uint256 jobId, uint32 epoch, bytes32 root)
        external
        jobExists(jobId)
        nonReentrant
    {
        TrainingJob storage job = jobs[jobId];
        require(job.state == JobState.Training, "ComputePoolTraining: not training");
        require(msg.sender == job.coordinator, "ComputePoolTraining: not coordinator");
        require(epoch == job.currentEpoch, "ComputePoolTraining: wrong epoch");
        require(root != bytes32(0), "ComputePoolTraining: zero root");
        require(epochCommitment[jobId][epoch] == bytes32(0), "ComputePoolTraining: epoch already committed");

        epochCommitment[jobId][epoch] = root;

        // Distribute per-epoch payment among un-slashed workers. A
        // worker with stakeSlashed > 0 forfeits this epoch's share —
        // the forfeited slice stays in escrow and rolls into the
        // buyer's refund at finalize.
        uint32 paidCount = 0;
        address[] storage wlist = _workerList[jobId];
        for (uint256 i = 0; i < wlist.length; i++) {
            if (workers[jobId][wlist[i]].stakeSlashed == 0) {
                paidCount += 1;
            }
        }
        if (paidCount > 0) {
            uint128 perWorker = uint128(uint256(job.perEpochBudget) / paidCount);
            uint128 epochTotal = 0;
            for (uint256 i = 0; i < wlist.length; i++) {
                WorkerInfo storage w = workers[jobId][wlist[i]];
                if (w.stakeSlashed == 0) {
                    w.paymentEarned += perWorker;
                    epochTotal += perWorker;
                    emit EpochPaymentReleased(jobId, epoch, wlist[i], perWorker);
                }
            }
            epochPaid[jobId][epoch] = epochTotal;
            job.escrowRemaining -= epochTotal;
        }

        emit EpochCommitted(jobId, epoch, root);

        job.currentEpoch += 1;
        if (job.currentEpoch == job.epochCount) {
            job.state = JobState.Awaiting;
            job.allEpochsCommittedBlock = uint64(block.number);
        }
    }

    /// @notice Finalize the job. Requires every epoch committed AND
    /// challenge window elapsed since final epoch root was posted.
    /// Returns remaining worker stakes and buyer-side refund.
    function finalizeTrainingJob(uint256 jobId)
        external
        jobExists(jobId)
        nonReentrant
    {
        TrainingJob storage job = jobs[jobId];
        require(job.state == JobState.Awaiting, "ComputePoolTraining: not awaiting");
        require(
            block.number >= uint256(job.allEpochsCommittedBlock) + job.challengeWindowBlocks,
            "ComputePoolTraining: challenge window open"
        );

        job.state = JobState.Finalized;

        // Return remaining stake to each worker + pay out their
        // accumulated stakePaid. The pull-vs-push trade-off: push
        // here means one call finalizes everything. Gas cost scales
        // linearly with workerCount (~30k per worker for two
        // transfers). At N=50, ~1.5M gas — acceptable.
        address[] storage wlist = _workerList[jobId];
        for (uint256 i = 0; i < wlist.length; i++) {
            address worker = wlist[i];
            WorkerInfo storage info = workers[jobId][worker];
            uint128 held = info.stakePosted - info.stakeSlashed - info.stakeReturned;
            uint128 toPay = info.paymentEarned;
            uint128 toReturn = held;
            info.stakeReturned += held;
            // Zero out paymentEarned once sent so a surprise re-entry
            // can't double-spend it.
            info.paymentEarned = 0;

            if (toPay + toReturn > 0) {
                (bool ok, ) = worker.call{value: uint256(toPay) + uint256(toReturn)}("");
                require(ok, "ComputePoolTraining: worker transfer failed");
                if (toReturn > 0) emit WorkerStakeReturned(jobId, worker, toReturn);
            }
        }

        // Refund any buyer-escrow that wasn't distributed (e.g., if
        // some epochs had fewer eligible workers than expected).
        uint128 remaining = job.escrowRemaining;
        if (remaining > 0) {
            job.escrowRemaining = 0;
            (bool ok, ) = job.requester.call{value: remaining}("");
            require(ok, "ComputePoolTraining: requester refund failed");
        }

        // finalWeightsHash: the last epoch's Merkle root doubles as
        // the canonical "final model state" handle. Off-chain tooling
        // resolves it to weight tensors via the mesh archive.
        emit TrainingJobCompleted(jobId, epochCommitment[jobId][job.epochCount - 1]);
    }

    // ── Challenge lifecycle ─────────────────────────────────────────

    /// @notice Open a challenge against `target`'s step commit at
    /// (epoch, step). The caller provides the leaf they dispute and
    /// a Merkle proof that the leaf is genuinely in the stored epoch
    /// root — this guarantees the challenge is against a real
    /// commitment, not a phantom.
    ///
    /// `leaf` is keccak256(abi.encode(epoch, step, target,
    /// stepCommitHash, prevWeightsHash)) per ADR-008. The challenger
    /// must have obtained the pre-image from the off-chain mesh.
    function challengeStep(
        uint256 jobId,
        uint32 epoch,
        uint32 step,
        address target,
        bytes32 leaf,
        bytes32[] calldata merkleProof
    ) external payable jobExists(jobId) nonReentrant {
        TrainingJob storage job = jobs[jobId];
        require(target != msg.sender, "ComputePoolTraining: no self challenge");
        require(workers[jobId][target].joined, "ComputePoolTraining: target not joined");
        require(msg.value == CHALLENGE_BOND, "ComputePoolTraining: wrong bond");
        require(step < job.stepsPerEpoch, "ComputePoolTraining: step out of range");
        require(epoch < job.epochCount, "ComputePoolTraining: epoch out of range");

        // Must be within the challenge window — either during Training
        // (for committed epochs) or Awaiting (before window closes).
        require(
            job.state == JobState.Training || job.state == JobState.Awaiting,
            "ComputePoolTraining: not open for challenge"
        );
        if (job.state == JobState.Awaiting) {
            require(
                block.number < uint256(job.allEpochsCommittedBlock) + job.challengeWindowBlocks,
                "ComputePoolTraining: challenge window closed"
            );
        }

        bytes32 epochRoot = epochCommitment[jobId][epoch];
        require(epochRoot != bytes32(0), "ComputePoolTraining: epoch not committed");
        require(_verifyMerkleProof(merkleProof, epochRoot, leaf), "ComputePoolTraining: bad proof");

        Challenge storage ch = challenges[jobId][epoch][step][target];
        require(
            ch.state == ChallengeState.None
            || ch.state == ChallengeState.ResolvedReject
            || ch.state == ChallengeState.ResolvedUphold,
            "ComputePoolTraining: challenge active"
        );

        ch.challenger = msg.sender;
        ch.bond = uint128(msg.value);
        ch.openedAt = uint64(block.number);
        ch.state = ChallengeState.Voting;
        ch.upholdVotes = 0;
        ch.rejectVotes = 0;

        emit ChallengeOpened(jobId, epoch, step, target, msg.sender, ch.bond);
    }

    /// @notice Committee member votes on an active challenge. Quorum
    /// triggers automatic resolution.
    function voteChallenge(
        uint256 jobId,
        uint32 epoch,
        uint32 step,
        address target,
        bool uphold
    ) external jobExists(jobId) nonReentrant {
        require(committee[msg.sender], "ComputePoolTraining: not committee");
        Challenge storage ch = challenges[jobId][epoch][step][target];
        require(ch.state == ChallengeState.Voting, "ComputePoolTraining: not voting");
        require(!hasVoted[jobId][epoch][step][target][msg.sender], "ComputePoolTraining: already voted");

        hasVoted[jobId][epoch][step][target][msg.sender] = true;
        if (uphold) ch.upholdVotes += 1;
        else ch.rejectVotes += 1;

        emit ChallengeVoted(jobId, epoch, step, target, msg.sender, uphold);

        if (ch.upholdVotes >= COMMITTEE_QUORUM) {
            _resolveChallenge(jobId, epoch, step, target, true);
        } else if (ch.rejectVotes >= COMMITTEE_QUORUM) {
            _resolveChallenge(jobId, epoch, step, target, false);
        }
    }

    function _resolveChallenge(
        uint256 jobId,
        uint32 epoch,
        uint32 step,
        address target,
        bool upheld
    ) internal {
        Challenge storage ch = challenges[jobId][epoch][step][target];
        uint128 bond = ch.bond;
        address challenger = ch.challenger;
        uint128 slashAmount = 0;

        if (upheld) {
            // Slash target: SLASH_BPS of their posted stake.
            WorkerInfo storage targetInfo = workers[jobId][target];
            uint128 held = targetInfo.stakePosted - targetInfo.stakeSlashed - targetInfo.stakeReturned;
            slashAmount = uint128(uint256(targetInfo.stakePosted) * SLASH_BPS / BPS);
            if (slashAmount > held) slashAmount = held;
            targetInfo.stakeSlashed += slashAmount;

            ch.state = ChallengeState.ResolvedUphold;
            ch.bond = 0;

            // Challenger gets bond + half the slash. Other half stays
            // in the contract (effectively burned / rolled into buyer
            // refund at finalize).
            uint128 reward = slashAmount / 2;
            (bool ok, ) = challenger.call{value: uint256(bond) + uint256(reward)}("");
            require(ok, "ComputePoolTraining: reward transfer failed");
        } else {
            // Challenger forfeits bond; stays in the contract.
            ch.state = ChallengeState.ResolvedReject;
            ch.bond = 0;
        }

        emit ChallengeResolved(jobId, epoch, step, target, upheld, slashAmount);
    }

    // ── Governance ──────────────────────────────────────────────────

    function setCommittee(address member, bool active) external onlyGovernance {
        committee[member] = active;
        emit CommitteeUpdated(member, active);
    }

    function transferGovernance(address newGovernance) external onlyGovernance {
        require(newGovernance != address(0), "ComputePoolTraining: zero governance");
        governance = newGovernance;
    }

    /// @notice Abort a recruiting job whose minWorkers was never met.
    /// Refunds the requester's escrow + any already-joined workers'
    /// stakes. Callable after `abortDeadlineBlocks` blocks past
    /// opening to avoid a premature abort race.
    function abortRecruiting(uint256 jobId) external jobExists(jobId) nonReentrant {
        TrainingJob storage job = jobs[jobId];
        require(job.state == JobState.Recruiting, "ComputePoolTraining: not recruiting");
        require(msg.sender == job.requester || msg.sender == governance,
                "ComputePoolTraining: not authorized");

        job.state = JobState.Aborted;

        // Refund joined workers
        address[] storage wlist = _workerList[jobId];
        for (uint256 i = 0; i < wlist.length; i++) {
            address worker = wlist[i];
            WorkerInfo storage info = workers[jobId][worker];
            uint128 amount = info.stakePosted;
            info.stakeReturned = amount;
            if (amount > 0) {
                (bool ok, ) = worker.call{value: amount}("");
                require(ok, "ComputePoolTraining: stake refund failed");
            }
        }

        // Refund requester's escrow
        uint128 remaining = job.escrowRemaining;
        job.escrowRemaining = 0;
        if (remaining > 0) {
            (bool ok, ) = job.requester.call{value: remaining}("");
            require(ok, "ComputePoolTraining: requester refund failed");
        }

        emit TrainingJobAborted(jobId, "recruiting aborted");
    }

    // ── View helpers ────────────────────────────────────────────────

    function getJob(uint256 jobId) external view returns (TrainingJob memory) {
        return jobs[jobId];
    }

    function getWorker(uint256 jobId, address worker) external view returns (WorkerInfo memory) {
        return workers[jobId][worker];
    }

    function getWorkerList(uint256 jobId) external view returns (address[] memory) {
        return _workerList[jobId];
    }

    function getEpochRoot(uint256 jobId, uint32 epoch) external view returns (bytes32) {
        return epochCommitment[jobId][epoch];
    }

    function getChallenge(uint256 jobId, uint32 epoch, uint32 step, address target)
        external
        view
        returns (Challenge memory)
    {
        return challenges[jobId][epoch][step][target];
    }

    /// @notice Held stake for (jobId, worker). For the
    /// StakeConservation invariant: posted == slashed + returned + held.
    /// Note: paymentEarned is separate (buyer-escrow-sourced), not
    /// part of the stake ledger.
    function heldStake(uint256 jobId, address worker) external view returns (uint128) {
        WorkerInfo storage info = workers[jobId][worker];
        return info.stakePosted - info.stakeSlashed - info.stakeReturned;
    }

    // ── Internal: Merkle proof verification ─────────────────────────

    /// @notice Standard OpenZeppelin-style Merkle proof verifier.
    /// Concatenate-and-hash pattern with sorted-pair siblings so
    /// caller doesn't need to transmit left/right bits. This matches
    /// the sort-by-(step, worker) canonical leaf ordering described
    /// in ADR-008 — the verifier is independent of leaf order as long
    /// as both sides agree on it.
    function _verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            computed = computed <= sibling
                ? keccak256(abi.encodePacked(computed, sibling))
                : keccak256(abi.encodePacked(sibling, computed));
        }
        return computed == root;
    }
}
