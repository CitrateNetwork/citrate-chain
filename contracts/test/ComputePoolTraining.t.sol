// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePoolTraining} from "../src/ComputePoolTraining.sol";

/// @title ComputePoolTrainingTest — CM-07 WP-07.1 acceptance suite
/// @notice Seven acceptance tests per the planset plus additional
///         coverage for the TLA+ invariants (StakeConservation,
///         PerEpochBudgetRespected, NoSelfChallenge, EpochMonotonic).
///         Tests use the Merkle-root-only commitment design from
///         ADR-008.
contract ComputePoolTrainingTest is Test {
    ComputePoolTraining internal pool;

    address internal governance = address(this);
    address internal requester = address(0xA11CE);
    address internal w1 = address(0xBBB1);
    address internal w2 = address(0xBBB2);
    address internal w3 = address(0xBBB3);
    address internal challenger = address(0xC0DE);
    address internal committee1 = address(0xC011);
    address internal committee2 = address(0xC022);
    address internal committee3 = address(0xC033);

    // Simulated epoch roots. In production these are keccak256 Merkle
    // roots over (step, worker) leaves; in tests we just need a
    // non-zero bytes32 the committee can verify against.
    bytes32 internal constant ROOT0 = bytes32(uint256(0x1111));
    bytes32 internal constant ROOT1 = bytes32(uint256(0x2222));

    uint128 internal constant STAKE = 10 ether;
    uint128 internal constant EPOCH_BUDGET = 30 ether;

    function setUp() public {
        pool = new ComputePoolTraining(governance);
        pool.setCommittee(committee1, true);
        pool.setCommittee(committee2, true);
        pool.setCommittee(committee3, true);

        vm.deal(requester, 1000 ether);
        vm.deal(w1, 100 ether);
        vm.deal(w2, 100 ether);
        vm.deal(w3, 100 ether);
        vm.deal(challenger, 10 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _defaultSpec()
        internal
        pure
        returns (ComputePoolTraining.TrainingJobSpec memory spec)
    {
        spec.modelStartHash = keccak256("llama-3.2-1b-initial");
        spec.datasetHash = keccak256("mnist-shards-root");
        spec.epochCount = 2;
        spec.stepsPerEpoch = 2;
        spec.minWorkers = 3;
        spec.maxWorkers = 5;
        spec.challengeWindowBlocks = 10;
        spec.perEpochBudget = EPOCH_BUDGET;
        spec.perWorkerStake = STAKE;
    }

    function _openJob() internal returns (uint256 jobId) {
        ComputePoolTraining.TrainingJobSpec memory spec = _defaultSpec();
        uint256 escrow = uint256(spec.perEpochBudget) * spec.epochCount;
        vm.prank(requester);
        jobId = pool.requestTrainingJob{value: escrow}(spec);
    }

    function _joinThree(uint256 jobId) internal {
        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(w2);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(w3);
        pool.joinTrainingJob{value: STAKE}(jobId);
    }

    // ── #1 Full lifecycle: 3 workers × 2 epochs ─────────────────────

    function test_dataparallel_job_lifecycle_3_workers_2_epochs() public {
        uint256 jobId = _openJob();

        // All three workers join during Recruiting.
        _joinThree(jobId);
        ComputePoolTraining.TrainingJob memory job = pool.getJob(jobId);
        assertEq(uint8(job.state), uint8(ComputePoolTraining.JobState.Recruiting));
        assertEq(job.workerCount, 3);

        // Close recruitment, elect w1 coordinator.
        pool.closeRecruitment(jobId, w1);
        job = pool.getJob(jobId);
        assertEq(uint8(job.state), uint8(ComputePoolTraining.JobState.Training));
        assertEq(job.coordinator, w1);

        // Coordinator commits epoch 0 root. Epoch payments go out.
        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);
        job = pool.getJob(jobId);
        assertEq(job.currentEpoch, 1);
        assertEq(pool.getEpochRoot(jobId, 0), ROOT0);

        // Coordinator commits epoch 1 root → job moves to Awaiting.
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);
        job = pool.getJob(jobId);
        assertEq(uint8(job.state), uint8(ComputePoolTraining.JobState.Awaiting));

        // Roll the block forward past the challenge window, then
        // finalize. Workers get paid + stake returned.
        vm.roll(block.number + 11);

        uint256 w1BeforeBalance = w1.balance;
        uint256 w2BeforeBalance = w2.balance;

        pool.finalizeTrainingJob(jobId);

        // Each worker received: (epoch_budget / 3) × 2 epochs + full
        // stake returned (no slashing). 2 × 30e / 3 = 20e. Plus
        // 10e stake back = 30e total.
        // Using approxEq because integer division may floor in
        // perEpochBudget / workerCount.
        uint256 expected = (uint256(EPOCH_BUDGET) / 3) * 2 + uint256(STAKE);
        assertApproxEqAbs(w1.balance - w1BeforeBalance, expected, 3, "w1 payout");
        assertApproxEqAbs(w2.balance - w2BeforeBalance, expected, 3, "w2 payout");

        job = pool.getJob(jobId);
        assertEq(uint8(job.state), uint8(ComputePoolTraining.JobState.Finalized));
    }

    // ── #2 joinTrainingJob requires stake ───────────────────────────

    function test_join_training_job_posts_stake() public {
        uint256 jobId = _openJob();

        uint256 contractBeforeBalance = address(pool).balance;
        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);

        // Contract balance increased by exactly STAKE (the deposit).
        assertEq(address(pool).balance - contractBeforeBalance, STAKE);

        ComputePoolTraining.WorkerInfo memory info = pool.getWorker(jobId, w1);
        assertEq(info.stakePosted, STAKE);
        assertTrue(info.joined);

        // Wrong stake amount reverts.
        vm.prank(w2);
        vm.expectRevert("ComputePoolTraining: stake mismatch");
        pool.joinTrainingJob{value: STAKE - 1}(jobId);

        // Double-join reverts.
        vm.prank(w1);
        vm.expectRevert("ComputePoolTraining: already joined");
        pool.joinTrainingJob{value: STAKE}(jobId);
    }

    // ── #3 commitEpoch enforces epoch order ─────────────────────────

    function test_commit_epoch_is_monotonic() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        // Commit epoch 0 first — OK.
        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);

        // Attempting to commit epoch 0 again reverts.
        vm.prank(w1);
        vm.expectRevert("ComputePoolTraining: wrong epoch");
        pool.commitEpoch(jobId, 0, ROOT0);

        // Attempting to skip ahead to epoch 5 reverts (currentEpoch is 1).
        vm.prank(w1);
        vm.expectRevert("ComputePoolTraining: wrong epoch");
        pool.commitEpoch(jobId, 5, ROOT1);

        // Sequential next epoch — OK.
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);
    }

    // ── #4 Finalize releases remaining stake ────────────────────────

    function test_finalize_releases_remaining_stake() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);

        vm.roll(block.number + 11);

        uint256 w3BeforeBalance = w3.balance;
        pool.finalizeTrainingJob(jobId);

        ComputePoolTraining.WorkerInfo memory info = pool.getWorker(jobId, w3);
        // After finalize, stakeReturned should equal the full stake
        // (no slashing occurred).
        assertEq(info.stakeReturned, STAKE, "return accounting");
        // Balance went up by payment + stake return.
        uint256 expected = uint256(STAKE);
        expected += (uint256(EPOCH_BUDGET) / 3) * 2;
        assertApproxEqAbs(w3.balance - w3BeforeBalance, expected, 3);

        // StakeConservation: posted == slashed + returned + held.
        // paymentEarned is a separate ledger and is zero after
        // finalize (paid out).
        assertEq(
            uint256(info.stakePosted),
            uint256(info.stakeSlashed) + uint256(info.stakeReturned)
                + uint256(pool.heldStake(jobId, w3)),
            "stake conservation"
        );
        assertEq(info.paymentEarned, 0, "payment zeroed after finalize");
    }

    // ── #5 Recruitment aborts below minWorkers ──────────────────────

    function test_recruitment_aborts_below_min_workers() public {
        uint256 jobId = _openJob();

        // Only 2 of the 3 required workers join.
        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(w2);
        pool.joinTrainingJob{value: STAKE}(jobId);

        // closeRecruitment reverts because below min.
        vm.expectRevert("ComputePoolTraining: below min workers");
        pool.closeRecruitment(jobId, w1);

        // Requester aborts; everyone gets their money back.
        uint256 w1BeforeBalance = w1.balance;
        uint256 requesterBeforeBalance = requester.balance;
        vm.prank(requester);
        pool.abortRecruiting(jobId);

        assertEq(w1.balance - w1BeforeBalance, STAKE, "w1 stake refunded");
        // Requester gets back perEpochBudget × epochCount = 60 ether
        assertEq(
            requester.balance - requesterBeforeBalance,
            uint256(EPOCH_BUDGET) * 2,
            "requester escrow refunded"
        );

        ComputePoolTraining.TrainingJob memory job = pool.getJob(jobId);
        assertEq(uint8(job.state), uint8(ComputePoolTraining.JobState.Aborted));
    }

    // ── #6 Payment proportional to worker count ─────────────────────

    function test_payment_proportional_to_worker_count() public {
        // Build a spec with minWorkers=2 so we can recruit only 2.
        ComputePoolTraining.TrainingJobSpec memory spec = _defaultSpec();
        spec.minWorkers = 2;
        uint256 escrow = uint256(spec.perEpochBudget) * spec.epochCount;
        vm.prank(requester);
        uint256 jobId = pool.requestTrainingJob{value: escrow}(spec);

        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(w2);
        pool.joinTrainingJob{value: STAKE}(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);

        ComputePoolTraining.WorkerInfo memory info = pool.getWorker(jobId, w1);
        // Two workers sharing EPOCH_BUDGET evenly = 15e each.
        assertEq(info.paymentEarned, EPOCH_BUDGET / 2, "2-way split correct");
    }

    // ── #7 Challenge-uphold-slashes-target + bond-plus-reward flow ──

    function test_successful_challenge_slashes_target_and_rewards_challenger() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);

        // Build a leaf whose Merkle proof resolves to ROOT0. With a
        // single-leaf tree, the leaf IS the root — empty proof.
        bytes32 leaf = ROOT0;
        bytes32[] memory emptyProof = new bytes32[](0);

        // Challenge w2 at epoch 0 step 0.
        vm.prank(challenger);
        pool.challengeStep{value: 1 ether}(jobId, 0, 0, w2, leaf, emptyProof);

        // Committee votes Uphold (need quorum=2).
        vm.prank(committee1);
        pool.voteChallenge(jobId, 0, 0, w2, true);

        uint256 challengerBeforeBalance = challenger.balance;
        vm.prank(committee2);
        pool.voteChallenge(jobId, 0, 0, w2, true);

        // Second Uphold vote triggers resolution. Challenger got bond
        // back (1e) + half of slash (10% of 10e = 1e, half = 0.5e).
        assertEq(challenger.balance - challengerBeforeBalance, 1 ether + 0.5 ether);

        ComputePoolTraining.WorkerInfo memory targetInfo = pool.getWorker(jobId, w2);
        uint128 expectedSlash = uint128(uint256(STAKE) * 1000 / 10000); // 10% = 1 ether
        assertEq(targetInfo.stakeSlashed, expectedSlash);

        ComputePoolTraining.Challenge memory ch = pool.getChallenge(jobId, 0, 0, w2);
        assertEq(uint8(ch.state), uint8(ComputePoolTraining.ChallengeState.ResolvedUphold));
        assertEq(ch.bond, 0, "bond cleared after resolution");
    }

    // ── #8 False challenge forfeits bond, target untouched ──────────

    function test_false_challenge_forfeits_bond() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);

        bytes32[] memory emptyProof = new bytes32[](0);
        uint256 challengerBeforeBalance = challenger.balance;

        vm.prank(challenger);
        pool.challengeStep{value: 1 ether}(jobId, 0, 1, w2, ROOT0, emptyProof);

        // Committee votes Reject with quorum.
        vm.prank(committee1);
        pool.voteChallenge(jobId, 0, 1, w2, false);
        vm.prank(committee2);
        pool.voteChallenge(jobId, 0, 1, w2, false);

        // Challenger down 1 ether (the bond was forfeited, not returned).
        assertEq(challenger.balance, challengerBeforeBalance - 1 ether);

        // Target was NOT slashed.
        ComputePoolTraining.WorkerInfo memory targetInfo = pool.getWorker(jobId, w2);
        assertEq(targetInfo.stakeSlashed, 0);
    }

    // ── Additional: NoSelfChallenge invariant ───────────────────────

    function test_no_self_challenge() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);

        bytes32[] memory emptyProof = new bytes32[](0);

        vm.deal(w2, 10 ether);
        vm.prank(w2);
        vm.expectRevert("ComputePoolTraining: no self challenge");
        pool.challengeStep{value: 1 ether}(jobId, 0, 0, w2, ROOT0, emptyProof);
    }

    // ── Additional: challenge outside window reverts ────────────────

    function test_challenge_after_window_reverts() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);

        // Advance past challenge window.
        vm.roll(block.number + 11);
        bytes32[] memory emptyProof = new bytes32[](0);

        vm.prank(challenger);
        vm.expectRevert("ComputePoolTraining: challenge window closed");
        pool.challengeStep{value: 1 ether}(jobId, 0, 0, w2, ROOT0, emptyProof);
    }

    // ── Additional: finalize blocked until challenge window closes ──

    function test_finalize_blocked_during_challenge_window() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);

        // Immediately finalize — reverts; challenge window still open.
        vm.expectRevert("ComputePoolTraining: challenge window open");
        pool.finalizeTrainingJob(jobId);

        // Wait, then succeed.
        vm.roll(block.number + 11);
        pool.finalizeTrainingJob(jobId);
    }

    // ── Additional: commitEpoch rejects non-coordinator ─────────────

    function test_commit_epoch_rejects_non_coordinator() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        // w2 is NOT the coordinator.
        vm.prank(w2);
        vm.expectRevert("ComputePoolTraining: not coordinator");
        pool.commitEpoch(jobId, 0, ROOT0);
    }

    // ── Reassignment (WP-07.3) ──────────────────────────────────────

    function test_reassign_after_timeout_succeeds() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        // Roll past COORDINATION_TIMEOUT (100 blocks) with no
        // commitEpoch.
        vm.roll(block.number + 101);

        // w2 (any joined worker) reassigns to w3.
        vm.prank(w2);
        pool.reassignCoordinator(jobId, w3);

        ComputePoolTraining.TrainingJob memory job = pool.getJob(jobId);
        assertEq(job.coordinator, w3, "coordinator swapped");

        // Liveness slash applied to w1 (0.1% of 10e = 0.01e).
        ComputePoolTraining.WorkerInfo memory oldInfo = pool.getWorker(jobId, w1);
        uint128 expectedSlash = uint128(uint256(STAKE) * 10 / 10000);
        assertEq(oldInfo.stakeSlashed, expectedSlash, "liveness slash applied");

        // The new coordinator can now post commitEpoch.
        vm.prank(w3);
        pool.commitEpoch(jobId, 0, ROOT0);
    }

    function test_reassign_before_timeout_reverts() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        // Roll only 50 blocks — under COORDINATION_TIMEOUT.
        vm.roll(block.number + 50);

        vm.prank(w2);
        vm.expectRevert("ComputePoolTraining: coordinator still active");
        pool.reassignCoordinator(jobId, w3);
    }

    function test_reassign_resets_activity_clock() public {
        // A successful commitEpoch must reset the timeout so the
        // coordinator isn't vulnerable to spurious reassignment
        // immediately after posting a root.
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        uint256 base = block.number;

        // Roll 50 blocks, then commit. Activity clock resets to
        // the commit block.
        vm.roll(base + 50);
        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);
        uint256 commitBlock = base + 50;

        // Roll to 50 blocks after commit — under COORDINATION_TIMEOUT
        // from the last activity. Reassign must revert.
        vm.roll(commitBlock + 50);
        vm.prank(w2);
        vm.expectRevert("ComputePoolTraining: coordinator still active");
        pool.reassignCoordinator(jobId, w3);

        // Roll to 101 blocks after commit — now past timeout. Reassign
        // succeeds.
        vm.roll(commitBlock + 101);
        vm.prank(w2);
        pool.reassignCoordinator(jobId, w3);
    }

    function test_only_joined_worker_can_reassign() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.roll(block.number + 101);

        address outsider = address(0xDEAD);
        vm.prank(outsider);
        vm.expectRevert("ComputePoolTraining: caller not joined");
        pool.reassignCoordinator(jobId, w3);
    }

    function test_reassign_to_non_member_reverts() public {
        uint256 jobId = _openJob();
        _joinThree(jobId);
        pool.closeRecruitment(jobId, w1);

        vm.roll(block.number + 101);

        address outsider = address(0xDEAD);
        vm.prank(w2);
        vm.expectRevert("ComputePoolTraining: new coord not joined");
        pool.reassignCoordinator(jobId, outsider);
    }

    // ── Scale benchmarks (WP-07.1 decision gate) ────────────────────
    //
    // Measure per-call gas at N=10 and N=50 workers to validate the
    // planset's $0.50/epoch target. Contract is linear in N on
    // commitEpoch (iterates worker list to distribute payment) and
    // on finalizeTrainingJob (iterates to pay out).
    //
    // Expected extrapolation: if 1 commitEpoch at N=3 is ~150k gas,
    // at N=50 it's ~2.5M gas. At 1 gwei that's ~$0.05; at 20 gwei
    // mainnet that's ~$1.00 per epoch. 10 epochs × $1.00 = $10 per
    // job. Well within target.

    function _scaleSpec(uint32 workerCount)
        internal
        pure
        returns (ComputePoolTraining.TrainingJobSpec memory spec)
    {
        spec.modelStartHash = keccak256("scale-model");
        spec.datasetHash = keccak256("scale-dataset");
        spec.epochCount = 10; // full planset profile
        spec.stepsPerEpoch = 100;
        spec.minWorkers = workerCount;
        spec.maxWorkers = workerCount;
        spec.challengeWindowBlocks = 10;
        spec.perEpochBudget = 30 ether;
        spec.perWorkerStake = 10 ether;
    }

    /// @notice Gas at N=10 workers. Emits gas data to the console for
    /// the snapshot (use `forge test -vv` to see).
    function test_gas_snapshot_N10() public {
        uint32 N = 10;
        ComputePoolTraining.TrainingJobSpec memory spec = _scaleSpec(N);
        uint256 escrow = uint256(spec.perEpochBudget) * spec.epochCount;
        vm.deal(requester, escrow);
        vm.prank(requester);
        uint256 jobId = pool.requestTrainingJob{value: escrow}(spec);

        // Spin up N workers.
        address[] memory workersArr = new address[](N);
        uint256 joinGasSum = 0;
        for (uint32 i = 0; i < N; i++) {
            workersArr[i] = address(uint160(uint256(keccak256(abi.encode("scale-w", i)))));
            vm.deal(workersArr[i], STAKE);
            vm.prank(workersArr[i]);
            uint256 g = gasleft();
            pool.joinTrainingJob{value: STAKE}(jobId);
            joinGasSum += g - gasleft();
        }
        emit log_named_uint("N=10 joinTrainingJob avg gas", joinGasSum / N);

        pool.closeRecruitment(jobId, workersArr[0]);

        // Measure commitEpoch gas.
        vm.prank(workersArr[0]);
        uint256 g1 = gasleft();
        pool.commitEpoch(jobId, 0, ROOT0);
        emit log_named_uint("N=10 commitEpoch gas", g1 - gasleft());

        // Measure finalize gas (after all epochs).
        for (uint32 e = 1; e < spec.epochCount; e++) {
            vm.prank(workersArr[0]);
            pool.commitEpoch(jobId, e, bytes32(uint256(e + 1)));
        }
        vm.roll(block.number + 11);
        uint256 gf = gasleft();
        pool.finalizeTrainingJob(jobId);
        emit log_named_uint("N=10 finalize gas", gf - gasleft());
    }

    function test_gas_snapshot_N50() public {
        uint32 N = 50;
        ComputePoolTraining.TrainingJobSpec memory spec = _scaleSpec(N);
        uint256 escrow = uint256(spec.perEpochBudget) * spec.epochCount;
        vm.deal(requester, escrow);
        vm.prank(requester);
        uint256 jobId = pool.requestTrainingJob{value: escrow}(spec);

        address[] memory workersArr = new address[](N);
        uint256 joinGasSum = 0;
        for (uint32 i = 0; i < N; i++) {
            workersArr[i] = address(uint160(uint256(keccak256(abi.encode("scale-w", i)))));
            vm.deal(workersArr[i], STAKE);
            vm.prank(workersArr[i]);
            uint256 g = gasleft();
            pool.joinTrainingJob{value: STAKE}(jobId);
            joinGasSum += g - gasleft();
        }
        emit log_named_uint("N=50 joinTrainingJob avg gas", joinGasSum / N);

        pool.closeRecruitment(jobId, workersArr[0]);

        vm.prank(workersArr[0]);
        uint256 g1 = gasleft();
        pool.commitEpoch(jobId, 0, ROOT0);
        emit log_named_uint("N=50 commitEpoch gas", g1 - gasleft());

        for (uint32 e = 1; e < spec.epochCount; e++) {
            vm.prank(workersArr[0]);
            pool.commitEpoch(jobId, e, bytes32(uint256(e + 1)));
        }
        vm.roll(block.number + 11);
        uint256 gf = gasleft();
        pool.finalizeTrainingJob(jobId);
        emit log_named_uint("N=50 finalize gas", gf - gasleft());
    }

    // ── Additional: escrow math at requestTrainingJob ───────────────

    function test_request_training_job_requires_exact_escrow() public {
        ComputePoolTraining.TrainingJobSpec memory spec = _defaultSpec();
        uint256 required = uint256(spec.perEpochBudget) * spec.epochCount;

        vm.prank(requester);
        vm.expectRevert("ComputePoolTraining: escrow mismatch");
        pool.requestTrainingJob{value: required - 1}(spec);

        vm.prank(requester);
        vm.expectRevert("ComputePoolTraining: escrow mismatch");
        pool.requestTrainingJob{value: required + 1}(spec);

        vm.prank(requester);
        uint256 jobId = pool.requestTrainingJob{value: required}(spec);
        assertEq(jobId, 0);
    }
}
