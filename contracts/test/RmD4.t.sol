// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePoolTraining} from "../src/ComputePoolTraining.sol";

/// @title RmD4Test — RM-D4 SOL-06 + SOL-07 acceptance suite.
/// @notice
///   SOL-06 (HIGH) — challenge-upheld must disqualify the worker from
///                   subsequent epoch payouts. Pre-fix, eligibility
///                   used `stakeSlashed == 0`, which a partial-slash
///                   workflow could bypass. Post-fix uses an explicit
///                   `disqualified` flag set only on uphold.
///   SOL-07 (HIGH) — finalize / abortRecruiting must not revert if a
///                   single worker's `receive()` reverts. Pre-fix the
///                   loop did `worker.call{value:}` and propagated the
///                   failure via `require(ok)`, blocking the entire
///                   payout for everyone. Post-fix stashes the amount
///                   in `payoutPending` and emits `PayoutDeferred(...)`.
contract RmD4Test is Test {
    ComputePoolTraining internal pool;

    address internal governance = address(this);
    address internal requester = address(0xA11CE);
    address internal w1 = address(0xBBB1);
    address internal w2 = address(0xBBB2);
    address internal challenger = address(0xC0DE);
    address internal committee1 = address(0xC011);
    address internal committee2 = address(0xC022);

    bytes32 internal constant LEAF0 = bytes32(uint256(0x1111));
    bytes32 internal constant LEAF1 = bytes32(uint256(0x2222));
    bytes32 internal ROOT0 = keccak256(abi.encodePacked(bytes1(0x00), LEAF0));
    bytes32 internal ROOT1 = keccak256(abi.encodePacked(bytes1(0x00), LEAF1));

    uint128 internal constant STAKE = 10 ether;
    uint128 internal constant EPOCH_BUDGET = 30 ether;

    function setUp() public {
        pool = new ComputePoolTraining(governance);
        pool.setCommittee(committee1, true);
        pool.setCommittee(committee2, true);

        vm.deal(requester, 1000 ether);
        vm.deal(w1, 100 ether);
        vm.deal(w2, 100 ether);
        vm.deal(challenger, 10 ether);
    }

    function _spec()
        internal
        pure
        returns (ComputePoolTraining.TrainingJobSpec memory spec)
    {
        spec.modelStartHash = keccak256("model");
        spec.datasetHash = keccak256("dataset");
        spec.epochCount = 2;
        spec.stepsPerEpoch = 2;
        spec.minWorkers = 2;
        spec.maxWorkers = 4;
        spec.challengeWindowBlocks = 10;
        spec.perEpochBudget = EPOCH_BUDGET;
        spec.perWorkerStake = STAKE;
    }

    function _openJob() internal returns (uint256 jobId) {
        ComputePoolTraining.TrainingJobSpec memory spec = _spec();
        uint256 escrow = uint256(spec.perEpochBudget) * spec.epochCount;
        vm.prank(requester);
        jobId = pool.requestTrainingJob{value: escrow}(spec);
    }

    // ── SOL-06: disqualified worker excluded from epoch payouts ─────

    /// After a challenge is upheld at epoch 0, the target must be
    /// disqualified — `commitEpoch(1, ...)` must split the budget
    /// only across non-disqualified workers.
    function test_sol06_disqualified_worker_excluded_from_subsequent_epoch() public {
        uint256 jobId = _openJob();

        // Two workers join, w1 is coordinator.
        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(w2);
        pool.joinTrainingJob{value: STAKE}(jobId);
        pool.closeRecruitment(jobId, w1);

        // Coordinator commits epoch 0. Both workers earn budget/2.
        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);

        ComputePoolTraining.WorkerInfo memory beforeChallenge =
            pool.getWorker(jobId, w2);
        assertEq(beforeChallenge.paymentEarned, EPOCH_BUDGET / 2);
        assertFalse(beforeChallenge.disqualified, "not yet disqualified");

        // Challenge w2's step 0 commitment.
        vm.prank(challenger);
        pool.challengeStep{value: 1 ether}(jobId, 0, 0, w2, LEAF0, new bytes32[](0));

        // Committee upholds → w2 slashed AND disqualified.
        vm.prank(committee1);
        pool.voteChallenge(jobId, 0, 0, w2, true);
        vm.prank(committee2);
        pool.voteChallenge(jobId, 0, 0, w2, true);

        ComputePoolTraining.WorkerInfo memory afterChallenge =
            pool.getWorker(jobId, w2);
        assertTrue(afterChallenge.disqualified, "SOL-06: must be disqualified");
        assertGt(uint256(afterChallenge.stakeSlashed), 0, "stake slashed");

        // Coordinator commits epoch 1. Only w1 should be paid the
        // full budget (w2 is disqualified).
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);

        ComputePoolTraining.WorkerInfo memory w1Info = pool.getWorker(jobId, w1);
        ComputePoolTraining.WorkerInfo memory w2Info = pool.getWorker(jobId, w2);

        // w1: epoch0 share (budget/2) + epoch1 share (full budget).
        assertEq(
            w1Info.paymentEarned,
            EPOCH_BUDGET / 2 + EPOCH_BUDGET,
            "SOL-06: w1 gets full epoch1 budget"
        );
        // w2 paymentEarned unchanged from epoch0 (no epoch1 credit).
        assertEq(
            w2Info.paymentEarned,
            EPOCH_BUDGET / 2,
            "SOL-06: disqualified w2 receives no epoch1 credit"
        );
    }

    // ── SOL-07: griefer worker cannot DoS finalize ──────────────────

    /// A worker contract whose `receive()` reverts MUST NOT block
    /// finalize for the rest of the workers. Their payment is stashed
    /// in `payoutPending` and they can claim it later (after fixing
    /// their fallback) via `claimDeferredPayout`.
    function test_sol07_griefer_worker_does_not_block_finalize() public {
        // Deploy a griefer worker contract whose receive() reverts.
        Griefer griefer = new Griefer();
        vm.deal(address(griefer), STAKE);

        uint256 jobId = _openJob();

        // w1 + griefer join.
        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(address(griefer));
        pool.joinTrainingJob{value: STAKE}(jobId);
        pool.closeRecruitment(jobId, w1);

        // Run the full epoch lifecycle.
        vm.prank(w1);
        pool.commitEpoch(jobId, 0, ROOT0);
        vm.prank(w1);
        pool.commitEpoch(jobId, 1, ROOT1);

        vm.roll(block.number + 11);

        // Pre-fix: this would revert because griefer's receive()
        // reverts and the loop required `ok`.
        // Post-fix: succeeds; griefer's payout is deferred.
        uint256 w1BeforeBalance = w1.balance;
        pool.finalizeTrainingJob(jobId);

        // w1 must have received their payout in full.
        uint256 w1Expected = (uint256(EPOCH_BUDGET) / 2) * 2 + uint256(STAKE);
        assertApproxEqAbs(
            w1.balance - w1BeforeBalance,
            w1Expected,
            3,
            "SOL-07: w1 paid even though griefer reverted"
        );

        // Griefer's payment is parked in payoutPending.
        ComputePoolTraining.WorkerInfo memory gInfo =
            pool.getWorker(jobId, address(griefer));
        assertGt(uint256(gInfo.payoutPending), 0, "SOL-07: payout deferred");

        // Job must be finalized (not stuck in Awaiting).
        ComputePoolTraining.TrainingJob memory job = pool.getJob(jobId);
        assertEq(
            uint8(job.state),
            uint8(ComputePoolTraining.JobState.Finalized),
            "SOL-07: job finalized despite griefer"
        );

        // Once griefer disables its revert, claimDeferredPayout works.
        griefer.allowReceive(true);
        uint256 gBeforeBalance = address(griefer).balance;
        uint128 stashed = gInfo.payoutPending;
        vm.prank(address(griefer));
        pool.claimDeferredPayout(jobId);
        assertEq(
            address(griefer).balance - gBeforeBalance,
            stashed,
            "SOL-07: claim returns stashed amount"
        );

        // Pending balance is zeroed; double-claim reverts.
        ComputePoolTraining.WorkerInfo memory gInfoAfter =
            pool.getWorker(jobId, address(griefer));
        assertEq(uint256(gInfoAfter.payoutPending), 0, "pending zeroed");

        vm.prank(address(griefer));
        vm.expectRevert("ComputePoolTraining: nothing to claim");
        pool.claimDeferredPayout(jobId);
    }

    /// abortRecruiting MUST behave the same way under griefer pressure.
    function test_sol07_griefer_does_not_block_abortRecruiting() public {
        Griefer griefer = new Griefer();
        vm.deal(address(griefer), STAKE);

        // Use a spec with minWorkers=3 so two joiners is below min.
        ComputePoolTraining.TrainingJobSpec memory spec = _spec();
        spec.minWorkers = 3;
        uint256 escrow = uint256(spec.perEpochBudget) * spec.epochCount;
        vm.prank(requester);
        uint256 jobId = pool.requestTrainingJob{value: escrow}(spec);

        vm.prank(w1);
        pool.joinTrainingJob{value: STAKE}(jobId);
        vm.prank(address(griefer));
        pool.joinTrainingJob{value: STAKE}(jobId);

        // Abort. w1 gets refunded, griefer's stake is stashed.
        uint256 w1BeforeBalance = w1.balance;
        vm.prank(requester);
        pool.abortRecruiting(jobId);

        assertEq(w1.balance - w1BeforeBalance, STAKE, "w1 refunded on abort");

        ComputePoolTraining.WorkerInfo memory gInfo =
            pool.getWorker(jobId, address(griefer));
        assertEq(uint256(gInfo.payoutPending), uint256(STAKE),
                 "griefer stake deferred, not lost");
    }
}

/// Helper contract: a worker whose `receive()` reverts unless toggled.
contract Griefer {
    bool public acceptValue;

    function allowReceive(bool ok) external {
        acceptValue = ok;
    }

    receive() external payable {
        require(acceptValue, "Griefer: rejecting");
    }
}
