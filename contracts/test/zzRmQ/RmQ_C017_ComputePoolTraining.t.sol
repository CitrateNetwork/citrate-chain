// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePoolTraining} from "../../src/ComputePoolTraining.sol";

/// @title RmQ_C017 — ComputePoolTraining sybil-coordinator escrow drain
/// @notice CHAIN-B-C017 (HELD/reroll). Pre-fix `closeRecruitment` was
///         permissionless AND let the caller name any joined worker
///         (including itself) as coordinator. A sybil could join `minWorkers`
///         times, self-appoint coordinator, then `commitEpoch` arbitrary
///         roots and drain the buyer's entire escrow. Fix: only the requester
///         (or governance) may close recruitment / appoint the coordinator.
contract RmQ_C017_ComputePoolTraining is Test {
    ComputePoolTraining internal pool;

    address internal governance = makeAddr("governance");
    address internal requester = makeAddr("requester");
    address internal sybil = makeAddr("sybil");

    uint128 internal constant EPOCH_BUDGET = 1 ether;
    uint128 internal constant WORKER_STAKE = 1 ether;

    function setUp() public {
        pool = new ComputePoolTraining(governance);
        vm.deal(requester, 100 ether);
        vm.deal(sybil, 100 ether);
    }

    function _spec() internal pure returns (ComputePoolTraining.TrainingJobSpec memory s) {
        s = ComputePoolTraining.TrainingJobSpec({
            modelStartHash: keccak256("m0"),
            datasetHash: keccak256("d0"),
            epochCount: 2,
            stepsPerEpoch: 1,
            minWorkers: 1,
            maxWorkers: 4,
            challengeWindowBlocks: 10,
            perEpochBudget: EPOCH_BUDGET,
            perWorkerStake: WORKER_STAKE
        });
    }

    function _openAndJoin() internal returns (uint256 jobId) {
        vm.prank(requester);
        jobId = pool.requestTrainingJob{value: uint256(EPOCH_BUDGET) * 2}(_spec());
        // A single sybil satisfies minWorkers == 1.
        vm.prank(sybil);
        pool.joinTrainingJob{value: WORKER_STAKE}(jobId);
    }

    /// GREEN: a sybil worker cannot self-appoint as coordinator.
    /// RED (pre-fix): `closeRecruitment(jobId, sybil)` from the sybil succeeds,
    /// moving the job to Training with the sybil as coordinator — who could
    /// then drain `escrowRemaining` via `commitEpoch`.
    function test_C017_sybil_cannot_close_recruitment_as_coordinator() public {
        uint256 jobId = _openAndJoin();

        vm.prank(sybil);
        vm.expectRevert("ComputePoolTraining: not authorized");
        pool.closeRecruitment(jobId, sybil);

        ComputePoolTraining.TrainingJob memory job = pool.getJob(jobId);
        assertEq(uint(job.state), uint(ComputePoolTraining.JobState.Recruiting), "still recruiting");
        assertEq(job.coordinator, address(0), "no coordinator appointed");
        assertEq(uint256(job.escrowRemaining), uint256(EPOCH_BUDGET) * 2, "escrow intact");
    }

    /// The buyer (requester) can still close recruitment and appoint a
    /// coordinator — the feature is preserved for the authorized party.
    function test_C017_requester_can_close_recruitment() public {
        uint256 jobId = _openAndJoin();

        vm.prank(requester);
        pool.closeRecruitment(jobId, sybil);

        ComputePoolTraining.TrainingJob memory job = pool.getJob(jobId);
        assertEq(uint(job.state), uint(ComputePoolTraining.JobState.Training), "training");
        assertEq(job.coordinator, sybil, "coordinator appointed by requester");
    }

    receive() external payable {}
}
