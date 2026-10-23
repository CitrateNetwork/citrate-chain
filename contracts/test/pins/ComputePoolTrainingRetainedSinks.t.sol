// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePoolTraining} from "../../src/ComputePoolTraining.sol";

/// Every value the training pool keeps (the unpaid half of an upheld slash and
/// a governance liveness slash) must land in `retainedSlashAndBonds`, the only
/// amount `sweepRetained` can move. The rejected-challenge bond already has a
/// test; these pin the two other accumulator writes.
contract ComputePoolTrainingRetainedSinksTest is Test {
    ComputePoolTraining internal t;
    address internal constant REQUESTER = address(0xAA);
    address internal constant W1 = address(0x11);
    address internal constant W2 = address(0x22);
    address internal constant CHALLENGER = address(0xC0);
    address internal constant SINK = address(0x7EA);
    bytes32 internal constant LEAF = bytes32("leaf");
    uint256 internal job;

    function setUp() public {
        t = new ComputePoolTraining(address(this));
        vm.deal(REQUESTER, 100 ether);
        vm.deal(W1, 20 ether);
        vm.deal(W2, 20 ether);
        vm.deal(CHALLENGER, 10 ether);
        ComputePoolTraining.TrainingJobSpec memory spec = ComputePoolTraining.TrainingJobSpec({
            modelStartHash: bytes32("m"),
            datasetHash: bytes32("d"),
            epochCount: 2,
            stepsPerEpoch: 10,
            minWorkers: 2,
            maxWorkers: 2,
            challengeWindowBlocks: 50,
            perEpochBudget: 1 ether,
            perWorkerStake: 10 ether
        });
        vm.prank(REQUESTER);
        job = t.requestTrainingJob{value: 2 ether}(spec);
        vm.prank(W1);
        t.joinTrainingJob{value: 10 ether}(job);
        vm.prank(W2);
        t.joinTrainingJob{value: 10 ether}(job);
        vm.prank(REQUESTER);
        t.closeRecruitment(job, W1);
        vm.prank(W1);
        t.commitEpoch(job, 0, keccak256(abi.encodePacked(bytes1(0x00), LEAF)));
        t.setCommittee(address(0xE1), true);
        t.setCommittee(address(0xE2), true);
    }

    function test_upheldSlashUnpaidHalfIsRetainedAndSweepable() public {
        vm.prank(CHALLENGER);
        t.challengeStep{value: 1 ether}(job, 0, 0, W2, LEAF, new bytes32[](0));
        vm.prank(address(0xE1));
        t.voteChallenge(job, 0, 0, W2, true);
        vm.prank(address(0xE2));
        t.voteChallenge(job, 0, 0, W2, true);

        // 10% of 10 ether = 1 ether slashed; the challenger is paid half.
        assertEq(t.retainedSlashAndBonds(), 0.5 ether, "unpaid half of the slash is retained");
        uint256 before = SINK.balance;
        t.sweepRetained(SINK);
        assertEq(SINK.balance - before, 0.5 ether, "retained half is sweepable");
    }

    function test_governanceLivenessSlashIsRetainedAndSweepable() public {
        vm.roll(block.number + t.COORDINATION_TIMEOUT() + 1);
        t.reassignCoordinator(job, W2); // governance-adjudicated stall

        uint256 expected = 10 ether * t.LIVENESS_SLASH_BPS() / 10_000;
        assertEq(t.getWorker(job, W1).stakeSlashed, expected, "stalled coordinator slashed");
        assertEq(t.retainedSlashAndBonds(), expected, "liveness slash is retained");
        uint256 before = SINK.balance;
        t.sweepRetained(SINK);
        assertEq(SINK.balance - before, expected, "liveness slash is sweepable");
    }

    function test_requesterReassignDoesNotSlashOrRetain() public {
        vm.roll(block.number + t.COORDINATION_TIMEOUT() + 1);
        vm.prank(REQUESTER);
        t.reassignCoordinator(job, W2);
        assertEq(t.getWorker(job, W1).stakeSlashed, 0, "plain replacement, no slash");
        assertEq(t.retainedSlashAndBonds(), 0);
    }
}
