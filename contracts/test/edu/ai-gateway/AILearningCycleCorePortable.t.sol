// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AILearningCycleCorePortable} from "../../../src/edu/ai-gateway/AILearningCycleCorePortable.sol";
import {IAILearningCycleCore} from "../../../src/edu/ai-gateway/IAILearningCycleCore.sol";

contract AILearningCycleCorePortableTest is Test {
    AILearningCycleCorePortable cycle;

    address governance = address(0x1000);
    address coordinator = address(0xC00D);
    address participant1 = address(0xA1);
    address participant2 = address(0xA2);
    address participant3 = address(0xA3);
    address nobody = address(0xBEEF);

    bytes32 commitment1 = keccak256("training-data-1");
    bytes32 commitment2 = keccak256("training-data-2");
    bytes32 adapterHash = keccak256("lora-adapter-weights");
    bytes32 evalManifest = keccak256("eval-manifest-v1");

    function setUp() public {
        cycle = new AILearningCycleCorePortable(governance);
    }

    // ===================================================================
    // CYCLE LIFECYCLE — Happy Path
    // ===================================================================

    function test_open_cycle() public {
        vm.prank(coordinator);
        uint256 cycleId = cycle.openCycle(100);

        assertEq(uint256(cycle.getCycleState(cycleId)), uint256(IAILearningCycleCore.CycleState.Open));
        assertEq(cycle.cycleCount(), 1);
    }

    function test_full_lifecycle() public {
        // Open
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        assertEq(uint256(cycle.getCycleState(cid)), uint256(IAILearningCycleCore.CycleState.Open));

        // Join
        vm.prank(participant1);
        cycle.joinCycle(cid);

        // Start collecting
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        assertEq(uint256(cycle.getCycleState(cid)), uint256(IAILearningCycleCore.CycleState.Collecting));

        // Submit commitment
        vm.prank(participant1);
        cycle.submitCommitment(cid, commitment1);

        // Start aggregating
        vm.prank(coordinator);
        cycle.startAggregating(cid);
        assertEq(uint256(cycle.getCycleState(cid)), uint256(IAILearningCycleCore.CycleState.Aggregating));

        // Record adapter
        vm.prank(coordinator);
        cycle.recordAdapter(cid, adapterHash, evalManifest);

        // Finalize
        vm.prank(coordinator);
        cycle.finalizeCycle(cid);
        assertEq(uint256(cycle.getCycleState(cid)), uint256(IAILearningCycleCore.CycleState.Finalized));
    }

    // ===================================================================
    // INVARIANT 1: StateTransitionsAcyclic
    // ===================================================================

    function test_invariant_cannot_go_backwards_collecting_to_open() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(coordinator);
        cycle.startCollecting(cid);

        // Cannot call startCollecting again (already in Collecting, needs Open)
        vm.prank(coordinator);
        vm.expectRevert(); // InvalidStateTransition
        cycle.startCollecting(cid);
    }

    function test_invariant_cannot_finalize_from_open() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(coordinator);
        vm.expectRevert(); // InvalidStateTransition
        cycle.finalizeCycle(cid);
    }

    function test_invariant_cannot_finalize_from_collecting() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(coordinator);
        vm.expectRevert(); // InvalidStateTransition
        cycle.finalizeCycle(cid);
    }

    // ===================================================================
    // INVARIANT 2: JoinOnlyWhenOpen
    // ===================================================================

    function test_invariant_join_during_open() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(participant1);
        cycle.joinCycle(cid); // OK
        assertTrue(cycle.isParticipant(cid, participant1));
    }

    function test_invariant_join_during_collecting() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(participant1);
        cycle.joinCycle(cid); // OK — spec allows joining during Collecting too
        assertTrue(cycle.isParticipant(cid, participant1));
    }

    function test_invariant_cannot_join_during_aggregating() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);

        vm.prank(participant1);
        vm.expectRevert(); // InvalidStateTransition
        cycle.joinCycle(cid);
    }

    function test_invariant_cannot_join_finalized() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(participant1);
        cycle.joinCycle(cid);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(participant1);
        cycle.submitCommitment(cid, commitment1);
        vm.prank(coordinator);
        cycle.startAggregating(cid);
        vm.prank(coordinator);
        cycle.recordAdapter(cid, adapterHash, evalManifest);
        vm.prank(coordinator);
        cycle.finalizeCycle(cid);

        vm.prank(participant2);
        vm.expectRevert();
        cycle.joinCycle(cid);
    }

    // ===================================================================
    // INVARIANT 3: CommitOnlyWhenCollecting
    // ===================================================================

    function test_invariant_cannot_commit_when_open() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(participant1);
        cycle.joinCycle(cid);

        vm.prank(participant1);
        vm.expectRevert(); // InvalidStateTransition
        cycle.submitCommitment(cid, commitment1);
    }

    function test_invariant_cannot_commit_when_aggregating() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(participant1);
        cycle.joinCycle(cid);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);

        vm.prank(participant1);
        vm.expectRevert();
        cycle.submitCommitment(cid, commitment1);
    }

    // ===================================================================
    // INVARIANT 4: AdapterOnlyWhenAggregating
    // ===================================================================

    function test_invariant_cannot_record_adapter_when_collecting() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(coordinator);
        vm.expectRevert();
        cycle.recordAdapter(cid, adapterHash, evalManifest);
    }

    function test_invariant_adapter_when_aggregating_succeeds() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);

        vm.prank(coordinator);
        cycle.recordAdapter(cid, adapterHash, evalManifest); // OK
    }

    // ===================================================================
    // INVARIANT 5: FinalizeOnlyOnce
    // ===================================================================

    function test_invariant_cannot_finalize_twice() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);
        vm.prank(coordinator);
        cycle.finalizeCycle(cid);

        vm.prank(coordinator);
        vm.expectRevert(); // InvalidStateTransition (Finalized != Aggregating)
        cycle.finalizeCycle(cid);
    }

    // ===================================================================
    // INVARIANT 6: ParticipantCountMonotonic
    // ===================================================================

    function test_invariant_participant_count_grows() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(participant1);
        cycle.joinCycle(cid);
        vm.prank(participant2);
        cycle.joinCycle(cid);
        vm.prank(participant3);
        cycle.joinCycle(cid);

        (,,,uint256 count,) = cycle.getCycleInfo(cid);
        assertEq(count, 3);
    }

    function test_invariant_cannot_join_twice() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(participant1);
        cycle.joinCycle(cid);

        vm.prank(participant1);
        vm.expectRevert(); // AlreadyJoined
        cycle.joinCycle(cid);
    }

    // ===================================================================
    // INVARIANT 7: NoCommitWithoutJoin
    // ===================================================================

    function test_invariant_non_participant_cannot_commit() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(nobody);
        vm.expectRevert(); // NotParticipant
        cycle.submitCommitment(cid, commitment1);
    }

    function test_invariant_cannot_commit_twice() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(participant1);
        cycle.joinCycle(cid);
        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(participant1);
        cycle.submitCommitment(cid, commitment1);

        vm.prank(participant1);
        vm.expectRevert(); // AlreadyCommitted
        cycle.submitCommitment(cid, commitment1);
    }

    // ===================================================================
    // ACCESS CONTROL
    // ===================================================================

    function test_only_coordinator_can_transition() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);

        vm.prank(nobody);
        vm.expectRevert(); // NotCoordinator
        cycle.startCollecting(cid);
    }

    function test_only_coordinator_can_record_adapter() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);

        vm.prank(nobody);
        vm.expectRevert(); // NotCoordinator
        cycle.recordAdapter(cid, adapterHash, evalManifest);
    }

    function test_only_coordinator_can_finalize() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);

        vm.prank(nobody);
        vm.expectRevert(); // NotCoordinator
        cycle.finalizeCycle(cid);
    }

    // ===================================================================
    // EDGE CASES
    // ===================================================================

    function test_zero_commitment_reverts() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(participant1);
        cycle.joinCycle(cid);
        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(participant1);
        vm.expectRevert(); // ZeroHash
        cycle.submitCommitment(cid, bytes32(0));
    }

    function test_zero_adapter_hash_reverts() public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(coordinator);
        cycle.startCollecting(cid);
        vm.prank(coordinator);
        cycle.startAggregating(cid);

        vm.prank(coordinator);
        vm.expectRevert(); // ZeroHash
        cycle.recordAdapter(cid, bytes32(0), evalManifest);
    }

    function test_nonexistent_cycle_reverts() public {
        vm.expectRevert(); // CycleNotFound
        cycle.getCycleState(999);
    }

    function test_multiple_independent_cycles() public {
        vm.prank(coordinator);
        uint256 cid1 = cycle.openCycle(100);
        vm.prank(coordinator);
        uint256 cid2 = cycle.openCycle(200);

        assertEq(uint256(cycle.getCycleState(cid1)), uint256(IAILearningCycleCore.CycleState.Open));
        assertEq(uint256(cycle.getCycleState(cid2)), uint256(IAILearningCycleCore.CycleState.Open));

        // Advance cycle 1 without affecting cycle 2
        vm.prank(coordinator);
        cycle.startCollecting(cid1);
        assertEq(uint256(cycle.getCycleState(cid1)), uint256(IAILearningCycleCore.CycleState.Collecting));
        assertEq(uint256(cycle.getCycleState(cid2)), uint256(IAILearningCycleCore.CycleState.Open));
    }

    // ===================================================================
    // FUZZ TESTS
    // ===================================================================

    function testFuzz_open_any_checkpoint(uint256 checkpoint) public {
        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(checkpoint);
        (,uint256 cp,,,) = cycle.getCycleInfo(cid);
        assertEq(cp, checkpoint);
    }

    function testFuzz_any_commitment_hash(bytes32 c) public {
        vm.assume(c != bytes32(0));

        vm.prank(coordinator);
        uint256 cid = cycle.openCycle(100);
        vm.prank(participant1);
        cycle.joinCycle(cid);
        vm.prank(coordinator);
        cycle.startCollecting(cid);

        vm.prank(participant1);
        cycle.submitCommitment(cid, c);
    }
}
