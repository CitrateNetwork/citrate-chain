// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LearningCycleManager} from "../src/LearningCycleManager.sol";

contract LearningCycleManagerTest is Test {
    LearningCycleManager internal lcm;

    address internal governance = address(this);
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal charlie = address(0xC4A1);
    address internal dave = address(0xDA7E);
    address internal eve = address(0xE7E);
    address internal outsider = address(0xBAD1);

    function setUp() public {
        lcm = new LearningCycleManager();

        vm.deal(governance, 1000 ether);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);
        vm.deal(dave, 100 ether);
        vm.deal(eve, 100 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _openCycle(uint256 height) internal returns (uint256) {
        lcm.openCycle(height);
        return lcm.currentCycleId();
    }

    function _registerParticipant(uint256 cycleId, address participant) internal {
        vm.prank(participant);
        lcm.registerParticipant(cycleId);
    }

    function _submitCommitment(uint256 cycleId, address participant, bytes32 commitment) internal {
        vm.prank(participant);
        lcm.submitEmbeddingCommitment(cycleId, commitment);
    }

    /// @dev Full cycle through AdapterGen state, ready for finalization
    function _setupFullCycle() internal returns (uint256 cycleId) {
        cycleId = _openCycle(1000);

        // Register 4 participants
        _registerParticipant(cycleId, alice);
        _registerParticipant(cycleId, bob);
        _registerParticipant(cycleId, charlie);
        _registerParticipant(cycleId, dave);

        // Submit embedding commitments
        _submitCommitment(cycleId, alice, keccak256("alice_embedding"));
        _submitCommitment(cycleId, bob, keccak256("bob_embedding"));
        _submitCommitment(cycleId, charlie, keccak256("charlie_embedding"));
        _submitCommitment(cycleId, dave, keccak256("dave_embedding"));

        // Advance to Aggregating
        lcm.advanceToAggregating(cycleId);

        // Assign mentors: alice mentors bob, charlie mentors dave
        lcm.recordMentorAssignment(cycleId, alice, bob);
        lcm.recordMentorAssignment(cycleId, charlie, dave);

        // Record adapters
        lcm.recordAdapter(cycleId, alice, keccak256("alice_adapter"));
        lcm.recordAdapter(cycleId, charlie, keccak256("charlie_adapter"));
    }

    // ── Cycle Lifecycle Tests ────────────────────────────────────────

    function test_open_and_register() public {
        uint256 cid = _openCycle(500);
        assertEq(cid, 1);
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Open));

        _registerParticipant(cid, alice);

        // State should auto-transition to Collecting
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Collecting));
        assertTrue(lcm.isParticipant(cid, alice));

        (
            uint256 checkpointHeight,
            LearningCycleManager.CycleState state,
            uint256 participantCount,
            ,,,,
        ) = lcm.getCycleInfo(cid);
        assertEq(checkpointHeight, 500);
        assertEq(uint256(state), uint256(LearningCycleManager.CycleState.Collecting));
        assertEq(participantCount, 1);
    }

    function test_submit_embedding_commitment() public {
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);

        bytes32 commitment = keccak256("alice_embedding_data");
        _submitCommitment(cid, alice, commitment);

        assertEq(lcm.embeddingCommitments(cid, alice), commitment);
    }

    function test_state_only_forward() public {
        uint256 cid = _openCycle(500);

        // Cannot advance from Open to Aggregating directly (need participants)
        vm.expectRevert("Not in Collecting state");
        lcm.advanceToAggregating(cid);

        // Register to move to Collecting
        _registerParticipant(cid, alice);
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Collecting));

        // Finish this cycle so _setupFullCycle can open a new one
        _registerParticipant(cid, bob);
        _submitCommitment(cid, alice, keccak256("a1"));
        _submitCommitment(cid, bob, keccak256("b1"));
        lcm.advanceToAggregating(cid);
        lcm.recordMentorAssignment(cid, alice, bob);
        lcm.recordAdapter(cid, alice, keccak256("ad1"));
        lcm.finalizeCycle{value: 10 ether}(cid);

        // Open and complete a second cycle
        uint256 cid2 = _setupFullCycle();
        lcm.finalizeCycle{value: 100 ether}(cid2);
        assertEq(uint256(lcm.getCycleState(cid2)), uint256(LearningCycleManager.CycleState.Finalized));

        // Cannot register in a finalized cycle
        vm.prank(eve);
        vm.expectRevert("Registration closed");
        lcm.registerParticipant(cid2);
    }

    function test_record_mentor_and_adapter() public {
        uint256 cid = _openCycle(1000);
        _registerParticipant(cid, alice);
        _registerParticipant(cid, bob);
        _submitCommitment(cid, alice, keccak256("alice_emb"));
        _submitCommitment(cid, bob, keccak256("bob_emb"));

        lcm.advanceToAggregating(cid);

        // Record mentor assignment (auto-transitions to AdapterGen)
        lcm.recordMentorAssignment(cid, alice, bob);
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.AdapterGen));
        assertEq(lcm.mentorAssignments(cid, bob), alice);
        assertTrue(lcm.isMentor(cid, alice));

        // Record adapter
        bytes32 adapterHash = keccak256("alice_adapter_weights");
        lcm.recordAdapter(cid, alice, adapterHash);
        assertEq(lcm.adapterHashes(cid, alice), adapterHash);
    }

    function test_finalize_distributes_rewards() public {
        uint256 cid = _setupFullCycle();

        // Finalize with 100 SALT
        lcm.finalizeCycle{value: 100 ether}(cid);

        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Finalized));

        (,,,, uint256 totalRewards, bool rewardsDistributed,,) = lcm.getCycleInfo(cid);
        assertEq(totalRewards, 100 ether);
        assertTrue(rewardsDistributed);

        // Verify reward allocation:
        // 4 participants, 2 mentors (alice, charlie), 2 mentees (bob, dave), aggregator = governance
        // Participant pool = 40 ether / 4 = 10 each
        // Mentor pool = 35 ether / 2 = 17.5 each
        // Mentee pool = 15 ether / 2 = 7.5 each
        // Aggregator pool = 100 - 40 - 35 - 15 = 10 ether

        // alice: 10 (participant) + 17.5 (mentor) = 27.5 ether
        assertEq(lcm.getReward(cid, alice), 27.5 ether);

        // bob: 10 (participant) + 7.5 (mentee) = 17.5 ether
        assertEq(lcm.getReward(cid, bob), 17.5 ether);

        // charlie: 10 (participant) + 17.5 (mentor) = 27.5 ether
        assertEq(lcm.getReward(cid, charlie), 27.5 ether);

        // dave: 10 (participant) + 7.5 (mentee) = 17.5 ether
        assertEq(lcm.getReward(cid, dave), 17.5 ether);

        // governance (aggregator): 10 ether
        assertEq(lcm.getReward(cid, governance), 10 ether);
    }

    function test_claim_after_finalize() public {
        uint256 cid = _setupFullCycle();
        lcm.finalizeCycle{value: 100 ether}(cid);

        // Alice claims her 27.5 SALT
        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        lcm.claimCycleReward(cid);
        assertEq(alice.balance - aliceBefore, 27.5 ether);
        assertTrue(lcm.hasClaimed(cid, alice));

        // Bob claims his 17.5 SALT
        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        lcm.claimCycleReward(cid);
        assertEq(bob.balance - bobBefore, 17.5 ether);
    }

    function test_cannot_register_after_aggregating() public {
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);
        _registerParticipant(cid, bob);

        _submitCommitment(cid, alice, keccak256("a"));
        _submitCommitment(cid, bob, keccak256("b"));

        lcm.advanceToAggregating(cid);

        // Try to register in Aggregating state — should revert
        vm.prank(charlie);
        vm.expectRevert("Registration closed");
        lcm.registerParticipant(cid);
    }

    function test_cycle_id_monotonic() public {
        uint256 cid1 = _setupFullCycle();
        lcm.finalizeCycle{value: 10 ether}(cid1);

        uint256 cid2 = _openCycle(2000);
        assertEq(cid2, cid1 + 1);

        // Finalize cid2 so we can open cid3
        _registerParticipant(cid2, alice);
        _submitCommitment(cid2, alice, keccak256("a2"));
        _registerParticipant(cid2, bob);
        _submitCommitment(cid2, bob, keccak256("b2"));
        lcm.advanceToAggregating(cid2);
        lcm.recordMentorAssignment(cid2, alice, bob);
        lcm.recordAdapter(cid2, alice, keccak256("ad2"));
        lcm.finalizeCycle{value: 10 ether}(cid2);

        uint256 cid3 = _openCycle(3000);
        assertEq(cid3, cid2 + 1);
        assertTrue(cid3 > cid2);
        assertTrue(cid2 > cid1);
    }

    function test_participant_share_calculation() public {
        // 2 participants, no mentors/mentees (only participant + aggregator shares)
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);
        _registerParticipant(cid, bob);
        _submitCommitment(cid, alice, keccak256("a"));
        _submitCommitment(cid, bob, keccak256("b"));
        lcm.advanceToAggregating(cid);

        // Assign alice as mentor for bob
        lcm.recordMentorAssignment(cid, alice, bob);
        lcm.recordAdapter(cid, alice, keccak256("adapter_a"));

        // Finalize with 100 SALT
        lcm.finalizeCycle{value: 100 ether}(cid);

        // 2 participants: 40/2 = 20 each
        // 1 mentor (alice): 35 SALT
        // 1 mentee (bob): 15 SALT
        // aggregator (governance): 10 SALT

        // alice: 20 (participant) + 35 (mentor) = 55
        assertEq(lcm.getReward(cid, alice), 55 ether);

        // bob: 20 (participant) + 15 (mentee) = 35
        assertEq(lcm.getReward(cid, bob), 35 ether);

        // governance (aggregator): 10
        assertEq(lcm.getReward(cid, governance), 10 ether);
    }

    function test_mentor_bonus() public {
        // A mentor with 2 mentees should still get their fair share
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);
        _registerParticipant(cid, bob);
        _registerParticipant(cid, charlie);
        _submitCommitment(cid, alice, keccak256("a"));
        _submitCommitment(cid, bob, keccak256("b"));
        _submitCommitment(cid, charlie, keccak256("c"));
        lcm.advanceToAggregating(cid);

        // alice mentors both bob and charlie
        lcm.recordMentorAssignment(cid, alice, bob);
        lcm.recordMentorAssignment(cid, alice, charlie);
        lcm.recordAdapter(cid, alice, keccak256("alice_adapter"));

        lcm.finalizeCycle{value: 90 ether}(cid);

        // participant pool = 36 / 3 = 12 each
        // mentor pool = 31.5 / 1 = 31.5 (alice is the only mentor)
        // mentee pool = 13.5 / 2 = 6.75 each (bob, charlie)
        // aggregator = 90 - 36 - 31.5 - 13.5 = 9

        // alice: 12 + 31.5 = 43.5
        assertEq(lcm.getReward(cid, alice), 43.5 ether);

        // bob: 12 + 6.75 = 18.75
        assertEq(lcm.getReward(cid, bob), 18.75 ether);

        // charlie: 12 + 6.75 = 18.75
        assertEq(lcm.getReward(cid, charlie), 18.75 ether);
    }

    // ── Additional Tests ─────────────────────────────────────────────

    function test_double_register_reverts() public {
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);

        vm.prank(alice);
        vm.expectRevert("Already registered");
        lcm.registerParticipant(cid);
    }

    function test_double_claim_reverts() public {
        uint256 cid = _setupFullCycle();
        lcm.finalizeCycle{value: 100 ether}(cid);

        vm.prank(alice);
        lcm.claimCycleReward(cid);

        vm.prank(alice);
        vm.expectRevert("Already claimed");
        lcm.claimCycleReward(cid);
    }

    function test_outsider_cannot_claim() public {
        uint256 cid = _setupFullCycle();
        lcm.finalizeCycle{value: 100 ether}(cid);

        vm.prank(outsider);
        vm.expectRevert("No reward");
        lcm.claimCycleReward(cid);
    }

    function test_non_governance_cannot_open_cycle() public {
        vm.prank(outsider);
        vm.expectRevert("Not governance");
        lcm.openCycle(1000);
    }

    function test_non_governance_cannot_finalize() public {
        uint256 cid = _setupFullCycle();

        vm.deal(outsider, 100 ether);
        vm.prank(outsider);
        vm.expectRevert("Not governance");
        lcm.finalizeCycle{value: 10 ether}(cid);
    }

    function test_cannot_open_before_previous_finalized() public {
        _openCycle(500);

        vm.expectRevert("Previous cycle not finalized");
        lcm.openCycle(1000);
    }

    function test_empty_commitment_reverts() public {
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);

        vm.prank(alice);
        vm.expectRevert("Empty commitment");
        lcm.submitEmbeddingCommitment(cid, bytes32(0));
    }

    function test_double_commitment_reverts() public {
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);

        _submitCommitment(cid, alice, keccak256("first"));

        vm.prank(alice);
        vm.expectRevert("Already committed");
        lcm.submitEmbeddingCommitment(cid, keccak256("second"));
    }

    function test_self_mentor_reverts() public {
        uint256 cid = _openCycle(500);
        _registerParticipant(cid, alice);
        _registerParticipant(cid, bob);
        _submitCommitment(cid, alice, keccak256("a"));
        _submitCommitment(cid, bob, keccak256("b"));
        lcm.advanceToAggregating(cid);

        vm.expectRevert("Cannot self-mentor");
        lcm.recordMentorAssignment(cid, alice, alice);
    }

    function test_get_participants_and_mentors() public {
        uint256 cid = _setupFullCycle();

        address[] memory parts = lcm.getParticipants(cid);
        assertEq(parts.length, 4);

        address[] memory mentors = lcm.getMentors(cid);
        assertEq(mentors.length, 2);
    }

    function test_governance_transfer() public {
        lcm.transferGovernance(alice);
        assertEq(lcm.governance(), alice);

        // Old governance can no longer open cycles
        vm.expectRevert("Not governance");
        lcm.openCycle(1000);

        // New governance can
        vm.prank(alice);
        lcm.openCycle(1000);
    }

    function test_finalize_zero_rewards_reverts() public {
        uint256 cid = _setupFullCycle();

        vm.expectRevert("No rewards sent");
        lcm.finalizeCycle{value: 0}(cid);
    }

    function test_nonexistent_cycle_reverts() public {
        vm.expectRevert("Cycle does not exist");
        lcm.getCycleState(999);
    }

    function test_receive_accepts_salt() public {
        (bool ok, ) = address(lcm).call{value: 1 ether}("");
        assertTrue(ok, "Contract should accept direct SALT transfers");
    }

    // ── phaseStartBlock Tests ─────────────────────────────────────────

    function test_phaseStartBlock_set_on_open() public {
        uint256 blockBefore = block.number;
        uint256 cid = _openCycle(500);

        (,,,,,,, uint256 phaseStartBlock) = lcm.getCycleInfo(cid);
        assertGe(phaseStartBlock, blockBefore, "phaseStartBlock should be >= block at open");
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Open));
    }

    function test_phaseStartBlock_updates_on_each_transition() public {
        // Open the cycle and record phaseStartBlock for Open state
        uint256 cid = _openCycle(1000);
        (,,,,,,, uint256 openBlock) = lcm.getCycleInfo(cid);
        assertGt(openBlock, 0, "Open phase should have non-zero phaseStartBlock");

        // Advance a few blocks to ensure phaseStartBlock changes are detectable
        vm.roll(block.number + 5);

        // Register alice -> auto-transitions to Collecting
        _registerParticipant(cid, alice);
        (,,,,,,, uint256 collectingBlock) = lcm.getCycleInfo(cid);
        assertGe(collectingBlock, openBlock, "Collecting phaseStartBlock >= Open phaseStartBlock");
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Collecting));

        // Register bob and submit embeddings
        _registerParticipant(cid, bob);
        _submitCommitment(cid, alice, keccak256("alice_emb"));
        _submitCommitment(cid, bob, keccak256("bob_emb"));

        vm.roll(block.number + 3);

        // Advance to Aggregating
        lcm.advanceToAggregating(cid);
        (,,,,,,, uint256 aggregatingBlock) = lcm.getCycleInfo(cid);
        assertGe(aggregatingBlock, collectingBlock, "Aggregating phaseStartBlock >= Collecting phaseStartBlock");
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Aggregating));

        vm.roll(block.number + 2);

        // Record mentor assignment -> auto-transitions to AdapterGen
        lcm.recordMentorAssignment(cid, alice, bob);
        (,,,,,,, uint256 adapterGenBlock) = lcm.getCycleInfo(cid);
        assertGe(adapterGenBlock, aggregatingBlock, "AdapterGen phaseStartBlock >= Aggregating phaseStartBlock");
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.AdapterGen));

        // Record adapter
        lcm.recordAdapter(cid, alice, keccak256("alice_adapter"));

        vm.roll(block.number + 4);

        // Finalize
        lcm.finalizeCycle{value: 10 ether}(cid);
        (,,,,,,, uint256 finalizedBlock) = lcm.getCycleInfo(cid);
        assertGe(finalizedBlock, adapterGenBlock, "Finalized phaseStartBlock >= AdapterGen phaseStartBlock");
        assertEq(uint256(lcm.getCycleState(cid)), uint256(LearningCycleManager.CycleState.Finalized));
    }
}
