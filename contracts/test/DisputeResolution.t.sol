// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DisputeResolution} from "../src/DisputeResolution.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @notice Mock NematocystSlashing for dispute integration testing.
contract MockSlashingForDispute {
    address[] internal _slashedAddrs;
    uint8[] internal _slashedTiers;
    uint256 internal _count;

    function slash(address provider, uint8 tier, bytes calldata) external {
        _slashedAddrs.push(provider);
        _slashedTiers.push(tier);
        _count++;
    }

    function slashCount() external view returns (uint256) {
        return _count;
    }

    function getSlash(uint256 idx) external view returns (address provider, uint8 tier) {
        provider = _slashedAddrs[idx];
        tier = _slashedTiers[idx];
    }
}

contract DisputeResolutionTest is Test {
    DisputeResolution internal dispute;
    MockSlashingForDispute internal mockSlashing;

    address internal governance = address(this);
    address internal challenger = address(0xC001);
    address internal defender = address(0xD001);
    address internal outsider = address(0xBAD1);

    uint256 internal constant BOND = 10 ether;
    uint256 internal constant MAX_ROUNDS = 20;
    uint256 internal constant RANGE_START = 0;
    uint256 internal constant RANGE_END = 1048576; // 2^20

    function setUp() public {
        dispute = new DisputeResolution(BOND, MAX_ROUNDS);
        mockSlashing = new MockSlashingForDispute();
        dispute.setSlashingContract(address(mockSlashing));

        vm.deal(challenger, 1000 ether);
        vm.deal(defender, 1000 ether);
        vm.deal(outsider, 100 ether);
        vm.deal(address(dispute), 100 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _initiate() internal returns (uint256 disputeId) {
        vm.prank(challenger);
        disputeId = dispute.initiateDispute{value: BOND}(
            1, defender, RANGE_START, RANGE_END
        );
    }

    function _initiateAndAcknowledge() internal returns (uint256 disputeId) {
        disputeId = _initiate();
        vm.prank(defender);
        dispute.acknowledgeDispute{value: BOND}(disputeId);
    }

    function _bisectOnce(uint256 disputeId) internal {
        vm.prank(challenger);
        dispute.bisect(disputeId, true);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-2: BondRequired — active disputes must have bonds posted
    // ══════════════════════════════════════════════════════════════════

    function test_initiate_requires_bond() public {
        vm.prank(challenger);
        vm.expectRevert("Insufficient challenger bond");
        dispute.initiateDispute{value: BOND - 1}(1, defender, RANGE_START, RANGE_END);
    }

    function test_initiate_sets_bonds() public {
        uint256 disputeId = _initiate();
        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);

        assertEq(d.challengerBond, BOND);
        assertEq(d.defenderBond, 0);
        assertEq(d.challenger, challenger);
        assertEq(d.defender, defender);
        assertTrue(d.state == DisputeResolution.DisputeState.Initiated);
    }

    function test_acknowledge_requires_bond() public {
        uint256 disputeId = _initiate();

        vm.prank(defender);
        vm.expectRevert("Insufficient defender bond");
        dispute.acknowledgeDispute{value: BOND - 1}(disputeId);
    }

    function test_acknowledge_transitions_to_bisecting() public {
        uint256 disputeId = _initiateAndAcknowledge();
        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);

        assertTrue(d.state == DisputeResolution.DisputeState.Bisecting);
        assertEq(d.defenderBond, BOND);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-3: RangeNarrows — range halves each round
    // ══════════════════════════════════════════════════════════════════

    function test_bisection_halves_range() public {
        uint256 disputeId = _initiateAndAcknowledge();

        vm.prank(challenger);
        dispute.bisect(disputeId, true);

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        assertEq(d.rangeStart, RANGE_START);
        assertEq(d.rangeEnd, RANGE_END / 2);

        vm.prank(challenger);
        dispute.bisect(disputeId, false);

        d = dispute.getDispute(disputeId);
        assertEq(d.rangeStart, RANGE_END / 4);
        assertEq(d.rangeEnd, RANGE_END / 2);
    }

    function test_range_strictly_decreases_over_rounds() public {
        uint256 disputeId = _initiateAndAcknowledge();
        uint256 prevSize = RANGE_END - RANGE_START;

        for (uint256 i = 0; i < 5; i++) {
            vm.prank(challenger);
            dispute.bisect(disputeId, true);
            uint256 newSize = dispute.getRangeSize(disputeId);
            assertTrue(newSize < prevSize, "Range did not decrease");
            prevSize = newSize;
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-4: TerminatesInMaxRounds — round <= maxBisectionRounds
    // ══════════════════════════════════════════════════════════════════

    function test_cannot_exceed_max_rounds() public {
        DisputeResolution smallDispute = new DisputeResolution(1 ether, 3);
        vm.deal(challenger, 1000 ether);
        vm.deal(defender, 1000 ether);

        vm.prank(challenger);
        uint256 dId = smallDispute.initiateDispute{value: 1 ether}(1, defender, 0, 1000);
        vm.prank(defender);
        smallDispute.acknowledgeDispute{value: 1 ether}(dId);

        for (uint256 i = 0; i < 3; i++) {
            vm.prank(challenger);
            smallDispute.bisect(dId, true);
        }

        vm.prank(challenger);
        vm.expectRevert("Max rounds reached");
        smallDispute.bisect(dId, true);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-5: WinnerGetsBond — resolved => winner gets loser's bond
    // ══════════════════════════════════════════════════════════════════

    function test_challenger_wins_gets_both_bonds() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);

        uint256 challengerBefore = challenger.balance;
        dispute.resolve(disputeId, true);
        assertEq(challenger.balance, challengerBefore + BOND * 2);
    }

    function test_defender_wins_gets_both_bonds() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);

        uint256 defenderBefore = defender.balance;
        dispute.resolve(disputeId, false);
        assertEq(defender.balance, defenderBefore + BOND * 2);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-6: LoserSlashed — defender loses => stake slashed
    // ══════════════════════════════════════════════════════════════════

    function test_defender_slashed_on_loss() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);
        dispute.resolve(disputeId, true);

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        assertTrue(d.defenderSlashed);

        assertEq(mockSlashing.slashCount(), 1);
        (address slashedAddr, uint8 tier) = mockSlashing.getSlash(0);
        assertEq(slashedAddr, defender);
        assertEq(tier, 1);
    }

    function test_defender_not_slashed_on_win() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);
        dispute.resolve(disputeId, false);

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        assertFalse(d.defenderSlashed);
        assertEq(mockSlashing.slashCount(), 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-7: NoPaymentBeforeResolution
    // ══════════════════════════════════════════════════════════════════

    function test_bonds_not_released_before_resolution() public {
        uint256 disputeId = _initiateAndAcknowledge();

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        assertEq(d.challengerBond, BOND);
        assertEq(d.defenderBond, BOND);
        assertFalse(d.winnerPaid);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-9: InactiveClean — inactive disputes are pristine
    // ══════════════════════════════════════════════════════════════════

    function test_fresh_dispute_slot_is_clean() public view {
        DisputeResolution.Dispute memory d = dispute.getDispute(999);
        assertTrue(d.state == DisputeResolution.DisputeState.Inactive);
        assertEq(d.challengerBond, 0);
        assertEq(d.defenderBond, 0);
        assertTrue(d.outcome == DisputeResolution.Outcome.None);
        assertFalse(d.winnerPaid);
        assertFalse(d.defenderSlashed);
    }
}

// ══════════════════════════════════════════════════════════════════════
// Part 2: Timeout, Access Control, Validation, Adversarial, Governance
// ══════════════════════════════════════════════════════════════════════

contract DisputeResolutionTimeoutTest is Test {
    DisputeResolution internal dispute;
    MockSlashingForDispute internal mockSlashing;

    address internal governance = address(this);
    address internal challenger = address(0xC001);
    address internal defender = address(0xD001);
    address internal outsider = address(0xBAD1);

    uint256 internal constant BOND = 10 ether;
    uint256 internal constant MAX_ROUNDS = 20;
    uint256 internal constant RANGE_START = 0;
    uint256 internal constant RANGE_END = 1048576; // 2^20

    function setUp() public {
        dispute = new DisputeResolution(BOND, MAX_ROUNDS);
        mockSlashing = new MockSlashingForDispute();
        dispute.setSlashingContract(address(mockSlashing));

        vm.deal(challenger, 1000 ether);
        vm.deal(defender, 1000 ether);
        vm.deal(outsider, 100 ether);
        vm.deal(address(dispute), 100 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _initiate() internal returns (uint256 disputeId) {
        vm.prank(challenger);
        disputeId = dispute.initiateDispute{value: BOND}(
            1, defender, RANGE_START, RANGE_END
        );
    }

    function _initiateAndAcknowledge() internal returns (uint256 disputeId) {
        disputeId = _initiate();
        vm.prank(defender);
        dispute.acknowledgeDispute{value: BOND}(disputeId);
    }

    function _bisectOnce(uint256 disputeId) internal {
        vm.prank(challenger);
        dispute.bisect(disputeId, true);
    }

    // ══════════════════════════════════════════════════════════════════
    // Timeout Tests
    // ══════════════════════════════════════════════════════════════════

    function test_timeout_defender_fails_to_acknowledge() public {
        uint256 disputeId = _initiate();

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        vm.roll(d.deadline + 1);

        uint256 challengerBefore = challenger.balance;
        dispute.timeoutDispute(disputeId);

        d = dispute.getDispute(disputeId);
        assertTrue(d.state == DisputeResolution.DisputeState.Resolved);
        assertTrue(d.outcome == DisputeResolution.Outcome.ChallengerWon);

        // Only the actually posted challenger bond is refundable. No
        // defender bond exists until the defender acknowledges.
        assertEq(challenger.balance, challengerBefore + BOND);
        assertEq(mockSlashing.slashCount(), 0);
    }

    function test_timeout_before_deadline_reverts() public {
        uint256 disputeId = _initiate();

        vm.expectRevert("Deadline not expired");
        dispute.timeoutDispute(disputeId);
    }

    function test_timeout_during_bisection() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        vm.roll(d.deadline + 1);

        dispute.timeoutDispute(disputeId);

        d = dispute.getDispute(disputeId);
        assertTrue(d.state == DisputeResolution.DisputeState.Resolved);
        assertTrue(d.outcome == DisputeResolution.Outcome.ChallengerWon);
    }

    // ══════════════════════════════════════════════════════════════════
    // Access Control Tests
    // ══════════════════════════════════════════════════════════════════

    function test_only_challenger_can_bisect() public {
        uint256 disputeId = _initiateAndAcknowledge();

        vm.prank(outsider);
        vm.expectRevert("Not the challenger");
        dispute.bisect(disputeId, true);
    }

    function test_only_defender_can_respond() public {
        uint256 disputeId = _initiateAndAcknowledge();

        vm.prank(outsider);
        vm.expectRevert("Not the defender");
        dispute.respond(disputeId, keccak256("step_result"));
    }

    function test_only_defender_can_acknowledge() public {
        uint256 disputeId = _initiate();

        vm.prank(outsider);
        vm.expectRevert("Not the defender");
        dispute.acknowledgeDispute{value: BOND}(disputeId);
    }

    function test_only_governance_can_resolve() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);

        vm.prank(outsider);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        dispute.resolve(disputeId, true);
    }

    // ══════════════════════════════════════════════════════════════════
    // Validation Tests
    // ══════════════════════════════════════════════════════════════════

    function test_cannot_dispute_yourself() public {
        vm.prank(challenger);
        vm.expectRevert("Cannot dispute yourself");
        dispute.initiateDispute{value: BOND}(1, challenger, RANGE_START, RANGE_END);
    }

    function test_cannot_dispute_zero_defender() public {
        vm.prank(challenger);
        vm.expectRevert("Zero defender address");
        dispute.initiateDispute{value: BOND}(1, address(0), RANGE_START, RANGE_END);
    }

    function test_invalid_range_reverts() public {
        vm.prank(challenger);
        vm.expectRevert("Invalid range");
        dispute.initiateDispute{value: BOND}(1, defender, 100, 50);
    }

    function test_same_job_cannot_be_disputed_twice() public {
        _initiate();

        vm.prank(challenger);
        vm.expectRevert("Job already disputed");
        dispute.initiateDispute{value: BOND}(1, defender, RANGE_START, RANGE_END);
    }

    function test_resolve_requires_at_least_one_round() public {
        uint256 disputeId = _initiateAndAcknowledge();

        vm.expectRevert("At least one round required");
        dispute.resolve(disputeId, true);
    }

    function test_bisect_past_deadline_reverts() public {
        uint256 disputeId = _initiateAndAcknowledge();

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        vm.roll(d.deadline + 1);

        vm.prank(challenger);
        vm.expectRevert("Deadline expired");
        dispute.bisect(disputeId, true);
    }

    // ══════════════════════════════════════════════════════════════════
    // Adversarial: Grief Attack (from AdversarialCompute.tla)
    // ══════════════════════════════════════════════════════════════════

    function test_grief_attack_costs_bond() public {
        uint256 disputeId = _initiateAndAcknowledge();
        _bisectOnce(disputeId);

        dispute.resolve(disputeId, false);

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        assertEq(d.challengerBond, 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // Defender Response Tests
    // ══════════════════════════════════════════════════════════════════

    function test_defender_can_respond() public {
        uint256 disputeId = _initiateAndAcknowledge();

        bytes32 stepHash = keccak256("step_result_at_midpoint");
        vm.prank(defender);
        dispute.respond(disputeId, stepHash);

        assertEq(dispute.defenderCommits(disputeId), stepHash);
    }

    // ══════════════════════════════════════════════════════════════════
    // Governance Tests
    // ══════════════════════════════════════════════════════════════════

    function test_setDisputeBond() public {
        dispute.setDisputeBond(20 ether);
        assertEq(dispute.disputeBond(), 20 ether);
    }

    function test_setDisputeBond_zero_reverts() public {
        vm.expectRevert("Bond must be >= 1");
        dispute.setDisputeBond(0);
    }

    function test_setMaxBisectionRounds() public {
        dispute.setMaxBisectionRounds(30);
        assertEq(dispute.maxBisectionRounds(), 30);
    }

    function test_transferGovernance() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        dispute.transferGovernance(challenger);
        assertEq(dispute.pendingGovernance(), challenger);
        vm.prank(challenger);
        dispute.acceptGovernance();
        assertEq(dispute.governance(), challenger);
    }

    function test_constructor_zero_bond_reverts() public {
        vm.expectRevert("Bond must be >= 1");
        new DisputeResolution(0, 20);
    }

    function test_constructor_zero_rounds_reverts() public {
        vm.expectRevert("MaxRounds must be >= 1");
        new DisputeResolution(10 ether, 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // View Functions
    // ══════════════════════════════════════════════════════════════════

    function test_isDisputeActive() public {
        uint256 disputeId = _initiateAndAcknowledge();
        assertTrue(dispute.isDisputeActive(disputeId));

        _bisectOnce(disputeId);
        dispute.resolve(disputeId, true);

        assertFalse(dispute.isDisputeActive(disputeId));
    }

    function test_getRangeSize() public {
        uint256 disputeId = _initiateAndAcknowledge();
        assertEq(dispute.getRangeSize(disputeId), RANGE_END - RANGE_START);

        _bisectOnce(disputeId);
        assertEq(dispute.getRangeSize(disputeId), (RANGE_END - RANGE_START) / 2);
    }
}
