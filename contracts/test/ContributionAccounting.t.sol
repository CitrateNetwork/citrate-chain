// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ContributionAccounting} from "../src/ContributionAccounting.sol";

contract ContributionAccountingTest is Test {
    ContributionAccounting internal accounting;

    address internal governance = address(this); // deployer is governance
    address internal recorder = address(0xEC01);
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal charlie = address(0xC4A1);
    address internal outsider = address(0xBAD1);

    function setUp() public {
        accounting = new ContributionAccounting();

        // Fund test addresses
        vm.deal(governance, 100 ether);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
        vm.deal(charlie, 10 ether);

        // Authorise a recorder contract
        accounting.addRecorder(recorder);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _record(
        address contributor,
        ContributionAccounting.ContributionType ctype,
        uint256 amount
    ) internal {
        vm.prank(recorder);
        accounting.recordContribution(contributor, ctype, amount);
    }

    // ── test_record_contribution_increases_score ─────────────────────

    function test_record_contribution_increases_score() public {
        assertEq(accounting.scores(alice), 0);

        // Record 10 Validation contributions (weight 10000 = 1.0x)
        _record(alice, ContributionAccounting.ContributionType.Validation, 10);

        // Expected score: 10 * 10000 / 10000 = 10
        assertEq(accounting.scores(alice), 10);
        assertEq(accounting.totalScore(), 10);
    }

    // ── test_weighted_score_calculation ──────────────────────────────

    function test_weighted_score_calculation() public {
        // Validation: 100 * 10000/10000 = 100
        // ModelHosting: 50 * 15000/10000 = 75
        // Total = 175
        _record(alice, ContributionAccounting.ContributionType.Validation, 100);
        _record(alice, ContributionAccounting.ContributionType.ModelHosting, 50);

        assertEq(accounting.scores(alice), 175);
    }

    // ── test_adapter_creation_weighted_2x ────────────────────────────

    function test_adapter_creation_weighted_2x() public {
        // AdapterCreation weight = 20000 (2.0x)
        // 10 contributions -> score = 10 * 20000 / 10000 = 20
        _record(alice, ContributionAccounting.ContributionType.AdapterCreation, 10);
        assertEq(accounting.scores(alice), 20);
    }

    // ── test_governance_weighted_half ────────────────────────────────

    function test_governance_weighted_half() public {
        // Governance weight = 5000 (0.5x)
        // 10 contributions -> score = 10 * 5000 / 10000 = 5
        _record(alice, ContributionAccounting.ContributionType.Governance, 10);
        assertEq(accounting.scores(alice), 5);
    }

    // ── test_unauthorized_recorder_reverts ───────────────────────────

    function test_unauthorized_recorder_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("Not authorized");
        accounting.recordContribution(
            alice,
            ContributionAccounting.ContributionType.Validation,
            1
        );
    }

    // ── test_zero_contribution_reverts ───────────────────────────────

    function test_zero_contribution_reverts() public {
        vm.prank(recorder);
        vm.expectRevert("Zero amount");
        accounting.recordContribution(
            alice,
            ContributionAccounting.ContributionType.Validation,
            0
        );
    }

    // ── test_fund_and_claim_rewards ─────────────────────────────────

    function test_fund_and_claim_rewards() public {
        // Alice is the sole contributor
        _record(alice, ContributionAccounting.ContributionType.Validation, 100);

        // Fund the pool with 10 ETH
        accounting.fundRewards{value: 10 ether}();
        assertEq(accounting.rewardPool(), 10 ether);

        // Distribute rewards (allocates shares to claimable balances)
        accounting.distributeRewards();

        // Alice claims — she has 100% of totalScore so gets the full pool
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        accounting.claimRewards();

        assertEq(alice.balance - balBefore, 10 ether);
        assertEq(accounting.distributed(alice), 10 ether);
        assertEq(accounting.totalDistributed(), 10 ether);
    }

    // ── test_proportional_distribution ───────────────────────────────

    function test_proportional_distribution() public {
        // Alice: 100 Validation (weight 1.0x) -> score 100
        // Bob:   100 Validation (weight 1.0x) -> score 100
        // Total = 200. Each gets 50%.
        _record(alice, ContributionAccounting.ContributionType.Validation, 100);
        _record(bob, ContributionAccounting.ContributionType.Validation, 100);

        accounting.fundRewards{value: 10 ether}();

        // Distribute allocates fair shares
        accounting.distributeRewards();

        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        accounting.claimRewards();
        // Alice should get 10 * 100/200 = 5 ETH
        assertEq(alice.balance - aliceBefore, 5 ether);

        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        accounting.claimRewards();
        // Bob gets 5 ETH as well
        assertEq(bob.balance - bobBefore, 5 ether);
    }

    // ── test_update_weight ──────────────────────────────────────────

    function test_update_weight() public {
        // Default Validation weight = 10000
        assertEq(accounting.weights(ContributionAccounting.ContributionType.Validation), 10000);

        // Governance updates it to 20000
        vm.expectEmit(false, false, false, true);
        emit ContributionAccounting.WeightUpdated(
            ContributionAccounting.ContributionType.Validation,
            10000,
            20000
        );
        accounting.updateWeight(ContributionAccounting.ContributionType.Validation, 20000);

        assertEq(accounting.weights(ContributionAccounting.ContributionType.Validation), 20000);
    }

    // ── test_multiple_contributors_fair_split ────────────────────────

    function test_multiple_contributors_fair_split() public {
        // Alice: 100 AdapterCreation (2.0x) -> score 200
        // Bob:   200 Validation (1.0x) -> score 200
        // Charlie: 400 Governance (0.5x) -> score 200
        // All equal scores -> each gets 1/3 of pool
        _record(alice, ContributionAccounting.ContributionType.AdapterCreation, 100);
        _record(bob, ContributionAccounting.ContributionType.Validation, 200);
        _record(charlie, ContributionAccounting.ContributionType.Governance, 400);

        assertEq(accounting.scores(alice), 200);
        assertEq(accounting.scores(bob), 200);
        assertEq(accounting.scores(charlie), 200);
        assertEq(accounting.totalScore(), 600);

        // Fund 9 ETH (divisible by 3)
        accounting.fundRewards{value: 9 ether}();

        // Distribute allocates exact shares
        accounting.distributeRewards();

        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        accounting.claimRewards();
        assertEq(alice.balance - aliceBefore, 3 ether);

        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        accounting.claimRewards();
        assertEq(bob.balance - bobBefore, 3 ether);

        uint256 charlieBefore = charlie.balance;
        vm.prank(charlie);
        accounting.claimRewards();
        assertEq(charlie.balance - charlieBefore, 3 ether);
    }

    // ── test_score_updates_on_each_record ────────────────────────────

    function test_score_updates_on_each_record() public {
        // First record: 5 Validation -> score = 5
        _record(alice, ContributionAccounting.ContributionType.Validation, 5);
        assertEq(accounting.scores(alice), 5);
        assertEq(accounting.totalScore(), 5);

        // Second record: 10 ModelHosting (1.5x) -> score = 5 + 15 = 20
        _record(alice, ContributionAccounting.ContributionType.ModelHosting, 10);
        assertEq(accounting.scores(alice), 20);
        assertEq(accounting.totalScore(), 20);

        // Third record: 4 AdapterCreation (2.0x) -> score = 5 + 15 + 8 = 28
        _record(alice, ContributionAccounting.ContributionType.AdapterCreation, 4);
        assertEq(accounting.scores(alice), 28);
        assertEq(accounting.totalScore(), 28);
    }

    // ── test_non_governance_cannot_update_weight ─────────────────────

    function test_non_governance_cannot_update_weight() public {
        vm.prank(outsider);
        vm.expectRevert("Not governance");
        accounting.updateWeight(ContributionAccounting.ContributionType.Validation, 50000);
    }

    // ── test_add_recorder ───────────────────────────────────────────

    function test_add_recorder() public {
        address newRecorder = address(0xEE01);

        // Initially not a recorder
        assertFalse(accounting.isRecorder(newRecorder));

        // Governance adds it
        accounting.addRecorder(newRecorder);
        assertTrue(accounting.isRecorder(newRecorder));

        // New recorder can record contributions
        vm.prank(newRecorder);
        accounting.recordContribution(
            alice,
            ContributionAccounting.ContributionType.DataProvision,
            7
        );

        // DataProvision weight = 15000 -> score = 7 * 15000 / 10000 = 10
        // (integer division: 105000 / 10000 = 10)
        assertEq(accounting.scores(alice), 10);
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_receive_fallback_funds_pool() public {
        // Sending ETH directly to the contract should fund the pool
        (bool ok, ) = address(accounting).call{value: 2 ether}("");
        assertTrue(ok);
        assertEq(accounting.rewardPool(), 2 ether);
    }

    function test_claim_with_nothing_claimable_reverts() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 10);
        accounting.fundRewards{value: 1 ether}();
        // No distributeRewards called, so nothing is claimable yet
        vm.prank(alice);
        vm.expectRevert("Nothing to claim");
        accounting.claimRewards();
    }

    function test_outsider_claim_reverts() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 10);
        accounting.fundRewards{value: 1 ether}();
        accounting.distributeRewards();

        // Outsider has no score -> nothing claimable
        vm.prank(outsider);
        vm.expectRevert("Nothing to claim");
        accounting.claimRewards();
    }

    function test_distribute_requires_governance() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 10);
        accounting.fundRewards{value: 1 ether}();

        vm.prank(outsider);
        vm.expectRevert("Not governance");
        accounting.distributeRewards();
    }

    function test_distribute_increments_epoch() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 10);
        accounting.fundRewards{value: 1 ether}();

        assertEq(accounting.currentEpoch(), 0);
        accounting.distributeRewards();
        assertEq(accounting.currentEpoch(), 1);

        // Fund again for next epoch
        accounting.fundRewards{value: 1 ether}();
        accounting.distributeRewards();
        assertEq(accounting.currentEpoch(), 2);
    }

    function test_pending_reward_view() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 100);
        _record(bob, ContributionAccounting.ContributionType.Validation, 100);
        accounting.fundRewards{value: 10 ether}();

        assertEq(accounting.pendingReward(alice), 5 ether);
        assertEq(accounting.pendingReward(bob), 5 ether);
        assertEq(accounting.pendingReward(outsider), 0);
    }

    function test_remove_recorder() public {
        assertTrue(accounting.isRecorder(recorder));
        accounting.removeRecorder(recorder);
        assertFalse(accounting.isRecorder(recorder));

        vm.prank(recorder);
        vm.expectRevert("Not authorized");
        accounting.recordContribution(alice, ContributionAccounting.ContributionType.Validation, 1);
    }

    function test_governance_can_record_directly() public {
        // governance (deployer) can record without being an explicit recorder
        accounting.recordContribution(
            alice,
            ContributionAccounting.ContributionType.BridgeInfra,
            10
        );
        // BridgeInfra weight = 10000 -> score = 10
        assertEq(accounting.scores(alice), 10);
    }

    function test_emit_contribution_recorded() public {
        vm.expectEmit(true, false, false, true);
        emit ContributionAccounting.ContributionRecorded(
            alice,
            ContributionAccounting.ContributionType.Validation,
            5
        );
        _record(alice, ContributionAccounting.ContributionType.Validation, 5);
    }

    function test_emit_reward_claimed() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 100);
        accounting.fundRewards{value: 1 ether}();
        accounting.distributeRewards();

        vm.expectEmit(true, false, false, true);
        emit ContributionAccounting.RewardClaimed(alice, 1 ether);
        vm.prank(alice);
        accounting.claimRewards();
    }

    function test_all_seven_types_accumulate() public {
        // Record 10000 of each type, verify total score
        _record(alice, ContributionAccounting.ContributionType.Validation, 10000);       // 10000 * 10000/10000 = 10000
        _record(alice, ContributionAccounting.ContributionType.ModelHosting, 10000);      // 10000 * 15000/10000 = 15000
        _record(alice, ContributionAccounting.ContributionType.AdapterCreation, 10000);   // 10000 * 20000/10000 = 20000
        _record(alice, ContributionAccounting.ContributionType.DataProvision, 10000);     // 10000 * 15000/10000 = 15000
        _record(alice, ContributionAccounting.ContributionType.AppDevelopment, 10000);    // 10000 * 10000/10000 = 10000
        _record(alice, ContributionAccounting.ContributionType.BridgeInfra, 10000);       // 10000 * 10000/10000 = 10000
        _record(alice, ContributionAccounting.ContributionType.Governance, 10000);        // 10000 *  5000/10000 =  5000

        // Total expected: 10000 + 15000 + 20000 + 15000 + 10000 + 10000 + 5000 = 85000
        assertEq(accounting.scores(alice), 85000);
    }

    function test_fund_rewards_zero_reverts() public {
        vm.expectRevert("Zero funding");
        accounting.fundRewards{value: 0}();
    }

    function test_add_recorder_zero_address_reverts() public {
        vm.expectRevert("Zero address");
        accounting.addRecorder(address(0));
    }

    function test_non_governance_cannot_add_recorder() public {
        vm.prank(outsider);
        vm.expectRevert("Not governance");
        accounting.addRecorder(address(0x1234));
    }

    function test_distribute_empty_pool_reverts() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 10);
        vm.expectRevert("Empty pool");
        accounting.distributeRewards();
    }

    function test_distribute_no_contributions_reverts() public {
        accounting.fundRewards{value: 1 ether}();
        vm.expectRevert("No contributions");
        accounting.distributeRewards();
    }

    function test_multiple_epochs_accumulate_claimable() public {
        _record(alice, ContributionAccounting.ContributionType.Validation, 100);

        // Epoch 1: fund 5 ETH
        accounting.fundRewards{value: 5 ether}();
        accounting.distributeRewards();

        // Epoch 2: fund another 5 ETH
        accounting.fundRewards{value: 5 ether}();
        accounting.distributeRewards();

        // Alice should have 10 ETH claimable (5 + 5)
        assertEq(accounting.claimable(alice), 10 ether);

        uint256 balBefore = alice.balance;
        vm.prank(alice);
        accounting.claimRewards();
        assertEq(alice.balance - balBefore, 10 ether);
    }

    function test_contributor_count() public {
        assertEq(accounting.contributorCount(), 0);
        _record(alice, ContributionAccounting.ContributionType.Validation, 1);
        assertEq(accounting.contributorCount(), 1);
        _record(bob, ContributionAccounting.ContributionType.Validation, 1);
        assertEq(accounting.contributorCount(), 2);
        // Recording again for alice should not increase count
        _record(alice, ContributionAccounting.ContributionType.ModelHosting, 1);
        assertEq(accounting.contributorCount(), 2);
    }
}
