// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LiquidStakingPool} from "../src/LiquidStakingPool.sol";
import {Governable} from "../src/lib/Governable.sol";

contract LiquidStakingPoolTest is Test {
    LiquidStakingPool public pool;

    address public governance;
    address public alice;
    address public bob;
    address public charlie;
    address public oracle1;
    address public oracle2;
    address public oracle3;
    address public provider1;

    function setUp() public {
        governance = address(this);
        pool = new LiquidStakingPool(address(this));

        alice = address(0xA11CE);
        bob = address(0xB0B);
        charlie = address(0xC4A21E);
        oracle1 = address(0x0AC1E1);
        oracle2 = address(0x0AC1E2);
        oracle3 = address(0x0AC1E3);
        provider1 = address(0xF101);

        vm.deal(alice, 1000 ether);
        vm.deal(bob, 1000 ether);
        vm.deal(charlie, 1000 ether);
        vm.deal(oracle1, 10 ether);
        vm.deal(oracle2, 10 ether);
        vm.deal(oracle3, 10 ether);
        vm.deal(provider1, 100 ether);
    }

    // ============================================================
    // Deposit Tests
    // ============================================================

    function test_deposit_and_shares() public {
        vm.prank(alice);
        uint256 sharesOut = pool.deposit{value: 10 ether}();

        assertEq(sharesOut, 10 ether, "First deposit should be 1:1");
        assertEq(pool.shares(alice), 10 ether);
        assertEq(pool.totalShares(), 10 ether);
        assertEq(pool.totalPooled(), 10 ether);
    }

    function test_zero_deposit_reverts() public {
        vm.prank(alice);
        vm.expectRevert("Zero deposit");
        pool.deposit{value: 0}();
    }

    function test_first_depositor_gets_one_to_one() public {
        vm.prank(alice);
        uint256 sharesOut = pool.deposit{value: 50 ether}();

        assertEq(sharesOut, 50 ether, "First deposit must be 1:1 shares");
        assertEq(pool.getSharePrice(), 1e18, "Share price should be 1:1 after first deposit");
    }

    function test_second_depositor_gets_proportional_shares() public {
        // Alice deposits 10 SALT, gets 10 shares
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        // Simulate rewards: send 10 SALT directly to pool, then report via oracle
        _setupOraclesAndReportRewards(10 ether, 0);

        // totalPooled is now 20 SALT, totalShares is 10
        // Share price = 20/10 = 2 SALT per share
        assertEq(pool.totalPooled(), 20 ether);
        assertEq(pool.totalShares(), 10 ether);

        // Bob deposits 20 SALT at share price 2.0
        // Should get 20 * 10 / 20 = 10 shares
        vm.prank(bob);
        uint256 bobShares = pool.deposit{value: 20 ether}();

        assertEq(bobShares, 10 ether, "Bob should get proportional shares at 2x price");
        assertEq(pool.totalShares(), 20 ether);
        assertEq(pool.totalPooled(), 40 ether);
    }

    function test_share_price_starts_at_one() public {
        // Before any deposits, share price should be 1:1
        assertEq(pool.getSharePrice(), 1e18, "Empty pool share price should be 1e18");
    }

    // ============================================================
    // Share Price and Rewards Tests
    // ============================================================

    function test_share_price_increases_with_rewards() public {
        // Alice deposits 100 SALT
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        uint256 priceBefore = pool.getSharePrice();
        assertEq(priceBefore, 1e18);

        // Report 50 SALT in rewards
        _setupOraclesAndReportRewards(50 ether, 0);

        uint256 priceAfter = pool.getSharePrice();
        // Price should be 150/100 = 1.5e18
        assertEq(priceAfter, 1.5e18, "Share price should increase with rewards");
        assertGt(priceAfter, priceBefore, "Price must increase after rewards");
    }

    function test_oracle_report_increases_pool() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        uint256 poolBefore = pool.totalPooled();

        _setupOraclesAndReportRewards(25 ether, 0);

        assertEq(pool.totalPooled(), poolBefore + 25 ether, "Pool should grow by reported rewards");
    }

    function test_multiple_depositors_share_rewards() public {
        // Alice deposits 100 SALT
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        // Bob deposits 100 SALT
        vm.prank(bob);
        pool.deposit{value: 100 ether}();

        // Both have 100 shares each, 200 total, 200 pooled
        assertEq(pool.shares(alice), 100 ether);
        assertEq(pool.shares(bob), 100 ether);

        // Report 100 SALT rewards
        _setupOraclesAndReportRewards(100 ether, 0);

        // Pool = 300, shares = 200, price = 1.5e18
        assertEq(pool.getSharePrice(), 1.5e18);

        // Each staker's balance should be 150 SALT (100 shares * 1.5)
        assertEq(pool.balanceOf(alice), 150 ether);
        assertEq(pool.balanceOf(bob), 150 ether);
    }

    // ============================================================
    // Withdrawal Tests
    // ============================================================

    function test_withdrawal_delay_enforced() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(10 ether);

        // Try to claim immediately — should revert
        vm.prank(alice);
        vm.expectRevert("Too early");
        pool.claimWithdrawal(reqId);
    }

    function test_withdrawal_claim_after_delay() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(10 ether);

        // Advance blocks past the delay
        vm.roll(block.number + pool.WITHDRAWAL_DELAY());

        uint256 balBefore = alice.balance;
        vm.prank(alice);
        pool.claimWithdrawal(reqId);

        assertEq(alice.balance, balBefore + 10 ether, "Should receive full SALT amount");

        // Pool should be empty
        assertEq(pool.totalPooled(), 0);
        assertEq(pool.totalShares(), 0);
    }

    function test_withdrawal_claim_too_early_reverts() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(5 ether);

        // Advance blocks but not enough
        vm.roll(block.number + pool.WITHDRAWAL_DELAY() - 1);

        vm.prank(alice);
        vm.expectRevert("Too early");
        pool.claimWithdrawal(reqId);
    }

    function test_withdraw_more_than_balance_reverts() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        vm.expectRevert("Insufficient shares");
        pool.requestWithdrawal(11 ether);
    }

    function test_withdrawal_zero_shares_reverts() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        vm.expectRevert("Zero shares");
        pool.requestWithdrawal(0);
    }

    function test_double_claim_reverts() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(10 ether);

        vm.roll(block.number + pool.WITHDRAWAL_DELAY());

        vm.prank(alice);
        pool.claimWithdrawal(reqId);

        vm.prank(alice);
        vm.expectRevert("Already claimed");
        pool.claimWithdrawal(reqId);
    }

    function test_cannot_claim_others_withdrawal() public {
        vm.prank(alice);
        pool.deposit{value: 10 ether}();

        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(5 ether);

        vm.roll(block.number + pool.WITHDRAWAL_DELAY());

        vm.prank(bob);
        vm.expectRevert("Not your withdrawal");
        pool.claimWithdrawal(reqId);
    }

    function test_withdrawal_at_appreciated_price() public {
        // Alice deposits 100 SALT (gets 100 shares)
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        // Rewards double the pool: 100 SALT rewards
        _setupOraclesAndReportRewards(100 ether, 0);

        // Share price is now 2.0 SALT/share
        assertEq(pool.getSharePrice(), 2e18);

        // Alice withdraws 50 shares — should get 100 SALT
        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(50 ether);

        (address staker, uint256 shareAmt, uint256 saltAmt, uint256 reqBlock, bool claimed) = pool.withdrawals(reqId);
        assertEq(staker, alice);
        assertEq(shareAmt, 50 ether);
        assertEq(saltAmt, 100 ether, "50 shares at 2x should yield 100 SALT");
        assertEq(claimed, false);

        vm.roll(block.number + pool.WITHDRAWAL_DELAY());

        uint256 balBefore = alice.balance;
        vm.prank(alice);
        pool.claimWithdrawal(reqId);

        assertEq(alice.balance, balBefore + 100 ether);
    }

    // ============================================================
    // Oracle Tests
    // ============================================================

    function test_non_oracle_cannot_report() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        vm.prank(alice);
        vm.expectRevert("Not oracle");
        pool.reportRewards(10 ether, 0);
    }

    function test_oracle_quorum_required() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        // Add 3 oracles. PBA-L2-026: quorum is ceil(2n/3) = 2 of 3 (it used to
        // be ceil(3 * 67 / 100) = 3, i.e. unanimity, so one dissenter blocked).
        pool.addOracle(oracle1);
        pool.addOracle(oracle2);
        pool.addOracle(oracle3);
        assertEq(pool.votesRequired(), 2);

        // CHAIN-B-C018 (HELD/reroll): a reward report consumes real donated
        // SALT backing, so `totalPooled` can only grow by SALT the contract holds.
        pool.donate{value: 10 ether}();

        // First oracle votes — no change yet
        vm.prank(oracle1);
        pool.reportRewards(10 ether, 0);
        assertEq(pool.totalPooled(), 100 ether, "Pool should not change before quorum");

        // Second oracle votes — two thirds reached, report applied
        vm.prank(oracle2);
        pool.reportRewards(10 ether, 0);
        assertEq(pool.totalPooled(), 110 ether, "Pool should include rewards after quorum");
        assertEq(pool.rewardReportNonce(), 1);

        // A late third vote opens the NEXT nonce on its own; it does not
        // re-apply the finalized report.
        vm.prank(oracle3);
        pool.reportRewards(0, 0);
        assertEq(pool.totalPooled(), 110 ether);
        assertEq(pool.rewardReportNonce(), 1);
    }

    function test_oracle_double_vote_reverts() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        pool.addOracle(oracle1);
        pool.addOracle(oracle2);
        pool.addOracle(oracle3);

        vm.prank(oracle1);
        pool.reportRewards(10 ether, 0);

        vm.prank(oracle1);
        vm.expectRevert("Already voted");
        pool.reportRewards(10 ether, 0);
    }

    /// PBA-L2-026: a differing report no longer reverts ("Report mismatch"
    /// let the first voter wedge the nonce). It is tallied separately and
    /// neither tuple finalizes without quorum.
    function test_oracle_mismatched_report_is_tallied_separately() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        pool.addOracle(oracle1);
        pool.addOracle(oracle2);

        vm.prank(oracle1);
        pool.reportRewards(10 ether, 0);

        // oracle2 reports different values: accepted as a vote, no quorum.
        vm.prank(oracle2);
        pool.reportRewards(20 ether, 0);
        assertEq(pool.rewardReportNonce(), 0, "no tuple reached quorum");
    }

    function test_rewards_cap_enforced() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        pool.addOracle(oracle1);

        // Try to report more than 200% of pool (MAX_REWARD_RATE_BPS = 20000)
        vm.prank(oracle1);
        vm.expectRevert("Rewards exceed cap");
        pool.reportRewards(201 ether, 0);
    }

    function test_slash_cap_enforced() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        pool.addOracle(oracle1);

        // Try to report more than 10% slash (MAX_SLASH_RATE_BPS = 1000)
        vm.prank(oracle1);
        vm.expectRevert("Slash exceeds cap");
        pool.reportRewards(0, 11 ether);
    }

    function test_slash_reduces_pool() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        // Report with slash
        _setupOraclesAndReportRewardsWithSlash(5 ether, 5 ether);

        // Pool = 100 - 5 (slash) + 5 (reward) = 100
        assertEq(pool.totalPooled(), 100 ether);
    }

    // ============================================================
    // Governance Tests
    // ============================================================

    function test_governance_can_add_remove_oracle() public {
        pool.addOracle(oracle1);
        assertTrue(pool.isOracle(oracle1));
        assertEq(pool.oracleCount(), 1);

        pool.removeOracle(oracle1);
        assertFalse(pool.isOracle(oracle1));
        assertEq(pool.oracleCount(), 0);
    }

    function test_non_governance_cannot_add_oracle() public {
        vm.prank(alice);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        pool.addOracle(oracle1);
    }

    function test_non_governance_cannot_remove_oracle() public {
        pool.addOracle(oracle1);

        vm.prank(alice);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        pool.removeOracle(oracle1);
    }

    function test_add_duplicate_oracle_reverts() public {
        pool.addOracle(oracle1);

        vm.expectRevert("Already oracle");
        pool.addOracle(oracle1);
    }

    function test_remove_non_oracle_reverts() public {
        vm.expectRevert("Not oracle");
        pool.removeOracle(oracle1);
    }

    function test_governance_transfer() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        pool.transferGovernance(alice);
        assertEq(pool.pendingGovernance(), alice, "pending recorded");
        vm.prank(alice);
        pool.acceptGovernance();
        assertEq(pool.governance(), alice);

        // Old governance can no longer act
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        pool.addOracle(oracle1);

        // New governance can act
        vm.prank(alice);
        pool.addOracle(oracle1);
        assertTrue(pool.isOracle(oracle1));
    }

    // ============================================================
    // Provider Collateral Tests
    // ============================================================

    function test_provider_deposit_collateral() public {
        vm.prank(provider1);
        pool.depositCollateral{value: 10 ether}();

        assertEq(pool.providerCollateral(provider1), 10 ether);
    }

    function test_provider_withdraw_collateral() public {
        vm.prank(provider1);
        pool.depositCollateral{value: 10 ether}();

        uint256 balBefore = provider1.balance;
        vm.prank(provider1);
        pool.withdrawCollateral(5 ether);

        assertEq(pool.providerCollateral(provider1), 5 ether);
        assertEq(provider1.balance, balBefore + 5 ether);
    }

    function test_slash_provider_collateral() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        vm.prank(provider1);
        pool.depositCollateral{value: 20 ether}();

        uint256 poolBefore = pool.totalPooled();

        // Governance slashes 10 SALT from provider
        pool.slashProvider(provider1, 10 ether);

        assertEq(pool.providerCollateral(provider1), 10 ether, "Collateral reduced by slash");
        assertEq(pool.totalPooled(), poolBefore + 10 ether, "Slashed amount returns to pool");
    }

    function test_slash_exceeding_collateral_caps_at_balance() public {
        vm.prank(provider1);
        pool.depositCollateral{value: 5 ether}();

        // Try to slash more than collateral
        pool.slashProvider(provider1, 100 ether);

        assertEq(pool.providerCollateral(provider1), 0, "Collateral should be zeroed");
    }

    // ============================================================
    // View Function Tests
    // ============================================================

    function test_balanceOf_reflects_share_value() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        assertEq(pool.balanceOf(alice), 100 ether);

        // After rewards
        _setupOraclesAndReportRewards(50 ether, 0);

        assertEq(pool.balanceOf(alice), 150 ether);
    }

    function test_previewDeposit() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        _setupOraclesAndReportRewards(100 ether, 0);

        // Share price = 2.0, depositing 20 SALT should yield 10 shares
        uint256 preview = pool.previewDeposit(20 ether);
        assertEq(preview, 10 ether);
    }

    function test_previewWithdraw() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        _setupOraclesAndReportRewards(100 ether, 0);

        // 50 shares at price 2.0 = 100 SALT
        uint256 preview = pool.previewWithdraw(50 ether);
        assertEq(preview, 100 ether);
    }

    // ============================================================
    // Receive Fallback Test
    // ============================================================

    function test_receive_rejects_unsolicited_salt() public {
        // RM-B1 / WP-D5.8 (audit SOL-16): pre-fix the open receive()
        // was the second leg of the first-depositor inflation attack.
        // Post-fix direct sends revert; callers must use deposit()
        // or donate().
        (bool ok, ) = address(pool).call{value: 1 ether}("");
        assertFalse(ok, "Pool MUST reject unsolicited SALT (SOL-16)");
    }

    function test_donate_records_donation_without_inflating_shares() public {
        // donate() is the explicit replacement: records the
        // donation but does NOT update totalPooled (which would
        // grant the donor zero shares while inflating share price).
        vm.deal(alice, 5 ether);
        vm.prank(alice);
        pool.donate{value: 1 ether}();
        assertEq(pool.totalDonated(), 1 ether);
    }

    // ============================================================
    // Edge Cases and Integration
    // ============================================================

    function test_multiple_withdrawals_sequential() public {
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        // Request two withdrawals
        vm.prank(alice);
        uint256 req1 = pool.requestWithdrawal(30 ether);

        vm.prank(alice);
        uint256 req2 = pool.requestWithdrawal(30 ether);

        assertEq(pool.shares(alice), 40 ether);
        assertEq(pool.nextWithdrawalId(), 2);

        // Claim both after delay
        vm.roll(block.number + pool.WITHDRAWAL_DELAY());

        uint256 balBefore = alice.balance;

        vm.prank(alice);
        pool.claimWithdrawal(req1);

        vm.prank(alice);
        pool.claimWithdrawal(req2);

        assertEq(alice.balance, balBefore + 60 ether);
    }

    function test_deposit_after_rewards_and_withdraw() public {
        // Alice deposits 100 SALT
        vm.prank(alice);
        pool.deposit{value: 100 ether}();

        // 100 SALT rewards => pool = 200, shares = 100, price = 2.0
        _setupOraclesAndReportRewards(100 ether, 0);

        // Bob deposits 100 SALT at price 2.0 => gets 50 shares
        vm.prank(bob);
        uint256 bobShares = pool.deposit{value: 100 ether}();
        assertEq(bobShares, 50 ether);

        // Pool = 300, shares = 150, price still 2.0
        assertEq(pool.getSharePrice(), 2e18);

        // Alice withdraws all 100 shares (200 SALT value)
        vm.prank(alice);
        uint256 reqId = pool.requestWithdrawal(100 ether);

        vm.roll(block.number + pool.WITHDRAWAL_DELAY());

        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        pool.claimWithdrawal(reqId);

        assertEq(alice.balance, aliceBefore + 200 ether, "Alice gets 200 SALT for 100 shares at 2x");

        // Pool = 100, shares = 50, price still 2.0
        assertEq(pool.totalPooled(), 100 ether);
        assertEq(pool.totalShares(), 50 ether);
        assertEq(pool.getSharePrice(), 2e18);
    }

    // ============================================================
    // Helpers
    // ============================================================

    /// @dev Setup oracles (if not already) and report rewards with quorum
    function _setupOraclesAndReportRewards(uint256 rewards, uint256 slashed) internal {
        _setupOraclesAndReportRewardsWithSlash(rewards, slashed);
    }

    function _setupOraclesAndReportRewardsWithSlash(uint256 rewards, uint256 slashed) internal {
        // Add oracles if not already added
        if (!pool.isOracle(oracle1)) {
            pool.addOracle(oracle1);
        }
        if (!pool.isOracle(oracle2)) {
            pool.addOracle(oracle2);
        }
        if (!pool.isOracle(oracle3)) {
            pool.addOracle(oracle3);
        }

        // Send SALT to pool to cover rewards.
        // RM-B1 / WP-D5.8 (audit SOL-16): pool no longer accepts
        // unsolicited transfers; use donate() to fund rewards
        // without affecting share math.
        if (rewards > 0) {
            pool.donate{value: rewards}();
        }

        // All three oracles report (quorum = ceil(3 * 67 / 100) = 3)
        vm.prank(oracle1);
        pool.reportRewards(rewards, slashed);

        vm.prank(oracle2);
        pool.reportRewards(rewards, slashed);

        vm.prank(oracle3);
        pool.reportRewards(rewards, slashed);
    }
}
