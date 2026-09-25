// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ComputePricingOracle} from "../src/ComputePricingOracle.sol";
import {Governable} from "../src/lib/Governable.sol";

contract ComputePricingOracleTest is Test {
    ComputePricingOracle public oracle;

    address public governance;
    address public oracle1;
    address public oracle2;
    address public oracle3;
    address public oracle4;
    address public oracle5;
    address public nonMember;

    // Initial prices: 13 cents/PFLOP-hour compute, 100 cents ($1.00) SALT
    uint256 constant INITIAL_COMPUTE_PRICE = 13;
    uint256 constant INITIAL_SALT_PRICE = 100;

    function setUp() public {
        governance = address(this);
        oracle1 = address(0x0AC1E1);
        oracle2 = address(0x0AC1E2);
        oracle3 = address(0x0AC1E3);
        oracle4 = address(0x0AC1E4);
        oracle5 = address(0x0AC1E5);
        nonMember = address(0xDEAD);

        oracle = new ComputePricingOracle(INITIAL_COMPUTE_PRICE, INITIAL_SALT_PRICE);

        // Add 3 oracle members (quorum = ceil(3 * 67 / 100) = ceil(2.01) = 3 ... let's use 5 for easier quorum)
        // With 3 oracles: votesNeeded = ceil(3*67/100) = ceil(201/100) = 3 (all must agree)
        // With 5 oracles: votesNeeded = ceil(5*67/100) = ceil(335/100) = 4
        // Let's use 3 for simplicity in most tests (all 3 = quorum)
        oracle.addOracleMember(oracle1);
        oracle.addOracleMember(oracle2);
        oracle.addOracleMember(oracle3);
    }

    // ============================================================
    // Helper: push a compute price update through quorum
    // ============================================================

    function _reachComputePriceQuorum(uint256 newPrice) internal {
        vm.prank(oracle1);
        oracle.proposeComputePrice(newPrice);
        vm.prank(oracle2);
        oracle.proposeComputePrice(newPrice);
        vm.prank(oracle3);
        oracle.proposeComputePrice(newPrice);
    }

    function _reachSaltPriceQuorum(uint256 newPrice) internal {
        vm.prank(oracle1);
        oracle.proposeSaltPrice(newPrice);
        vm.prank(oracle2);
        oracle.proposeSaltPrice(newPrice);
        vm.prank(oracle3);
        oracle.proposeSaltPrice(newPrice);
    }

    // ============================================================
    // Test 1: Deploy with correct initial prices
    // ============================================================

    function test_deploy_correct_initial_prices() public view {
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "compute price mismatch");
        assertEq(oracle.saltPriceUsdCents(), INITIAL_SALT_PRICE, "SALT price mismatch");
        assertEq(oracle.governance(), governance, "governance mismatch");
        assertEq(oracle.lastUpdateBlock(), block.number, "lastUpdateBlock mismatch");
        assertEq(oracle.priceHistoryLength(), 1, "should have initial snapshot");

        // Verify derived saltPerPflopHour = 13 * 1e18 / 100 = 0.13e18
        uint256 expected = (INITIAL_COMPUTE_PRICE * 1e18) / INITIAL_SALT_PRICE;
        assertEq(oracle.saltPerPflopHour(), expected, "saltPerPflopHour mismatch");
    }

    function test_deploy_reverts_zero_compute_price() public {
        vm.expectRevert("ComputePricingOracle: zero compute price");
        new ComputePricingOracle(0, INITIAL_SALT_PRICE);
    }

    function test_deploy_reverts_zero_salt_price() public {
        vm.expectRevert("ComputePricingOracle: zero SALT price");
        new ComputePricingOracle(INITIAL_COMPUTE_PRICE, 0);
    }

    // ============================================================
    // Test 2: Oracle member can propose compute price
    // ============================================================

    function test_oracle_member_can_propose_compute_price() public {
        // RM-B1 / WP-D5.3 (audit SOL-10): each addOracleMember +
        // removeOracleMember bumps `computePriceNonce` to invalidate
        // any in-flight proposal. setUp() adds 3 oracles → nonce=3
        // before any proposal. Tests now capture the pre-action
        // nonce and assert deltas instead of absolute values.
        uint256 nonceBefore = oracle.computePriceNonce();

        uint256 newPrice = 14;
        vm.prank(oracle1);
        oracle.proposeComputePrice(newPrice);

        // Should have 1 vote, not finalized yet (need 3 with 3 oracles)
        (uint256 computeVotes, uint256 computeNonce,,) = oracle.getPendingVotes();
        assertEq(computeVotes, 1, "vote count");
        assertEq(computeNonce, nonceBefore, "nonce unchanged before quorum");

        // Price should NOT have changed yet
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "price should not change yet");
    }

    // ============================================================
    // Test 3: Oracle member can propose SALT price
    // ============================================================

    function test_oracle_member_can_propose_salt_price() public {
        // 105 is within 10% of 100
        uint256 newPrice = 105;
        // C037(b): membership changes now bump BOTH tracks, so the salt nonce
        // is not 0 after setUp's three addOracleMember calls. A single vote does
        // not finalize, so the nonce is unchanged by the proposal itself.
        uint256 saltNonceBefore = oracle.saltPriceNonce();
        vm.prank(oracle1);
        oracle.proposeSaltPrice(newPrice);

        (,, uint256 saltVotes, uint256 saltNonce) = oracle.getPendingVotes();
        assertEq(saltVotes, 1, "vote count");
        assertEq(saltNonce, saltNonceBefore, "nonce unchanged before quorum");
        assertEq(oracle.saltPriceUsdCents(), INITIAL_SALT_PRICE, "price should not change yet");
    }

    // ============================================================
    // Test 4: Non-member cannot propose
    // ============================================================

    function test_non_member_cannot_propose_compute_price() public {
        vm.prank(nonMember);
        vm.expectRevert("ComputePricingOracle: not oracle member");
        oracle.proposeComputePrice(14);
    }

    function test_non_member_cannot_propose_salt_price() public {
        vm.prank(nonMember);
        vm.expectRevert("ComputePricingOracle: not oracle member");
        oracle.proposeSaltPrice(105);
    }

    // ============================================================
    // Test 5: Price updates after quorum reached
    // ============================================================

    function test_compute_price_updates_at_quorum() public {
        // SOL-10: nonce is bumped on each addOracle (3 in setUp)
        // plus on quorum-finalize (1) = +1 from the action itself.
        uint256 nonceBefore = oracle.computePriceNonce();
        uint256 newPrice = 14; // within 10% of 13
        _reachComputePriceQuorum(newPrice);

        assertEq(oracle.computePriceUsdCents(), newPrice, "compute price should have updated");
        assertEq(oracle.computePriceNonce(), nonceBefore + 1, "nonce +1 from quorum finalize");
        assertEq(oracle.priceHistoryLength(), 2, "should have new snapshot");
    }

    function test_salt_price_updates_at_quorum() public {
        uint256 newPrice = 110; // within 10% of 100
        // C037(b): setUp's membership changes bump saltPriceNonce, so assert a
        // +1 delta from the quorum finalize rather than an absolute value.
        uint256 nonceBefore = oracle.saltPriceNonce();
        _reachSaltPriceQuorum(newPrice);

        assertEq(oracle.saltPriceUsdCents(), newPrice, "SALT price should have updated");
        assertEq(oracle.saltPriceNonce(), nonceBefore + 1, "nonce +1 from quorum finalize");
    }

    // ============================================================
    // Test 6: Price does not update before quorum
    // ============================================================

    function test_compute_price_no_update_before_quorum() public {
        uint256 newPrice = 14;

        vm.prank(oracle1);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "should not update after 1 vote");

        vm.prank(oracle2);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "should not update after 2 votes");

        // With 3 oracles, quorum = ceil(3*67/100) = 3, so the 3rd vote triggers update
        vm.prank(oracle3);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), newPrice, "should update after 3 votes");
    }

    // ============================================================
    // Test 7: computeToSalt returns correct value
    // ============================================================

    function test_computeToSalt_correct_value() public view {
        // saltPerPflopHour = 13 * 1e18 / 100 = 0.13e18 = 130000000000000000
        // For 1 PFLOP-hour (1e18 in 18-decimal representation):
        // cost = 1e18 * 0.13e18 / 1e18 = 0.13e18 = 130000000000000000
        uint256 onePflopHour = 1e18;
        uint256 cost = oracle.computeToSalt(onePflopHour);
        uint256 expected = (INITIAL_COMPUTE_PRICE * 1e18) / INITIAL_SALT_PRICE;
        assertEq(cost, expected, "1 PFLOP-hour cost mismatch");

        // For 10 PFLOP-hours:
        uint256 tenPflopHours = 10e18;
        uint256 cost10 = oracle.computeToSalt(tenPflopHours);
        assertEq(cost10, expected * 10, "10 PFLOP-hours cost mismatch");
    }

    function test_computeToSalt_zero_input() public view {
        assertEq(oracle.computeToSalt(0), 0, "zero input should return zero");
    }

    // ============================================================
    // Test 8: estimateJobCost with Commitment tier (1.0x)
    // ============================================================

    function test_estimateJobCost_commitment_tier() public view {
        // 1e12 tokens = 1 PFLOP-hour
        // Cost = 1 PFLOP-hour * 0.13 SALT/PFLOP-hour * 1.0x = 0.13 SALT
        uint256 saltCost = oracle.estimateJobCost(
            bytes32(0),
            1e12, // inputTokens
            0,    // outputTokens
            0     // Commitment tier
        );

        uint256 expectedSaltPerPflop = (INITIAL_COMPUTE_PRICE * 1e18) / INITIAL_SALT_PRICE;
        // pflopHours = 1e12 * 1e18 / 1e12 = 1e18
        // baseCost = 1e18 * expectedSaltPerPflop / 1e18 = expectedSaltPerPflop
        // finalCost = baseCost * 10000 / 10000 = baseCost
        assertEq(saltCost, expectedSaltPerPflop, "Commitment tier cost mismatch");
    }

    // ============================================================
    // Test 9: estimateJobCost with ZKProof tier (1.5x)
    // ============================================================

    function test_estimateJobCost_zkproof_tier() public view {
        uint256 saltCost = oracle.estimateJobCost(
            bytes32(0),
            1e12, // inputTokens
            0,
            1     // ZKProof tier
        );

        uint256 expectedSaltPerPflop = (INITIAL_COMPUTE_PRICE * 1e18) / INITIAL_SALT_PRICE;
        uint256 expectedCost = (expectedSaltPerPflop * 15000) / 10000; // 1.5x
        assertEq(saltCost, expectedCost, "ZKProof tier cost mismatch");
    }

    // ============================================================
    // Test 10: estimateJobCost with TEE tier (2.0x)
    // ============================================================

    function test_estimateJobCost_tee_tier() public view {
        uint256 saltCost = oracle.estimateJobCost(
            bytes32(0),
            1e12, // inputTokens
            0,
            2     // TEE tier
        );

        uint256 expectedSaltPerPflop = (INITIAL_COMPUTE_PRICE * 1e18) / INITIAL_SALT_PRICE;
        uint256 expectedCost = (expectedSaltPerPflop * 20000) / 10000; // 2.0x
        assertEq(saltCost, expectedCost, "TEE tier cost mismatch");
    }

    // ============================================================
    // Test 11: Staleness check returns true when stale
    // ============================================================

    function test_staleness_returns_true_when_stale() public {
        // Roll forward past MAX_STALENESS
        vm.roll(block.number + oracle.MAX_STALENESS() + 1);
        assertTrue(oracle.isPriceStale(), "should be stale");
    }

    // ============================================================
    // Test 12: Staleness check returns false when fresh
    // ============================================================

    function test_staleness_returns_false_when_fresh() public view {
        assertFalse(oracle.isPriceStale(), "should not be stale right after deploy");
    }

    function test_staleness_returns_false_at_boundary() public {
        // Roll forward exactly to MAX_STALENESS (not past it)
        vm.roll(block.number + oracle.MAX_STALENESS());
        assertFalse(oracle.isPriceStale(), "should not be stale at exactly MAX_STALENESS");
    }

    // ============================================================
    // Test 13: Price change rate limited (>10% rejected)
    // ============================================================

    function test_compute_price_rate_limited() public {
        // Current compute price: 13
        // Max 10% change: 13 * 1000 / 10000 = 1.3 => so max new price = 13 + 1 = 14 (integer floor)
        // Price 15 should be rejected: 15 - 13 = 2 > 1.3
        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: exceeds max price change");
        oracle.proposeComputePrice(15);
    }

    function test_salt_price_rate_limited() public {
        // Current SALT price: 100
        // Max 10% change: 100 * 1000 / 10000 = 10
        // Price 111 should be rejected: 111 - 100 = 11 > 10
        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: exceeds max price change");
        oracle.proposeSaltPrice(111);
    }

    function test_compute_price_rate_limited_decrease() public {
        // Current compute price: 13
        // Max decrease: 1.3 => 13 - 1 = 12 is ok, 13 - 2 = 11 is too much
        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: exceeds max price change");
        oracle.proposeComputePrice(11);
    }

    function test_compute_price_at_rate_limit_boundary() public {
        // 14 - 13 = 1, max delta = 1 (floor of 1.3). 1 <= 1 is OK.
        vm.prank(oracle1);
        oracle.proposeComputePrice(14); // should succeed
    }

    // ============================================================
    // Test 14: Price history tracks updates
    // ============================================================

    function test_price_history_tracks_updates() public {
        assertEq(oracle.priceHistoryLength(), 1, "initial snapshot");

        // Update compute price
        _reachComputePriceQuorum(14);
        assertEq(oracle.priceHistoryLength(), 2, "snapshot after compute update");

        // Update SALT price
        _reachSaltPriceQuorum(110);
        assertEq(oracle.priceHistoryLength(), 3, "snapshot after SALT update");

        // Verify latest snapshot
        ComputePricingOracle.PriceSnapshot memory snap = oracle.getPriceSnapshot(2);
        assertEq(snap.computePriceUsdCents, 14, "snapshot compute price");
        assertEq(snap.saltPriceUsdCents, 110, "snapshot SALT price");
    }

    // ============================================================
    // Test 15: Fuzz — computeToSalt never returns 0 for valid inputs
    // ============================================================

    function testFuzz_computeToSalt_nonzero_for_valid_input(uint256 pflopHours) public view {
        // Bound to reasonable range: 1 to 1e30 (avoids overflow)
        pflopHours = bound(pflopHours, 1, 1e30);
        uint256 cost = oracle.computeToSalt(pflopHours);
        // With compute=13 and salt=100, ratio is 0.13
        // For very small pflopHours, cost could round to 0
        // But pflopHours >= 1 and saltPerPflopHour = 0.13e18
        // cost = pflopHours * 0.13e18 / 1e18
        // For pflopHours >= 8, cost >= 1 (8 * 0.13 = 1.04 => floor 1)
        // For pflopHours >= 1, cost could be 0 due to integer division
        // The invariant: if pflopHours >= (1e18 / saltPerPflopHour) + 1, cost > 0
        if (pflopHours >= 8) {
            assertGt(cost, 0, "cost should be nonzero for pflopHours >= 8");
        }
    }

    // ============================================================
    // Test 16: Fuzz — estimateJobCost bounded by reasonable range
    // ============================================================

    function testFuzz_estimateJobCost_bounded(
        uint256 inputTokens,
        uint256 outputTokens,
        uint8 verificationTier
    ) public view {
        inputTokens = bound(inputTokens, 0, 1e18);      // up to 1 exatoken
        outputTokens = bound(outputTokens, 0, 1e18);
        verificationTier = uint8(bound(verificationTier, 0, 2));

        uint256 cost = oracle.estimateJobCost(bytes32(0), inputTokens, outputTokens, verificationTier);

        // Cost should never exceed a reasonable upper bound
        // Max: 2e18 tokens / 1e12 = 2e6 PFLOP-hours * 0.13 SALT * 2.0x TEE = 520000 SALT
        // In wei: 520000 * 1e18 = 5.2e23
        if (inputTokens + outputTokens > 0) {
            assertLe(cost, 6e23, "cost should be bounded");
        } else {
            assertEq(cost, 0, "zero tokens = zero cost");
        }
    }

    // ============================================================
    // Additional Tests: Edge Cases & Governance
    // ============================================================

    function test_oracle_cannot_double_vote_compute() public {
        vm.prank(oracle1);
        oracle.proposeComputePrice(14);

        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: already voted");
        oracle.proposeComputePrice(14);
    }

    function test_oracle_cannot_double_vote_salt() public {
        vm.prank(oracle1);
        oracle.proposeSaltPrice(105);

        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: already voted");
        oracle.proposeSaltPrice(105);
    }

    /// PBA-L2-044: divergent submissions no longer revert ("price
    /// mismatch" let one member stall every round); the quorum's median wins.
    function test_oracle_compute_price_is_median_of_submissions() public {
        vm.prank(oracle1);
        oracle.proposeComputePrice(14);
        vm.prank(oracle2);
        oracle.proposeComputePrice(12); // different value accepted
        vm.prank(oracle3);
        oracle.proposeComputePrice(13);
        assertEq(oracle.computePriceUsdCents(), 13);
    }

    function test_oracle_salt_price_is_median_of_submissions() public {
        vm.prank(oracle1);
        oracle.proposeSaltPrice(105);
        vm.prank(oracle2);
        oracle.proposeSaltPrice(95); // different value accepted
        vm.prank(oracle3);
        oracle.proposeSaltPrice(104);
        assertEq(oracle.saltPriceUsdCents(), 104);
    }

    function test_add_oracle_member_governance_only() public {
        vm.prank(nonMember);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        oracle.addOracleMember(address(0xBEEF));
    }

    function test_remove_oracle_member_governance_only() public {
        vm.prank(nonMember);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        oracle.removeOracleMember(oracle1);
    }

    function test_add_oracle_member() public {
        oracle.addOracleMember(oracle4);
        assertTrue(oracle.isOracleMember(oracle4), "should be member");
        assertEq(oracle.oracleCount(), 4, "count should be 4");
    }

    function test_remove_oracle_member() public {
        oracle.removeOracleMember(oracle3);
        assertFalse(oracle.isOracleMember(oracle3), "should not be member");
        assertEq(oracle.oracleCount(), 2, "count should be 2");
    }

    function test_add_duplicate_member_reverts() public {
        vm.expectRevert("ComputePricingOracle: already member");
        oracle.addOracleMember(oracle1);
    }

    function test_remove_non_member_reverts() public {
        vm.expectRevert("ComputePricingOracle: not member");
        oracle.removeOracleMember(nonMember);
    }

    function test_add_zero_address_reverts() public {
        vm.expectRevert("ComputePricingOracle: zero address");
        oracle.addOracleMember(address(0));
    }

    function test_transfer_governance() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        address newGov = address(0xBEEF);
        oracle.transferGovernance(newGov);
        assertEq(oracle.pendingGovernance(), newGov, "pending recorded");
        vm.prank(newGov);
        oracle.acceptGovernance();
        assertEq(oracle.governance(), newGov, "governance should transfer");
    }

    function test_transfer_governance_zero_address_reverts() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        oracle.transferGovernance(address(0));
    }

    function test_transfer_governance_non_governance_reverts() public {
        vm.prank(nonMember);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        oracle.transferGovernance(nonMember);
    }

    function test_invalid_verification_tier_reverts() public {
        vm.expectRevert("ComputePricingOracle: invalid tier");
        oracle.estimateJobCost(bytes32(0), 1e12, 0, 3);
    }

    function test_zero_price_proposal_reverts() public {
        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: zero price");
        oracle.proposeComputePrice(0);
    }

    function test_zero_salt_price_proposal_reverts() public {
        vm.prank(oracle1);
        vm.expectRevert("ComputePricingOracle: zero price");
        oracle.proposeSaltPrice(0);
    }

    function test_estimateJobCost_with_both_input_and_output_tokens() public view {
        // 5e11 input + 5e11 output = 1e12 total = 1 PFLOP-hour
        uint256 cost = oracle.estimateJobCost(
            bytes32(0),
            5e11,  // inputTokens
            5e11,  // outputTokens
            0      // Commitment
        );

        uint256 expectedSaltPerPflop = (INITIAL_COMPUTE_PRICE * 1e18) / INITIAL_SALT_PRICE;
        assertEq(cost, expectedSaltPerPflop, "combined tokens cost");
    }

    function test_estimateJobCost_zero_tokens() public view {
        uint256 cost = oracle.estimateJobCost(bytes32(0), 0, 0, 0);
        assertEq(cost, 0, "zero tokens = zero cost");
    }

    function test_sequential_price_updates() public {
        // SOL-10: addOracle bumps nonce, so the absolute nonce is
        // not 0 at start. Capture the baseline + assert delta.
        uint256 nonceBefore = oracle.computePriceNonce();

        // First update: 13 -> 14
        _reachComputePriceQuorum(14);
        assertEq(oracle.computePriceUsdCents(), 14);

        // C037(a): a per-track cooldown now separates finalized updates, so the
        // second update must wait MIN_UPDATE_INTERVAL blocks. Pre-fix both
        // finalized in the same block, letting movement compound.
        vm.roll(block.number + oracle.MIN_UPDATE_INTERVAL());

        // Second update: 14 -> 15 (within 10% of 14: max delta = 1.4 => 1)
        _reachComputePriceQuorum(15);
        assertEq(oracle.computePriceUsdCents(), 15);

        assertEq(oracle.computePriceNonce(), nonceBefore + 2, "+2 from two quorum finalizes");
    }

    function test_last_update_block_refreshes() public {
        uint256 initialBlock = oracle.lastUpdateBlock();

        vm.roll(block.number + 100);
        _reachComputePriceQuorum(14);

        assertGt(oracle.lastUpdateBlock(), initialBlock, "lastUpdateBlock should advance");
        assertEq(oracle.lastUpdateBlock(), block.number, "should be current block");
    }

    function test_staleness_reset_after_update() public {
        // Make it stale
        vm.roll(block.number + oracle.MAX_STALENESS() + 1);
        assertTrue(oracle.isPriceStale(), "should be stale");

        // Update price resets staleness
        _reachComputePriceQuorum(14);
        assertFalse(oracle.isPriceStale(), "should be fresh after update");
    }

    function test_quorum_with_5_oracles() public {
        // Add 2 more oracles (total: 5)
        oracle.addOracleMember(oracle4);
        oracle.addOracleMember(oracle5);
        assertEq(oracle.oracleCount(), 5);

        // votesNeeded = ceil(5 * 67 / 100) = ceil(335/100) = 4
        uint256 newPrice = 14;

        vm.prank(oracle1);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "no update after 1 vote");

        vm.prank(oracle2);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "no update after 2 votes");

        vm.prank(oracle3);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), INITIAL_COMPUTE_PRICE, "no update after 3 votes");

        vm.prank(oracle4);
        oracle.proposeComputePrice(newPrice);
        assertEq(oracle.computePriceUsdCents(), newPrice, "should update after 4 votes (quorum)");
    }
}
