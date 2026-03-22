// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TestnetFarmingAccounting} from "../src/TestnetFarmingAccounting.sol";
import {ContributionAccounting} from "../src/ContributionAccounting.sol";
import {StablecoinTreasury} from "../src/StablecoinTreasury.sol";

/// @dev Minimal ERC-20 mock for testing
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "MockERC20: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "MockERC20: insufficient balance");
        require(allowance[from][msg.sender] >= amount, "MockERC20: insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TestnetFarmingAccountingTest is Test {
    TestnetFarmingAccounting public farming;
    ContributionAccounting public contributions;
    StablecoinTreasury public treasury;
    MockERC20 public usdc;

    address public governance;
    address public alice;
    address public bob;
    address public charlie;
    address public dave;
    address public outsider;

    function setUp() public {
        governance = address(this);
        alice = address(0xA11CE);
        bob = address(0xB0B);
        charlie = address(0xC4A1);
        dave = address(0xDA7E);
        outsider = address(0xBAD1);

        // Deploy contribution accounting
        contributions = new ContributionAccounting();

        // Deploy treasury
        treasury = new StablecoinTreasury(governance);

        // Deploy USDC
        usdc = new MockERC20("USD Coin", "USDC", 6);
        treasury.addStablecoin(address(usdc));

        // Deploy farming accounting
        farming = new TestnetFarmingAccounting(
            address(contributions),
            address(treasury),
            governance
        );

        // Record contributions (governance can record directly)
        // Alice: 100 Validation (1.0x) -> score 100
        contributions.recordContribution(
            alice,
            ContributionAccounting.ContributionType.Validation,
            100
        );
        // Bob: 50 ModelHosting (1.5x) -> score 75
        contributions.recordContribution(
            bob,
            ContributionAccounting.ContributionType.ModelHosting,
            50
        );
        // Charlie: 25 AdapterCreation (2.0x) -> score 50
        contributions.recordContribution(
            charlie,
            ContributionAccounting.ContributionType.AdapterCreation,
            25
        );
        // Dave: 100 Governance (0.5x) -> score 50
        contributions.recordContribution(
            dave,
            ContributionAccounting.ContributionType.Governance,
            100
        );
        // Total score: 100 + 75 + 50 + 50 = 275
    }

    // ============================================================
    // Helper: take snapshot with all 4 participants
    // ============================================================

    function _takeFullSnapshot() internal {
        address[] memory participants = new address[](4);
        participants[0] = alice;
        participants[1] = bob;
        participants[2] = charlie;
        participants[3] = dave;
        farming.takeSnapshot(participants);
    }

    /// @dev Fund the farming contract with USDC and activate distribution
    function _activateDistribution(uint256 pool) internal {
        usdc.mint(address(farming), pool);
        farming.activateDistribution(address(usdc), pool);
    }

    // ============================================================
    // Test 1: Deploy with correct initial state
    // ============================================================

    function test_deploy_correct_state() public view {
        assertEq(address(farming.contributions()), address(contributions));
        assertEq(address(farming.treasury()), address(treasury));
        assertEq(farming.governance(), governance);
        assertFalse(farming.snapshotTaken());
        assertFalse(farming.distributionActive());
    }

    function test_deploy_zero_contributions_reverts() public {
        vm.expectRevert("TestnetFarming: zero contributions");
        new TestnetFarmingAccounting(address(0), address(treasury), governance);
    }

    function test_deploy_zero_treasury_reverts() public {
        vm.expectRevert("TestnetFarming: zero treasury");
        new TestnetFarmingAccounting(address(contributions), address(0), governance);
    }

    function test_deploy_zero_governance_reverts() public {
        vm.expectRevert("TestnetFarming: zero governance");
        new TestnetFarmingAccounting(address(contributions), address(treasury), address(0));
    }

    // ============================================================
    // Test 2: Take snapshot
    // ============================================================

    function test_take_snapshot() public {
        _takeFullSnapshot();

        assertTrue(farming.snapshotTaken());
        assertEq(farming.snapshotBlock(), block.number);
        assertEq(farming.snapshotParticipantCount(), 4);
        assertEq(farming.totalSnapshotScore(), 275);

        assertEq(farming.snapshotScores(alice), 100);
        assertEq(farming.snapshotScores(bob), 75);
        assertEq(farming.snapshotScores(charlie), 50);
        assertEq(farming.snapshotScores(dave), 50);
    }

    function test_take_snapshot_twice_reverts() public {
        _takeFullSnapshot();

        address[] memory participants = new address[](1);
        participants[0] = alice;
        vm.expectRevert("TestnetFarming: snapshot already taken");
        farming.takeSnapshot(participants);
    }

    function test_take_snapshot_non_governance_reverts() public {
        address[] memory participants = new address[](1);
        participants[0] = alice;
        vm.prank(outsider);
        vm.expectRevert("TestnetFarming: not governance");
        farming.takeSnapshot(participants);
    }

    function test_take_snapshot_empty_reverts() public {
        address[] memory participants = new address[](0);
        vm.expectRevert("TestnetFarming: empty participants");
        farming.takeSnapshot(participants);
    }

    function test_take_snapshot_duplicate_reverts() public {
        address[] memory participants = new address[](2);
        participants[0] = alice;
        participants[1] = alice;
        vm.expectRevert("TestnetFarming: duplicate participant");
        farming.takeSnapshot(participants);
    }

    function test_take_snapshot_zero_address_reverts() public {
        address[] memory participants = new address[](1);
        participants[0] = address(0);
        vm.expectRevert("TestnetFarming: zero address");
        farming.takeSnapshot(participants);
    }

    function test_take_snapshot_skips_zero_scores() public {
        // outsider has no contributions
        address[] memory participants = new address[](2);
        participants[0] = alice;
        participants[1] = outsider; // this will have 0 score but no revert since outsider != address(0)

        // But outsider has 0 score — should be skipped
        // Actually let's check: the function requires totalSnapshotScore > 0
        // Alice has 100, so totalSnapshotScore > 0 is fine
        farming.takeSnapshot(participants);

        // Only alice should be in snapshot (outsider has 0 score)
        assertEq(farming.snapshotParticipantCount(), 1);
        assertEq(farming.totalSnapshotScore(), 100);
    }

    function test_take_snapshot_all_zero_scores_reverts() public {
        address[] memory participants = new address[](1);
        participants[0] = outsider;
        vm.expectRevert("TestnetFarming: no scores");
        farming.takeSnapshot(participants);
    }

    // ============================================================
    // Test 3: Snapshot batch
    // ============================================================

    function test_snapshot_batch() public {
        // Initial snapshot with 2
        address[] memory batch1 = new address[](2);
        batch1[0] = alice;
        batch1[1] = bob;
        farming.takeSnapshot(batch1);

        assertEq(farming.snapshotParticipantCount(), 2);
        assertEq(farming.totalSnapshotScore(), 175);

        // Add more via batch
        address[] memory batch2 = new address[](2);
        batch2[0] = charlie;
        batch2[1] = dave;
        farming.takeSnapshotBatch(batch2);

        assertEq(farming.snapshotParticipantCount(), 4);
        assertEq(farming.totalSnapshotScore(), 275);
    }

    function test_snapshot_batch_without_initial_reverts() public {
        address[] memory batch = new address[](1);
        batch[0] = alice;
        vm.expectRevert("TestnetFarming: initial snapshot not taken");
        farming.takeSnapshotBatch(batch);
    }

    function test_snapshot_batch_skips_duplicates() public {
        address[] memory batch1 = new address[](2);
        batch1[0] = alice;
        batch1[1] = bob;
        farming.takeSnapshot(batch1);

        // Batch with alice again (should be silently skipped)
        address[] memory batch2 = new address[](2);
        batch2[0] = alice; // duplicate
        batch2[1] = charlie;
        farming.takeSnapshotBatch(batch2);

        // Should still be 3, not 4
        assertEq(farming.snapshotParticipantCount(), 3);
        assertEq(farming.totalSnapshotScore(), 225); // 100 + 75 + 50
    }

    // ============================================================
    // Test 4: Activate distribution
    // ============================================================

    function test_activate_distribution() public {
        _takeFullSnapshot();

        uint256 pool = 1_000_000e6; // $1M
        usdc.mint(address(farming), pool);

        farming.activateDistribution(address(usdc), pool);

        assertTrue(farming.distributionActive());
        assertEq(farming.distributionStablecoin(), address(usdc));
        assertEq(farming.distributionPool(), pool);
    }

    function test_activate_distribution_no_snapshot_reverts() public {
        vm.expectRevert("TestnetFarming: no snapshot");
        farming.activateDistribution(address(usdc), 1000e6);
    }

    function test_activate_distribution_already_active_reverts() public {
        _takeFullSnapshot();
        usdc.mint(address(farming), 2_000_000e6);
        farming.activateDistribution(address(usdc), 1_000_000e6);

        vm.expectRevert("TestnetFarming: already active");
        farming.activateDistribution(address(usdc), 1_000_000e6);
    }

    function test_activate_distribution_insufficient_balance_reverts() public {
        _takeFullSnapshot();
        // Don't mint enough
        usdc.mint(address(farming), 100e6);

        vm.expectRevert("TestnetFarming: insufficient balance");
        farming.activateDistribution(address(usdc), 1_000_000e6);
    }

    function test_activate_distribution_zero_stablecoin_reverts() public {
        _takeFullSnapshot();
        vm.expectRevert("TestnetFarming: zero stablecoin");
        farming.activateDistribution(address(0), 1_000_000e6);
    }

    function test_activate_distribution_zero_amount_reverts() public {
        _takeFullSnapshot();
        vm.expectRevert("TestnetFarming: zero amount");
        farming.activateDistribution(address(usdc), 0);
    }

    function test_activate_distribution_non_governance_reverts() public {
        _takeFullSnapshot();
        vm.prank(outsider);
        vm.expectRevert("TestnetFarming: not governance");
        farming.activateDistribution(address(usdc), 1_000_000e6);
    }

    // ============================================================
    // Test 5: Claim distribution
    // ============================================================

    function test_claim_basic() public {
        _takeFullSnapshot();
        uint256 pool = 1_000_000e6;
        _activateDistribution(pool);

        // Alice: score=100/275 of $1M
        uint256 aliceExpected = (pool * 100) / 275;

        vm.prank(alice);
        farming.claim();

        assertEq(usdc.balanceOf(alice), aliceExpected);
        assertTrue(farming.hasClaimed(alice));
        assertEq(farming.claimedAmount(alice), aliceExpected);
        assertEq(farming.totalClaimed(), aliceExpected);
    }

    function test_claim_all_participants() public {
        _takeFullSnapshot();
        uint256 pool = 275_000e6; // easily divisible by 275

        _activateDistribution(pool);

        // Alice: 100/275 * 275000e6 = 100000e6
        vm.prank(alice);
        farming.claim();
        assertEq(usdc.balanceOf(alice), 100_000e6);

        // Bob: 75/275 * 275000e6 = 75000e6
        vm.prank(bob);
        farming.claim();
        assertEq(usdc.balanceOf(bob), 75_000e6);

        // Charlie: 50/275 * 275000e6 = 50000e6
        vm.prank(charlie);
        farming.claim();
        assertEq(usdc.balanceOf(charlie), 50_000e6);

        // Dave: 50/275 * 275000e6 = 50000e6
        vm.prank(dave);
        farming.claim();
        assertEq(usdc.balanceOf(dave), 50_000e6);

        assertEq(farming.totalClaimed(), 275_000e6);
    }

    function test_claim_double_claim_reverts() public {
        _takeFullSnapshot();
        _activateDistribution(1_000_000e6);

        vm.prank(alice);
        farming.claim();

        vm.prank(alice);
        vm.expectRevert("TestnetFarming: already claimed");
        farming.claim();
    }

    function test_claim_not_in_snapshot_reverts() public {
        _takeFullSnapshot();
        _activateDistribution(1_000_000e6);

        vm.prank(outsider);
        vm.expectRevert("TestnetFarming: not in snapshot");
        farming.claim();
    }

    function test_claim_distribution_not_active_reverts() public {
        _takeFullSnapshot();

        vm.prank(alice);
        vm.expectRevert("TestnetFarming: distribution not active");
        farming.claim();
    }

    // ============================================================
    // Test 6: Calculate share view
    // ============================================================

    function test_calculate_share() public {
        _takeFullSnapshot();
        uint256 pool = 275_000e6;
        _activateDistribution(pool);

        assertEq(farming.calculateShare(alice), 100_000e6);
        assertEq(farming.calculateShare(bob), 75_000e6);
        assertEq(farming.calculateShare(charlie), 50_000e6);
        assertEq(farming.calculateShare(dave), 50_000e6);
        assertEq(farming.calculateShare(outsider), 0);
    }

    function test_calculate_share_before_distribution() public {
        _takeFullSnapshot();
        // Distribution not active yet
        assertEq(farming.calculateShare(alice), 0);
    }

    // ============================================================
    // Test 7: Top contributors leaderboard
    // ============================================================

    function test_top_contributors() public {
        _takeFullSnapshot();
        uint256 pool = 275_000e6;
        _activateDistribution(pool);

        (
            address[] memory addrs,
            uint256[] memory scoresList,
            uint256[] memory shares
        ) = farming.getTopContributors(3);

        assertEq(addrs.length, 3);
        // Alice should be first (score 100)
        assertEq(addrs[0], alice);
        assertEq(scoresList[0], 100);
        assertEq(shares[0], 100_000e6);

        // Bob second (score 75)
        assertEq(addrs[1], bob);
        assertEq(scoresList[1], 75);
    }

    function test_top_contributors_more_than_total() public {
        _takeFullSnapshot();

        (
            address[] memory addrs,
            uint256[] memory scoresList,
        ) = farming.getTopContributors(100);

        // Should return all 4
        assertEq(addrs.length, 4);
        // First should be highest score
        assertEq(scoresList[0], 100);
    }

    // ============================================================
    // Test 8: Snapshot page view
    // ============================================================

    function test_get_snapshot_page() public {
        _takeFullSnapshot();

        (address[] memory addrs, uint256[] memory scoresList) = farming.getSnapshotPage(0, 2);
        assertEq(addrs.length, 2);
        assertEq(addrs[0], alice);
        assertEq(addrs[1], bob);
        assertEq(scoresList[0], 100);

        (address[] memory addrs2, uint256[] memory scoresList2) = farming.getSnapshotPage(2, 2);
        assertEq(addrs2.length, 2);
        assertEq(addrs2[0], charlie);
        assertEq(addrs2[1], dave);
        assertEq(scoresList2[0], 50);
    }

    function test_get_snapshot_page_out_of_bounds() public {
        _takeFullSnapshot();
        (address[] memory addrs,) = farming.getSnapshotPage(100, 10);
        assertEq(addrs.length, 0);
    }

    // ============================================================
    // Test 9: Remaining distribution
    // ============================================================

    function test_remaining_distribution() public {
        _takeFullSnapshot();
        uint256 pool = 275_000e6;
        _activateDistribution(pool);

        assertEq(farming.remainingDistribution(), pool);

        vm.prank(alice);
        farming.claim();
        assertEq(farming.remainingDistribution(), pool - 100_000e6);
    }

    function test_remaining_distribution_before_active() public view {
        assertEq(farming.remainingDistribution(), 0);
    }

    // ============================================================
    // Test 10: Sweep remaining
    // ============================================================

    function test_sweep() public {
        _takeFullSnapshot();
        uint256 pool = 275_000e6;
        _activateDistribution(pool);

        // Only alice claims
        vm.prank(alice);
        farming.claim();

        // Governance sweeps remaining
        farming.sweep(governance);
        assertEq(usdc.balanceOf(governance), pool - 100_000e6);
    }

    function test_sweep_non_governance_reverts() public {
        _takeFullSnapshot();
        _activateDistribution(100_000e6);

        vm.prank(outsider);
        vm.expectRevert("TestnetFarming: not governance");
        farming.sweep(governance);
    }

    function test_sweep_not_active_reverts() public {
        vm.expectRevert("TestnetFarming: distribution not active");
        farming.sweep(governance);
    }

    function test_sweep_zero_address_reverts() public {
        _takeFullSnapshot();
        _activateDistribution(100_000e6);

        vm.expectRevert("TestnetFarming: zero address");
        farming.sweep(address(0));
    }

    // ============================================================
    // Test 11: Cannot re-snapshot after distribution
    // ============================================================

    function test_cannot_batch_after_distribution() public {
        _takeFullSnapshot();
        _activateDistribution(100_000e6);

        address[] memory batch = new address[](1);
        batch[0] = outsider;
        vm.expectRevert("TestnetFarming: distribution already active");
        farming.takeSnapshotBatch(batch);
    }

    // ============================================================
    // Test 12: Transfer governance
    // ============================================================

    function test_transfer_governance() public {
        farming.transferGovernance(alice);
        assertEq(farming.governance(), alice);
    }

    function test_transfer_governance_zero_reverts() public {
        vm.expectRevert("TestnetFarming: zero address");
        farming.transferGovernance(address(0));
    }

    function test_transfer_governance_non_governance_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("TestnetFarming: not governance");
        farming.transferGovernance(outsider);
    }

    // ============================================================
    // Test 13: Fuzz — distribution proportionality
    // ============================================================

    function testFuzz_distribution_proportional(uint256 pool) public {
        pool = bound(pool, 275, 1_000_000_000e6); // At least 275 (1 per score point) to $1B

        _takeFullSnapshot();
        _activateDistribution(pool);

        uint256 aliceShare = farming.calculateShare(alice);
        uint256 bobShare = farming.calculateShare(bob);
        uint256 charlieShare = farming.calculateShare(charlie);
        uint256 daveShare = farming.calculateShare(dave);

        // Alice (100/275) should get more than Bob (75/275)
        assertGe(aliceShare, bobShare, "alice >= bob");
        // Bob (75/275) should get more than Charlie (50/275)
        assertGe(bobShare, charlieShare, "bob >= charlie");
        // Charlie and Dave have equal scores
        assertEq(charlieShare, daveShare, "charlie == dave");

        // Total allocated should be <= pool (due to rounding)
        uint256 totalAllocated = aliceShare + bobShare + charlieShare + daveShare;
        assertLe(totalAllocated, pool, "total <= pool");

        // Dust should be minimal (< participantCount)
        assertLe(pool - totalAllocated, 4, "dust < participant count");
    }

    // ============================================================
    // Test 14: Fuzz — no double claim
    // ============================================================

    function testFuzz_no_double_claim(uint256 pool) public {
        pool = bound(pool, 275, 1_000_000_000e6);

        _takeFullSnapshot();
        _activateDistribution(pool);

        vm.prank(alice);
        farming.claim();

        vm.prank(alice);
        vm.expectRevert("TestnetFarming: already claimed");
        farming.claim();
    }

    // ============================================================
    // Test 15: Full lifecycle end-to-end
    // ============================================================

    function test_full_lifecycle() public {
        // 1. Contributions already recorded in setUp

        // 2. Take snapshot
        _takeFullSnapshot();

        // 3. Verify snapshot
        assertEq(farming.snapshotParticipantCount(), 4);
        assertEq(farming.totalSnapshotScore(), 275);

        // 4. Activate distribution with $275K (exactly $1K per score point)
        uint256 pool = 275_000e6;
        _activateDistribution(pool);

        // 5. All participants claim
        vm.prank(alice);
        farming.claim();
        vm.prank(bob);
        farming.claim();
        vm.prank(charlie);
        farming.claim();
        vm.prank(dave);
        farming.claim();

        // 6. Verify balances
        assertEq(usdc.balanceOf(alice), 100_000e6);   // $100K
        assertEq(usdc.balanceOf(bob), 75_000e6);      // $75K
        assertEq(usdc.balanceOf(charlie), 50_000e6);   // $50K
        assertEq(usdc.balanceOf(dave), 50_000e6);      // $50K

        // 7. All claimed
        assertEq(farming.totalClaimed(), pool);
        assertEq(farming.remainingDistribution(), 0);
    }

    // ============================================================
    // Test 16: ContributionAccounting pagination
    // ============================================================

    function test_contribution_accounting_pagination() public view {
        // Verify the new pagination functions work
        assertEq(contributions.getContributorCount(), 4);

        (address[] memory addrs, uint256[] memory scoresList) =
            contributions.getContributorListPage(0, 2);
        assertEq(addrs.length, 2);
        assertEq(addrs[0], alice);
        assertEq(addrs[1], bob);
        assertGt(scoresList[0], 0);

        (address[] memory addrs2, uint256[] memory scoresList2) =
            contributions.getContributorListPage(2, 10);
        assertEq(addrs2.length, 2); // only 2 remaining
        assertEq(addrs2[0], charlie);
        assertEq(addrs2[1], dave);
        assertGt(scoresList2[0], 0);
    }

    function test_contribution_accounting_pagination_out_of_bounds() public view {
        (address[] memory addrs,) = contributions.getContributorListPage(100, 10);
        assertEq(addrs.length, 0);
    }

    // ============================================================
    // Test 17: Sweep after partial claims
    // ============================================================

    function test_sweep_after_partial_claims() public {
        _takeFullSnapshot();
        uint256 pool = 275_000e6;
        _activateDistribution(pool);

        // Only alice and bob claim
        vm.prank(alice);
        farming.claim();
        vm.prank(bob);
        farming.claim();

        uint256 claimed = 100_000e6 + 75_000e6; // $175K
        uint256 unclaimed = pool - claimed; // $100K

        farming.sweep(governance);
        assertEq(usdc.balanceOf(governance), unclaimed);
    }
}
