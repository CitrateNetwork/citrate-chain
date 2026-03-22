// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {StablecoinTreasury} from "../src/StablecoinTreasury.sol";

/// @dev Minimal ERC-20 mock for testing stablecoin interactions
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

contract StablecoinTreasuryTest is Test {
    StablecoinTreasury public treasury;
    MockERC20 public usdc;
    MockERC20 public usdt;
    MockERC20 public dai;

    address public governance;
    address public alice;
    address public bob;
    address public charlie;
    address public outsider;

    function setUp() public {
        governance = address(this);
        alice = address(0xA11CE);
        bob = address(0xB0B);
        charlie = address(0xC4A1);
        outsider = address(0xBAD1);

        treasury = new StablecoinTreasury(governance);

        // Deploy mock stablecoins
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockERC20("Tether USD", "USDT", 6);
        dai = new MockERC20("Dai Stablecoin", "DAI", 18);

        // Add stablecoins
        treasury.addStablecoin(address(usdc));
        treasury.addStablecoin(address(usdt));

        // Mint tokens to test accounts
        usdc.mint(alice, 1_000_000e6);   // $1M USDC
        usdc.mint(bob, 500_000e6);       // $500K USDC
        usdt.mint(alice, 1_000_000e6);   // $1M USDT
        dai.mint(alice, 1_000_000e18);   // $1M DAI
    }

    // ============================================================
    // Test 1: Deploy with correct initial state
    // ============================================================

    function test_deploy_correct_state() public view {
        assertEq(treasury.governance(), governance);
        assertEq(treasury.totalValueUsd(), 0);
        assertEq(treasury.currentEpoch(), 0);
        assertEq(treasury.stablecoinCount(), 2);
        assertTrue(treasury.acceptedStablecoins(address(usdc)));
        assertTrue(treasury.acceptedStablecoins(address(usdt)));
    }

    function test_deploy_zero_governance_reverts() public {
        vm.expectRevert("StablecoinTreasury: zero governance");
        new StablecoinTreasury(address(0));
    }

    // ============================================================
    // Test 2: Add/remove stablecoins
    // ============================================================

    function test_add_stablecoin() public {
        treasury.addStablecoin(address(dai));
        assertTrue(treasury.acceptedStablecoins(address(dai)));
        assertEq(treasury.stablecoinCount(), 3);
    }

    function test_add_stablecoin_duplicate_reverts() public {
        vm.expectRevert("StablecoinTreasury: already accepted");
        treasury.addStablecoin(address(usdc));
    }

    function test_add_stablecoin_zero_address_reverts() public {
        vm.expectRevert("StablecoinTreasury: zero address");
        treasury.addStablecoin(address(0));
    }

    function test_add_stablecoin_non_governance_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("StablecoinTreasury: not governance");
        treasury.addStablecoin(address(dai));
    }

    function test_remove_stablecoin() public {
        treasury.removeStablecoin(address(usdt));
        assertFalse(treasury.acceptedStablecoins(address(usdt)));
        assertEq(treasury.stablecoinCount(), 1);
    }

    function test_remove_stablecoin_not_accepted_reverts() public {
        vm.expectRevert("StablecoinTreasury: not accepted");
        treasury.removeStablecoin(address(dai));
    }

    // ============================================================
    // Test 3: Deposit stablecoins
    // ============================================================

    function test_deposit_usdc() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        assertEq(treasury.stablecoinBalances(address(usdc)), 100_000e6);
        assertEq(treasury.totalValueUsd(), 100_000e6);
        assertEq(usdc.balanceOf(address(treasury)), 100_000e6);
    }

    function test_deposit_not_accepted_reverts() public {
        vm.startPrank(alice);
        dai.approve(address(treasury), 1000e18);
        vm.expectRevert("StablecoinTreasury: token not accepted");
        treasury.deposit(address(dai), 1000e18);
        vm.stopPrank();
    }

    function test_deposit_zero_amount_reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 0);
        vm.expectRevert("StablecoinTreasury: zero amount");
        treasury.deposit(address(usdc), 0);
        vm.stopPrank();
    }

    function test_deposit_multiple_stablecoins() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 50_000e6);
        treasury.deposit(address(usdc), 50_000e6);
        usdt.approve(address(treasury), 30_000e6);
        treasury.deposit(address(usdt), 30_000e6);
        vm.stopPrank();

        assertEq(treasury.stablecoinBalances(address(usdc)), 50_000e6);
        assertEq(treasury.stablecoinBalances(address(usdt)), 30_000e6);
        assertEq(treasury.totalValueUsd(), 80_000e6);
    }

    // ============================================================
    // Test 4: Epoch tracking
    // ============================================================

    function test_deposit_records_epoch_revenue() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        StablecoinTreasury.EpochRevenue memory rev = treasury.getEpochRevenue(0);
        assertEq(rev.totalUsd, 100_000e6);
    }

    function test_epoch_advances_after_epoch_length() public {
        // Deposit in epoch 0
        vm.startPrank(alice);
        usdc.approve(address(treasury), 200_000e6);
        treasury.deposit(address(usdc), 100_000e6);

        // Advance past EPOCH_LENGTH blocks
        vm.roll(block.number + 1000);

        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        assertEq(treasury.currentEpoch(), 1);

        StablecoinTreasury.EpochRevenue memory rev1 = treasury.getEpochRevenue(1);
        assertEq(rev1.totalUsd, 100_000e6);
    }

    // ============================================================
    // Test 5: Distribute
    // ============================================================

    function test_distribute_to_recipients() public {
        // Deposit first
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        // Distribute to bob and charlie
        address[] memory recipients = new address[](2);
        recipients[0] = bob;
        recipients[1] = charlie;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 60_000e6;
        amounts[1] = 40_000e6;

        treasury.distribute(address(usdc), recipients, amounts);

        assertEq(usdc.balanceOf(bob), 500_000e6 + 60_000e6); // original + distributed
        assertEq(usdc.balanceOf(charlie), 40_000e6);
        assertEq(treasury.stablecoinBalances(address(usdc)), 0);
        assertEq(treasury.totalValueUsd(), 0);
        assertEq(treasury.totalDistributed(), 100_000e6);
    }

    function test_distribute_non_governance_reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50_000e6;

        vm.prank(outsider);
        vm.expectRevert("StablecoinTreasury: not governance");
        treasury.distribute(address(usdc), recipients, amounts);
    }

    function test_distribute_empty_recipients_reverts() public {
        address[] memory recipients = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        vm.expectRevert("StablecoinTreasury: empty recipients");
        treasury.distribute(address(usdc), recipients, amounts);
    }

    function test_distribute_length_mismatch_reverts() public {
        address[] memory recipients = new address[](2);
        recipients[0] = bob;
        recipients[1] = charlie;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000e6;

        vm.expectRevert("StablecoinTreasury: length mismatch");
        treasury.distribute(address(usdc), recipients, amounts);
    }

    function test_distribute_insufficient_balance_reverts() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000e6; // more than balance (0)

        vm.expectRevert("StablecoinTreasury: insufficient balance");
        treasury.distribute(address(usdc), recipients, amounts);
    }

    function test_distribute_zero_amount_reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100e6);
        treasury.deposit(address(usdc), 100e6);
        vm.stopPrank();

        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0;

        vm.expectRevert("StablecoinTreasury: zero amount in batch");
        treasury.distribute(address(usdc), recipients, amounts);
    }

    function test_distribute_zero_recipient_reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100e6);
        treasury.deposit(address(usdc), 100e6);
        vm.stopPrank();

        address[] memory recipients = new address[](1);
        recipients[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50e6;

        vm.expectRevert("StablecoinTreasury: zero recipient");
        treasury.distribute(address(usdc), recipients, amounts);
    }

    // ============================================================
    // Test 6: Emergency withdrawal
    // ============================================================

    function test_emergency_withdraw() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        treasury.emergencyWithdraw(address(usdc), governance);

        assertEq(usdc.balanceOf(governance), 100_000e6);
        assertEq(treasury.stablecoinBalances(address(usdc)), 0);
        assertEq(treasury.totalValueUsd(), 0);
    }

    function test_emergency_withdraw_non_governance_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("StablecoinTreasury: not governance");
        treasury.emergencyWithdraw(address(usdc), outsider);
    }

    function test_emergency_withdraw_zero_balance_reverts() public {
        vm.expectRevert("StablecoinTreasury: no balance");
        treasury.emergencyWithdraw(address(usdc), governance);
    }

    function test_emergency_withdraw_zero_address_reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 100e6);
        treasury.deposit(address(usdc), 100e6);
        vm.stopPrank();

        vm.expectRevert("StablecoinTreasury: zero address");
        treasury.emergencyWithdraw(address(usdc), address(0));
    }

    // ============================================================
    // Test 7: Total value locked across stablecoins
    // ============================================================

    function test_tvl_across_stablecoins() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 50_000e6);
        treasury.deposit(address(usdc), 50_000e6);
        usdt.approve(address(treasury), 30_000e6);
        treasury.deposit(address(usdt), 30_000e6);
        vm.stopPrank();

        assertEq(treasury.totalValueLocked(), 80_000e6);
    }

    // ============================================================
    // Test 8: Transfer governance
    // ============================================================

    function test_transfer_governance() public {
        treasury.transferGovernance(alice);
        assertEq(treasury.governance(), alice);
    }

    function test_transfer_governance_zero_reverts() public {
        vm.expectRevert("StablecoinTreasury: zero address");
        treasury.transferGovernance(address(0));
    }

    function test_transfer_governance_non_governance_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("StablecoinTreasury: not governance");
        treasury.transferGovernance(outsider);
    }

    // ============================================================
    // Test 9: Record activity
    // ============================================================

    function test_record_activity() public {
        treasury.recordActivity(5, 100);
        StablecoinTreasury.EpochRevenue memory rev = treasury.getEpochRevenue(0);
        assertEq(rev.computeJobsCount, 5);
        assertEq(rev.inferenceCalls, 100);
    }

    // ============================================================
    // Test 10: Get accepted stablecoins
    // ============================================================

    function test_get_accepted_stablecoins() public view {
        address[] memory coins = treasury.getAcceptedStablecoins();
        assertEq(coins.length, 2);
        assertEq(coins[0], address(usdc));
        assertEq(coins[1], address(usdt));
    }

    // ============================================================
    // Test 11: Fuzz deposit amounts
    // ============================================================

    function testFuzz_deposit_updates_balances(uint256 amount) public {
        amount = bound(amount, 1, 1_000_000e6);

        usdc.mint(alice, amount);
        vm.startPrank(alice);
        usdc.approve(address(treasury), amount);
        treasury.deposit(address(usdc), amount);
        vm.stopPrank();

        assertEq(treasury.stablecoinBalances(address(usdc)), amount);
        assertEq(treasury.totalValueLocked(), amount);
    }

    // ============================================================
    // Test 12: Fuzz distribution proportionality
    // ============================================================

    function testFuzz_distribute_proportional(uint256 a, uint256 b) public {
        a = bound(a, 1, 500_000e6);
        b = bound(b, 1, 500_000e6);

        // Deposit enough
        uint256 total = a + b;
        usdc.mint(alice, total);
        vm.startPrank(alice);
        usdc.approve(address(treasury), total);
        treasury.deposit(address(usdc), total);
        vm.stopPrank();

        // Distribute
        address[] memory recipients = new address[](2);
        recipients[0] = bob;
        recipients[1] = charlie;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = a;
        amounts[1] = b;

        uint256 bobBefore = usdc.balanceOf(bob);
        uint256 charlieBefore = usdc.balanceOf(charlie);

        treasury.distribute(address(usdc), recipients, amounts);

        assertEq(usdc.balanceOf(bob) - bobBefore, a);
        assertEq(usdc.balanceOf(charlie) - charlieBefore, b);
        assertEq(treasury.totalDistributed(), total);
    }

    // ============================================================
    // Test 13: Max stablecoins limit
    // ============================================================

    function test_max_stablecoins_limit() public {
        // Already have 2, add 18 more
        for (uint256 i = 0; i < 18; i++) {
            MockERC20 token = new MockERC20("Token", "TKN", 6);
            treasury.addStablecoin(address(token));
        }
        assertEq(treasury.stablecoinCount(), 20);

        // 21st should fail
        MockERC20 extra = new MockERC20("Extra", "XTR", 6);
        vm.expectRevert("StablecoinTreasury: max stablecoins");
        treasury.addStablecoin(address(extra));
    }

    // ============================================================
    // Test 14: Multiple deposits accumulate
    // ============================================================

    function test_multiple_deposits_accumulate() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 300_000e6);

        treasury.deposit(address(usdc), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        treasury.deposit(address(usdc), 100_000e6);
        vm.stopPrank();

        assertEq(treasury.stablecoinBalances(address(usdc)), 300_000e6);
        assertEq(treasury.totalValueUsd(), 300_000e6);
    }

    // ============================================================
    // Test 15: Remove stablecoin does not affect existing balance
    // ============================================================

    function test_remove_stablecoin_keeps_balance() public {
        vm.startPrank(alice);
        usdc.approve(address(treasury), 50_000e6);
        treasury.deposit(address(usdc), 50_000e6);
        vm.stopPrank();

        // Remove USDC from accepted list
        treasury.removeStablecoin(address(usdc));

        // Balance still tracked
        assertEq(treasury.stablecoinBalances(address(usdc)), 50_000e6);

        // Can still distribute existing balance
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50_000e6;
        treasury.distribute(address(usdc), recipients, amounts);

        assertEq(usdc.balanceOf(bob), 500_000e6 + 50_000e6);
    }

    // ============================================================
    // Test 16: Deposit after transfer failure reverts
    // ============================================================

    function test_deposit_without_approval_reverts() public {
        // Alice does NOT approve the treasury
        vm.prank(alice);
        vm.expectRevert("StablecoinTreasury: transfer failed");
        treasury.deposit(address(usdc), 100_000e6);
    }
}
