// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {BulkComputeGateway} from "../src/BulkComputeGateway.sol";
import {StablecoinTreasury} from "../src/StablecoinTreasury.sol";
import {ComputePricingOracle} from "../src/ComputePricingOracle.sol";

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

contract BulkComputeGatewayTest is Test {
    BulkComputeGateway public gateway;
    StablecoinTreasury public treasury;
    ComputePricingOracle public oracle;
    MockERC20 public usdc;

    address public governance;
    address public school1;
    address public school2;
    address public marketplace;
    address public outsider;

    // Oracle: 13 cents/PFLOP-hour compute, 100 cents ($1.00) SALT
    uint256 constant COMPUTE_PRICE = 13;
    uint256 constant SALT_PRICE = 100;

    function setUp() public {
        governance = address(this);
        school1 = address(0x5C001);
        school2 = address(0x5C002);
        marketplace = address(0x4A4B);
        outsider = address(0xBAD1);

        // Deploy oracle
        oracle = new ComputePricingOracle(COMPUTE_PRICE, SALT_PRICE);

        // Deploy treasury
        treasury = new StablecoinTreasury(governance);

        // Deploy USDC mock
        usdc = new MockERC20("USD Coin", "USDC", 6);
        treasury.addStablecoin(address(usdc));

        // Deploy gateway
        gateway = new BulkComputeGateway(
            address(treasury),
            address(oracle),
            governance
        );

        // Authorize gateway as a spender and set up permissions
        gateway.authorizeSpender(marketplace);

        // Mint USDC to schools
        usdc.mint(school1, 10_000_000e6);  // $10M USDC
        usdc.mint(school2, 5_000_000e6);   // $5M USDC
    }

    // ============================================================
    // Helper
    // ============================================================

    function _purchaseCredits(address school, uint256 usdAmount) internal returns (uint256) {
        vm.startPrank(school);
        usdc.approve(address(gateway), usdAmount);
        uint256 credits = gateway.purchaseComputeCredits(address(usdc), usdAmount);
        vm.stopPrank();
        return credits;
    }

    // ============================================================
    // Test 1: Deploy with correct initial state
    // ============================================================

    function test_deploy_correct_state() public view {
        assertEq(address(gateway.treasury()), address(treasury));
        assertEq(address(gateway.oracle()), address(oracle));
        assertEq(gateway.governance(), governance);
        assertEq(gateway.totalCreditsPurchased(), 0);
        assertEq(gateway.totalCreditsSpent(), 0);
    }

    function test_deploy_zero_treasury_reverts() public {
        vm.expectRevert("BulkComputeGateway: zero treasury");
        new BulkComputeGateway(address(0), address(oracle), governance);
    }

    function test_deploy_zero_oracle_reverts() public {
        vm.expectRevert("BulkComputeGateway: zero oracle");
        new BulkComputeGateway(address(treasury), address(0), governance);
    }

    function test_deploy_zero_governance_reverts() public {
        vm.expectRevert("BulkComputeGateway: zero governance");
        new BulkComputeGateway(address(treasury), address(oracle), address(0));
    }

    // ============================================================
    // Test 2: Purchase compute credits
    // ============================================================

    function test_purchase_credits_basic() public {
        // $1,000 purchase (1_000_000_000 in 6 decimals = $1000)
        // Wait: $1000 in 6 decimals = 1_000_000_000? No: $1000 = 1000 * 1e6 = 1_000_000_000. Yes.
        // Actually $1000 in USDC 6 decimals = 1000 * 10^6 = 1,000,000,000. Hmm, that's $1000.
        // No wait. USDC has 6 decimals. $1.00 = 1_000_000. $1000 = 1_000_000_000.
        // But our MIN_PURCHASE is 10_000_000 ($10). So $1000 is fine.
        uint256 usdAmount = 1_000_000_000; // $1,000

        uint256 credits = _purchaseCredits(school1, usdAmount);

        // Expected: (1_000_000_000 * 1e14) / 13 = 1e23 / 13 ≈ 7.692e21
        uint256 expected = (usdAmount * 1e14) / COMPUTE_PRICE;
        assertEq(credits, expected, "credits mismatch");
        assertEq(gateway.computeCredits(school1), expected);
        assertEq(gateway.totalCreditsPurchased(), expected);
    }

    function test_purchase_credits_deposited_to_treasury() public {
        uint256 usdAmount = 100_000_000; // $100
        _purchaseCredits(school1, usdAmount);

        assertEq(treasury.stablecoinBalances(address(usdc)), usdAmount);
        assertEq(treasury.totalValueLocked(), usdAmount);
    }

    function test_purchase_below_minimum_reverts() public {
        vm.startPrank(school1);
        usdc.approve(address(gateway), 1_000_000); // $1
        vm.expectRevert("BulkComputeGateway: below minimum");
        gateway.purchaseComputeCredits(address(usdc), 1_000_000);
        vm.stopPrank();
    }

    function test_purchase_with_unaccepted_stablecoin_reverts() public {
        MockERC20 badToken = new MockERC20("Bad", "BAD", 6);
        badToken.mint(school1, 100_000e6);

        vm.startPrank(school1);
        badToken.approve(address(gateway), 100_000e6);
        vm.expectRevert("BulkComputeGateway: stablecoin not accepted");
        gateway.purchaseComputeCredits(address(badToken), 100_000e6);
        vm.stopPrank();
    }

    // ============================================================
    // Test 3: Purchase with stale oracle reverts
    // ============================================================

    function test_purchase_with_stale_oracle_reverts() public {
        // Roll past MAX_STALENESS
        vm.roll(block.number + oracle.MAX_STALENESS() + 1);

        vm.startPrank(school1);
        usdc.approve(address(gateway), 100_000_000);
        vm.expectRevert("BulkComputeGateway: oracle price stale");
        gateway.purchaseComputeCredits(address(usdc), 100_000_000);
        vm.stopPrank();
    }

    // ============================================================
    // Test 4: Spend credits
    // ============================================================

    function test_spend_credits() public {
        uint256 credits = _purchaseCredits(school1, 100_000_000); // $100
        uint256 spendAmount = credits / 2;

        vm.prank(marketplace);
        bool ok = gateway.spendCredits(school1, spendAmount);
        assertTrue(ok);

        assertEq(gateway.computeCredits(school1), credits - spendAmount);
        assertEq(gateway.totalCreditsSpent(), spendAmount);
    }

    function test_spend_credits_insufficient_reverts() public {
        _purchaseCredits(school1, 100_000_000);

        vm.prank(marketplace);
        vm.expectRevert("BulkComputeGateway: insufficient credits");
        gateway.spendCredits(school1, type(uint256).max);
    }

    function test_spend_credits_zero_reverts() public {
        vm.prank(marketplace);
        vm.expectRevert("BulkComputeGateway: zero credits");
        gateway.spendCredits(school1, 0);
    }

    function test_spend_credits_unauthorized_reverts() public {
        _purchaseCredits(school1, 100_000_000);

        vm.prank(outsider);
        vm.expectRevert("BulkComputeGateway: not authorized spender");
        gateway.spendCredits(school1, 1);
    }

    // ============================================================
    // Test 5: Governance can spend credits
    // ============================================================

    function test_governance_can_spend_credits() public {
        uint256 credits = _purchaseCredits(school1, 100_000_000);

        // Governance is always authorized
        bool ok = gateway.spendCredits(school1, credits);
        assertTrue(ok);
        assertEq(gateway.computeCredits(school1), 0);
    }

    // ============================================================
    // Test 6: Estimate calls remaining
    // ============================================================

    function test_estimate_calls_remaining() public {
        uint256 credits = _purchaseCredits(school1, 100_000_000); // $100

        // Average 1000 tokens per call
        // pflopPerCall = 1000 * 1e6 = 1e9
        // callsRemaining = credits / 1e9
        uint256 calls = gateway.estimateCallsRemaining(school1, 1000);
        assertEq(calls, credits / (1000 * 1e6));
        assertGt(calls, 0);
    }

    function test_estimate_calls_remaining_zero_tokens() public {
        _purchaseCredits(school1, 100_000_000);
        assertEq(gateway.estimateCallsRemaining(school1, 0), 0);
    }

    function test_estimate_calls_remaining_no_credits() public {
        assertEq(gateway.estimateCallsRemaining(school1, 1000), 0);
    }

    // ============================================================
    // Test 7: Purchase history
    // ============================================================

    function test_purchase_history() public {
        _purchaseCredits(school1, 100_000_000);  // $100
        _purchaseCredits(school1, 200_000_000);  // $200

        assertEq(gateway.purchaseCount(), 2);
        assertEq(gateway.institutionPurchaseCount(school1), 2);

        BulkComputeGateway.Purchase[] memory history = gateway.getPurchaseHistory(school1);
        assertEq(history.length, 2);
        assertEq(history[0].usdAmount, 100_000_000);
        assertEq(history[1].usdAmount, 200_000_000);
        assertEq(history[0].institution, school1);
    }

    function test_purchase_history_empty() public view {
        BulkComputeGateway.Purchase[] memory history = gateway.getPurchaseHistory(school1);
        assertEq(history.length, 0);
    }

    // ============================================================
    // Test 8: Multiple institutions
    // ============================================================

    function test_multiple_institutions() public {
        uint256 credits1 = _purchaseCredits(school1, 100_000_000);
        uint256 credits2 = _purchaseCredits(school2, 200_000_000);

        assertEq(gateway.computeCredits(school1), credits1);
        assertEq(gateway.computeCredits(school2), credits2);
        assertEq(gateway.totalCreditsPurchased(), credits1 + credits2);
    }

    // ============================================================
    // Test 9: Admin functions
    // ============================================================

    function test_authorize_spender() public {
        address newSpender = address(0x1234);
        gateway.authorizeSpender(newSpender);
        assertTrue(gateway.authorizedSpenders(newSpender));
    }

    function test_revoke_spender() public {
        gateway.revokeSpender(marketplace);
        assertFalse(gateway.authorizedSpenders(marketplace));
    }

    function test_authorize_spender_non_governance_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("BulkComputeGateway: not governance");
        gateway.authorizeSpender(address(0x1234));
    }

    function test_authorize_spender_zero_address_reverts() public {
        vm.expectRevert("BulkComputeGateway: zero address");
        gateway.authorizeSpender(address(0));
    }

    function test_set_oracle() public {
        ComputePricingOracle newOracle = new ComputePricingOracle(20, 200);
        gateway.setOracle(address(newOracle));
        assertEq(address(gateway.oracle()), address(newOracle));
    }

    function test_set_treasury() public {
        StablecoinTreasury newTreasury = new StablecoinTreasury(governance);
        gateway.setTreasury(address(newTreasury));
        assertEq(address(gateway.treasury()), address(newTreasury));
    }

    function test_transfer_governance() public {
        gateway.transferGovernance(school1);
        assertEq(gateway.governance(), school1);
    }

    function test_transfer_governance_zero_reverts() public {
        vm.expectRevert("BulkComputeGateway: zero address");
        gateway.transferGovernance(address(0));
    }

    function test_transfer_governance_non_governance_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("BulkComputeGateway: not governance");
        gateway.transferGovernance(outsider);
    }

    // ============================================================
    // Test 10: Current credit price
    // ============================================================

    function test_current_credit_price() public view {
        // computePriceUsdCents = 13 => 13 * 10_000 = 130_000 (6-decimal USD)
        assertEq(gateway.currentCreditPriceUsd(), 130_000);
    }

    // ============================================================
    // Test 11: Fuzz — credits proportional to payment
    // ============================================================

    function testFuzz_credits_proportional(uint256 amount) public {
        amount = bound(amount, 10_000_000, 1_000_000_000_000); // $10 to $1M

        usdc.mint(school1, amount);

        uint256 credits = _purchaseCredits(school1, amount);

        uint256 expected = (amount * 1e14) / COMPUTE_PRICE;
        assertEq(credits, expected, "credits should be proportional");
    }

    // ============================================================
    // Test 12: Fuzz — spend never exceeds balance
    // ============================================================

    function testFuzz_spend_bounded(uint256 purchaseAmt, uint256 spendAmt) public {
        purchaseAmt = bound(purchaseAmt, 10_000_000, 1_000_000_000);
        usdc.mint(school1, purchaseAmt);

        uint256 credits = _purchaseCredits(school1, purchaseAmt);
        spendAmt = bound(spendAmt, 1, credits);

        vm.prank(marketplace);
        bool ok = gateway.spendCredits(school1, spendAmt);
        assertTrue(ok);
        assertEq(gateway.computeCredits(school1), credits - spendAmt);
    }

    // ============================================================
    // Test 13: Credits accumulate across purchases
    // ============================================================

    function test_credits_accumulate() public {
        uint256 c1 = _purchaseCredits(school1, 50_000_000);
        uint256 c2 = _purchaseCredits(school1, 50_000_000);

        assertEq(gateway.computeCredits(school1), c1 + c2);
        assertEq(gateway.totalCreditsPurchased(), c1 + c2);
    }

    // ============================================================
    // Test 14: Spend credits from multiple spenders
    // ============================================================

    function test_multiple_spenders() public {
        address spender2 = address(0xABC);
        gateway.authorizeSpender(spender2);

        uint256 credits = _purchaseCredits(school1, 100_000_000);
        uint256 half = credits / 2;

        vm.prank(marketplace);
        gateway.spendCredits(school1, half);

        vm.prank(spender2);
        gateway.spendCredits(school1, half);

        // Some dust might remain due to integer division
        assertLe(gateway.computeCredits(school1), 1);
    }

    // ============================================================
    // Test 15: Get credit balance
    // ============================================================

    function test_get_credit_balance() public {
        uint256 credits = _purchaseCredits(school1, 100_000_000);
        assertEq(gateway.getCreditBalance(school1), credits);
        assertEq(gateway.getCreditBalance(school2), 0);
    }

    // ============================================================
    // Test 16: Purchase without approval reverts
    // ============================================================

    function test_purchase_without_approval_reverts() public {
        vm.prank(school1);
        vm.expectRevert("BulkComputeGateway: transfer from buyer failed");
        gateway.purchaseComputeCredits(address(usdc), 100_000_000);
    }
}
