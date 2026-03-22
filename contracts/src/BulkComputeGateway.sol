// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./StablecoinTreasury.sol";
import "./interfaces/IComputePricingOracle.sol";

/// @title BulkComputeGateway — Institutional Compute Credit Purchases
/// @notice Schools and institutions buy compute credits with stablecoins.
///         Credits are denominated in PFLOP-hours (18 decimals) and priced
///         via the ComputePricingOracle. Credits can be spent on ComputeMarketplace
///         jobs, and remaining credits can be queried for inference estimation.
///
/// @dev Flow:
///   1. Institution calls purchaseComputeCredits(stablecoin, usdAmount)
///   2. Stablecoins are deposited into StablecoinTreasury
///   3. Credits (PFLOP-hours) are calculated from oracle pricing
///   4. Institution spends credits via spendCredits() (called by marketplace)
///   5. estimateCallsRemaining() returns approximate inference budget
///
/// Sprint ECON-2 — WP-E2.1
contract BulkComputeGateway is ReentrancyGuard {
    // ============================================================
    // Constants
    // ============================================================

    /// @notice Minimum purchase amount in USD (6 decimals): $10.00
    uint256 public constant MIN_PURCHASE_USD = 10_000_000;

    /// @notice Basis points denominator
    uint256 private constant BPS = 10_000;

    // ============================================================
    // State — Dependencies
    // ============================================================

    /// @notice Treasury that receives stablecoin deposits
    StablecoinTreasury public treasury;

    /// @notice Oracle for compute-to-USD pricing
    IComputePricingOracle public oracle;

    /// @notice Governance address
    address public governance;

    // ============================================================
    // State — Authorized Spenders
    // ============================================================

    /// @notice Contracts authorized to spend credits on behalf of institutions
    ///         (e.g., ComputeMarketplace)
    mapping(address => bool) public authorizedSpenders;

    // ============================================================
    // State — Credit Balances
    // ============================================================

    /// @notice Compute credits per institution (PFLOP-hours, 18 decimals)
    mapping(address => uint256) public computeCredits;

    /// @notice Total credits purchased across all institutions
    uint256 public totalCreditsPurchased;

    /// @notice Total credits spent across all institutions
    uint256 public totalCreditsSpent;

    // ============================================================
    // State — Purchase Tracking
    // ============================================================

    struct Purchase {
        address institution;
        address stablecoin;
        uint256 usdAmount;
        uint256 creditsReceived;
        uint256 timestamp;
        uint256 blockNumber;
    }

    Purchase[] public purchases;
    mapping(address => uint256[]) public institutionPurchases;

    // ============================================================
    // Events
    // ============================================================

    event CreditsPurchased(
        address indexed institution,
        address indexed stablecoin,
        uint256 usdAmount,
        uint256 creditsReceived,
        uint256 purchaseIndex
    );
    event CreditsSpent(
        address indexed institution,
        address indexed spender,
        uint256 creditAmount
    );
    event SpenderAuthorized(address indexed spender);
    event SpenderRevoked(address indexed spender);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event GovernanceTransferred(address indexed oldGov, address indexed newGov);

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyGovernance() {
        require(msg.sender == governance, "BulkComputeGateway: not governance");
        _;
    }

    modifier onlyAuthorizedSpender() {
        require(
            authorizedSpenders[msg.sender] || msg.sender == governance,
            "BulkComputeGateway: not authorized spender"
        );
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    /// @notice Deploy the gateway
    /// @param _treasury StablecoinTreasury address
    /// @param _oracle ComputePricingOracle address
    /// @param _governance Governance address
    constructor(
        address _treasury,
        address _oracle,
        address _governance
    ) {
        require(_treasury != address(0), "BulkComputeGateway: zero treasury");
        require(_oracle != address(0), "BulkComputeGateway: zero oracle");
        require(_governance != address(0), "BulkComputeGateway: zero governance");

        treasury = StablecoinTreasury(_treasury);
        oracle = IComputePricingOracle(_oracle);
        governance = _governance;
    }

    // ============================================================
    // Core — Purchase Credits
    // ============================================================

    /// @notice Purchase compute credits with stablecoins
    /// @param stablecoin Address of the stablecoin to pay with
    /// @param amount Amount of stablecoin (in token's native decimals, assumed 6 for USD)
    /// @return creditsReceived PFLOP-hours purchased (18 decimals)
    /// @dev Caller must have approved this contract on the stablecoin for `amount`.
    ///      The stablecoins are forwarded to the StablecoinTreasury.
    function purchaseComputeCredits(
        address stablecoin,
        uint256 amount
    ) external nonReentrant returns (uint256 creditsReceived) {
        require(amount >= MIN_PURCHASE_USD, "BulkComputeGateway: below minimum");
        require(
            treasury.acceptedStablecoins(stablecoin),
            "BulkComputeGateway: stablecoin not accepted"
        );
        require(!oracle.isPriceStale(), "BulkComputeGateway: oracle price stale");

        // Transfer stablecoin from buyer to this contract first
        bool transferOk = _transferFrom(stablecoin, msg.sender, address(this), amount);
        require(transferOk, "BulkComputeGateway: transfer from buyer failed");

        // Approve treasury to pull from this contract
        _approve(stablecoin, address(treasury), amount);

        // Deposit into treasury
        treasury.deposit(stablecoin, amount);

        // Calculate credits from oracle pricing
        // amount is in USD (6 decimals for USDC)
        // computePriceUsdCents is USD cents per PFLOP-hour (e.g., 13 = $0.13)
        // credits = amount_in_cents * 1e18 / computePriceUsdCents
        // amount is in 6-decimal USD, so amount * 100 = cents (6+2=8 decimal cents)
        // But we need to be careful: amount = 1_000_000 means $1.00 = 100 cents
        // cents = amount / 10_000 (since amount is in 6 decimals, dividing by 10^4 gives cents)
        // Wait: $1.00 in 6 decimals = 1_000_000. In cents = 100. So 1_000_000 / 10_000 = 100. Correct.
        // credits (PFLOP-hours in 18 decimals) = (amount / 10_000) * 1e18 / computePriceUsdCents
        // = amount * 1e18 / (10_000 * computePriceUsdCents)
        // = amount * 1e14 / computePriceUsdCents
        uint256 computePrice = oracle.computePriceUsdCents();
        require(computePrice > 0, "BulkComputeGateway: zero compute price");

        creditsReceived = (amount * 1e14) / computePrice;
        require(creditsReceived > 0, "BulkComputeGateway: zero credits");

        computeCredits[msg.sender] += creditsReceived;
        totalCreditsPurchased += creditsReceived;

        // Record purchase
        uint256 purchaseIndex = purchases.length;
        purchases.push(Purchase({
            institution: msg.sender,
            stablecoin: stablecoin,
            usdAmount: amount,
            creditsReceived: creditsReceived,
            timestamp: block.timestamp,
            blockNumber: block.number
        }));
        institutionPurchases[msg.sender].push(purchaseIndex);

        // Record activity in treasury
        treasury.recordActivity(1, 0);

        emit CreditsPurchased(
            msg.sender,
            stablecoin,
            amount,
            creditsReceived,
            purchaseIndex
        );
    }

    // ============================================================
    // Core — Spend Credits
    // ============================================================

    /// @notice Spend compute credits for an institution
    /// @param institution Address of the institution whose credits to spend
    /// @param creditAmount PFLOP-hours to deduct (18 decimals)
    /// @return success Whether the spend was successful
    /// @dev Only callable by authorized spenders (ComputeMarketplace) or governance
    function spendCredits(
        address institution,
        uint256 creditAmount
    ) external onlyAuthorizedSpender returns (bool success) {
        require(creditAmount > 0, "BulkComputeGateway: zero credits");
        require(
            computeCredits[institution] >= creditAmount,
            "BulkComputeGateway: insufficient credits"
        );

        computeCredits[institution] -= creditAmount;
        totalCreditsSpent += creditAmount;

        emit CreditsSpent(institution, msg.sender, creditAmount);
        return true;
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get credit balance for an institution
    /// @param institution Address to check
    /// @return credits PFLOP-hours remaining (18 decimals)
    function getCreditBalance(address institution) external view returns (uint256 credits) {
        return computeCredits[institution];
    }

    /// @notice Estimate remaining inference calls for an institution
    /// @param institution Address to estimate for
    /// @param avgTokensPerCall Average tokens per inference call
    /// @return callsRemaining Approximate number of inference calls possible
    /// @dev Uses the TOKENS_TO_PFLOP_FACTOR from the oracle (1e12 tokens = 1 PFLOP-hour)
    function estimateCallsRemaining(
        address institution,
        uint256 avgTokensPerCall
    ) external view returns (uint256 callsRemaining) {
        if (avgTokensPerCall == 0) return 0;

        uint256 credits = computeCredits[institution];
        if (credits == 0) return 0;

        // Each call uses avgTokensPerCall tokens
        // 1e12 tokens = 1 PFLOP-hour (from oracle constant TOKENS_TO_PFLOP_FACTOR)
        // pflop_per_call = avgTokensPerCall / 1e12 (raw) = avgTokensPerCall * 1e18 / 1e12 (18 dec) = avgTokensPerCall * 1e6
        // callsRemaining = credits / pflop_per_call = credits / (avgTokensPerCall * 1e6)
        uint256 pflopPerCall = avgTokensPerCall * 1e6; // in 18-decimal PFLOP-hours
        if (pflopPerCall == 0) return type(uint256).max;

        callsRemaining = credits / pflopPerCall;
    }

    /// @notice Get the total number of purchases
    function purchaseCount() external view returns (uint256) {
        return purchases.length;
    }

    /// @notice Get purchase history for an institution
    /// @param institution Address to query
    /// @return result Array of Purchase structs
    function getPurchaseHistory(
        address institution
    ) external view returns (Purchase[] memory result) {
        uint256[] storage indices = institutionPurchases[institution];
        result = new Purchase[](indices.length);
        for (uint256 i = 0; i < indices.length; i++) {
            result[i] = purchases[indices[i]];
        }
    }

    /// @notice Get the number of purchases for an institution
    function institutionPurchaseCount(address institution) external view returns (uint256) {
        return institutionPurchases[institution].length;
    }

    /// @notice Get current credit price in USD per PFLOP-hour (6 decimals)
    /// @return priceUsd6 Price in 6-decimal USD
    function currentCreditPriceUsd() external view returns (uint256 priceUsd6) {
        // computePriceUsdCents = cents per PFLOP-hour (e.g., 13 = $0.13)
        // Convert to 6-decimal USD: cents * 10_000 = 6-decimal USD
        // 13 cents = 0.13 USD = 130_000 in 6 decimals
        return oracle.computePriceUsdCents() * 10_000;
    }

    // ============================================================
    // Admin Functions
    // ============================================================

    /// @notice Authorize a spender (e.g., ComputeMarketplace)
    function authorizeSpender(address spender) external onlyGovernance {
        require(spender != address(0), "BulkComputeGateway: zero address");
        authorizedSpenders[spender] = true;
        emit SpenderAuthorized(spender);
    }

    /// @notice Revoke a spender
    function revokeSpender(address spender) external onlyGovernance {
        authorizedSpenders[spender] = false;
        emit SpenderRevoked(spender);
    }

    /// @notice Update the oracle address
    function setOracle(address newOracle) external onlyGovernance {
        require(newOracle != address(0), "BulkComputeGateway: zero address");
        address old = address(oracle);
        oracle = IComputePricingOracle(newOracle);
        emit OracleUpdated(old, newOracle);
    }

    /// @notice Update the treasury address
    function setTreasury(address newTreasury) external onlyGovernance {
        require(newTreasury != address(0), "BulkComputeGateway: zero address");
        address old = address(treasury);
        treasury = StablecoinTreasury(newTreasury);
        emit TreasuryUpdated(old, newTreasury);
    }

    /// @notice Transfer governance
    function transferGovernance(address newGovernance) external onlyGovernance {
        require(newGovernance != address(0), "BulkComputeGateway: zero address");
        address old = governance;
        governance = newGovernance;
        emit GovernanceTransferred(old, newGovernance);
    }

    // ============================================================
    // Internal Helpers
    // ============================================================

    /// @dev Low-level ERC-20 transferFrom
    function _transferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal returns (bool) {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount)
        );
        return success && (data.length == 0 || abi.decode(data, (bool)));
    }

    /// @dev Low-level ERC-20 approve
    function _approve(
        address token,
        address spender,
        uint256 amount
    ) internal returns (bool) {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSignature("approve(address,uint256)", spender, amount)
        );
        return success && (data.length == 0 || abi.decode(data, (bool)));
    }
}
