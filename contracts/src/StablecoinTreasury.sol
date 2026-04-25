// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";

/// @title StablecoinTreasury — Stablecoin Accumulation & Distribution
/// @notice Accumulates stablecoins from institutional compute purchases.
///         At testnet end, governance distributes proportional shares to
///         participants based on their Shapley-weighted contribution scores.
///
/// @dev Treasury design:
///   - Accepts deposits of approved stablecoins (USDC, USDT, DAI, etc.)
///   - Tracks per-epoch revenue (epoch = 1000 blocks)
///   - Governance-controlled distribution to arrays of recipients
///   - Emergency withdrawal to governance multisig
///   - No SALT involved; stablecoins only (ERC-20 transferFrom)
///
/// Sprint ECON-2 — WP-E2.1
contract StablecoinTreasury is ReentrancyGuard, Governable {
    // ============================================================
    // Constants
    // ============================================================

    /// @notice Blocks per epoch (matches ContributionAccounting.EPOCH_LENGTH)
    uint256 public constant EPOCH_LENGTH = 1000;

    /// @notice Maximum number of accepted stablecoins (gas safety)
    uint256 public constant MAX_STABLECOINS = 20;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ============================================================
    // State — Accepted Stablecoins
    // ============================================================

    /// @notice Whether a token is accepted as a stablecoin deposit
    mapping(address => bool) public acceptedStablecoins;

    /// @notice List of all accepted stablecoin addresses (for enumeration)
    address[] public stablecoinList;

    /// @notice Per-stablecoin balance held in this treasury
    mapping(address => uint256) public stablecoinBalances;

    /// @notice Total value in USD terms (6 decimals, USDC standard)
    ///         Assumes all accepted stablecoins are 1:1 USD pegged
    uint256 public totalValueUsd;

    // ============================================================
    // State — Epoch Revenue Tracking
    // ============================================================

    struct EpochRevenue {
        uint256 totalUsd;
        uint256 computeJobsCount;
        uint256 inferenceCalls;
        uint256 startBlock;
        uint256 endBlock;
    }

    mapping(uint256 => EpochRevenue) public epochRevenue;
    uint256 public currentEpoch;

    /// @notice Block number when the first deposit was made (epoch anchor)
    uint256 public genesisBlock;

    // ============================================================
    // State — Distribution Tracking
    // ============================================================

    /// @notice Total USD distributed across all distributions
    uint256 public totalDistributed;

    // ============================================================
    // Events
    // ============================================================

    event StablecoinAdded(address indexed token);
    event StablecoinRemoved(address indexed token);
    event Deposited(
        address indexed depositor,
        address indexed stablecoin,
        uint256 amount,
        uint256 epoch
    );
    event Distributed(
        address indexed stablecoin,
        uint256 totalAmount,
        uint256 recipientCount
    );
    event EmergencyWithdrawal(
        address indexed stablecoin,
        address indexed to,
        uint256 amount
    );
    // GovernanceTransferred event provided by Governable mixin.
    event EpochAdvanced(uint256 indexed epoch, uint256 startBlock, uint256 endBlock);

    // ============================================================
    // Modifiers
    // ============================================================

    // `onlyGovernance` is inherited from Governable.

    // ============================================================
    // Constructor
    // ============================================================

    /// @notice Deploy the treasury
    /// @param _governance Governance multisig or deployer address
    constructor(address _governance) Governable(_governance) {
        genesisBlock = block.number;
        // Initialize epoch 0
        epochRevenue[0] = EpochRevenue({
            totalUsd: 0,
            computeJobsCount: 0,
            inferenceCalls: 0,
            startBlock: block.number,
            endBlock: block.number + EPOCH_LENGTH - 1
        });
    }

    // ============================================================
    // Stablecoin Management (governance only)
    // ============================================================

    /// @notice Add a stablecoin to the accepted list
    /// @param token ERC-20 stablecoin address
    function addStablecoin(address token) external onlyGovernance {
        require(token != address(0), "StablecoinTreasury: zero address");
        require(!acceptedStablecoins[token], "StablecoinTreasury: already accepted");
        require(stablecoinList.length < MAX_STABLECOINS, "StablecoinTreasury: max stablecoins");

        acceptedStablecoins[token] = true;
        stablecoinList.push(token);

        emit StablecoinAdded(token);
    }

    /// @notice Remove a stablecoin from the accepted list
    /// @param token ERC-20 stablecoin address to remove
    function removeStablecoin(address token) external onlyGovernance {
        require(acceptedStablecoins[token], "StablecoinTreasury: not accepted");

        acceptedStablecoins[token] = false;

        // Remove from list (swap-and-pop)
        for (uint256 i = 0; i < stablecoinList.length; i++) {
            if (stablecoinList[i] == token) {
                stablecoinList[i] = stablecoinList[stablecoinList.length - 1];
                stablecoinList.pop();
                break;
            }
        }

        emit StablecoinRemoved(token);
    }

    // ============================================================
    // Deposit
    // ============================================================

    /// @notice Deposit stablecoins into the treasury
    /// @param stablecoin Address of the ERC-20 stablecoin
    /// @param amount Amount to deposit (in token's native decimals)
    /// @dev Caller must have approved this contract for `amount` on the stablecoin.
    ///      All accepted stablecoins are assumed to be 1:1 USD-pegged.
    function deposit(address stablecoin, uint256 amount) external nonReentrant {
        require(acceptedStablecoins[stablecoin], "StablecoinTreasury: token not accepted");
        require(amount > 0, "StablecoinTreasury: zero amount");

        // Transfer stablecoin from depositor to this contract
        bool success = _transferFrom(stablecoin, msg.sender, address(this), amount);
        require(success, "StablecoinTreasury: transfer failed");

        stablecoinBalances[stablecoin] += amount;
        totalValueUsd += amount;

        // Advance epoch if needed and record revenue
        _advanceEpochIfNeeded();
        epochRevenue[currentEpoch].totalUsd += amount;

        emit Deposited(msg.sender, stablecoin, amount, currentEpoch);
    }

    /// @notice Record compute job and inference metadata for current epoch
    /// @param jobCount Number of compute jobs completed
    /// @param inferenceCount Number of inference calls completed
    /// @dev Called by authorized protocol contracts (BulkComputeGateway)
    function recordActivity(uint256 jobCount, uint256 inferenceCount) external {
        _advanceEpochIfNeeded();
        epochRevenue[currentEpoch].computeJobsCount += jobCount;
        epochRevenue[currentEpoch].inferenceCalls += inferenceCount;
    }

    // ============================================================
    // Distribution (governance only)
    // ============================================================

    /// @notice Distribute stablecoin to an array of recipients
    /// @param stablecoin Address of the stablecoin to distribute
    /// @param recipients Array of recipient addresses
    /// @param amounts Array of amounts (must match recipients length)
    function distribute(
        address stablecoin,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external onlyGovernance nonReentrant {
        require(recipients.length > 0, "StablecoinTreasury: empty recipients");
        require(recipients.length == amounts.length, "StablecoinTreasury: length mismatch");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            require(recipients[i] != address(0), "StablecoinTreasury: zero recipient");
            require(amounts[i] > 0, "StablecoinTreasury: zero amount in batch");
            totalAmount += amounts[i];
        }

        require(
            stablecoinBalances[stablecoin] >= totalAmount,
            "StablecoinTreasury: insufficient balance"
        );

        stablecoinBalances[stablecoin] -= totalAmount;
        totalValueUsd -= totalAmount;
        totalDistributed += totalAmount;

        for (uint256 i = 0; i < recipients.length; i++) {
            bool success = _transfer(stablecoin, recipients[i], amounts[i]);
            require(success, "StablecoinTreasury: transfer failed");
        }

        emit Distributed(stablecoin, totalAmount, recipients.length);
    }

    // ============================================================
    // Emergency (governance only)
    // ============================================================

    /// @notice Emergency withdraw all of a stablecoin to a governance-controlled address
    /// @param stablecoin The stablecoin to withdraw
    /// @param to Destination address
    function emergencyWithdraw(address stablecoin, address to) external onlyGovernance nonReentrant {
        require(to != address(0), "StablecoinTreasury: zero address");
        uint256 balance = stablecoinBalances[stablecoin];
        require(balance > 0, "StablecoinTreasury: no balance");

        stablecoinBalances[stablecoin] = 0;
        totalValueUsd -= balance;

        bool success = _transfer(stablecoin, to, balance);
        require(success, "StablecoinTreasury: transfer failed");

        emit EmergencyWithdrawal(stablecoin, to, balance);
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Total value locked across all stablecoins
    /// @return tvl Total in USD terms (6 decimals)
    function totalValueLocked() external view returns (uint256 tvl) {
        return totalValueUsd;
    }

    /// @notice Get the number of accepted stablecoins
    function stablecoinCount() external view returns (uint256) {
        return stablecoinList.length;
    }

    /// @notice Get all accepted stablecoin addresses
    function getAcceptedStablecoins() external view returns (address[] memory) {
        return stablecoinList;
    }

    /// @notice Get epoch revenue data
    /// @param epoch Epoch number
    function getEpochRevenue(uint256 epoch) external view returns (EpochRevenue memory) {
        return epochRevenue[epoch];
    }

    /// @notice Get the current epoch number based on block
    function getCurrentEpoch() external view returns (uint256) {
        return _computeEpoch();
    }

    // ============================================================
    // Governance
    // ============================================================

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ============================================================
    // Internal Helpers
    // ============================================================

    /// @dev Advance epoch if the current block has passed the epoch boundary
    function _advanceEpochIfNeeded() internal {
        uint256 computedEpoch = _computeEpoch();
        if (computedEpoch > currentEpoch) {
            currentEpoch = computedEpoch;
            uint256 startBlock = genesisBlock + (computedEpoch * EPOCH_LENGTH);
            epochRevenue[currentEpoch] = EpochRevenue({
                totalUsd: 0,
                computeJobsCount: 0,
                inferenceCalls: 0,
                startBlock: startBlock,
                endBlock: startBlock + EPOCH_LENGTH - 1
            });
            emit EpochAdvanced(currentEpoch, startBlock, startBlock + EPOCH_LENGTH - 1);
        }
    }

    /// @dev Calculate current epoch from block number
    function _computeEpoch() internal view returns (uint256) {
        if (block.number < genesisBlock) return 0;
        return (block.number - genesisBlock) / EPOCH_LENGTH;
    }

    /// @dev Low-level ERC-20 transferFrom call
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

    /// @dev Low-level ERC-20 transfer call
    function _transfer(
        address token,
        address to,
        uint256 amount
    ) internal returns (bool) {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        return success && (data.length == 0 || abi.decode(data, (bool)));
    }
}
