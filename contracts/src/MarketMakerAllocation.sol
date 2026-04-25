// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/Governable.sol";

/**
 * @title MarketMakerAllocation
 * @notice Receives 10% of gas pool fees as a cooperative incentive for the
 *         designated market maker. The market maker provides deep liquidity,
 *         handles CEX listings, and maintains healthy orderbooks.
 *
 * @dev Design:
 *   - Gas fees flow: 10% skimmed to this contract BEFORE the 7-way revenue split
 *   - The remaining 90% enters the normal revenue distribution (validators, stakers, treasury, etc.)
 *   - Market maker address is changeable via DAO governance vote
 *   - Accumulated SALT can be withdrawn by the current market maker
 *   - All parameter changes require governance approval
 *
 * Economic rationale:
 *   - Consolidates CEX listing fees + liquidity provision into one strategic partner
 *   - 10% of gas fees aligns market maker incentives with network usage
 *   - Higher network usage = more gas fees = more market maker revenue = deeper liquidity
 *   - DAO can replace market maker if service quality drops
 */
contract MarketMakerAllocation is Governable {
    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /// @notice Current market maker address (receives gas fee allocation)
    address public marketMaker;

    // Governance state lives in Governable mixin (audit SOL-21).

    /// @notice Allocation rate in basis points (default: 1000 = 10%)
    uint256 public allocationBps;

    /// @notice Maximum allocation rate (cap at 15% to protect network economics)
    uint256 public constant MAX_ALLOCATION_BPS = 1500;

    /// @notice Minimum allocation rate (floor at 1% to maintain relationship)
    uint256 public constant MIN_ALLOCATION_BPS = 100;

    /// @notice Total SALT allocated to market maker historically
    uint256 public totalAllocated;

    /// @notice Total SALT withdrawn by market maker
    uint256 public totalWithdrawn;

    /// @notice Block number of last allocation rate change
    uint256 public lastRateChangeBlock;

    /// @notice Minimum blocks between rate changes (7 days at 2s blocks)
    uint256 public constant RATE_CHANGE_COOLDOWN = 302_400;

    /// @notice Market maker change history for transparency
    struct MarketMakerChange {
        address previousMaker;
        address newMaker;
        uint256 blockNumber;
        string reason;
    }
    MarketMakerChange[] public changeHistory;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event AllocationReceived(uint256 amount, uint256 blockNumber);
    event Withdrawn(address indexed marketMaker, uint256 amount);
    event MarketMakerChanged(
        address indexed previousMaker,
        address indexed newMaker,
        string reason
    );
    event AllocationRateChanged(uint256 previousBps, uint256 newBps);
    // GovernanceTransferred event provided by Governable mixin.

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    // `onlyGovernance` is inherited from Governable.

    modifier onlyMarketMaker() {
        require(msg.sender == marketMaker, "Only market maker");
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address _marketMaker, address _governance) Governable(_governance) {
        require(_marketMaker != address(0), "Zero market maker address");
        marketMaker = _marketMaker;
        allocationBps = 1000; // 10% default
        lastRateChangeBlock = block.number;
    }

    // -----------------------------------------------------------------------
    // Receive — accepts SALT (native token) allocations
    // -----------------------------------------------------------------------

    /// @notice Receives gas fee allocation. Called by the block producer or
    ///         revenue distribution contract before the 7-way split.
    receive() external payable {
        totalAllocated += msg.value;
        emit AllocationReceived(msg.value, block.number);
    }

    // -----------------------------------------------------------------------
    // Market Maker Functions
    // -----------------------------------------------------------------------

    /// @notice Market maker withdraws accumulated SALT
    function withdraw(uint256 amount) external onlyMarketMaker {
        uint256 balance = address(this).balance;
        require(amount <= balance, "Insufficient balance");
        totalWithdrawn += amount;
        (bool ok, ) = marketMaker.call{value: amount}("");
        require(ok, "Transfer failed");
        emit Withdrawn(marketMaker, amount);
    }

    /// @notice Market maker withdraws all accumulated SALT
    function withdrawAll() external onlyMarketMaker {
        uint256 balance = address(this).balance;
        require(balance > 0, "Nothing to withdraw");
        totalWithdrawn += balance;
        (bool ok, ) = marketMaker.call{value: balance}("");
        require(ok, "Transfer failed");
        emit Withdrawn(marketMaker, balance);
    }

    // -----------------------------------------------------------------------
    // Governance Functions
    // -----------------------------------------------------------------------

    /// @notice Change the market maker address (DAO governance vote required)
    /// @param newMaker New market maker address
    /// @param reason Human-readable reason for the change
    function changeMarketMaker(
        address newMaker,
        string calldata reason
    ) external onlyGovernance {
        require(newMaker != address(0), "Zero address");
        require(newMaker != marketMaker, "Same address");

        changeHistory.push(MarketMakerChange({
            previousMaker: marketMaker,
            newMaker: newMaker,
            blockNumber: block.number,
            reason: reason
        }));

        emit MarketMakerChanged(marketMaker, newMaker, reason);
        marketMaker = newMaker;
    }

    /// @notice Change the allocation rate (basis points)
    /// @param newBps New rate in basis points (100-1500)
    function changeAllocationRate(uint256 newBps) external onlyGovernance {
        require(newBps >= MIN_ALLOCATION_BPS, "Below minimum (1%)");
        require(newBps <= MAX_ALLOCATION_BPS, "Above maximum (15%)");
        require(
            block.number >= lastRateChangeBlock + RATE_CHANGE_COOLDOWN,
            "Rate change cooldown active"
        );

        emit AllocationRateChanged(allocationBps, newBps);
        allocationBps = newBps;
        lastRateChangeBlock = block.number;
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    /// @notice Calculate the market maker's share of a given gas fee amount
    /// @param gasFees Total gas fees collected in a block/epoch
    /// @return makerShare Amount allocated to market maker
    /// @return remainder Amount remaining for the 7-way revenue split
    function calculateAllocation(uint256 gasFees) external view returns (
        uint256 makerShare,
        uint256 remainder
    ) {
        makerShare = (gasFees * allocationBps) / 10000;
        remainder = gasFees - makerShare;
    }

    /// @notice Current SALT balance available for withdrawal
    function availableBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Number of market maker changes in history
    function changeHistoryCount() external view returns (uint256) {
        return changeHistory.length;
    }
}
