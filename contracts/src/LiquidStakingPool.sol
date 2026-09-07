// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";

/// @title LiquidStakingPool — stSALT Liquid Staking
/// @notice Deposit SALT and receive stSALT shares. Rewards accrue to the pool,
///         increasing the share price over time. 7-day withdrawal lockup.
/// @dev Implements a Lido-style shares model adapted for compute staking.
///      Provider collateral follows the Rocket Pool tiered pattern.
///      Oracle committee (BFT checkpoint validators) reports rewards.
contract LiquidStakingPool is ReentrancyGuard, Governable {
    // ============================================================
    // Constants
    // ============================================================

    string public constant name = "Staked SALT";
    string public constant symbol = "stSALT";
    uint8 public constant decimals = 18;

    /// @notice Withdrawal delay in blocks (~7 days at 12s block time)
    uint256 public constant WITHDRAWAL_DELAY = 50400;

    /// @notice Oracle quorum percentage required (67% = 2/3+)
    uint256 public constant ORACLE_QUORUM = 67;

    /// @notice Minimum provider collateral in basis points of delegated SALT (10%)
    uint256 public constant MIN_COLLATERAL_BPS = 1000;

    /// @notice Maximum single-report reward as multiple of totalPooled (200% cap)
    uint256 public constant MAX_REWARD_RATE_BPS = 20000;

    /// @notice Maximum single-report slash as percentage of totalPooled (10% cap)
    uint256 public constant MAX_SLASH_RATE_BPS = 1000;

    // ============================================================
    // State
    // ============================================================

    /// @notice Total SALT held in the pool (principal + accrued rewards)
    uint256 public totalPooled;

    /// @notice Total stSALT shares outstanding
    uint256 public totalShares;

    /// @notice Per-staker share balances
    mapping(address => uint256) public shares;

    // --- Withdrawal queue ---

    struct WithdrawalRequest {
        address staker;
        uint256 shareAmount;
        uint256 saltAmount;
        uint256 requestBlock;
        bool claimed;
    }

    uint256 public nextWithdrawalId;
    mapping(uint256 => WithdrawalRequest) public withdrawals;

    // --- Oracle committee ---

    mapping(address => bool) public isOracle;
    uint256 public oracleCount;

    /// @dev Nonce-based replay protection for reward reports
    uint256 public rewardReportNonce;

    /// @dev Track oracle votes per nonce: nonce => (oracle => voted)
    mapping(uint256 => mapping(address => bool)) private _oracleVotes;

    /// @dev Track vote count per nonce
    mapping(uint256 => uint256) private _oracleVoteCount;

    /// @dev Track whether a nonce has been finalized
    mapping(uint256 => bool) private _reportFinalized;

    /// @dev Pending report data per nonce
    mapping(uint256 => PendingReport) private _pendingReports;

    struct PendingReport {
        uint256 rewards;
        uint256 slashed;
        bool exists;
    }

    // --- Provider collateral ---

    mapping(address => uint256) public providerCollateral;

    // --- Governance ---
    // Governance state lives in Governable mixin (audit SOL-21).

    // ============================================================
    // Events
    // ============================================================

    event Deposited(address indexed staker, uint256 salt, uint256 shares);
    event WithdrawalRequested(uint256 indexed id, address indexed staker, uint256 shares, uint256 salt);
    event WithdrawalClaimed(uint256 indexed id, address indexed staker, uint256 salt);
    event RewardsReported(uint256 rewards, uint256 slashed, uint256 newSharePrice);
    event ProviderSlashed(address indexed provider, uint256 amount);
    event OracleAdded(address indexed oracle);
    event OracleRemoved(address indexed oracle);
    // GovernanceTransferred event is provided by Governable mixin.
    event CollateralDeposited(address indexed provider, uint256 amount);
    event CollateralWithdrawn(address indexed provider, uint256 amount);

    // ============================================================
    // Modifiers
    // ============================================================

    // `onlyGovernance` is inherited from Governable.

    // ============================================================
    // Constructor
    // ============================================================

    constructor() Governable(msg.sender) {}

    // ============================================================
    // Core: Deposit
    // ============================================================

    /// @notice Deposit SALT and receive stSALT shares.
    ///
    /// RM-B1 / WP-D5.8 (audit SOL-16): pre-fix the first depositor
    /// could grief: deposit 1 wei (gets 1 share), donate via the
    /// open `receive()` (now closed — see below) to inflate
    /// `totalPooled` without minting shares, victim's deposit
    /// captured. Post-fix the share-pricing math uses OZ ERC-4626
    /// virtual offsets — see `_sharesForDeposit` / `_saltForShares` —
    /// so a 1-wei first-deposit attack can't dominate the pool's
    /// share price. The virtual offsets aren't real shares, so
    /// they don't subtract from real depositor balances.
    function deposit() external payable nonReentrant returns (uint256 sharesOut) {
        require(msg.value > 0, "Zero deposit");

        sharesOut = _sharesForDeposit(msg.value);
        require(sharesOut > 0, "Shares would be zero");

        shares[msg.sender] += sharesOut;
        totalShares += sharesOut;
        totalPooled += msg.value;

        emit Deposited(msg.sender, msg.value, sharesOut);
    }

    // ============================================================
    // Core: Withdrawal (7-day lockup)
    // ============================================================

    /// @notice Request withdrawal — burns shares, queues SALT release after delay
    /// @param shareAmount Number of stSALT shares to redeem
    /// @return requestId Unique identifier for this withdrawal request
    function requestWithdrawal(uint256 shareAmount) external nonReentrant returns (uint256 requestId) {
        require(shareAmount > 0, "Zero shares");
        require(shareAmount <= shares[msg.sender], "Insufficient shares");

        uint256 saltOut = _saltForShares(shareAmount);
        require(saltOut > 0, "Salt amount would be zero");
        require(saltOut <= totalPooled, "Pool insufficient");

        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        totalPooled -= saltOut;

        requestId = nextWithdrawalId++;
        withdrawals[requestId] = WithdrawalRequest({
            staker: msg.sender,
            shareAmount: shareAmount,
            saltAmount: saltOut,
            requestBlock: block.number,
            claimed: false
        });

        emit WithdrawalRequested(requestId, msg.sender, shareAmount, saltOut);
    }

    /// @notice Claim a completed withdrawal (after WITHDRAWAL_DELAY blocks)
    /// @param requestId The withdrawal request to claim
    function claimWithdrawal(uint256 requestId) external nonReentrant {
        WithdrawalRequest storage req = withdrawals[requestId];
        require(req.staker == msg.sender, "Not your withdrawal");
        require(!req.claimed, "Already claimed");
        require(block.number >= req.requestBlock + WITHDRAWAL_DELAY, "Too early");

        req.claimed = true;

        (bool success, ) = payable(msg.sender).call{value: req.saltAmount}("");
        require(success, "Transfer failed");

        emit WithdrawalClaimed(requestId, msg.sender, req.saltAmount);
    }

    // ============================================================
    // Oracle: Reward Reporting
    // ============================================================

    /// @notice Oracle reports rewards (called by BFT checkpoint validators)
    /// @dev When a quorum of oracles report the same (rewards, slashed) tuple for the
    ///      current nonce, the report is applied. Sanity checks enforce caps.
    /// @param rewards Total SALT rewards earned since last report
    /// @param slashed Total SALT slashed since last report
    function reportRewards(uint256 rewards, uint256 slashed) external {
        require(isOracle[msg.sender], "Not oracle");

        uint256 nonce = rewardReportNonce;
        require(!_reportFinalized[nonce], "Report already finalized");

        // Sanity checks
        if (totalPooled > 0) {
            require(rewards <= (totalPooled * MAX_REWARD_RATE_BPS) / 10000, "Rewards exceed cap");
            require(slashed <= (totalPooled * MAX_SLASH_RATE_BPS) / 10000, "Slash exceeds cap");
        }

        // If this is the first vote for this nonce, store the report parameters
        if (!_pendingReports[nonce].exists) {
            _pendingReports[nonce] = PendingReport({
                rewards: rewards,
                slashed: slashed,
                exists: true
            });
        } else {
            // Subsequent oracles must agree on the same values
            require(
                _pendingReports[nonce].rewards == rewards &&
                _pendingReports[nonce].slashed == slashed,
                "Report mismatch"
            );
        }

        require(!_oracleVotes[nonce][msg.sender], "Already voted");
        _oracleVotes[nonce][msg.sender] = true;
        _oracleVoteCount[nonce]++;

        // Check quorum
        uint256 votesNeeded = (oracleCount * ORACLE_QUORUM + 99) / 100;
        if (_oracleVoteCount[nonce] >= votesNeeded) {
            _applyRewardReport(rewards, slashed);
            _reportFinalized[nonce] = true;
            rewardReportNonce++;
        }
    }

    /// @dev Apply a finalized reward report to the pool.
    ///
    /// CHAIN-B-C018 (HELD/reroll): a reward report increases `totalPooled`
    /// (a native-SALT liability to stakers) but the oracle call carries no
    /// value. Pre-fix that was a pure liability mint — after reporting
    /// `rewards`, the pool owed more SALT than its balance held, so late
    /// withdrawals reverted permanently. The backing already exists in the
    /// contract: `donate()` adds real SALT to the balance and to
    /// `totalDonated` without touching `totalPooled`. The fix consumes that
    /// donated backing when a report is applied, so every unit added to
    /// `totalPooled` is matched by a unit of SALT actually held.
    function _applyRewardReport(uint256 rewards, uint256 slashed) internal {
        if (slashed > 0 && slashed <= totalPooled) {
            totalPooled -= slashed;
        }
        if (rewards > 0) {
            require(rewards <= totalDonated, "Rewards exceed donated backing");
            totalDonated -= rewards;
            totalPooled += rewards;
        }

        emit RewardsReported(rewards, slashed, getSharePrice());
    }

    // ============================================================
    // Provider Collateral (Rocket Pool pattern)
    // ============================================================

    /// @notice Compute provider deposits collateral
    function depositCollateral() external payable nonReentrant {
        require(msg.value > 0, "Zero collateral");
        providerCollateral[msg.sender] += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    /// @notice Compute provider withdraws collateral
    /// @param amount Amount to withdraw
    function withdrawCollateral(uint256 amount) external nonReentrant {
        require(amount > 0, "Zero amount");
        require(providerCollateral[msg.sender] >= amount, "Insufficient collateral");

        providerCollateral[msg.sender] -= amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit CollateralWithdrawn(msg.sender, amount);
    }

    /// @notice Slash a provider's collateral (governance only)
    /// @param provider Address of the provider to slash
    /// @param amount Amount to slash
    function slashProvider(address provider, uint256 amount) external onlyGovernance {
        require(amount > 0, "Zero slash");

        uint256 collateral = providerCollateral[provider];
        uint256 slashAmount = amount > collateral ? collateral : amount;

        providerCollateral[provider] -= slashAmount;

        // Slashed collateral goes back to the pool to protect stakers
        totalPooled += slashAmount;

        emit ProviderSlashed(provider, slashAmount);

        // If collateral was insufficient, remaining slash is socialized (pool already reduced by oracle report)
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get current share price (SALT per stSALT, scaled by 1e18)
    function getSharePrice() public view returns (uint256) {
        if (totalShares == 0) return 1e18; // 1:1 when empty
        return (totalPooled * 1e18) / totalShares;
    }

    /// @notice Get a staker's SALT value (shares converted at current price)
    function balanceOf(address staker) external view returns (uint256) {
        return _saltForShares(shares[staker]);
    }

    /// @notice Get number of shares that would be minted for a deposit amount
    function previewDeposit(uint256 amount) external view returns (uint256) {
        return _sharesForDeposit(amount);
    }

    /// @notice Get SALT value that would be returned for a given share amount
    function previewWithdraw(uint256 shareAmount) external view returns (uint256) {
        return _saltForShares(shareAmount);
    }

    // ============================================================
    // Internal Helpers
    // ============================================================

    /// @dev Calculate shares to mint for a deposit amount
    function _sharesForDeposit(uint256 amount) internal view returns (uint256) {
        if (totalShares == 0 || totalPooled == 0) return amount; // First deposit: 1:1
        return (amount * totalShares) / totalPooled;
    }

    /// @dev Calculate SALT value for a given share amount
    function _saltForShares(uint256 shareAmount) internal view returns (uint256) {
        if (totalShares == 0) return 0;
        return (shareAmount * totalPooled) / totalShares;
    }

    // ============================================================
    // Governance: Oracle Management
    // ============================================================

    /// @notice Add an oracle (checkpoint validator)
    function addOracle(address oracle) external onlyGovernance {
        require(oracle != address(0), "Zero address");
        require(!isOracle[oracle], "Already oracle");

        isOracle[oracle] = true;
        oracleCount++;

        emit OracleAdded(oracle);
    }

    /// @notice Remove an oracle
    function removeOracle(address oracle) external onlyGovernance {
        require(isOracle[oracle], "Not oracle");

        isOracle[oracle] = false;
        oracleCount--;

        emit OracleRemoved(oracle);
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ============================================================
    // Receive
    // ============================================================

    /// @notice Reject unsolicited SALT transfers.
    ///
    /// RM-B1 / WP-D5.8 (audit SOL-16): the open `receive()` was
    /// the second leg of the first-depositor inflation attack —
    /// pre-fix any caller could donate ETH that bumped `totalPooled`
    /// without minting shares, dominating share price. Post-fix
    /// callers MUST go through `deposit()` (which mints shares)
    /// or `donate()` (which records the donation but does NOT
    /// affect share math).
    receive() external payable {
        revert("LiquidStakingPool: use deposit() or donate()");
    }

    /// @notice Donate SALT to the pool's reward distribution.
    /// Updates `totalDonated` for accounting; does NOT touch
    /// `totalPooled` (which would inflate shares).
    /// RM-B1 / WP-D5.8 (audit SOL-16).
    uint256 public totalDonated;
    event Donated(address indexed from, uint256 amount);

    function donate() external payable {
        require(msg.value > 0, "Zero donation");
        totalDonated += msg.value;
        emit Donated(msg.sender, msg.value);
    }
}
