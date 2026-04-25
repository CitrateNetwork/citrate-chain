// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/Governable.sol";

/// @title ContributionAccounting — 7-Type Contribution Tracking
/// @notice Tracks contributions across 7 types with weighted scores.
///         Distributes rewards proportional to weighted contribution scores.
///
/// Paper VII's Shapley-value contribution categories:
///   Validation, ModelHosting, AdapterCreation, DataProvision,
///   AppDevelopment, BridgeInfra, Governance
///
/// Sprint FORMAL — WP-F.9
contract ContributionAccounting is Governable {
    // ── Types ───────────────────────────────────────────────────────

    /// 7 contribution types (Paper VII)
    enum ContributionType {
        Validation,      // Block proposal + BFT signatures
        ModelHosting,    // Inference requests served
        AdapterCreation, // LoRA adapters accepted by network
        DataProvision,   // Training data contributed (IPFS)
        AppDevelopment,  // Tools/UIs deployed
        BridgeInfra,     // Cross-chain relay operations
        Governance       // Votes cast + proposals
    }

    uint8 internal constant NUM_TYPES = 7;

    // ── State ───────────────────────────────────────────────────────

    /// Weights per type (basis points, 10000 = 1.0x)
    mapping(ContributionType => uint256) public weights;

    /// Per-contributor, per-type counts
    mapping(address => mapping(ContributionType => uint256)) public contributions;

    /// Cached weighted scores (recomputed on every record)
    mapping(address => uint256) public scores;

    /// Sum of all contributor scores
    uint256 public totalScore;

    /// Funds awaiting distribution (not yet allocated to an epoch)
    uint256 public rewardPool;

    /// Per-contributor claimable balance (allocated by distributeRewards)
    mapping(address => uint256) public claimable;

    /// Cumulative rewards already withdrawn per contributor
    mapping(address => uint256) public distributed;

    /// Global cumulative distributed rewards
    uint256 public totalDistributed;

    /// Epoch counter (incremented by distributeRewards)
    uint256 public currentEpoch;

    /// Number of blocks per epoch (informational)
    uint256 public constant EPOCH_LENGTH = 1000;

    /// Active contributor list (for bounded iteration in distributeRewards)
    address[] public contributorList;
    mapping(address => bool) public isContributor;

    // ── Access Control ──────────────────────────────────────────────

    // Governance state lives in Governable mixin (audit SOL-21).

    /// Protocol contracts authorised to call recordContribution
    mapping(address => bool) public isRecorder;

    // ── Events ──────────────────────────────────────────────────────

    event ContributionRecorded(
        address indexed contributor,
        ContributionType ctype,
        uint256 amount
    );

    event RewardsDistributed(
        uint256 epoch,
        uint256 totalRewards,
        uint256 recipients
    );

    event RewardClaimed(
        address indexed contributor,
        uint256 amount
    );

    event WeightUpdated(
        ContributionType ctype,
        uint256 oldWeight,
        uint256 newWeight
    );

    event RecorderAdded(address indexed recorder);

    event RecorderRemoved(address indexed recorder);

    // ── Constructor ─────────────────────────────────────────────────

    constructor() Governable(msg.sender) {
        // Default weights (basis points): 10000 = 1.0x multiplier
        weights[ContributionType.Validation]      = 10000;  // 1.0x
        weights[ContributionType.ModelHosting]     = 15000;  // 1.5x
        weights[ContributionType.AdapterCreation]  = 20000;  // 2.0x
        weights[ContributionType.DataProvision]    = 15000;  // 1.5x
        weights[ContributionType.AppDevelopment]   = 10000;  // 1.0x
        weights[ContributionType.BridgeInfra]      = 10000;  // 1.0x
        weights[ContributionType.Governance]       =  5000;  // 0.5x
    }

    // ── Core Functions ──────────────────────────────────────────────

    /// @notice Record a contribution (called by authorised protocol contracts or governance)
    /// @param contributor Address that performed the contribution
    /// @param ctype       One of the 7 contribution types
    /// @param amount      Raw contribution amount (e.g. 1 block proposal, N inferences)
    function recordContribution(
        address contributor,
        ContributionType ctype,
        uint256 amount
    ) external {
        require(isRecorder[msg.sender] || msg.sender == governance(), "Not authorized");
        require(amount > 0, "Zero amount");

        contributions[contributor][ctype] += amount;

        // Track contributor for distribution iteration
        if (!isContributor[contributor]) {
            isContributor[contributor] = true;
            contributorList.push(contributor);
        }

        // Recompute weighted score and update the global total
        uint256 oldScore = scores[contributor];
        uint256 newScore = _computeScore(contributor);
        scores[contributor] = newScore;
        totalScore = totalScore + newScore - oldScore;

        emit ContributionRecorded(contributor, ctype, amount);
    }

    /// @notice Fund the reward pool with native token (SALT)
    function fundRewards() external payable {
        require(msg.value > 0, "Zero funding");
        rewardPool += msg.value;
    }

    /// @notice Distribute the current reward pool proportionally to all contributors.
    ///         Each contributor's share is computed as (pool * score / totalScore) and
    ///         added to their claimable balance. This freezes fair shares at the point
    ///         of distribution, so claim order does not affect amounts.
    function distributeRewards() external onlyGovernance {
        require(rewardPool > 0, "Empty pool");
        require(totalScore > 0, "No contributions");

        uint256 pool = rewardPool;
        uint256 totalAllocated = 0;
        uint256 recipientCount = 0;
        currentEpoch++;

        // Allocate proportional shares to each contributor
        for (uint256 i = 0; i < contributorList.length; i++) {
            address c = contributorList[i];
            if (scores[c] > 0) {
                uint256 share = (pool * scores[c]) / totalScore;
                if (share > 0) {
                    claimable[c] += share;
                    totalAllocated += share;
                    recipientCount++;
                }
            }
        }

        // Deduct allocated amount from pool (dust stays in pool)
        rewardPool -= totalAllocated;

        emit RewardsDistributed(currentEpoch, totalAllocated, recipientCount);
    }

    /// @notice Claim all accumulated rewards for the caller
    function claimRewards() external {
        uint256 amount = claimable[msg.sender];
        require(amount > 0, "Nothing to claim");

        claimable[msg.sender] = 0;
        distributed[msg.sender] += amount;
        totalDistributed += amount;

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "Transfer failed");

        emit RewardClaimed(msg.sender, amount);
    }

    // ── View Functions ──────────────────────────────────────────────

    /// @notice Get a contributor's cached weighted score
    function getScore(address contributor) external view returns (uint256) {
        return scores[contributor];
    }

    /// @notice Get the raw contribution count for a specific type
    function getContribution(
        address contributor,
        ContributionType ctype
    ) external view returns (uint256) {
        return contributions[contributor][ctype];
    }

    /// @notice Compute the expected share if distributeRewards() were called now
    function pendingReward(address contributor) external view returns (uint256) {
        if (totalScore == 0 || rewardPool == 0) return 0;
        return (rewardPool * scores[contributor]) / totalScore;
    }

    /// @notice Number of tracked contributors
    function contributorCount() external view returns (uint256) {
        return contributorList.length;
    }

    /// @notice Get the total count of contributors (alias for snapshot iteration)
    function getContributorCount() external view returns (uint256) {
        return contributorList.length;
    }

    /// @notice Get a paginated page of contributors and their scores
    /// @param offset Starting index in the contributorList
    /// @param limit Maximum number of entries to return
    /// @return addrs Array of contributor addresses
    /// @return _scores Array of corresponding weighted scores
    function getContributorListPage(
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory addrs, uint256[] memory _scores) {
        uint256 total = contributorList.length;
        if (offset >= total) {
            return (new address[](0), new uint256[](0));
        }

        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;

        addrs = new address[](count);
        _scores = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            address c = contributorList[offset + i];
            addrs[i] = c;
            _scores[i] = scores[c];
        }
    }

    // ── Governance Functions ────────────────────────────────────────

    /// @notice Update the weight for a contribution type
    function updateWeight(ContributionType ctype, uint256 newWeight) external onlyGovernance {
        uint256 old = weights[ctype];
        weights[ctype] = newWeight;
        emit WeightUpdated(ctype, old, newWeight);
    }

    /// @notice Add a protocol contract that may call recordContribution
    function addRecorder(address recorder) external onlyGovernance {
        require(recorder != address(0), "Zero address");
        isRecorder[recorder] = true;
        emit RecorderAdded(recorder);
    }

    /// @notice Remove a previously authorised recorder
    function removeRecorder(address recorder) external onlyGovernance {
        isRecorder[recorder] = false;
        emit RecorderRemoved(recorder);
    }

    // ── Internal ────────────────────────────────────────────────────

    /// @dev Weighted score = SUM( contributions[type] * weights[type] / 10000 )
    function _computeScore(address contributor) internal view returns (uint256) {
        uint256 score = 0;
        for (uint8 i = 0; i < NUM_TYPES; i++) {
            ContributionType ctype = ContributionType(i);
            score += (contributions[contributor][ctype] * weights[ctype]) / 10000;
        }
        return score;
    }

    // ── Fallback ────────────────────────────────────────────────────

    /// @dev Accept direct ETH transfers into the reward pool
    receive() external payable {
        rewardPool += msg.value;
    }
}
