// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";
import "./ContributionAccounting.sol";
import "./StablecoinTreasury.sol";

/// @title TestnetFarmingAccounting — Testnet-End Stablecoin Distribution
/// @notice At testnet conclusion, takes a one-time snapshot of all
///         ContributionAccounting scores and distributes treasury stablecoins
///         proportional to each participant's Shapley-weighted contribution.
///
/// @dev Lifecycle:
///   1. Governance calls takeSnapshot() with all participant addresses
///      (can be called in batches via takeSnapshotBatch())
///   2. Governance calls activateDistribution(stablecoin) to lock the pool
///   3. Participants call claim() to receive their share
///   4. Governance can call sweep() after distribution window closes
///
/// Invariants:
///   - Snapshot can only be taken once
///   - Distribution cannot start until snapshot is complete
///   - No re-snapshot after distribution starts
///   - Each participant claims exactly once
///   - Sum of all claims <= distributionPool
///
/// Sprint ECON-2 — WP-E2.2
contract TestnetFarmingAccounting is ReentrancyGuard, Governable {
    // ============================================================
    // State — Dependencies
    // ============================================================

    /// @notice ContributionAccounting contract (read scores from)
    ContributionAccounting public contributions;

    /// @notice StablecoinTreasury (source of distribution funds)
    StablecoinTreasury public treasury;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ============================================================
    // State — Snapshot
    // ============================================================

    /// @notice Whether the snapshot has been taken
    bool public snapshotTaken;

    /// @notice Block number when snapshot was taken
    uint256 public snapshotBlock;

    /// @notice Snapshot of each participant's weighted score
    mapping(address => uint256) public snapshotScores;

    /// @notice Ordered list of participants in the snapshot
    address[] public snapshotParticipants;

    /// @notice Whether an address is in the snapshot (dedup guard)
    mapping(address => bool) public isSnapshotted;

    /// @notice Sum of all snapshotted scores
    uint256 public totalSnapshotScore;

    // ============================================================
    // State — Distribution
    // ============================================================

    /// @notice Whether distribution is active
    bool public distributionActive;

    /// @notice Stablecoin used for distribution
    address public distributionStablecoin;

    /// @notice Total stablecoin pool available for distribution
    uint256 public distributionPool;

    /// @notice Whether a participant has already claimed
    mapping(address => bool) public hasClaimed;

    /// @notice Total stablecoin claimed so far
    uint256 public totalClaimed;

    /// @notice Amount claimed per participant (for transparency)
    mapping(address => uint256) public claimedAmount;

    // ============================================================
    // Events
    // ============================================================

    event SnapshotTaken(uint256 participantCount, uint256 totalScore, uint256 blockNumber);
    event SnapshotBatchAdded(uint256 batchSize, uint256 totalParticipants);
    event DistributionActivated(
        address indexed stablecoin,
        uint256 pool,
        uint256 participantCount
    );
    event Claimed(
        address indexed participant,
        uint256 amount,
        uint256 score,
        uint256 totalScore
    );
    event Swept(address indexed stablecoin, address indexed to, uint256 amount);
    // GovernanceTransferred event provided by Governable mixin.

    // ============================================================
    // Modifiers
    // ============================================================

    // `onlyGovernance` is inherited from Governable.

    // ============================================================
    // Constructor
    // ============================================================

    /// @notice Deploy the testnet farming accounting
    /// @param _contributions ContributionAccounting contract address
    /// @param _treasury StablecoinTreasury contract address
    /// @param _governance Governance address
    constructor(
        address _contributions,
        address _treasury,
        address _governance
    ) Governable(_governance) {
        require(_contributions != address(0), "TestnetFarming: zero contributions");
        require(_treasury != address(0), "TestnetFarming: zero treasury");

        contributions = ContributionAccounting(payable(_contributions));
        treasury = StablecoinTreasury(_treasury);
    }

    // ============================================================
    // Snapshot (governance only)
    // ============================================================

    /// @notice Take a one-time snapshot of contribution scores for all participants
    /// @param participants Array of participant addresses to snapshot
    /// @dev Can only be called once. For large sets, use takeSnapshotBatch() instead.
    function takeSnapshot(address[] calldata participants) external onlyGovernance {
        require(!snapshotTaken, "TestnetFarming: snapshot already taken");
        require(!distributionActive, "TestnetFarming: distribution already active");
        require(participants.length > 0, "TestnetFarming: empty participants");

        snapshotTaken = true;
        snapshotBlock = block.number;

        for (uint256 i = 0; i < participants.length; i++) {
            address p = participants[i];
            require(p != address(0), "TestnetFarming: zero address");
            require(!isSnapshotted[p], "TestnetFarming: duplicate participant");

            uint256 score = contributions.scores(p);
            if (score > 0) {
                snapshotScores[p] = score;
                snapshotParticipants.push(p);
                isSnapshotted[p] = true;
                totalSnapshotScore += score;
            }
        }

        require(totalSnapshotScore > 0, "TestnetFarming: no scores");

        emit SnapshotTaken(
            snapshotParticipants.length,
            totalSnapshotScore,
            block.number
        );
    }

    /// @notice Add a batch of participants to the snapshot (for large sets)
    /// @param participants Batch of participant addresses
    /// @dev First call must still go through takeSnapshot() to set snapshotTaken.
    ///      Subsequent batches use this function. NOT available after distribution.
    function takeSnapshotBatch(address[] calldata participants) external onlyGovernance {
        require(snapshotTaken, "TestnetFarming: initial snapshot not taken");
        require(!distributionActive, "TestnetFarming: distribution already active");
        require(participants.length > 0, "TestnetFarming: empty batch");

        for (uint256 i = 0; i < participants.length; i++) {
            address p = participants[i];
            require(p != address(0), "TestnetFarming: zero address");
            if (isSnapshotted[p]) continue; // skip duplicates silently in batch

            uint256 score = contributions.scores(p);
            if (score > 0) {
                snapshotScores[p] = score;
                snapshotParticipants.push(p);
                isSnapshotted[p] = true;
                totalSnapshotScore += score;
            }
        }

        emit SnapshotBatchAdded(participants.length, snapshotParticipants.length);
    }

    // ============================================================
    // Distribution Activation (governance only)
    // ============================================================

    /// @notice Activate distribution with a specific stablecoin
    /// @param stablecoin The stablecoin to distribute
    /// @param amount The total pool to distribute (must be transferred to this contract first)
    /// @dev Governance must transfer stablecoins to this contract before calling.
    ///      The contract checks its own balance of the stablecoin.
    function activateDistribution(address stablecoin, uint256 amount) external onlyGovernance {
        require(snapshotTaken, "TestnetFarming: no snapshot");
        require(!distributionActive, "TestnetFarming: already active");
        require(totalSnapshotScore > 0, "TestnetFarming: no scores");
        require(stablecoin != address(0), "TestnetFarming: zero stablecoin");
        require(amount > 0, "TestnetFarming: zero amount");

        // Verify the contract holds enough stablecoin
        uint256 balance = _balanceOf(stablecoin, address(this));
        require(balance >= amount, "TestnetFarming: insufficient balance");

        distributionActive = true;
        distributionStablecoin = stablecoin;
        distributionPool = amount;

        emit DistributionActivated(stablecoin, amount, snapshotParticipants.length);
    }

    // ============================================================
    // Claim
    // ============================================================

    /// @notice Claim your proportional share of the distribution pool
    /// @dev share = distributionPool * snapshotScore / totalSnapshotScore
    function claim() external nonReentrant {
        require(distributionActive, "TestnetFarming: distribution not active");
        require(!hasClaimed[msg.sender], "TestnetFarming: already claimed");
        require(isSnapshotted[msg.sender], "TestnetFarming: not in snapshot");

        uint256 score = snapshotScores[msg.sender];
        require(score > 0, "TestnetFarming: zero score");

        uint256 share = (distributionPool * score) / totalSnapshotScore;
        require(share > 0, "TestnetFarming: zero share");

        hasClaimed[msg.sender] = true;
        claimedAmount[msg.sender] = share;
        totalClaimed += share;

        bool success = _transfer(distributionStablecoin, msg.sender, share);
        require(success, "TestnetFarming: transfer failed");

        emit Claimed(msg.sender, share, score, totalSnapshotScore);
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Calculate a participant's share without claiming
    /// @param participant Address to calculate share for
    /// @return usdShare Amount of stablecoin they would receive
    function calculateShare(address participant) external view returns (uint256 usdShare) {
        if (!distributionActive || totalSnapshotScore == 0) return 0;

        uint256 score = snapshotScores[participant];
        if (score == 0) return 0;

        return (distributionPool * score) / totalSnapshotScore;
    }

    /// @notice Get top contributors by score (sorted descending)
    /// @param count Maximum number of contributors to return
    /// @return addrs Addresses of top contributors
    /// @return scoresList Scores of each top contributor
    /// @return shares USD share of each top contributor (0 if distribution not active)
    function getTopContributors(uint256 count) external view returns (
        address[] memory addrs,
        uint256[] memory scoresList,
        uint256[] memory shares
    ) {
        uint256 total = snapshotParticipants.length;
        if (count > total) count = total;

        // Copy into memory arrays for sorting
        address[] memory allAddrs = new address[](total);
        uint256[] memory allScores = new uint256[](total);
        for (uint256 i = 0; i < total; i++) {
            allAddrs[i] = snapshotParticipants[i];
            allScores[i] = snapshotScores[snapshotParticipants[i]];
        }

        // Simple selection sort for top `count` elements
        for (uint256 i = 0; i < count; i++) {
            uint256 maxIdx = i;
            for (uint256 j = i + 1; j < total; j++) {
                if (allScores[j] > allScores[maxIdx]) {
                    maxIdx = j;
                }
            }
            if (maxIdx != i) {
                // Swap
                (allAddrs[i], allAddrs[maxIdx]) = (allAddrs[maxIdx], allAddrs[i]);
                (allScores[i], allScores[maxIdx]) = (allScores[maxIdx], allScores[i]);
            }
        }

        // Build result arrays
        addrs = new address[](count);
        scoresList = new uint256[](count);
        shares = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            addrs[i] = allAddrs[i];
            scoresList[i] = allScores[i];
            if (distributionActive && totalSnapshotScore > 0) {
                shares[i] = (distributionPool * allScores[i]) / totalSnapshotScore;
            }
        }
    }

    /// @notice Get the number of snapshot participants
    function snapshotParticipantCount() external view returns (uint256) {
        return snapshotParticipants.length;
    }

    /// @notice Get snapshot participants paginated
    /// @param offset Start index
    /// @param limit Maximum items to return
    function getSnapshotPage(
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory addrs, uint256[] memory scoresList) {
        uint256 total = snapshotParticipants.length;
        if (offset >= total) {
            return (new address[](0), new uint256[](0));
        }

        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;

        addrs = new address[](count);
        scoresList = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            address p = snapshotParticipants[offset + i];
            addrs[i] = p;
            scoresList[i] = snapshotScores[p];
        }
    }

    /// @notice Remaining unclaimed distribution
    function remainingDistribution() external view returns (uint256) {
        if (!distributionActive) return 0;
        return distributionPool - totalClaimed;
    }

    // ============================================================
    // Governance
    // ============================================================

    /// @notice Sweep remaining stablecoins after distribution window
    /// @param to Destination address
    /// @dev Only callable by governance after distribution is active
    function sweep(address to) external onlyGovernance nonReentrant {
        require(distributionActive, "TestnetFarming: distribution not active");
        require(to != address(0), "TestnetFarming: zero address");

        uint256 remaining = _balanceOf(distributionStablecoin, address(this));
        require(remaining > 0, "TestnetFarming: nothing to sweep");

        bool success = _transfer(distributionStablecoin, to, remaining);
        require(success, "TestnetFarming: transfer failed");

        emit Swept(distributionStablecoin, to, remaining);
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ============================================================
    // Internal Helpers
    // ============================================================

    /// @dev Low-level ERC-20 transfer
    function _transfer(address token, address to, uint256 amount) internal returns (bool) {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        return success && (data.length == 0 || abi.decode(data, (bool)));
    }

    /// @dev Low-level ERC-20 balanceOf
    function _balanceOf(address token, address account) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", account)
        );
        if (!success || data.length < 32) return 0;
        return abi.decode(data, (uint256));
    }
}
