// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./lib/ReentrancyGuard.sol";

/// @title NematocystSlashing — Graduated 3-Tier Slashing with Correlation Multiplier
/// @notice Implements the nematocyst slashing model from the Citrate economics design:
///         Tier 1 (Spirocyst/Latency) = 5% stake, Tier 2 (Mastigophore/Inconsistency) = 20%,
///         Tier 3 (Penetrant/Byzantine) = 100% + permanent ban.
///         The Ethereum-research correlation multiplier scales penalties when multiple
///         providers are slashed in the same window.
/// @dev WP-F.10
contract NematocystSlashing is ReentrancyGuard {
    // ── Types ───────────────────────────────────────────────────────

    enum SlashTier { Latency, Inconsistency, Byzantine }

    // ── Constants ────────────────────────────────────────────────────

    /// @notice Tier 1 (Spirocyst) — missed checkpoints. 5% of stake.
    uint256 public constant LATENCY_PENALTY_BPS = 500;

    /// @notice Tier 2 (Mastigophore) — Belnap `Both` fraction too high. 20% of stake.
    uint256 public constant INCONSISTENCY_PENALTY_BPS = 2000;

    /// @notice Tier 3 (Penetrant) — equivocation / double-signing. 100% of stake.
    uint256 public constant BYZANTINE_PENALTY_BPS = 10000;

    /// @notice Correlation window in blocks for the correlation multiplier calculation.
    uint256 public constant CORRELATION_WINDOW = 50;

    /// @notice Minimum stake required to register as a provider (100 SALT).
    uint256 public constant MIN_STAKE = 100 ether;

    /// @notice Basis points denominator.
    uint256 private constant BPS = 10000;

    /// @notice Maximum correlation multiplier (3x, stored as 3e18 for 18-decimal precision).
    uint256 private constant MAX_CORRELATION_MUL = 3e18;

    /// @notice 1x multiplier in 18-decimal precision.
    uint256 private constant ONE = 1e18;

    // ── State ────────────────────────────────────────────────────────

    /// @notice Provider stakes (SALT deposited).
    mapping(address => uint256) public stakes;

    /// @notice Permanently banned providers (Tier 3 slash).
    mapping(address => bool) public banned;

    /// @notice Total registered (non-banned) providers.
    uint256 public totalProviders;

    /// @notice Slash count per block number (for correlation multiplier).
    mapping(uint256 => uint256) public slashesInBlock;

    /// @notice Governance address (can call slash).
    address public governance;

    // ── Events ───────────────────────────────────────────────────────

    event Staked(address indexed provider, uint256 amount);
    event Unstaked(address indexed provider, uint256 amount);
    event Slashed(
        address indexed provider,
        SlashTier tier,
        uint256 amount,
        uint256 correlationMultiplier
    );
    event Banned(address indexed provider);
    event GovernanceTransferred(address indexed oldGov, address indexed newGov);

    // ── Modifiers ────────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governance, "Not governance");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────

    constructor() {
        governance = msg.sender;
    }

    // ── Provider Staking ─────────────────────────────────────────────

    /// @notice Stake SALT to become a slashable provider.
    function stake() external payable nonReentrant {
        require(msg.value > 0, "Zero stake");
        require(!banned[msg.sender], "Provider is banned");

        bool isNew = stakes[msg.sender] == 0;
        stakes[msg.sender] += msg.value;
        require(stakes[msg.sender] >= MIN_STAKE, "Below minimum stake");

        if (isNew) {
            totalProviders++;
        }

        emit Staked(msg.sender, msg.value);
    }

    /// @notice Withdraw entire stake (only for providers who are not banned).
    /// @dev Provider is deregistered after full unstake.
    function unstake() external nonReentrant {
        require(!banned[msg.sender], "Provider is banned");
        uint256 amount = stakes[msg.sender];
        require(amount > 0, "No stake");

        stakes[msg.sender] = 0;
        totalProviders--;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit Unstaked(msg.sender, amount);
    }

    // ── Slashing ─────────────────────────────────────────────────────

    /// @notice Slash a provider according to the given tier.
    /// @param provider The address being slashed.
    /// @param tier The severity tier (Latency, Inconsistency, Byzantine).
    /// @param evidence Opaque evidence payload (e.g. equivocation proof).
    function slash(
        address provider,
        SlashTier tier,
        bytes calldata evidence
    ) external onlyGovernance {
        require(evidence.length > 0, "Evidence required");
        require(!banned[provider], "Already banned");
        require(stakes[provider] > 0, "Not staked");

        // Record the slash event in the current block for correlation tracking
        slashesInBlock[block.number]++;

        // Compute base penalty in basis points
        uint256 baseBps = _tierPenaltyBps(tier);

        // Compute raw penalty before correlation multiplier
        uint256 rawPenalty = (stakes[provider] * baseBps) / BPS;

        // Apply correlation multiplier (scaled by 1e18)
        uint256 corrMul = getCorrelationMultiplier();
        uint256 penalty = (rawPenalty * corrMul) / ONE;

        // Cap at the provider's full stake
        if (penalty > stakes[provider]) {
            penalty = stakes[provider];
        }

        stakes[provider] -= penalty;

        // Tier 3 (Byzantine) always results in a permanent ban
        if (tier == SlashTier.Byzantine) {
            banned[provider] = true;
            totalProviders--;

            // Any remaining stake is also forfeited
            uint256 remaining = stakes[provider];
            stakes[provider] = 0;
            penalty += remaining;

            emit Banned(provider);
        } else if (stakes[provider] == 0) {
            // If all stake was consumed by a non-Byzantine slash, deregister
            totalProviders--;
        }

        emit Slashed(provider, tier, penalty, corrMul);
    }

    // ── Correlation Multiplier ───────────────────────────────────────

    /// @notice Returns the correlation multiplier (scaled by 1e18).
    /// @dev Formula from Ethereum research:
    ///      multiplier = min(3, slashed_in_window * 30 / total_providers)
    ///      The minimum effective multiplier is 1e18 (1x) — penalties are never reduced.
    function getCorrelationMultiplier() public view returns (uint256) {
        if (totalProviders == 0) return ONE;

        // Sum slashes across the correlation window
        uint256 slashedInWindow = _slashesInWindow();

        // multiplier = slashedInWindow * 30 / totalProviders  (scaled by 1e18)
        uint256 mul = (slashedInWindow * 30 * ONE) / totalProviders;

        // Floor at 1x
        if (mul < ONE) {
            mul = ONE;
        }

        // Cap at 3x
        if (mul > MAX_CORRELATION_MUL) {
            mul = MAX_CORRELATION_MUL;
        }

        return mul;
    }

    // ── View Functions ───────────────────────────────────────────────

    /// @notice Check whether a provider is currently slashable (staked and not banned).
    function isSlashable(address provider) external view returns (bool) {
        return stakes[provider] > 0 && !banned[provider];
    }

    /// @notice Total number of slash events in the current correlation window.
    function slashesInWindow() external view returns (uint256) {
        return _slashesInWindow();
    }

    // ── Governance ───────────────────────────────────────────────────

    /// @notice Transfer governance to a new address.
    function transferGovernance(address newGovernance) external onlyGovernance {
        require(newGovernance != address(0), "Zero address");
        address oldGov = governance;
        governance = newGovernance;
        emit GovernanceTransferred(oldGov, newGovernance);
    }

    // ── Internal Helpers ─────────────────────────────────────────────

    /// @dev Returns the base penalty in basis points for a given tier.
    function _tierPenaltyBps(SlashTier tier) internal pure returns (uint256) {
        if (tier == SlashTier.Latency) return LATENCY_PENALTY_BPS;
        if (tier == SlashTier.Inconsistency) return INCONSISTENCY_PENALTY_BPS;
        return BYZANTINE_PENALTY_BPS; // Byzantine
    }

    /// @dev Sum slash events across the current correlation window.
    ///      Iterates backwards from the current block up to CORRELATION_WINDOW blocks.
    function _slashesInWindow() internal view returns (uint256) {
        uint256 total = 0;
        uint256 startBlock = block.number >= CORRELATION_WINDOW
            ? block.number - CORRELATION_WINDOW + 1
            : 0;

        for (uint256 b = startBlock; b <= block.number; b++) {
            total += slashesInBlock[b];
        }
        return total;
    }

    // ── Receive ──────────────────────────────────────────────────────

    /// @notice Accept SALT transfers (for slashed fund recovery / treasury).
    receive() external payable {}
}
