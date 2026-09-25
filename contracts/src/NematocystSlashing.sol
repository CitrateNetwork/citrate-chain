// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";

/// @title NematocystSlashing — Graduated 3-Tier Slashing with Correlation Multiplier
/// @notice Implements the nematocyst slashing model from the Citrate economics design:
///         Tier 1 (Spirocyst/Latency) = 5% stake, Tier 2 (Mastigophore/Inconsistency) = 20%,
///         Tier 3 (Penetrant/Byzantine) = 100% + permanent ban.
///         The Ethereum-research correlation multiplier scales penalties when multiple
///         providers are slashed in the same window.
/// @dev WP-F.10
contract NematocystSlashing is ReentrancyGuard, Governable {
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

    /// @notice PBA-L2-028: blocks an unstake waits, still slashable, before
    ///         it can be withdrawn (~7 days at 2 s blocks; longer than the
    ///         evidence window).
    uint256 public constant UNBONDING_PERIOD = 302_400;

    // ── State ────────────────────────────────────────────────────────

    /// @notice Provider stakes (SALT deposited).
    mapping(address => uint256) public stakes;

    /// @notice Permanently banned providers (Tier 3 slash).
    mapping(address => bool) public banned;

    /// @notice Total registered (non-banned) providers.
    uint256 public totalProviders;

    /// @notice Slash count per block number (for correlation multiplier).
    mapping(uint256 => uint256) public slashesInBlock;

    /// @notice PBA-L2-028: stake queued by `unstake()`, still slashable.
    mapping(address => uint256) public pendingUnstake;
    /// @notice Block from which `withdrawUnstaked()` may pay out.
    mapping(address => uint256) public unstakeReadyAt;
    /// @notice Cumulative SALT slashed, and how much governance has moved out.
    uint256 public slashedTotal;
    uint256 public slashedWithdrawn;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ── Events ───────────────────────────────────────────────────────

    event Staked(address indexed provider, uint256 amount);
    event Unstaked(address indexed provider, uint256 amount);
    event UnstakeRequested(address indexed provider, uint256 amount, uint256 readyAtBlock);
    event SlashedWithdrawn(address indexed to, uint256 amount);
    event Slashed(
        address indexed provider,
        SlashTier tier,
        uint256 amount,
        uint256 correlationMultiplier
    );
    event Banned(address indexed provider);
    // GovernanceTransferred event provided by Governable mixin.

    // ── Modifiers ────────────────────────────────────────────────────

    // `onlyGovernance` is inherited from Governable.

    // ── Constructor ──────────────────────────────────────────────────

    /// @param initialGovernance Explicit governance (PBA-L2-002: never msg.sender,
    ///        which is the CREATE2 factory under a salted ceremony deploy).
    constructor(address initialGovernance) Governable(initialGovernance) {}

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
    /// @notice Begin unbonding the caller's whole stake.
    /// @dev PBA-L2-028 (pre-bounty audit 2026-09-24): `unstake()` used to pay
    ///      out instantly, so a provider who misbehaved (or saw `slash()` in
    ///      the mempool) left with 100 % and the slash then reverted "Not
    ///      staked". Unstaking now queues the stake for `UNBONDING_PERIOD`
    ///      blocks (longer than the evidence window) during which it remains
    ///      fully slashable; `withdrawUnstaked()` pays out afterwards.
    function unstake() external nonReentrant {
        require(!banned[msg.sender], "Provider is banned");
        uint256 amount = stakes[msg.sender];
        require(amount > 0, "No stake");

        stakes[msg.sender] = 0;
        totalProviders--;
        pendingUnstake[msg.sender] += amount;
        unstakeReadyAt[msg.sender] = block.number + UNBONDING_PERIOD;

        emit UnstakeRequested(msg.sender, amount, unstakeReadyAt[msg.sender]);
    }

    /// @notice Withdraw stake whose unbonding period has elapsed.
    function withdrawUnstaked() external nonReentrant {
        require(!banned[msg.sender], "Provider is banned");
        uint256 amount = pendingUnstake[msg.sender];
        require(amount > 0, "Nothing unbonding");
        require(block.number >= unstakeReadyAt[msg.sender], "Still unbonding");

        pendingUnstake[msg.sender] = 0;
        unstakeReadyAt[msg.sender] = 0;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit Unstaked(msg.sender, amount);
    }

    // ── Slashing ─────────────────────────────────────────────────────

    /// @notice Slash a provider for misbehaviour. Reaches both active stake and
    ///         stake still unbonding (PBA-L2-028).
    function slash(
        address provider,
        SlashTier tier,
        bytes calldata evidence
    ) external onlyGovernance {
        require(evidence.length > 0, "Evidence required");
        require(!banned[provider], "Already banned");
        uint256 active = stakes[provider];
        uint256 unbonding = pendingUnstake[provider];
        uint256 base = active + unbonding;
        require(base > 0, "Not staked");

        // Record the slash event in the current block for correlation tracking
        slashesInBlock[block.number]++;

        uint256 rawPenalty = (base * _tierPenaltyBps(tier)) / BPS;
        uint256 corrMul = getCorrelationMultiplier();
        uint256 penalty = (rawPenalty * corrMul) / ONE;

        // Tier 3 (Byzantine) always forfeits everything and bans.
        if (tier == SlashTier.Byzantine || penalty > base) {
            penalty = base;
        }

        // Debit active stake first, then the unbonding queue.
        uint256 fromActive = penalty > active ? active : penalty;
        stakes[provider] = active - fromActive;
        pendingUnstake[provider] = unbonding - (penalty - fromActive);
        slashedTotal += penalty;

        if (tier == SlashTier.Byzantine) {
            banned[provider] = true;
            emit Banned(provider);
        }
        // An active provider whose active stake is now gone is deregistered
        // (unbonding providers were already deregistered by `unstake`).
        if (active > 0 && stakes[provider] == 0) {
            totalProviders--;
        }

        emit Slashed(provider, tier, penalty, corrMul);
    }

    /// @notice PBA-L2-028: slashed SALT used to accumulate here with no path
    ///         out. Governance moves it to the treasury (or a burn address).
    function withdrawSlashed(address to, uint256 amount) external onlyGovernance nonReentrant {
        require(to != address(0), "Zero recipient");
        require(amount > 0 && amount <= slashedTotal - slashedWithdrawn, "Exceeds slashed balance");
        slashedWithdrawn += amount;
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "Transfer failed");
        emit SlashedWithdrawn(to, amount);
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
        return (stakes[provider] + pendingUnstake[provider]) > 0 && !banned[provider];
    }

    /// @notice Total number of slash events in the current correlation window.
    function slashesInWindow() external view returns (uint256) {
        return _slashesInWindow();
    }

    // ── Governance ───────────────────────────────────────────────────

    // transferGovernance / acceptGovernance are inherited from Governable.

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
