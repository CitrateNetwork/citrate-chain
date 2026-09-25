// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./interfaces/IComputePricingOracle.sol";
import "./lib/Governable.sol";

/// @title ComputePricingOracle — On-Chain Compute-to-SALT Pricing
/// @notice BFT quorum oracle that maps real-world compute costs (PFLOP-hours) to SALT.
///         Establishes SALT's intrinsic floor price: 1 SALT >= the compute it buys on
///         the open market. Oracle committee (checkpoint validators) vote on price updates
///         with 67% quorum, rate-limited to max 10% change per update.
///
/// @dev Reference cloud GPU rates (March 2026):
///      - 8x A100 average competitive: ~$20/hr
///      - 8x A100 performance: ~2,496 TFLOPS FP16
///      - Cost per PFLOP-hour: ~$0.13 (= 13 USD cents)
///
/// @dev Price update flow:
///      1. Oracle member calls proposeComputePrice() or proposeSaltPrice()
///      2. If first proposal for current nonce, parameters are stored
///      3. Subsequent oracles must agree on the same value (BFT agreement)
///      4. At 67% quorum, price is finalized and applied
///      5. Rate limiter rejects changes > 10% from current price
///      6. lastUpdateBlock is set; staleness checked against MAX_STALENESS
contract ComputePricingOracle is IComputePricingOracle, Governable {
    // ============================================================
    // Constants
    // ============================================================

    /// @notice Oracle quorum percentage required (67% = 2/3+)
    uint256 public constant QUORUM = 67;

    /// @notice Maximum blocks between price updates before price is considered stale
    ///         ~1 day at ~12s block time: 86400 / 12 = 7200
    uint256 public constant MAX_STALENESS = 7200;

    /// @notice Maximum price change per update in basis points (10% = 1000 BPS)
    uint256 public constant MAX_PRICE_CHANGE_BPS = 1000;

    /// @notice Minimum blocks between two finalized updates of the SAME price
    ///         track. C037(a): without a cooldown the 10% cap is per-update and
    ///         `computePriceNonce++`/`saltPriceNonce++` reopen a fresh vote in
    ///         the same block, so N sequential proposals compound to 1.1^N in one
    ///         block. This bounds movement to MAX_PRICE_CHANGE_BPS per interval.
    uint256 public constant MIN_UPDATE_INTERVAL = 20;

    /// @notice Conversion factor: tokens to PFLOP-hours
    ///         Approximation: 1 token inference ~= 1e-12 PFLOP-hours
    ///         So 1e12 tokens = 1 PFLOP-hour. Factor is denominator.
    uint256 public constant TOKENS_TO_PFLOP_FACTOR = 1e12;

    /// @notice Verification tier multipliers in BPS (10000 = 1.0x)
    uint256 public constant VERIFICATION_MULTIPLIER_COMMITMENT = 10000; // 1.0x
    uint256 public constant VERIFICATION_MULTIPLIER_ZK = 15000;         // 1.5x
    uint256 public constant VERIFICATION_MULTIPLIER_TEE = 20000;        // 2.0x

    // ============================================================
    // State — Prices
    // ============================================================

    /// @notice Compute price in USD cents per PFLOP-hour (e.g., 13 = $0.13)
    uint256 public override computePriceUsdCents;

    /// @notice SALT price in USD cents (e.g., 100 = $1.00)
    uint256 public override saltPriceUsdCents;

    /// @notice Block number of last successful price update (either track).
    uint256 public lastUpdateBlock;

    /// @notice Block number of the last finalized compute-price update.
    uint256 public lastComputeUpdateBlock;
    /// @notice Block number of the last finalized SALT-price update.
    uint256 public lastSaltUpdateBlock;

    /// @notice Historical price snapshots for market maker data
    struct PriceSnapshot {
        uint256 computePriceUsdCents;
        uint256 saltPriceUsdCents;
        uint256 blockNumber;
        uint256 timestamp;
    }

    PriceSnapshot[] public priceHistory;

    // ============================================================
    // State — Oracle Committee
    // ============================================================

    mapping(address => bool) public isOracleMember;
    uint256 public oracleCount;

    // ============================================================
    // State — Compute Price Proposals (BFT vote)
    // ============================================================

    uint256 public computePriceNonce;

    /// @dev Pending compute price per nonce
    mapping(uint256 => uint256) private _pendingComputePrice;
    mapping(uint256 => bool) private _computeProposalExists;
    mapping(uint256 => mapping(address => bool)) private _computeVotes;
    mapping(uint256 => uint256) private _computeVoteCount;
    mapping(uint256 => bool) private _computeFinalized;

    // ============================================================
    // State — SALT Price Proposals (BFT vote)
    // ============================================================

    uint256 public saltPriceNonce;

    /// @dev Pending SALT price per nonce
    mapping(uint256 => uint256) private _pendingSaltPrice;
    mapping(uint256 => bool) private _saltProposalExists;
    mapping(uint256 => mapping(address => bool)) private _saltVotes;
    mapping(uint256 => uint256) private _saltVoteCount;
    mapping(uint256 => bool) private _saltFinalized;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ============================================================
    // Events
    // ============================================================

    event ComputePriceProposed(address indexed oracle, uint256 nonce, uint256 proposedPrice);
    event ComputePriceUpdated(uint256 oldPrice, uint256 newPrice, uint256 nonce);
    event SaltPriceProposed(address indexed oracle, uint256 nonce, uint256 proposedPrice);
    event SaltPriceUpdated(uint256 oldPrice, uint256 newPrice, uint256 nonce);
    event OracleMemberAdded(address indexed member);
    event OracleMemberRemoved(address indexed member);
    // GovernanceTransferred event is provided by Governable mixin.

    // ============================================================
    // Modifiers
    // ============================================================

    // `onlyGovernance` is inherited from Governable.

    modifier onlyOracle() {
        require(isOracleMember[msg.sender], "ComputePricingOracle: not oracle member");
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    /// @notice Deploy with initial prices
    /// @param _computePriceUsdCents Initial compute price in USD cents per PFLOP-hour
    /// @param _saltPriceUsdCents Initial SALT price in USD cents
    constructor(uint256 _computePriceUsdCents, uint256 _saltPriceUsdCents, address initialGovernance)
        Governable(initialGovernance)
    {
        require(_computePriceUsdCents > 0, "ComputePricingOracle: zero compute price");
        require(_saltPriceUsdCents > 0, "ComputePricingOracle: zero SALT price");

        computePriceUsdCents = _computePriceUsdCents;
        saltPriceUsdCents = _saltPriceUsdCents;
        lastUpdateBlock = block.number;

        // Record initial price in history
        priceHistory.push(PriceSnapshot({
            computePriceUsdCents: _computePriceUsdCents,
            saltPriceUsdCents: _saltPriceUsdCents,
            blockNumber: block.number,
            timestamp: block.timestamp
        }));
    }

    // ============================================================
    // Oracle Committee Management (governance only)
    // ============================================================

    /// @notice Add an oracle committee member.
    ///
    /// RM-B1 / WP-D5.3 (audit SOL-10): pre-fix membership changes
    /// mid-vote could finalize a sub-quorum proposal because
    /// `votesNeeded` was recomputed on every vote against the new
    /// `oracleCount` while `_computeVoteCount[nonce]` retained
    /// votes from removed members. Post-fix every membership
    /// change increments `computePriceNonce` to invalidate any
    /// in-flight proposal.
    function addOracleMember(address member) external onlyGovernance {
        require(member != address(0), "ComputePricingOracle: zero address");
        require(!isOracleMember[member], "ComputePricingOracle: already member");

        isOracleMember[member] = true;
        oracleCount++;
        // SOL-10 / C037(b): invalidate any in-flight proposal under the
        // pre-change membership — BOTH price tracks. The pre-fix code bumped
        // only `computePriceNonce`, leaving a live salt-price vote to finalize
        // against a `votesNeeded` computed from the new count while retaining
        // votes from the old membership.
        computePriceNonce++;
        saltPriceNonce++;

        emit OracleMemberAdded(member);
    }

    /// @notice Remove an oracle committee member.
    /// SOL-10: same nonce-bump as addOracleMember.
    function removeOracleMember(address member) external onlyGovernance {
        require(isOracleMember[member], "ComputePricingOracle: not member");

        isOracleMember[member] = false;
        oracleCount--;
        // SOL-10 / C037(b): bump BOTH tracks (see addOracleMember).
        computePriceNonce++;
        saltPriceNonce++;

        emit OracleMemberRemoved(member);
    }

    // ============================================================
    // Price Proposals — Compute Price
    // ============================================================

    /// @notice Oracle member proposes a new compute price (USD cents per PFLOP-hour)
    /// @param newPrice The proposed price in USD cents
    /// @dev At 67% quorum with agreement on the same value, price is updated.
    ///      Rate limited: max 10% change from current price per update.
    function proposeComputePrice(uint256 newPrice) external onlyOracle {
        require(newPrice > 0, "ComputePricingOracle: zero price");
        require(oracleCount > 0, "ComputePricingOracle: no oracles");

        uint256 nonce = computePriceNonce;
        require(!_computeFinalized[nonce], "ComputePricingOracle: already finalized");

        // Rate limit: max 10% change from current price
        _enforceRateLimit(computePriceUsdCents, newPrice);

        // First proposal stores the value; subsequent must agree
        if (!_computeProposalExists[nonce]) {
            _pendingComputePrice[nonce] = newPrice;
            _computeProposalExists[nonce] = true;
        } else {
            require(
                _pendingComputePrice[nonce] == newPrice,
                "ComputePricingOracle: price mismatch"
            );
        }

        require(!_computeVotes[nonce][msg.sender], "ComputePricingOracle: already voted");
        _computeVotes[nonce][msg.sender] = true;
        _computeVoteCount[nonce]++;

        emit ComputePriceProposed(msg.sender, nonce, newPrice);

        // Check quorum: ceil(oracleCount * QUORUM / 100), floor 1.
        // SOL-10: the `>= 1` floor prevents a degenerate case
        // where `oracleCount=0` (which `require(oracleCount > 0)`
        // already prevents) AND a more subtle case where
        // small oracleCount yields votesNeeded=0 via integer
        // truncation in some quorum settings.
        uint256 votesNeeded = (oracleCount * QUORUM + 99) / 100;
        if (votesNeeded == 0) {
            votesNeeded = 1;
        }
        if (_computeVoteCount[nonce] >= votesNeeded) {
            // C037(a): enforce a per-track cooldown so updates cannot compound
            // within one block. The first-ever update (lastComputeUpdateBlock==0)
            // is unconstrained.
            if (lastComputeUpdateBlock != 0) {
                require(
                    block.number >= lastComputeUpdateBlock + MIN_UPDATE_INTERVAL,
                    "ComputePricingOracle: update cooldown"
                );
            }
            uint256 oldPrice = computePriceUsdCents;
            computePriceUsdCents = newPrice;
            _computeFinalized[nonce] = true;
            computePriceNonce++;
            lastUpdateBlock = block.number;
            lastComputeUpdateBlock = block.number;

            _recordPriceSnapshot();

            emit ComputePriceUpdated(oldPrice, newPrice, nonce);
        }
    }

    // ============================================================
    // Price Proposals — SALT Price
    // ============================================================

    /// @notice Oracle member proposes a new SALT price (USD cents)
    /// @param newPrice The proposed price in USD cents
    /// @dev At 67% quorum with agreement, price is updated. Rate limited to 10%.
    function proposeSaltPrice(uint256 newPrice) external onlyOracle {
        require(newPrice > 0, "ComputePricingOracle: zero price");
        require(oracleCount > 0, "ComputePricingOracle: no oracles");

        uint256 nonce = saltPriceNonce;
        require(!_saltFinalized[nonce], "ComputePricingOracle: already finalized");

        // Rate limit: max 10% change from current price
        _enforceRateLimit(saltPriceUsdCents, newPrice);

        // First proposal stores the value; subsequent must agree
        if (!_saltProposalExists[nonce]) {
            _pendingSaltPrice[nonce] = newPrice;
            _saltProposalExists[nonce] = true;
        } else {
            require(
                _pendingSaltPrice[nonce] == newPrice,
                "ComputePricingOracle: price mismatch"
            );
        }

        require(!_saltVotes[nonce][msg.sender], "ComputePricingOracle: already voted");
        _saltVotes[nonce][msg.sender] = true;
        _saltVoteCount[nonce]++;

        emit SaltPriceProposed(msg.sender, nonce, newPrice);

        // Check quorum
        uint256 votesNeeded = (oracleCount * QUORUM + 99) / 100;
        if (_saltVoteCount[nonce] >= votesNeeded) {
            // C037(a): per-track cooldown (see proposeComputePrice).
            if (lastSaltUpdateBlock != 0) {
                require(
                    block.number >= lastSaltUpdateBlock + MIN_UPDATE_INTERVAL,
                    "ComputePricingOracle: update cooldown"
                );
            }
            uint256 oldPrice = saltPriceUsdCents;
            saltPriceUsdCents = newPrice;
            _saltFinalized[nonce] = true;
            saltPriceNonce++;
            lastUpdateBlock = block.number;
            lastSaltUpdateBlock = block.number;

            _recordPriceSnapshot();

            emit SaltPriceUpdated(oldPrice, newPrice, nonce);
        }
    }

    // ============================================================
    // View — Derived Pricing
    // ============================================================

    /// @notice SALT per PFLOP-hour (18 decimals)
    ///         = computePriceUsdCents * 1e18 / saltPriceUsdCents
    function saltPerPflopHour() external view override returns (uint256) {
        return _saltPerPflopHour();
    }

    /// @notice Convert PFLOP-hours to SALT cost
    /// @param pflopHours Number of PFLOP-hours (18 decimals)
    /// @return saltCost SALT required (18 decimals)
    function computeToSalt(uint256 pflopHours) external view override returns (uint256 saltCost) {
        saltCost = (pflopHours * _saltPerPflopHour()) / 1e18;
    }

    /// @notice Estimate job cost in SALT from model parameters
    /// @param modelHash Hash identifying the model (reserved for per-model pricing overrides)
    /// @param inputTokens Number of input tokens
    /// @param outputTokens Number of output tokens
    /// @param verificationTier 0=Commitment (1.0x), 1=ZKProof (1.5x), 2=TEE (2.0x)
    /// @return saltCost Estimated SALT cost (18 decimals)
    /// @dev Formula: (totalTokens / TOKENS_TO_PFLOP_FACTOR) * saltPerPflopHour * tierMultiplier
    function estimateJobCost(
        bytes32 modelHash,
        uint256 inputTokens,
        uint256 outputTokens,
        uint8 verificationTier
    ) external view override returns (uint256 saltCost) {
        // Suppress unused variable warning — modelHash reserved for future per-model pricing
        modelHash;

        require(verificationTier <= 2, "ComputePricingOracle: invalid tier");

        uint256 totalTokens = inputTokens + outputTokens;
        if (totalTokens == 0) return 0;

        // Convert tokens to PFLOP-hours (18 decimals)
        // pflopHours = totalTokens * 1e18 / TOKENS_TO_PFLOP_FACTOR
        uint256 pflopHours = (totalTokens * 1e18) / TOKENS_TO_PFLOP_FACTOR;

        // Base SALT cost
        uint256 baseCost = (pflopHours * _saltPerPflopHour()) / 1e18;

        // Apply verification tier multiplier
        uint256 multiplier = _tierMultiplier(verificationTier);
        saltCost = (baseCost * multiplier) / 10000;
    }

    /// @notice Whether the oracle price is stale
    /// @return True if more than MAX_STALENESS blocks since last update
    function isPriceStale() external view override returns (bool) {
        return block.number > lastUpdateBlock + MAX_STALENESS;
    }

    // ============================================================
    // View — Price History
    // ============================================================

    /// @notice Get the number of price snapshots recorded
    function priceHistoryLength() external view returns (uint256) {
        return priceHistory.length;
    }

    /// @notice Get a price snapshot by index
    /// @param index The index in the priceHistory array
    function getPriceSnapshot(uint256 index) external view returns (PriceSnapshot memory) {
        require(index < priceHistory.length, "ComputePricingOracle: index out of bounds");
        return priceHistory[index];
    }

    /// @notice Get current vote counts for pending proposals
    /// @return computeVotes Current vote count for compute price proposal
    /// @return computeNonce Current compute price nonce
    /// @return saltVotes Current vote count for SALT price proposal
    /// @return saltNonce Current SALT price nonce
    function getPendingVotes() external view returns (
        uint256 computeVotes,
        uint256 computeNonce,
        uint256 saltVotes,
        uint256 saltNonce
    ) {
        computeNonce = computePriceNonce;
        computeVotes = _computeVoteCount[computeNonce];
        saltNonce = saltPriceNonce;
        saltVotes = _saltVoteCount[saltNonce];
    }

    // ============================================================
    // Governance
    // ============================================================

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ============================================================
    // Internal Helpers
    // ============================================================

    /// @dev Calculate SALT per PFLOP-hour (18 decimals)
    function _saltPerPflopHour() internal view returns (uint256) {
        return (computePriceUsdCents * 1e18) / saltPriceUsdCents;
    }

    /// @dev Get verification tier multiplier in BPS
    function _tierMultiplier(uint8 tier) internal pure returns (uint256) {
        if (tier == 0) return VERIFICATION_MULTIPLIER_COMMITMENT;
        if (tier == 1) return VERIFICATION_MULTIPLIER_ZK;
        if (tier == 2) return VERIFICATION_MULTIPLIER_TEE;
        revert("ComputePricingOracle: invalid tier");
    }

    /// @dev Enforce rate limit: newPrice must be within MAX_PRICE_CHANGE_BPS of currentPrice
    function _enforceRateLimit(uint256 currentPrice, uint256 newPrice) internal pure {
        // Allow any change if current price is 0 (shouldn't happen, but defensive)
        if (currentPrice == 0) return;

        uint256 maxDelta = (currentPrice * MAX_PRICE_CHANGE_BPS) / 10000;

        if (newPrice > currentPrice) {
            require(
                newPrice - currentPrice <= maxDelta,
                "ComputePricingOracle: exceeds max price change"
            );
        } else {
            require(
                currentPrice - newPrice <= maxDelta,
                "ComputePricingOracle: exceeds max price change"
            );
        }
    }

    /// @dev Record a price snapshot in history
    function _recordPriceSnapshot() internal {
        priceHistory.push(PriceSnapshot({
            computePriceUsdCents: computePriceUsdCents,
            saltPriceUsdCents: saltPriceUsdCents,
            blockNumber: block.number,
            timestamp: block.timestamp
        }));
    }
}
