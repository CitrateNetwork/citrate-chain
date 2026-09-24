// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title ComputeLib — Shared computation helpers for the Compute subsystem
/// @notice Extracted to reduce stack depth in calling contracts.
///         Pure/view functions that perform scoring, BME calculation, and bid comparison.
library ComputeLib {
    /// @notice Basis points denominator
    uint256 internal constant BPS = 10000;

    /// @notice Scoring weights for provider selection (must sum to 100)
    uint256 internal constant WEIGHT_PRICE = 40;
    uint256 internal constant WEIGHT_REPUTATION = 30;
    uint256 internal constant WEIGHT_LOAD = 20;
    uint256 internal constant WEIGHT_VERIFICATION = 10;

    /// @notice BME burn rate divisor: 2.5% = 1/40
    uint256 internal constant BME_BURN_DIVISOR = 40;

    /// @notice Treasury fee divisor: 2.5% = 1/40
    uint256 internal constant TREASURY_DIVISOR = 40;

    /// @notice Struct returned from BME calculation to reduce stack variables
    struct BMEResult {
        uint256 providerAmount;
        uint256 burnAmount;
        uint256 treasuryAmount;
    }

    /// @notice Calculate BME (Burn-Mint-Equilibrium) payment split
    /// @param payment Total payment amount
    /// @return result The BME split: provider (95%), burn (2.5%), treasury (2.5%)
    function calculateBME(uint256 payment) internal pure returns (BMEResult memory result) {
        result.burnAmount = payment / BME_BURN_DIVISOR;
        result.treasuryAmount = payment / TREASURY_DIVISOR;
        result.providerAmount = payment - result.burnAmount - result.treasuryAmount;
    }

    /// @notice Score a provider for bid selection
    /// @dev Score = price(40%) + reputation(30%) + load(20%) + verificationHistory(10%)
    /// @param bidPrice The provider's bid price
    /// @param maxPrice The maximum price for the job
    /// @param reputationScore Provider's reputation in BPS
    /// @param currentActiveJobs Provider's current active jobs
    /// @param maxConcurrentJobs Provider's max concurrent jobs
    /// @param totalJobsCompleted Provider's total completed jobs
    /// @return score The composite score
    function scoreProvider(
        uint256 bidPrice,
        uint256 maxPrice,
        uint256 reputationScore,
        uint256 currentActiveJobs,
        uint256 maxConcurrentJobs,
        uint256 totalJobsCompleted
    ) internal pure returns (uint256 score) {
        // Price score: lower is better (inverted, normalized to 0..BPS)
        uint256 priceScore = BPS - ((BPS * bidPrice) / maxPrice);

        // Load score: lower current load is better
        uint256 loadScore = BPS;
        if (maxConcurrentJobs > 0) {
            loadScore = BPS - ((BPS * currentActiveJobs) / maxConcurrentJobs);
        }

        // Verification history: based on completed jobs (normalized, max BPS at 100 jobs)
        uint256 verifyScore = totalJobsCompleted > 100
            ? BPS
            : (totalJobsCompleted * BPS) / 100;

        score = (priceScore * WEIGHT_PRICE +
                 reputationScore * WEIGHT_REPUTATION +
                 loadScore * WEIGHT_LOAD +
                 verifyScore * WEIGHT_VERIFICATION) / 100;
    }

    /// @notice Calculate reputation score from job counts
    /// @param completedJobs Total completed jobs
    /// @param failedJobs Total failed jobs
    /// @return reputationScore Reputation in BPS
    function calculateReputation(
        uint256 completedJobs,
        uint256 failedJobs
    ) internal pure returns (uint256 reputationScore) {
        uint256 totalJobs = completedJobs + failedJobs;
        if (totalJobs > 0) {
            reputationScore = (completedJobs * BPS) / totalJobs;
        } else {
            reputationScore = BPS;
        }
    }

    /// @notice Calculate SLA penalty for a pool member
    /// @param memberStake Member's current stake
    /// @param slaPenaltyBps SLA penalty in basis points
    /// @param deficit Throughput deficit
    /// @param guaranteed Guaranteed throughput
    /// @return penalty Amount to slash
    function calculateSLAPenalty(
        uint256 memberStake,
        uint256 slaPenaltyBps,
        uint256 deficit,
        uint256 guaranteed
    ) internal pure returns (uint256 penalty) {
        penalty = (memberStake * slaPenaltyBps * deficit) / (BPS * guaranteed);
        if (penalty > memberStake) {
            penalty = memberStake;
        }
    }
}
