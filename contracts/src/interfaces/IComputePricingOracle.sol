// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IComputePricingOracle — Interface for Compute-to-SALT Pricing Oracle
/// @notice Maps real-world compute costs (PFLOP-hours) to SALT token value.
///         Establishes SALT's intrinsic floor price: SALT >= compute cost it buys.
interface IComputePricingOracle {
    /// @notice Current compute price in USD cents per PFLOP-hour
    ///         e.g., 13 = $0.13/PFLOP-hour (based on ~$20/hr for 8xA100 @ 2,496 TFLOPS)
    function computePriceUsdCents() external view returns (uint256);

    /// @notice Current SALT price in USD cents
    ///         e.g., 100 = $1.00
    function saltPriceUsdCents() external view returns (uint256);

    /// @notice Derived: SALT per PFLOP-hour (18 decimals)
    ///         = computePriceUsdCents * 1e18 / saltPriceUsdCents
    function saltPerPflopHour() external view returns (uint256);

    /// @notice Convert PFLOP-hours to SALT cost
    /// @param pflopHours Number of PFLOP-hours (18 decimals)
    /// @return saltCost SALT required (18 decimals)
    function computeToSalt(uint256 pflopHours) external view returns (uint256 saltCost);

    /// @notice Estimate job cost in SALT from model and token counts
    /// @param modelHash Hash identifying the model
    /// @param inputTokens Number of input tokens
    /// @param outputTokens Number of output tokens
    /// @param verificationTier 0=Commitment, 1=ZKProof, 2=TEE
    /// @return saltCost Estimated SALT cost (18 decimals)
    function estimateJobCost(
        bytes32 modelHash,
        uint256 inputTokens,
        uint256 outputTokens,
        uint8 verificationTier
    ) external view returns (uint256 saltCost);

    /// @notice Whether the oracle price is stale (exceeds MAX_STALENESS blocks)
    function isPriceStale() external view returns (bool);
}
