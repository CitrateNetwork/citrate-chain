// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title LegacyDeployGuard
/// @notice Retires the pre-HUP registry deploy scripts on chain 40204.
/// @dev `DeployCitAgent`, `DeployAnchorRegistry` and `DeploySkillRegistry` deploy the
///      versions of OrganizationSBT, AgentSBT, CapsuleRegistry, AnchorRegistry,
///      BenchmarkRegistry and SkillRegistry that the HUP registry redeploy (HUP-S7.1,
///      federation F-4) replaces. On 40204 they would put a second, unbooked or older
///      copy next to the redeployed set (plain CREATE for the cit-agent set, so a new
///      address every run). `script/DeployHupRegistries.s.sol` is the only deploy path
///      for these names on 40204 now; the scripts still run on a local chain, where
///      their tests and local development use them.
library LegacyDeployGuard {
    uint256 internal constant CITRATE_CHAIN_ID = 40204;

    /// The revert reason, kept in one place so the test pins the exact text.
    function reason(string memory script) internal pure returns (string memory) {
        return string.concat(
            script,
            " is retired on chain 40204: deploy with script/DeployHupRegistries.s.sol",
            " (docs/ops/HUP_REGISTRY_REDEPLOY_RUNBOOK.md)"
        );
    }

    /// Revert on chain 40204, before anything is broadcast.
    function refuseOnCitrate(string memory script) internal view {
        require(block.chainid != CITRATE_CHAIN_ID, reason(script));
    }
}
