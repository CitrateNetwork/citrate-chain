// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";

/// @notice Minimal interface — we only need authorizeSpender +
/// authorizedSpenders to perform + verify the grant.
interface IBulkComputeGatewayAdmin {
    function authorizeSpender(address spender) external;
    function authorizedSpenders(address spender) external view returns (bool);
    function governance() external view returns (address);
}

/// @title AuthorizeSpenders — CM-06 WP-06.2
/// @notice Governance one-time setup: authorise ComputeMarketplace
///         (and any other configured spenders) to call
///         BulkComputeGateway.spendCredits on behalf of buyers.
///
/// @dev Run after both contracts are deployed. Idempotent — re-runs
///      no-op for already-authorized spenders.
///
/// Required env:
///   CITRATE_BULK_GATEWAY_ADDRESS    BulkComputeGateway address
///   CITRATE_MARKETPLACE_ADDRESS     ComputeMarketplace address
///
/// Optional env:
///   CITRATE_EXTRA_SPENDER_1 ... 4   additional spender addresses
///                                     (gateway operator wallet,
///                                     credit-backed API key keeper,
///                                     etc.)
///
/// Usage:
///   forge script script/AuthorizeSpenders.s.sol:AuthorizeSpenders \
///       --rpc-url $CITRATE_RPC_URL \
///       --account $GOVERNANCE_KEYSTORE \
///       --broadcast
///
/// Verify on-chain (after broadcast):
///   cast call $CITRATE_BULK_GATEWAY_ADDRESS \
///       "authorizedSpenders(address)(bool)" \
///       $CITRATE_MARKETPLACE_ADDRESS \
///       --rpc-url $CITRATE_RPC_URL
///   → expected output: `true`
contract AuthorizeSpenders is ScriptEnv {
    function run() external {
        address gatewayAddr = vm.envAddress("CITRATE_BULK_GATEWAY_ADDRESS");
        address marketplaceAddr = vm.envAddress("CITRATE_MARKETPLACE_ADDRESS");

        IBulkComputeGatewayAdmin gateway = IBulkComputeGatewayAdmin(gatewayAddr);

        console.log("BulkComputeGateway:", gatewayAddr);
        console.log("ComputeMarketplace:", marketplaceAddr);
        console.log("Gateway governance:", gateway.governance());

        vm.startBroadcast();

        // Marketplace is the primary mandatory spender.
        _authorizeIfNeeded(gateway, marketplaceAddr, "ComputeMarketplace");

        // Optional extras — gateway operator wallet, etc.
        for (uint256 i = 1; i <= 4; i++) {
            string memory key = string.concat(
                "CITRATE_EXTRA_SPENDER_",
                _u2s(i)
            );
            address extra = envAddressOr(key, address(0));
            if (extra != address(0)) {
                _authorizeIfNeeded(gateway, extra, key);
            }
        }

        vm.stopBroadcast();

        // Post-broadcast verification log. The CI smoke check is
        // `cast call authorizedSpenders(marketplace)` returning true.
        require(
            gateway.authorizedSpenders(marketplaceAddr),
            "AuthorizeSpenders: post-broadcast check failed"
        );
        console.log(
            "OK: BulkComputeGateway.authorizedSpenders[ComputeMarketplace] = true"
        );
    }

    function _authorizeIfNeeded(
        IBulkComputeGatewayAdmin gateway,
        address spender,
        string memory label
    ) internal {
        if (gateway.authorizedSpenders(spender)) {
            console.log("(skip)", label, "already authorized:", spender);
            return;
        }
        gateway.authorizeSpender(spender);
        console.log("Authorized", label, ":", spender);
    }

    /// @dev Tiny uint→string for env-var key composition. Solidity
    /// doesn't have it built in for forge-std versions ≤ 1.9.x.
    function _u2s(uint256 n) internal pure returns (string memory) {
        if (n == 0) return "0";
        uint256 len;
        for (uint256 m = n; m != 0; m /= 10) len++;
        bytes memory out = new bytes(len);
        uint256 i = len;
        for (uint256 m = n; m != 0; m /= 10) {
            i--;
            out[i] = bytes1(uint8(48 + m % 10));
        }
        return string(out);
    }
}
