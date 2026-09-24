// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @title ScriptEnv
/// @notice Shared helpers for deployment scripts.
/// @dev Signing is provided by the forge CLI (`--account`, `--keystore`,
///      `--private-key`, etc). Scripts must never choose or embed a signer.
abstract contract ScriptEnv is Script {
    function deployerAddress() internal view returns (address deployer) {
        deployer = envAddressOr("CEREMONY_DEPLOYER_ADDRESS", address(0));
        if (deployer == address(0)) {
            deployer = envAddressOr("DEPLOYER_ADDRESS", address(0));
        }
        require(
            deployer != address(0),
            "set CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS"
        );
    }

    function envAddressOr(string memory key, address fallbackValue)
        internal
        view
        returns (address value)
    {
        try vm.envAddress(key) returns (address loaded) {
            return loaded;
        } catch {
            return fallbackValue;
        }
    }

    function envUintOr(string memory key, uint256 fallbackValue)
        internal
        view
        returns (uint256 value)
    {
        try vm.envUint(key) returns (uint256 loaded) {
            return loaded;
        } catch {
            return fallbackValue;
        }
    }
}
