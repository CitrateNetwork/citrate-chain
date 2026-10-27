// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @title ScriptEnv
/// @notice Shared helpers for deployment scripts.
/// @dev Signing is provided by the forge CLI (`--account`, `--keystore`,
///      `--private-key`, etc). Scripts must never choose or embed a signer.
abstract contract ScriptEnv is Script {
    /// @notice The deployer the scripts derive parameters from (treasury and fee
    ///         recipients, initial owners). Either input may name it; when both are
    ///         set they must name the same address, and a set input that is empty,
    ///         malformed or zero reverts instead of being skipped.
    function deployerAddress() internal view returns (address deployer) {
        address ceremony = _deployerInput("CEREMONY_DEPLOYER_ADDRESS");
        address plain = _deployerInput("DEPLOYER_ADDRESS");
        require(
            ceremony == address(0) || plain == address(0) || ceremony == plain,
            "CEREMONY_DEPLOYER_ADDRESS and DEPLOYER_ADDRESS name different deployers"
        );
        deployer = ceremony != address(0) ? ceremony : plain;
        require(
            deployer != address(0),
            "set CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS"
        );
    }

    /// @dev address(0) when `key` is unset; reverts when it is set but not a
    ///      non-zero address.
    function _deployerInput(string memory key) private view returns (address value) {
        if (!vm.envExists(key)) return address(0);
        try vm.envAddress(key) returns (address loaded) {
            value = loaded;
        } catch {
            revert(string.concat(key, " is set but is not an address"));
        }
        require(value != address(0), string.concat(key, " is the zero address"));
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

    /// @notice Read a governance/owner/admin address that must NOT be the
    ///         deployer on the production chain. Off-chain (dev/test) it falls
    ///         back to `deployer` for convenience, but on chain 40204 the deploy
    ///         REVERTS unless `key` is set to a non-deployer address.
    /// @dev Fail-closed remediation of findings G2/G4: several ceremony scripts
    ///      defaulted governance to the deployer, so a run that forgot to set
    ///      GOVERNANCE would silently leave the deployer EOA holding admin. This
    ///      makes that impossible on 40204 while keeping local dev flows working.
    ///      Mirrors the block.chainid == 40204 guard used for EXPECTED_IPFS_V3 in
    ///      DeployFederatedLearning.
    function requiredGovernance(string memory key, address deployer)
        internal
        view
        returns (address gov)
    {
        gov = envAddressOr(key, deployer);
        require(
            block.chainid != 40204 || gov != deployer,
            string.concat(key, " must be set to a non-deployer address on 40204")
        );
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
    /// @notice The protocol fee recipient the ceremony names (`key`, the
    ///         ceremony input TREASURY). Fee recipients are fixed at
    ///         construction, and moving one later is a timelocked governance
    ///         operation per contract, so the deploy account must never be it.
    ///         - set: must be a non-zero address, and not the deployer unless
    ///           governance is the deployer too (local dev);
    ///         - unset: required on 40204; elsewhere it falls back to
    ///           `governance` (governance-controlled, never the deployer when a
    ///           real governance is configured).
    function requiredTreasury(string memory key, address deployer, address governance)
        internal
        view
        returns (address t)
    {
        if (vm.envExists(key)) {
            try vm.envAddress(key) returns (address loaded) {
                t = loaded;
            } catch {
                revert(string.concat(key, " is set but is not an address"));
            }
            require(t != address(0), string.concat(key, " is the zero address"));
        } else {
            require(block.chainid != 40204, string.concat(key, " must be set on 40204"));
            t = governance;
        }
        require(t != deployer || governance == deployer, string.concat(key, " must not be the deployer"));
    }
}
