// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../Salts.sol";

/// @title Create2Deploy — reuse-or-deploy for salted ceremony deploys
/// @notice Ceremony scripts are re-run on chains where part of the stack is
///         already live. A salted `new X{salt:}()` reverts when the CREATE2
///         address is occupied, so a re-run died at the first unchanged
///         contract. Call sites use
///           `_isLive(n, init) ? X(payable(_create2Address(n, init))) : new X{salt: Salts.salt(n)}(args)`
///         so an existing contract (same init code by construction) is reused
///         and only the rest are deployed, still as `new X{salt:}` so forge's
///         broadcast records name every deployment.
abstract contract Create2Deploy is Script {
    address internal constant ARACHNID_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @notice Deterministic address for `name` + `initCode`.
    function _create2Address(string memory name, bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), ARACHNID_DEPLOYER, Salts.salt(name), keccak256(initCode))
                    )
                )
            )
        );
    }

    /// @notice True (and logged) when the salted CREATE2 address for
    ///         `name` + `initCode` already holds code, which is by construction
    ///         that exact init code: the caller reuses it instead of deploying.
    function _isLive(string memory name, bytes memory initCode) internal view returns (bool live) {
        address a = _create2Address(name, initCode);
        live = a.code.length != 0;
        if (live) console.log(string.concat("  reuse ", name, ":"), a);
    }
}
