// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {EnvSigner} from "./lib/EnvSigner.sol";

/// @title SendWithEnvKey: one transaction from a key held only in the process environment.
/// @notice Covers the r1007 post-genesis steps that would otherwise be plain `cast send`
///         (which cannot take a key from the environment in Foundry 1.9): D1, D6, D8 and
///         D10b funding, D4 `setPaymaster`, D4b `depositTo`, and D2b `initRoot`.
///
///   op run --env-file=<(printf 'PRIVATE_KEY=op://citrate-chain-ops/r1007 <ROLE>/password\n') -- \
///     env EXPECTED_SENDER=<role address> TO=<target> VALUE=<wei> DATA=$(cast calldata '<sig>' <args>) \
///     forge script script/SendWithEnvKey.s.sol --rpc-url <r1007> --broadcast --slow
///
/// PRIVATE_KEY and EXPECTED_SENDER are required: this script has no CLI-wallet fallback.
/// DATA defaults to empty (a plain transfer) and VALUE to 0. A plain transfer to an
/// account with code, or a call to an account without code, is refused (a wrong-target guard).
contract SendWithEnvKey is EnvSigner {
    function _to() internal view virtual returns (address) {
        return vm.envAddress("TO");
    }

    function _value() internal view virtual returns (uint256) {
        return vm.envOr("VALUE", uint256(0));
    }

    function _data() internal view virtual returns (bytes memory) {
        return vm.envOr("DATA", bytes(""));
    }

    function run() external returns (bool ok, bytes memory ret) {
        require(_envSignerKey() != 0, "SendWithEnvKey: PRIVATE_KEY is required");
        address to = _to();
        bytes memory data = _data();
        require(to != address(0), "SendWithEnvKey: TO is the zero address");
        if (data.length == 0) {
            require(to.code.length == 0, "SendWithEnvKey: plain transfer to a contract; pass DATA");
        } else {
            require(to.code.length != 0, "SendWithEnvKey: DATA for an account without code");
        }
        _startBroadcastEnv();
        (ok, ret) = to.call{value: _value()}(data);
        vm.stopBroadcast();
        require(ok, "SendWithEnvKey: the call reverted");
    }
}
