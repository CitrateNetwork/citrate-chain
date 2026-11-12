// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @title EnvSigner: broadcast from a key held only in the process environment.
/// @notice r1007 ceremony option A (fed GO2_COMMAND_SHEET section 12, lead decision 2026-11-11).
///         Foundry 1.9 does not read ETH_PRIVATE_KEY for `vm.startBroadcast()`, so the only way to
///         sign without a key in argv or on any disk is for the script itself to read the key:
///         `op run --env-file=<(printf 'PRIVATE_KEY=op://...\n') -- forge script ...`.
///
///         - PRIVATE_KEY unset: `vm.startBroadcast()` exactly as before (CLI wallet options).
///         - PRIVATE_KEY set: EXPECTED_SENDER is required, and the key's address must equal it
///           (a wrong-key guard), then `vm.startBroadcast(key)`.
///
///         The key is never logged or returned. Broadcasting from the same sender at the same
///         nonces creates the same contracts at the same addresses, so this changes no address
///         and no deployed bytecode. The hooks are virtual so tests can supply a key without
///         vm.setEnv, which is process-global and would leak into tests running in parallel.
abstract contract EnvSigner is Script {
    function _envSignerKey() internal view virtual returns (uint256) {
        return vm.envOr("PRIVATE_KEY", uint256(0));
    }

    function _envExpectedSender() internal view virtual returns (address) {
        return vm.envOr("EXPECTED_SENDER", address(0));
    }

    /// Start broadcasting: from the env key when one is set (guarded), else as before.
    function _startBroadcastEnv() internal {
        uint256 key = _envSignerKey();
        if (key == 0) {
            vm.startBroadcast();
            return;
        }
        address expected = _envExpectedSender();
        require(expected != address(0), "EnvSigner: PRIVATE_KEY is set but EXPECTED_SENDER is not");
        require(vm.addr(key) == expected, "EnvSigner: PRIVATE_KEY does not belong to EXPECTED_SENDER");
        vm.startBroadcast(key);
    }
}
