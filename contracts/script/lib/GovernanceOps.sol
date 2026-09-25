// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @title GovernanceOps — governance-gated post-deploy wiring that works with a multisig
/// @notice DPF deploy scripts wire recorders right after deploying. Those
///         setters are governance-gated, so when GOVERNANCE is a multisig (not
///         the broadcasting key) the direct call reverts and the whole run
///         fails. `_govCall` makes the call directly when the broadcaster IS
///         governance, and otherwise records it: it logs `target` + calldata
///         for the multisig to execute, and does NOT send anything.
abstract contract GovernanceOps is Script {
    uint256 internal queuedGovCalls;

    function _govCall(address governance, address broadcaster, address target, bytes memory data, string memory label)
        internal
    {
        if (governance == broadcaster) {
            (bool ok, bytes memory ret) = target.call(data);
            if (!ok) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            return;
        }
        queuedGovCalls++;
        console.log(string.concat("MULTISIG ACTION #", vm.toString(queuedGovCalls), " ", label));
        console.log("  to:", target);
        console.log(string.concat("  data: ", vm.toString(data)));
    }
}
