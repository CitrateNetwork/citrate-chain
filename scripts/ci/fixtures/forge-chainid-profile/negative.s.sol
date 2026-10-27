// SPDX-License-Identifier: Apache-2.0
// Fixture (forge-chainid-profile, negative): the profile comes from the shared node check, the
// remaining block.chainid uses only log it, and the commented-out branch is not code.
pragma solidity ^0.8.26;

import "./lib/GenesisProfile.sol";

contract DeployGenesisThing is GenesisProfile {
    function run() external {
        bool genesis = _resolveChainProfile(false).genesis;
        // if (block.chainid == 40204) { ... }   <- commented out, not a branch
        /* require(block.chainid != 1); */
        console.log("chain", block.chainid, genesis);
    }
}
