// SPDX-License-Identifier: Apache-2.0
// Fixture (forge-chainid-profile, negative): the shared check itself compares block.chainid
// with the node's answer; it defines _resolveChainProfile, so it is accepted.
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

abstract contract GenesisProfile is Script {
    function _resolveChainProfile(bool forced) internal returns (bool genesis) {
        uint256 node = 40204;
        require(node == block.chainid, "chain id mismatch");
        genesis = forced || block.chainid == 40204;
    }
}
