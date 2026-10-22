// SPDX-License-Identifier: Apache-2.0
// Fixture (forge-chainid-profile, positive): three branches on forge's simulated chain id with
// no node check. Each comparison line must be flagged.
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

contract DeployThing is Script {
    function run() external {
        // artifacts land in broadcast/* — a glob in a line comment must not hide the code below
        require(block.chainid != 40204, "legacy script: not for 40204");
        bool live = block.chainid == 40204;
        if (40204 == block.chainid) {
            vm.startBroadcast();
        }
        console.log("chain", block.chainid);
        live;
    }
}
