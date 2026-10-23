// SPDX-License-Identifier: Apache-2.0
// Fixture (forge-script-address-this, positive): a script that hands its own address to a
// deployed contract. `forge test` runs it; `forge script --broadcast` refuses it. Flagged.
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

contract DeployLedger is Script {
    function run() external {
        vm.startBroadcast();
        address[] memory admins = new address[](1);
        admins[0] = address(this);
        vm.stopBroadcast();
    }
}
