// SPDX-License-Identifier: Apache-2.0
// Fixture (forge-script-address-this, negative): the deploy account is the configured
// deployer; `address(this)` appears only in comments and a string. Nothing is flagged.
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

contract DeployLedger is Script {
    function run() external {
        address deployer = vm.envAddress("DEPLOYER");
        // not address(this): forge refuses it on a script run path
        vm.startBroadcast(deployer);
        address[] memory admins = new address[](1);
        admins[0] = deployer;
        require(admins[0] != address(0), "address(this) is never used");
        vm.stopBroadcast();
    }
}
