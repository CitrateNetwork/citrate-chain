// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {AnchorRegistry} from "../src/cit_agent/AnchorRegistry.sol";

/// Deploys `AnchorRegistry`, which citrate-quorum's address-book test requires
/// to be present in the main book and which the reroll left unbooked.
contract DeployAnchorRegistry is Script {
    function run() external returns (address a) {
        vm.startBroadcast();
        AnchorRegistry r = new AnchorRegistry();
        vm.stopBroadcast();
        a = address(r);
        console2.log("AnchorRegistry deployed at:", a);
    }
}
