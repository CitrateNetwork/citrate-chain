// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {AnchorRegistry} from "../src/cit_agent/AnchorRegistry.sol";
import {LegacyDeployGuard} from "./LegacyDeployGuard.sol";

/// Deploys `AnchorRegistry`, which citrate-quorum's address-book test requires
/// to be present in the main book and which the reroll left unbooked.
///
/// RETIRED on chain 40204 (HUP-S7.1): the redeploy set in
/// `script/DeployHupRegistries.s.sol` replaces this AnchorRegistry version. `run()`
/// reverts on 40204 and still deploys on a local chain.
contract DeployAnchorRegistry is Script {
    function run() external returns (address a) {
        LegacyDeployGuard.refuseOnCitrate("DeployAnchorRegistry");
        vm.startBroadcast();
        AnchorRegistry r = new AnchorRegistry();
        vm.stopBroadcast();
        a = address(r);
        console2.log("AnchorRegistry deployed at:", a);
    }
}
