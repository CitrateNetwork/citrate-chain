// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/ModelRegistry.sol";
import "../src/WrappedSALT.sol";
import "../src/X402Facilitator.sol";
import "../src/ModelMarketplace.sol";
import "../src/InferenceRouter.sol";

contract Deploy is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();

        vm.startBroadcast();

        // 1. Deploy ModelRegistry
        ModelRegistry registry = new ModelRegistry();
        console.log("ModelRegistry:", address(registry));

        // 2. Deploy WrappedSALT (wSALT)
        WrappedSALT wsalt = new WrappedSALT();
        console.log("WrappedSALT:", address(wsalt));

        // 3. Deploy X402Facilitator (wSALT, treasury=deployer, 100bps=1% fee)
        X402Facilitator facilitator = new X402Facilitator(address(wsalt), deployer, 100);
        console.log("X402Facilitator:", address(facilitator));

        // 4. Deploy ModelMarketplace (registry, treasury=deployer)
        ModelMarketplace marketplace = new ModelMarketplace(address(registry), deployer);
        console.log("ModelMarketplace:", address(marketplace));

        // 5. Deploy InferenceRouter
        InferenceRouter router = new InferenceRouter(address(registry));
        console.log("InferenceRouter:", address(router));

        vm.stopBroadcast();

        console.log("---");
        console.log("All contracts deployed to chain", block.chainid);
    }
}
