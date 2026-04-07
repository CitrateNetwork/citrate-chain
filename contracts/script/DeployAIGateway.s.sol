// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";

import "../src/edu/ai-gateway/AIModelRegistryPortable.sol";
import "../src/edu/ai-gateway/AIInferenceRouterPortable.sol";
import "../src/edu/ai-gateway/AILearningCycleCorePortable.sol";

/**
 * @title DeployAIGateway
 * @notice Deploys the portable AI Gateway EIP contracts.
 *         These implement the L0-L3 interfaces from the EIP spec as pure Solidity,
 *         deployable on any EVM chain (Ethereum, Citrate, Arbitrum, etc.).
 *
 * Run:
 *   forge script script/DeployAIGateway.s.sol \
 *     --rpc-url http://localhost:8545 \
 *     --account ceremony-deployer \
 *     --sender $DEPLOYER_ADDRESS \
 *     --broadcast -vvvv
 */
contract DeployAIGateway is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);

        console.log("=== Deploying AI Gateway (Portable) ===");
        console.log("Deployer:", deployer);
        console.log("Governance:", governance);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast();

        // L0 + L1: Model Registry (includes IAIBackendCapabilities)
        AIModelRegistryPortable registry = new AIModelRegistryPortable();
        console.log("AIModelRegistryPortable (L0+L1):", address(registry));

        // L2: Inference Router
        AIInferenceRouterPortable router = new AIInferenceRouterPortable(
            address(registry),
            governance
        );
        console.log("AIInferenceRouterPortable (L2):", address(router));

        // L3: Learning Cycle Core
        AILearningCycleCorePortable learningCycle = new AILearningCycleCorePortable(governance);
        console.log("AILearningCycleCorePortable (L3):", address(learningCycle));

        vm.stopBroadcast();

        console.log("");
        console.log("=== AI Gateway Deployed ===");
        console.log("Profile: PortableWasm (L0)");
        console.log("ERC-165 supported: IAIModelRegistry, IAIBackendCapabilities");
    }
}
