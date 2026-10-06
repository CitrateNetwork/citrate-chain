// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";

import "../src/edu/ai-gateway/AIInferenceRouterPortable.sol";
import "../src/edu/ai-gateway/AILearningCycleCorePortable.sol";

/**
 * @title RedeployPortableGov
 * @notice Re-deploys ONLY the two governance-bearing portable AI Gateway
 *         contracts (L2 router + L3 learning cycle) so their
 *         constructor-immutable `governance` points at the R2 multisig
 *         instead of the deployer EOA. The L0/L1 AIModelRegistryPortable is
 *         NOT redeployed (it has no governance arg and its CREATE2 address is
 *         already occupied); the existing registry address is reused.
 *
 *         Because `governance` is a constructor arg, changing it changes the
 *         CREATE2 init code hash, so these deploy to NEW addresses. The old
 *         deployer-governed instances are abandoned (no live state / no users).
 *
 * Run:
 *   REGISTRY=0x... GOVERNANCE=0x... forge script script/RedeployPortableGov.s.sol \
 *     --rpc-url $RPC --private-key $DEPLOYER_PRIVATE_KEY --broadcast
 */
contract RedeployPortableGov is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();
        address governance = requiredGovernance("GOVERNANCE", deployer);
        address registry = vm.envAddress("REGISTRY");

        require(governance != deployer, "GOVERNANCE must be the multisig, not the deployer");
        require(registry.code.length > 0, "REGISTRY has no code");

        console.log("Deployer:  ", deployer);
        console.log("Governance:", governance);
        console.log("Registry:  ", registry);

        vm.startBroadcast();

        AIInferenceRouterPortable router = new AIInferenceRouterPortable{salt: Salts.salt("AIInferenceRouterPortable")}(
            registry,
            governance
        );
        console.log("AIInferenceRouterPortable (L2):", address(router));

        AILearningCycleCorePortable learningCycle = new AILearningCycleCorePortable{salt: Salts.salt("AILearningCycleCorePortable")}(governance);
        console.log("AILearningCycleCorePortable (L3):", address(learningCycle));

        vm.stopBroadcast();

        require(router.governance() == governance, "router governance mismatch");
        require(learningCycle.governance() == governance, "learningCycle governance mismatch");
        console.log("OK: both governance() == multisig");
    }
}
