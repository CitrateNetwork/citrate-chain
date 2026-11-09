// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import {AgentDecisionRegistryV2} from "../src/rbac/AgentDecisionRegistryV2.sol";

/// @title DeployAgentDecisionRegistryV2: the agent decision registry alone, for block 0
/// @notice The Hermes features read AgentDecisionRegistryV2 (DeployHupRegistries checks it is
///         in the 40204 book). Its only other deploy script, DeployDpf02Rbac, also deploys the
///         customer RBAC set, which the owner keeps out of block 0 (2026-10-26). This script
///         deploys the registry by itself, through the Arachnid CREATE2 factory, with
///         GOVERNANCE as its governance (the constructor argument, so the deployer never
///         holds it). Same constructor and argument as DeployDpf02Rbac's.
///
///         Recorders are granted by a GOVERNANCE proposal after the ceremony (setRecorder).
///
///         Env: GOVERNANCE (on 40204 not the deployer, with code), CEREMONY_DEPLOYER_ADDRESS
///         or DEPLOYER_ADDRESS. A rerun over a chain where the projection has code reuses it.
contract DeployAgentDecisionRegistryV2 is ScriptEnv, AdminChecks, Create2Deploy {
    function initCode(address governance) public pure returns (bytes memory) {
        return abi.encodePacked(type(AgentDecisionRegistryV2).creationCode, abi.encode(governance));
    }

    function run() external returns (address registry) {
        address deployer = deployerAddress();
        return deployWith(deployer, requiredGovernance("GOVERNANCE", deployer));
    }

    /// Env-free entry point (tests call it directly).
    function deployWith(address deployer, address governance) public returns (address registry) {
        require(deployer != address(0), "deployer required");
        require(block.chainid != 40204 || governance != deployer, "GOVERNANCE must be set to a non-deployer address on 40204");
        require(block.chainid != 40204 || governance.code.length != 0, "GOVERNANCE has no code on this chain");
        bytes memory code = initCode(governance);
        registry = _create2Address("AgentDecisionRegistryV2", code);

        if (!_isLive("AgentDecisionRegistryV2", code)) {
            vm.startBroadcast(deployer);
            address got = address(new AgentDecisionRegistryV2{salt: Salts.salt("AgentDecisionRegistryV2")}(governance));
            vm.stopBroadcast();
            require(got == registry, "AgentDecisionRegistryV2 landed off its CREATE2 projection");
        }

        _assertGovernance("AgentDecisionRegistryV2", registry, governance);
        _assertNoDeployerAdmin("AgentDecisionRegistryV2", registry, deployer);
        _assertNoFactoryAdmin("AgentDecisionRegistryV2", registry);
        console.log("AgentDecisionRegistryV2:", registry);
        console.log("Governance:             ", governance);
    }
}
