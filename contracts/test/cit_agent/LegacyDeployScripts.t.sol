// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../../script/DeployCitAgent.s.sol";
import {DeployAnchorRegistry} from "../../script/DeployAnchorRegistry.s.sol";
import "../../script/DeploySkillRegistry.s.sol";
import "../../script/LegacyDeployGuard.sol";
import "../../src/cit_agent/AnchorRegistry.sol";

/// HUP-S7.1 (federation F-4): the pre-HUP deploy scripts for the registry set are retired
/// on chain 40204. Each one reverts there before it broadcasts anything, with a reason
/// that names the replacement script, and the anchor script still deploys off 40204.
contract LegacyDeployScriptsTest is Test {
    function _expectRetired(string memory script) internal {
        vm.expectRevert(bytes(LegacyDeployGuard.reason(script)));
    }

    function test_reasonNamesTheReplacement() public pure {
        assertEq(
            LegacyDeployGuard.reason("DeployCitAgent"),
            "DeployCitAgent is retired on chain 40204: deploy with script/DeployHupRegistries.s.sol"
            " (docs/ops/HUP_REGISTRY_REDEPLOY_RUNBOOK.md)"
        );
    }

    function test_deployCitAgent_refusesOn40204() public {
        vm.chainId(40204);
        DeployCitAgent script = new DeployCitAgent();
        _expectRetired("DeployCitAgent");
        script.run();
    }

    function test_deployAnchorRegistry_refusesOn40204() public {
        vm.chainId(40204);
        DeployAnchorRegistry script = new DeployAnchorRegistry();
        _expectRetired("DeployAnchorRegistry");
        script.run();
    }

    /// No DEPLOYER_ADDRESS is needed to see the refusal: the guard runs before any env read.
    function test_deploySkillRegistry_refusesOn40204() public {
        vm.chainId(40204);
        DeploySkillRegistry script = new DeploySkillRegistry();
        _expectRetired("DeploySkillRegistry");
        script.run();
    }

    function test_deployAnchorRegistry_stillDeploysOffCitrate() public {
        vm.chainId(31337);
        DeployAnchorRegistry script = new DeployAnchorRegistry();
        address a = script.run();
        assertTrue(a.code.length != 0);
        assertFalse(AnchorRegistry(a).isAnchored(bytes32(uint256(1))));
    }

    function test_guardIsANoOpOffCitrate() public {
        vm.chainId(1);
        LegacyDeployGuard.refuseOnCitrate("DeployCitAgent");
        vm.chainId(31337);
        LegacyDeployGuard.refuseOnCitrate("DeployCitAgent");
    }
}
