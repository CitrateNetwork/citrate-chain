// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../script/DeployAgentDecisionRegistryV2.s.sol";
import "../../script/Salts.sol";

/// The block-0 AgentDecisionRegistryV2: CREATE2 through the Arachnid factory, governed by
/// GOVERNANCE from its constructor, the deployer holding nothing; on 40204 the deployer or a
/// codeless address is refused as governance before anything is sent.
contract DeployAgentDecisionRegistryV2Test is Test {
    DeployAgentDecisionRegistryV2 internal script;
    address internal deployer;
    address internal governance;
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function setUp() public {
        script = new DeployAgentDecisionRegistryV2();
        deployer = makeAddr("deployer");
        governance = makeAddr("governance-timelock");
        vm.etch(governance, hex"00");
    }

    function _projection(address gov) internal view returns (address) {
        return vm.computeCreate2Address(Salts.salt("AgentDecisionRegistryV2"), keccak256(script.initCode(gov)), FACTORY);
    }

    function test_deploy_landsOnProjection_governedByGovernance() public {
        address r = script.deployWith(deployer, governance);
        assertEq(r, _projection(governance), "CREATE2 projection");
        assertGt(r.code.length, 0, "code");
        assertEq(AgentDecisionRegistryV2(r).governance(), governance, "governance");
        assertTrue(AgentDecisionRegistryV2(r).governance() != deployer, "deployer is not governance");
    }

    function test_deploy_isIdempotent_rerunReuses() public {
        address r1 = script.deployWith(deployer, governance);
        uint256 n = vm.getNonce(deployer);
        address r2 = script.deployWith(deployer, governance);
        assertEq(r1, r2, "same address");
        assertEq(vm.getNonce(deployer), n, "a rerun sends nothing");
    }

    function test_deploy_onlyGovernanceAdministers() public {
        address r = script.deployWith(deployer, governance);
        vm.prank(deployer);
        vm.expectRevert();
        AgentDecisionRegistryV2(r).setRecorder(deployer, true);
        vm.prank(governance);
        AgentDecisionRegistryV2(r).setRecorder(makeAddr("recorder"), true);
    }

    function test_on40204_deployerAsGovernance_refused() public {
        vm.chainId(40204);
        vm.etch(deployer, hex"00");
        vm.expectRevert(bytes("GOVERNANCE must be set to a non-deployer address on 40204"));
        script.deployWith(deployer, deployer);
    }

    function test_on40204_codelessGovernance_refused() public {
        vm.chainId(40204);
        vm.expectRevert(bytes("GOVERNANCE has no code on this chain"));
        script.deployWith(deployer, makeAddr("eoa-governance"));
    }

    /// Negative control: the projection depends on governance, so another governance is
    /// another address (a book entry cannot be satisfied by a registry governed elsewhere).
    function test_projection_dependsOnGovernance() public {
        assertTrue(_projection(governance) != _projection(makeAddr("other")), "governance is in the init code");
    }
}
