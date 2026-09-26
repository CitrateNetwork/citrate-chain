// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {AgentDecisionRegistry} from "../../src/AgentDecisionRegistry.sol";
import {SpecRegistry} from "../../src/SpecRegistry.sol";
import {MarketMakerAllocation} from "../../src/MarketMakerAllocation.sol";

/// Keep-live pins in DeployAll (owner decision D2 = KEEP): on 40204 the live
/// AgentDecisionRegistry / SpecRegistry / MarketMakerAllocation are reused,
/// elsewhere the normal reuse-or-deploy path runs.
contract PBA_R2_DeployAllKeepLive is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant LIVE_ADR = 0xd4008e0B4f0bD00d630810D1f7f0F78Db0BA837a;
    address constant LIVE_SPEC = 0x8cE7000C83D0ef5276A70BDC34bF2fa2FE0159ff;
    address constant LIVE_MMA = 0xfCC747D35d616c48bddef98a31B7e8ebC8786864;
    address multisig = makeAddr("multisig");

    /// Place a real instance's runtime code + first storage slots at `live`,
    /// standing in for the contract already deployed on 40204.
    function _plant(address live, address instance) internal {
        vm.etch(live, instance.code);
        for (uint256 i = 0; i < 16; i++) {
            vm.store(live, bytes32(i), vm.load(instance, bytes32(i)));
        }
    }

    function test_keepLive_on40204_reusesLiveRegistries() public {
        vm.chainId(40204);
        _plant(LIVE_ADR, address(new AgentDecisionRegistry(SENDER)));
        _plant(LIVE_SPEC, address(new SpecRegistry(SENDER)));
        _plant(LIVE_MMA, address(new MarketMakerAllocation(SENDER, SENDER)));

        DeployAll a = new DeployAll();
        DeployAll.Deployed memory d = a.deployWith(SENDER, multisig, multisig);
        assertEq(d.agentRegistry, LIVE_ADR, "AgentDecisionRegistry kept");
        assertEq(d.specRegistry, LIVE_SPEC, "SpecRegistry kept");
        assertEq(d.mmAlloc, LIVE_MMA, "MarketMakerAllocation kept");
        // everything else still deploys
        assertGt(d.registry.code.length, 0);
        assertGt(d.governor.code.length, 0);
    }

    function test_keepLive_on40204_requiresLiveCode() public {
        vm.chainId(40204);
        DeployAll a = new DeployAll();
        vm.expectRevert(bytes("AgentDecisionRegistry: kept live instance has no code"));
        a.deployWith(SENDER, multisig, multisig);
    }

    function test_keepLive_offChain40204_deploysFresh() public {
        DeployAll a = new DeployAll();
        DeployAll.Deployed memory d = a.deployWith(SENDER, multisig, multisig);
        assertTrue(d.agentRegistry != LIVE_ADR);
        assertTrue(d.specRegistry != LIVE_SPEC);
        assertTrue(d.mmAlloc != LIVE_MMA);
        assertGt(d.agentRegistry.code.length, 0);
        assertGt(d.specRegistry.code.length, 0);
        assertGt(d.mmAlloc.code.length, 0);
    }
}
