// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {RegistryGuardian2of3} from "../../src/amc/RegistryGuardian2of3.sol";
import {DeployRegistryGuardian} from "../../script/DeployRegistryGuardian.s.sol";
import {Salts} from "../../script/Salts.sol";

/// GEN-GUARD-ROTATE on r1007 (owner 2026-11-15): the seat's deploy and the GOVERNANCE
/// `setGuardian` proposal both wait for the canceller swap, the seat lands at its predicted
/// CREATE2 address, and the proposal, run through the 48 h timelock, seats it on the registry.
contract DeployRegistryGuardianTest is Test {
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address council = makeAddr("council");
    address grdTimelock = makeAddr("guardian-timelock");
    address v1 = makeAddr("canceller-v1");
    address v2 = makeAddr("canceller-v2");
    TimelockController tl;
    ProviderRegistry reg;
    DeployRegistryGuardian s;
    DeployRegistryGuardian.Inputs i;

    function setUp() public {
        address[] memory one = new address[](1);
        one[0] = council;
        tl = new TimelockController(48 hours, one, one, address(this));
        tl.grantRole(tl.CANCELLER_ROLE(), v1); // r1007 today: v1 is the extra canceller
        reg = new ProviderRegistry(address(tl), grdTimelock, 24 hours);
        s = new DeployRegistryGuardian();
        i = DeployRegistryGuardian.Inputs({
            registry: address(reg),
            governanceTimelock: address(tl),
            cancellerV1: v1,
            cancellerV2: v2,
            owner0: makeAddr("rg1"),
            owner1: makeAddr("rg2"),
            owner2: makeAddr("rg3")
        });
    }

    function _swap() internal {
        tl.grantRole(tl.CANCELLER_ROLE(), v2);
        tl.revokeRole(tl.CANCELLER_ROLE(), v1);
    }

    function _deploySeatViaFactory() internal returns (address seat) {
        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(Salts.salt("r1007.RegistryGuardian2of3"), s.seatInit(i)));
        require(ok, "factory deploy failed");
        seat = address(bytes20(ret));
    }

    function test_everything_waits_for_the_canceller_swap() public {
        vm.expectRevert(bytes("the canceller swap has not executed: v2 must hold CANCELLER and v1 must not"));
        s.checkPreconditions(i);
        vm.expectRevert(bytes("the canceller swap has not executed: v2 must hold CANCELLER and v1 must not"));
        s.buildProposal(i);
        _swap();
        s.checkPreconditions(i);
    }

    function test_the_proposal_needs_the_seat_deployed_first() public {
        _swap();
        vm.expectRevert(bytes("RegistryGuardian2of3: no code"));
        s.buildProposal(i);
    }

    function test_seat_lands_at_its_prediction_and_governance_seats_it_after_48h() public {
        _swap();
        address seat = _deploySeatViaFactory();
        assertEq(seat, s.predictSeat(i), "the factory deploy is the predicted seat");
        s.verifySeat(i, seat);
        RegistryGuardian2of3 g = RegistryGuardian2of3(seat);
        assertEq(address(g.registry()), address(reg));

        (bytes memory scheduleData, bytes memory executeData, bytes32 opId) = s.buildProposal(i);
        vm.prank(council);
        (bool ok,) = address(tl).call(scheduleData);
        assertTrue(ok, "schedule");
        assertTrue(tl.isOperationPending(opId));
        vm.warp(block.timestamp + 48 hours - 1);
        vm.prank(council);
        (ok,) = address(tl).call(executeData);
        assertFalse(ok, "no execute before the delay");
        vm.warp(block.timestamp + 1);
        vm.prank(council);
        (ok,) = address(tl).call(executeData);
        assertTrue(ok, "execute");
        assertEq(reg.guardian(), seat);

        // Built again once seated, the proposal is refused (nothing to rotate).
        vm.expectRevert(bytes("the registry's guardian is already the seat"));
        s.buildProposal(i);
    }

    function test_a_registry_under_another_governance_is_refused() public {
        _swap();
        ProviderRegistry other = new ProviderRegistry(makeAddr("not-gov"), grdTimelock, 24 hours);
        i.registry = address(other);
        vm.expectRevert(bytes("ProviderRegistry: governance is not GOVERNANCE_TIMELOCK"));
        s.checkPreconditions(i);
    }
}
