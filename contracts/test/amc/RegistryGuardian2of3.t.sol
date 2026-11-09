// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AmcTestBase} from "./AmcTestBase.sol";
import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {RegistryGuardian2of3, IProviderRegistryGuardianActions} from "../../src/amc/RegistryGuardian2of3.sol";
import {Governable} from "../../src/lib/Governable.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";

/// Owner decision Q-8(b): the guardian seat is a direct 2-of-3 with no delay that can only
/// remove or pause.
contract RegistryGuardian2of3Test is AmcTestBase {
    uint64 internal constant VETO = 24 hours;
    bytes32 internal constant HOSTS = keccak256("hosts");
    bytes32 internal constant POLICY = keccak256("policy");

    ProviderRegistry internal reg;
    RegistryGuardian2of3 internal g;
    address internal a = makeAddr("g0");
    address internal b = makeAddr("g1");
    address internal c = makeAddr("g2");
    bytes32 internal openai;

    function setUp() public {
        vm.warp(1_800_000_000);
        _deployTimelock();
        reg = new ProviderRegistry(address(timelock), guardian, VETO);
        g = new RegistryGuardian2of3(IProviderRegistryGuardianActions(address(reg)), a, b, c);
        vm.prank(address(timelock));
        reg.setGuardian(address(g));
        openai = reg.providerIdOf("openai");
        _list(openai);
    }

    function _list(bytes32 id) internal {
        vm.prank(address(timelock));
        reg.proposeListing(id, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        vm.warp(vm.getBlockTimestamp() + VETO);
        reg.finalizeListing(id);
    }

    function _run(RegistryGuardian2of3.Action action, bytes32 id) internal {
        vm.prank(a);
        bytes32 pid = g.propose(action, id, 5);
        vm.prank(b);
        g.approve(pid);
    }

    function test_constructorChecks() public {
        IProviderRegistryGuardianActions r = IProviderRegistryGuardianActions(address(reg));
        vm.expectRevert(RegistryGuardian2of3.RegistryHasNoCode.selector);
        new RegistryGuardian2of3(IProviderRegistryGuardianActions(makeAddr("eoa")), a, b, c);
        vm.expectRevert(RegistryGuardian2of3.DuplicateOwner.selector);
        new RegistryGuardian2of3(r, a, a, c);
        vm.expectRevert(InitialAdmin.InitialAdmin_Zero.selector);
        new RegistryGuardian2of3(r, a, b, address(0));
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new RegistryGuardian2of3(r, InitialAdmin.CREATE2_FACTORY, b, c);
    }

    function test_twoOfThreeDelistsWithNoDelay() public {
        uint256 t = vm.getBlockTimestamp();
        vm.prank(a);
        bytes32 pid = g.propose(RegistryGuardian2of3.Action.EmergencyDelist, openai, 9);
        assertTrue(reg.isListedWith(openai, HOSTS), "one approval does nothing");
        vm.prank(c);
        g.approve(pid);
        assertEq(vm.getBlockTimestamp(), t, "same block, no delay");
        assertEq(uint8(reg.statusOf(openai)), uint8(ProviderRegistry.Status.EmergencyDelisted));
        assertEq(reg.get(openai).reasonCode, 9);
        assertTrue(g.getProposal(pid).executed);
    }

    function test_twoOfThreeVetoesAPendingListing() public {
        bytes32 x = reg.providerIdOf("xai");
        vm.prank(address(timelock));
        reg.proposeListing(x, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        _run(RegistryGuardian2of3.Action.Veto, x);
        assertEq(uint8(reg.statusOf(x)), uint8(ProviderRegistry.Status.Unlisted));
    }

    function test_pauseStopsEverythingAndOnlyGovernanceResumes() public {
        bytes32 x = reg.providerIdOf("xai");
        vm.prank(address(timelock));
        reg.proposeListing(x, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        _run(RegistryGuardian2of3.Action.Pause, bytes32(0));
        assertTrue(reg.paused());
        assertFalse(reg.isListedWith(openai, HOSTS), "paused registry lists nothing");
        vm.warp(vm.getBlockTimestamp() + VETO);
        vm.expectRevert(ProviderRegistry.IsPaused.selector);
        reg.finalizeListing(x); // nothing can be added while paused
        vm.prank(address(g));
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.unpause();
        vm.prank(address(timelock));
        reg.unpause();
        assertTrue(reg.isListedWith(openai, HOSTS));
        reg.finalizeListing(x);
        vm.prank(address(timelock));
        vm.expectRevert(ProviderRegistry.NotPaused.selector);
        reg.unpause();
    }

    function test_oneOwnerAloneCannotAct() public {
        vm.startPrank(a);
        bytes32 pid = g.propose(RegistryGuardian2of3.Action.EmergencyDelist, openai, 1);
        vm.expectRevert(RegistryGuardian2of3.AlreadyApproved.selector);
        g.approve(pid);
        vm.stopPrank();
        assertTrue(reg.isListedWith(openai, HOSTS));
    }

    function test_strangersAndExpiryAndReplay() public {
        vm.prank(stranger);
        vm.expectRevert(RegistryGuardian2of3.NotOwner.selector);
        g.propose(RegistryGuardian2of3.Action.Pause, bytes32(0), 1);

        vm.prank(a);
        bytes32 pid = g.propose(RegistryGuardian2of3.Action.EmergencyDelist, openai, 1);
        vm.prank(stranger);
        vm.expectRevert(RegistryGuardian2of3.NotOwner.selector);
        g.approve(pid);

        vm.warp(vm.getBlockTimestamp() + 1 days);
        vm.prank(b);
        vm.expectRevert(RegistryGuardian2of3.Expired.selector);
        g.approve(pid);

        vm.prank(a);
        bytes32 pid2 = g.propose(RegistryGuardian2of3.Action.EmergencyDelist, openai, 1);
        assertTrue(pid2 != pid, "same action re-proposed gets a fresh id");
        vm.prank(b);
        g.approve(pid2);
        vm.prank(c);
        vm.expectRevert(RegistryGuardian2of3.AlreadyExecuted.selector);
        g.approve(pid2);

        vm.prank(b);
        vm.expectRevert(RegistryGuardian2of3.UnknownProposal.selector);
        g.approve(keccak256("nope"));
    }

    /// A failing registry call reverts the approval, so the proposal is not burned.
    function test_registryRefusalRevertsTheApproval() public {
        bytes32 x = reg.providerIdOf("xai"); // Unlisted: emergencyDelist is refused
        vm.prank(a);
        bytes32 pid = g.propose(RegistryGuardian2of3.Action.EmergencyDelist, x, 1);
        vm.prank(b);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Unlisted));
        g.approve(pid);
        assertFalse(g.getProposal(pid).executed);
    }

    /// Governance replaces the guardian seat; the 2-of-3 cannot block it and loses all power.
    function test_governanceRotatesTheSeat() public {
        RegistryGuardian2of3 next = new RegistryGuardian2of3(
            IProviderRegistryGuardianActions(address(reg)), makeAddr("n0"), makeAddr("n1"), makeAddr("n2")
        );
        _govCall(address(reg), abi.encodeCall(ProviderRegistry.setGuardian, (address(next))));
        assertEq(reg.guardian(), address(next));
        vm.prank(a);
        bytes32 pid = g.propose(RegistryGuardian2of3.Action.Pause, bytes32(0), 1);
        vm.prank(b);
        vm.expectRevert(ProviderRegistry.NotGuardian.selector);
        g.approve(pid);
    }

    function test_holdsNoValue() public {
        _assertRejectsValue(address(g));
    }

    function testFuzz_onlyOwnerPairsExecute(uint8 i, uint8 j) public {
        address[3] memory o = [a, b, c];
        i = uint8(bound(i, 0, 2));
        j = uint8(bound(j, 0, 2));
        vm.prank(o[i]);
        bytes32 pid = g.propose(RegistryGuardian2of3.Action.EmergencyDelist, openai, 1);
        vm.prank(o[j]);
        if (i == j) vm.expectRevert(RegistryGuardian2of3.AlreadyApproved.selector);
        g.approve(pid);
        assertEq(reg.isListedWith(openai, HOSTS), i == j);
    }
}
