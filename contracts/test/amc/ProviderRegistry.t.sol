// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AmcTestBase} from "./AmcTestBase.sol";
import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {Governable} from "../../src/lib/Governable.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract ProviderRegistryTest is AmcTestBase {
    uint64 internal constant VETO = 24 hours;

    ProviderRegistry internal reg;
    bytes32 internal openai;
    bytes32 internal constant HOSTS =
        keccak256('{"id":"openai","base":"https://api.openai.com","paths":["/v1/responses"]}');
    bytes32 internal constant POLICY = keccak256("policy-openai-r1");

    function setUp() public {
        vm.warp(1_800_000_000);
        _deployTimelock();
        reg = new ProviderRegistry(address(timelock), guardian, VETO);
        openai = reg.providerIdOf("openai");
    }

    function _propose(bytes32 id, bytes32 hostsC) internal {
        _govCall(
            address(reg),
            abi.encodeCall(ProviderRegistry.proposeListing, (id, ProviderRegistry.Kind.Vendor, hostsC, POLICY))
        );
    }

    function _list(bytes32 id) internal {
        _propose(id, HOSTS);
        vm.warp(vm.getBlockTimestamp() + VETO);
        vm.prank(stranger);
        reg.finalizeListing(id);
    }

    function _status(bytes32 id) internal view returns (uint8) {
        return uint8(reg.statusOf(id));
    }

    // ------------------------------------------------------------------ construction

    function test_constructorChecks() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        new ProviderRegistry(address(0), guardian, VETO);
        vm.expectRevert(Governable.Governable_Create2Factory.selector);
        new ProviderRegistry(InitialAdmin.CREATE2_FACTORY, guardian, VETO);
        vm.expectRevert(InitialAdmin.InitialAdmin_Zero.selector);
        new ProviderRegistry(address(timelock), address(0), VETO);
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new ProviderRegistry(address(timelock), InitialAdmin.CREATE2_FACTORY, VETO);
        vm.expectRevert(ProviderRegistry.GuardianIsGovernance.selector);
        new ProviderRegistry(address(timelock), address(timelock), VETO);
        vm.expectRevert(ProviderRegistry.BadVetoWindow.selector);
        new ProviderRegistry(address(timelock), guardian, 1 hours - 1);
        vm.expectRevert(ProviderRegistry.BadVetoWindow.selector);
        new ProviderRegistry(address(timelock), guardian, 7 days + 1);
        assertEq(reg.vetoWindow(), VETO);
        assertEq(reg.governance(), address(timelock));
        assertEq(reg.guardian(), guardian);
    }

    function test_providerIdIsDomainSeparated() public view {
        assertEq(openai, keccak256(abi.encodePacked("citrate.provider.v1:", "openai")));
        assertTrue(openai != keccak256(bytes("openai")));
    }

    // ------------------------------------------------------------------ listing lifecycle

    function test_listingWaitsTimelockThenVetoWindow() public {
        bytes memory data =
            abi.encodeCall(ProviderRegistry.proposeListing, (openai, ProviderRegistry.Kind.Vendor, HOSTS, POLICY));
        (, bytes32 salt) = _govSchedule(address(reg), data);
        vm.warp(vm.getBlockTimestamp() + GOV_DELAY - 1);
        vm.prank(govMultisig);
        vm.expectRevert(); // TimelockUnexpectedOperationState: not ready
        timelock.execute(address(reg), 0, data, bytes32(0), salt);
        vm.warp(vm.getBlockTimestamp() + 1);
        vm.prank(govMultisig);
        timelock.execute(address(reg), 0, data, bytes32(0), salt);

        assertEq(_status(openai), uint8(ProviderRegistry.Status.PendingListing));
        ProviderRegistry.Provider memory p = reg.get(openai);
        assertEq(p.vetoEndsAt, uint64(vm.getBlockTimestamp()) + VETO);
        assertEq(p.hostsCommitment, HOSTS);
        assertEq(p.policyCommitment, POLICY);
        assertFalse(reg.isListedWith(openai, HOSTS), "pending is not usable");

        vm.warp(vm.getBlockTimestamp() + VETO - 1);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.VetoWindowOpen.selector, p.vetoEndsAt));
        reg.finalizeListing(openai);
        vm.warp(vm.getBlockTimestamp() + 1);
        vm.prank(stranger); // permissionless liveness
        reg.finalizeListing(openai);
        assertEq(_status(openai), uint8(ProviderRegistry.Status.Listed));
        assertTrue(reg.isListedWith(openai, HOSTS));
        assertEq(reg.get(openai).listedAt, vm.getBlockTimestamp());
        assertEq(reg.get(openai).vetoEndsAt, 0);
    }

    function test_hostCommitmentMismatchIsNotUsable() public {
        _list(openai);
        assertFalse(reg.isListedWith(openai, keccak256("core build with a different host list")));
        assertFalse(reg.isListedWith(openai, bytes32(0)));
        assertFalse(reg.isListedWith(reg.providerIdOf("anthropic"), HOSTS));
    }

    function test_guardianVetoesAPendingListing() public {
        _propose(openai, HOSTS);
        vm.prank(guardian);
        reg.veto(openai, 7);
        assertEq(_status(openai), uint8(ProviderRegistry.Status.Unlisted));
        assertEq(reg.get(openai).reasonCode, 7);
        vm.warp(vm.getBlockTimestamp() + VETO);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Unlisted));
        reg.finalizeListing(openai);
        // Governance may propose again; it waits the full path again.
        _propose(openai, HOSTS);
        assertEq(_status(openai), uint8(ProviderRegistry.Status.PendingListing));
    }

    function test_vetoOnlyWhilePending() public {
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Unlisted));
        reg.veto(openai, 1);
        _list(openai);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Listed));
        reg.veto(openai, 1);
    }

    function test_emergencyDelistIsImmediateAndSticky() public {
        _list(openai);
        vm.prank(guardian);
        reg.emergencyDelist(openai, 42);
        assertEq(_status(openai), uint8(ProviderRegistry.Status.EmergencyDelisted));
        assertFalse(reg.isListedWith(openai, HOSTS));
        // No shortcut back to Listed.
        vm.expectRevert(
            abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.EmergencyDelisted)
        );
        reg.finalizeListing(openai);
        vm.prank(address(timelock));
        vm.expectRevert(
            abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.EmergencyDelisted)
        );
        reg.updateCommitments(openai, HOSTS, POLICY);
        // Relisting is a fresh proposal: timelock, then the veto window.
        _propose(openai, HOSTS);
        assertFalse(reg.isListedWith(openai, HOSTS));
        vm.warp(vm.getBlockTimestamp() + VETO);
        reg.finalizeListing(openai);
        assertTrue(reg.isListedWith(openai, HOSTS));
    }

    function test_emergencyDelistOnlyFromListed() public {
        _propose(openai, HOSTS);
        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.PendingListing)
        );
        reg.emergencyDelist(openai, 1);
    }

    function test_updateCommitmentsGoesBackThroughPending() public {
        _list(openai);
        bytes32 newHosts = keccak256("openai-v2-hosts");
        _govCall(address(reg), abi.encodeCall(ProviderRegistry.updateCommitments, (openai, newHosts, POLICY)));
        assertEq(_status(openai), uint8(ProviderRegistry.Status.PendingListing));
        assertFalse(reg.isListedWith(openai, HOSTS));
        assertFalse(reg.isListedWith(openai, newHosts));
        vm.prank(guardian);
        reg.veto(openai, 3);
        assertEq(_status(openai), uint8(ProviderRegistry.Status.Unlisted));
    }

    function test_delistTransitions() public {
        _list(openai);
        vm.prank(address(timelock));
        reg.delist(openai, 9);
        assertEq(_status(openai), uint8(ProviderRegistry.Status.Delisted));
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Delisted));
        reg.delist(openai, 9);

        bytes32 xai = reg.providerIdOf("xai");
        _propose(xai, HOSTS);
        vm.prank(address(timelock));
        reg.delist(xai, 1); // a pending listing can be withdrawn
        assertEq(_status(xai), uint8(ProviderRegistry.Status.Delisted));
        assertEq(reg.get(xai).vetoEndsAt, 0);

        bytes32 meta = reg.providerIdOf("meta");
        _list(meta);
        vm.prank(guardian);
        reg.emergencyDelist(meta, 1);
        vm.prank(address(timelock));
        reg.delist(meta, 2); // governance confirms an emergency delist
        assertEq(_status(meta), uint8(ProviderRegistry.Status.Delisted));

        bytes32 gemini = reg.providerIdOf("gemini");
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Unlisted));
        reg.delist(gemini, 1);
    }

    function test_proposeRefusedWhilePendingOrListedAndZeroInputs() public {
        vm.startPrank(address(timelock));
        reg.proposeListing(openai, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        vm.expectRevert(
            abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.PendingListing)
        );
        reg.proposeListing(openai, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        vm.warp(vm.getBlockTimestamp() + VETO);
        reg.finalizeListing(openai);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.WrongStatus.selector, ProviderRegistry.Status.Listed));
        reg.proposeListing(openai, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        bytes32 x = reg.providerIdOf("xai");
        vm.expectRevert(ProviderRegistry.ZeroCommitment.selector);
        reg.proposeListing(x, ProviderRegistry.Kind.Vendor, bytes32(0), POLICY);
        vm.expectRevert(ProviderRegistry.ZeroCommitment.selector);
        reg.proposeListing(x, ProviderRegistry.Kind.Vendor, HOSTS, bytes32(0));
        vm.expectRevert(ProviderRegistry.ZeroProviderId.selector);
        reg.proposeListing(bytes32(0), ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        vm.stopPrank();
    }

    function test_delegateKind() public {
        bytes32 cognition = reg.providerIdOf("cognition");
        _govCall(
            address(reg),
            abi.encodeCall(ProviderRegistry.proposeListing, (cognition, ProviderRegistry.Kind.Delegate, HOSTS, POLICY))
        );
        assertEq(uint8(reg.get(cognition).kind), uint8(ProviderRegistry.Kind.Delegate));
    }

    // ------------------------------------------------------------------ access control

    function test_onlyGovernanceForGovernanceFunctions() public {
        _list(openai);
        bytes32 xai = reg.providerIdOf("xai");
        address[3] memory callers = [govMultisig, guardian, stranger];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.startPrank(callers[i]);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            reg.proposeListing(xai, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            reg.updateCommitments(openai, HOSTS, POLICY);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            reg.delist(openai, 1);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            reg.setGuardian(stranger);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            reg.transferGovernance(stranger);
            vm.stopPrank();
        }
    }

    function test_onlyGuardianForVetoAndEmergency() public {
        _list(openai);
        address[3] memory callers = [address(timelock), govMultisig, stranger];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.startPrank(callers[i]);
            vm.expectRevert(ProviderRegistry.NotGuardian.selector);
            reg.emergencyDelist(openai, 1);
            vm.expectRevert(ProviderRegistry.NotGuardian.selector);
            reg.veto(openai, 1);
            vm.stopPrank();
        }
    }

    /// RT-15: the guardian has no timelock role, so it cannot cancel its own replacement.
    function test_guardianCannotBlockItsReplacement() public {
        address next = makeAddr("nextGuardian");
        bytes memory data = abi.encodeCall(ProviderRegistry.setGuardian, (next));
        (bytes32 id, bytes32 salt) = _govSchedule(address(reg), data);
        assertFalse(timelock.hasRole(timelock.CANCELLER_ROLE(), guardian));
        assertFalse(timelock.hasRole(timelock.PROPOSER_ROLE(), guardian));
        assertFalse(timelock.hasRole(timelock.EXECUTOR_ROLE(), guardian));
        bytes32 cancellerRole = timelock.CANCELLER_ROLE();
        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, cancellerRole)
        );
        timelock.cancel(id);
        vm.warp(vm.getBlockTimestamp() + GOV_DELAY);
        vm.prank(govMultisig);
        timelock.execute(address(reg), 0, data, bytes32(0), salt);
        assertEq(reg.guardian(), next);
        _list(openai);
        vm.prank(guardian);
        vm.expectRevert(ProviderRegistry.NotGuardian.selector);
        reg.emergencyDelist(openai, 1);
        vm.prank(next);
        reg.emergencyDelist(openai, 1);
    }

    function test_setGuardianRefusesGovernanceAndFactory() public {
        vm.startPrank(address(timelock));
        vm.expectRevert(ProviderRegistry.GuardianIsGovernance.selector);
        reg.setGuardian(address(timelock));
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        reg.setGuardian(InitialAdmin.CREATE2_FACTORY);
        vm.stopPrank();
    }

    function test_governanceTransferIsTwoStepAndGuardianCannotAccept() public {
        address nextGov = makeAddr("nextGovernance");
        _govCall(address(reg), abi.encodeCall(Governable.transferGovernance, (nextGov)));
        assertEq(reg.governance(), address(timelock));
        vm.prank(guardian);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        reg.acceptGovernance();
        vm.prank(nextGov);
        reg.acceptGovernance();
        assertEq(reg.governance(), nextGov);
    }

    function test_holdsNoValue() public {
        _assertRejectsValue(address(reg));
    }

    // ------------------------------------------------------------------ reads

    function test_providerIdsPagingAndNoDuplicateOnRelist() public {
        string[7] memory ids = ["openai", "anthropic", "gemini", "xai", "deepseek", "meta", "cognition"];
        vm.startPrank(address(timelock));
        for (uint256 i = 0; i < ids.length; i++) {
            reg.proposeListing(reg.providerIdOf(ids[i]), ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        }
        reg.delist(openai, 1);
        reg.proposeListing(openai, ProviderRegistry.Kind.Vendor, HOSTS, POLICY);
        vm.stopPrank();
        assertEq(reg.providerCount(), 7);
        bytes32[] memory page = reg.providerIds(5, 10);
        assertEq(page.length, 2);
        assertEq(page[1], reg.providerIdOf("cognition"));
        assertEq(reg.providerIds(7, 1).length, 0);
        assertEq(reg.providerIds(0, type(uint256).max).length, 7);
    }

    function testFuzz_finalizeOnlyAtOrAfterVetoEnd(uint64 wait) public {
        wait = uint64(bound(wait, 0, 3 * VETO));
        _propose(openai, HOSTS);
        uint64 ends = reg.get(openai).vetoEndsAt;
        vm.warp(vm.getBlockTimestamp() + wait);
        if (vm.getBlockTimestamp() < ends) {
            vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.VetoWindowOpen.selector, ends));
        }
        reg.finalizeListing(openai);
    }

    function testFuzz_strangerHasNoWritePath(address who, uint16 reason) public {
        vm.assume(who != guardian && who != address(timelock));
        _list(openai);
        vm.startPrank(who);
        vm.expectRevert(ProviderRegistry.NotGuardian.selector);
        reg.emergencyDelist(openai, reason);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.delist(openai, reason);
        vm.stopPrank();
        assertTrue(reg.isListedWith(openai, HOSTS));
    }
}

/// Random interleavings of every registry action by governance, guardian and anyone, checked
/// against a reference model of the 06 section 2 state machine.
contract ProviderRegistryHandler is Test {
    ProviderRegistry public reg;
    address public gov;
    address public grd;
    bytes32[3] public ids;

    mapping(bytes32 => ProviderRegistry.Status) public model;
    mapping(bytes32 => uint64) public modelVetoEnds;
    bool public violation;
    string public why;

    constructor(ProviderRegistry reg_, address gov_, address grd_) {
        reg = reg_;
        gov = gov_;
        grd = grd_;
        ids = [keccak256("p0"), keccak256("p1"), keccak256("p2")];
    }

    function _flag(string memory w) internal {
        violation = true;
        why = w;
    }

    function warp(uint32 dt) external {
        vm.warp(vm.getBlockTimestamp() + bound(dt, 0, 2 days));
    }

    function propose(uint256 i) external {
        bytes32 id = ids[i % 3];
        ProviderRegistry.Status s = model[id];
        vm.prank(gov);
        try reg.proposeListing(id, ProviderRegistry.Kind.Vendor, keccak256("h"), keccak256("p")) {
            if (s == ProviderRegistry.Status.PendingListing || s == ProviderRegistry.Status.Listed) {
                _flag("propose from pending/listed");
            }
            model[id] = ProviderRegistry.Status.PendingListing;
            modelVetoEnds[id] = uint64(vm.getBlockTimestamp()) + reg.vetoWindow();
        } catch {
            if (s != ProviderRegistry.Status.PendingListing && s != ProviderRegistry.Status.Listed) {
                _flag("propose refused from an allowed state");
            }
        }
    }

    function update(uint256 i) external {
        bytes32 id = ids[i % 3];
        ProviderRegistry.Status s = model[id];
        vm.prank(gov);
        try reg.updateCommitments(id, keccak256("h2"), keccak256("p2")) {
            if (s != ProviderRegistry.Status.Listed) _flag("update from non-listed");
            model[id] = ProviderRegistry.Status.PendingListing;
            modelVetoEnds[id] = uint64(vm.getBlockTimestamp()) + reg.vetoWindow();
        } catch {
            if (s == ProviderRegistry.Status.Listed) _flag("update refused while listed");
        }
    }

    function finalize(uint256 i, address anyone) external {
        bytes32 id = ids[i % 3];
        ProviderRegistry.Status s = model[id];
        vm.prank(anyone);
        try reg.finalizeListing(id) {
            if (s != ProviderRegistry.Status.PendingListing) _flag("finalize from non-pending");
            if (vm.getBlockTimestamp() < modelVetoEnds[id]) _flag("finalized inside the veto window");
            model[id] = ProviderRegistry.Status.Listed;
        } catch {
            if (s == ProviderRegistry.Status.PendingListing && vm.getBlockTimestamp() >= modelVetoEnds[id]) {
                _flag("finalize refused after the window");
            }
        }
    }

    function veto(uint256 i) external {
        bytes32 id = ids[i % 3];
        ProviderRegistry.Status s = model[id];
        vm.prank(grd);
        try reg.veto(id, 1) {
            if (s != ProviderRegistry.Status.PendingListing) _flag("veto from non-pending");
            model[id] = ProviderRegistry.Status.Unlisted;
        } catch {
            if (s == ProviderRegistry.Status.PendingListing) _flag("veto refused while pending");
        }
    }

    function emergency(uint256 i) external {
        bytes32 id = ids[i % 3];
        ProviderRegistry.Status s = model[id];
        vm.prank(grd);
        try reg.emergencyDelist(id, 1) {
            if (s != ProviderRegistry.Status.Listed) _flag("emergency delist from non-listed");
            model[id] = ProviderRegistry.Status.EmergencyDelisted;
        } catch {
            if (s == ProviderRegistry.Status.Listed) _flag("emergency delist refused while listed");
        }
    }

    function delist(uint256 i) external {
        bytes32 id = ids[i % 3];
        ProviderRegistry.Status s = model[id];
        vm.prank(gov);
        try reg.delist(id, 1) {
            if (s == ProviderRegistry.Status.Unlisted || s == ProviderRegistry.Status.Delisted) {
                _flag("delist from unlisted/delisted");
            }
            model[id] = ProviderRegistry.Status.Delisted;
        } catch {
            if (s != ProviderRegistry.Status.Unlisted && s != ProviderRegistry.Status.Delisted) {
                _flag("delist refused");
            }
        }
    }

    /// The guardian and strangers try the governance-only calls; none may succeed.
    function unauthorised(uint256 i, address who) external {
        if (who == gov) return;
        bytes32 id = ids[i % 3];
        vm.startPrank(who);
        try reg.proposeListing(id, ProviderRegistry.Kind.Vendor, keccak256("h"), keccak256("p")) {
            _flag("non-governance proposed");
        } catch {}
        try reg.delist(id, 1) {
            _flag("non-governance delisted");
        } catch {}
        try reg.setGuardian(who) {
            _flag("non-governance set the guardian");
        } catch {}
        vm.stopPrank();
    }
}

contract ProviderRegistryInvariantTest is Test {
    ProviderRegistry internal reg;
    ProviderRegistryHandler internal handler;
    address internal gov = makeAddr("gov");
    address internal grd = makeAddr("grd");

    function setUp() public {
        vm.warp(1_800_000_000);
        reg = new ProviderRegistry(gov, grd, 24 hours);
        handler = new ProviderRegistryHandler(reg, gov, grd);
        targetContract(address(handler));
    }

    function invariant_matchesStateMachineModel() public view {
        assertFalse(handler.violation(), handler.why());
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = handler.ids(i);
            assertEq(uint8(reg.statusOf(id)), uint8(handler.model(id)));
            if (reg.statusOf(id) == ProviderRegistry.Status.PendingListing) {
                assertEq(reg.get(id).vetoEndsAt, handler.modelVetoEnds(id));
            } else {
                assertEq(reg.get(id).vetoEndsAt, 0);
            }
        }
    }

    function invariant_rolesNeverMove() public view {
        assertEq(reg.governance(), gov);
        assertEq(reg.guardian(), grd);
        assertEq(reg.pendingGovernance(), address(0));
    }

    function invariant_holdsNoValue() public view {
        assertEq(address(reg).balance, 0);
    }
}
