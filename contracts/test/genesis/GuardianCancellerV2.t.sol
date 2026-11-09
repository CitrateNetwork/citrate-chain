// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GuardianCanceller} from "../../src/genesis/GuardianCanceller.sol";
import {GuardianCancellerV2} from "../../src/genesis/GuardianCancellerV2.sol";
import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {RegistryGuardian2of3, IProviderRegistryGuardianActions} from "../../src/amc/RegistryGuardian2of3.sol";
import {Salts} from "../../script/Salts.sol";

/// @title GuardianCancellerV2.t: the 0.6.0 ceremony-genesis canceller (owner decision V60-GEN-Q21)
/// @notice Built on the block-0 configuration of V60-GEN-Q9: a real GOVERNANCE TimelockController,
///         GuardianCancellerV2 holding its CANCELLER_ROLE, and the GUARDIAN council as guardian
///         of both the canceller and ProviderRegistry. Governance's post-genesis rotation of the
///         registry seat to RegistryGuardian2of3 must be outside the council's veto; every other
///         operation the council could cancel under v1 stays cancellable.
contract GuardianCancellerV2Test is Test {
    TimelockController internal tl;
    GuardianCancellerV2 internal c;
    ProviderRegistry internal registry;
    RegistryGuardian2of3 internal seat;

    address internal gov = makeAddr("governance-multisig");
    address internal council = makeAddr("guardian-council");
    bytes32 internal canceller;

    function setUp() public {
        address[] memory g = new address[](1);
        g[0] = gov;
        tl = new TimelockController(48 hours, g, g, address(0));
        registry = new ProviderRegistry(address(tl), council, 24 hours);
        c = new GuardianCancellerV2(address(tl), council, address(registry));
        canceller = tl.CANCELLER_ROLE();
        vm.prank(address(tl));
        tl.grantRole(canceller, address(c));
        seat = new RegistryGuardian2of3(
            IProviderRegistryGuardianActions(address(registry)), makeAddr("o0"), makeAddr("o1"), makeAddr("o2")
        );
    }

    // ── helpers ────────────────────────────────────────────────────

    function _schedule(address target, bytes memory data, bytes32 salt) internal returns (bytes32 id) {
        vm.prank(gov);
        tl.schedule(target, 0, data, bytes32(0), salt, 48 hours);
        id = tl.hashOperation(target, 0, data, bytes32(0), salt);
    }

    function _scheduleBatch(address[] memory t, bytes[] memory p, bytes32 salt) internal returns (bytes32 id) {
        uint256[] memory v = new uint256[](t.length);
        vm.prank(gov);
        tl.scheduleBatch(t, v, p, bytes32(0), salt, 48 hours);
        id = tl.hashOperationBatch(t, v, p, bytes32(0), salt);
    }

    function _rotation() internal view returns (bytes memory) {
        return abi.encodeCall(registry.setGuardian, (address(seat)));
    }

    function _refused(bytes32 id) internal {
        vm.expectRevert(abi.encodeWithSelector(GuardianCancellerV2.GuardianRemovalNotCancellable.selector, id));
    }

    // ── the rotation is outside the veto ───────────────────────────

    function test_council_cannot_cancel_the_registry_seat_rotation() public {
        bytes memory data = _rotation();
        bytes32 id = _schedule(address(registry), data, 0);
        vm.prank(council);
        _refused(id);
        c.cancel(address(registry), 0, data, bytes32(0), 0);
        assertTrue(tl.isOperationPending(id));

        vm.warp(block.timestamp + 48 hours);
        vm.prank(gov);
        tl.execute(address(registry), 0, data, bytes32(0), 0);
        assertEq(registry.guardian(), address(seat));
    }

    function test_council_cannot_cancel_the_rotation_in_a_batch() public {
        address[] memory t = new address[](1);
        bytes[] memory p = new bytes[](1);
        t[0] = address(registry);
        p[0] = _rotation();
        bytes32 id = _scheduleBatch(t, p, keccak256("solo"));
        vm.prank(council);
        _refused(id);
        c.cancelBatch(t, new uint256[](1), p, bytes32(0), keccak256("solo"));
    }

    function test_rotation_together_with_retiring_the_canceller_guardian_is_not_cancellable() public {
        address[] memory t = new address[](2);
        bytes[] memory p = new bytes[](2);
        t[0] = address(registry);
        p[0] = _rotation();
        t[1] = address(c);
        p[1] = abi.encodeCall(c.setGuardian, (makeAddr("next-council")));
        bytes32 id = _scheduleBatch(t, p, keccak256("both"));
        vm.prank(council);
        _refused(id);
        c.cancelBatch(t, new uint256[](2), p, bytes32(0), keccak256("both"));
    }

    // ── everything else stays cancellable ──────────────────────────

    function test_council_still_cancels_an_ordinary_registry_operation() public {
        bytes memory data = abi.encodeCall(
            registry.proposeListing,
            (keccak256("vendor"), ProviderRegistry.Kind.Vendor, keccak256("hosts"), keccak256("policy"))
        );
        bytes32 id = _schedule(address(registry), data, 0);
        vm.prank(council);
        c.cancel(address(registry), 0, data, bytes32(0), 0);
        assertFalse(tl.isOperation(id));
    }

    function test_rotation_to_the_current_guardian_stays_cancellable() public {
        bytes memory data = abi.encodeCall(registry.setGuardian, (council));
        bytes32 id = _schedule(address(registry), data, 0);
        vm.prank(council);
        c.cancel(address(registry), 0, data, bytes32(0), 0);
        assertFalse(tl.isOperation(id));
    }

    function test_rotation_mixed_with_another_call_stays_cancellable() public {
        address[] memory t = new address[](2);
        bytes[] memory p = new bytes[](2);
        t[0] = address(registry);
        p[0] = _rotation();
        t[1] = address(tl);
        p[1] = abi.encodeCall(tl.updateDelay, (0));
        bytes32 id = _scheduleBatch(t, p, keccak256("mixed"));
        vm.prank(council);
        c.cancelBatch(t, new uint256[](2), p, bytes32(0), keccak256("mixed"));
        assertFalse(tl.isOperation(id));
    }

    function test_setGuardian_on_another_registry_stays_cancellable() public {
        ProviderRegistry other = new ProviderRegistry(address(tl), council, 24 hours);
        bytes memory data = abi.encodeCall(other.setGuardian, (address(seat)));
        bytes32 id = _schedule(address(other), data, 0);
        vm.prank(council);
        c.cancel(address(other), 0, data, bytes32(0), 0);
        assertFalse(tl.isOperation(id));
    }

    function test_non_canonical_rotation_calldata_stays_cancellable() public {
        bytes memory data = bytes.concat(_rotation(), bytes1(0x00)); // trailing byte: not canonical
        bytes32 id = _schedule(address(registry), data, 0);
        vm.prank(council);
        c.cancel(address(registry), 0, data, bytes32(0), 0);
        assertFalse(tl.isOperation(id));
    }

    // ── v1 behaviour is kept ───────────────────────────────────────

    function test_v1_guardian_removal_still_not_cancellable() public {
        bytes memory data = abi.encodeCall(tl.revokeRole, (canceller, address(c)));
        bytes32 id = _schedule(address(tl), data, 0);
        vm.prank(council);
        _refused(id);
        c.cancel(address(tl), 0, data, bytes32(0), 0);
    }

    function test_only_the_council_cancels() public {
        bytes memory data = abi.encodeCall(tl.updateDelay, (0));
        _schedule(address(tl), data, 0);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(GuardianCancellerV2.NotGuardian.selector);
        c.cancel(address(tl), 0, data, bytes32(0), 0);
    }

    function test_constructor_requires_a_registry_with_code() public {
        vm.expectRevert(GuardianCancellerV2.RegistryHasNoCode.selector);
        new GuardianCancellerV2(address(tl), council, makeAddr("no-code"));
        assertEq(c.providerRegistry(), address(registry));
    }

    // ── genesis placement ──────────────────────────────────────────

    /// v2 has its own salt and init code, so its CREATE2 address can never collide with, or move,
    /// v1's (r1006/r1007 keep v1 at "Genesis.GuardianCanceller").
    function test_v2_has_its_own_salt_and_projection() public pure {
        address factory = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        address govTl = address(0x1111);
        address grdTl = address(0x2222);
        address reg = address(0x3333);
        bytes32 h1 = keccak256(abi.encodePacked(type(GuardianCanceller).creationCode, abi.encode(govTl, grdTl)));
        bytes32 h2 = keccak256(abi.encodePacked(type(GuardianCancellerV2).creationCode, abi.encode(govTl, grdTl, reg)));
        bytes32 s1 = Salts.salt("Genesis.GuardianCanceller");
        bytes32 s2 = Salts.salt("Genesis.GuardianCancellerV2");
        assertTrue(s1 != s2);
        address a1 = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), factory, s1, h1)))));
        address a2 = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), factory, s2, h2)))));
        assertTrue(a1 != a2);
    }
}
