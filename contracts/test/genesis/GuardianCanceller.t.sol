// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GuardianCanceller} from "../../src/genesis/GuardianCanceller.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";

/// @title GuardianCanceller.t: the guardian veto and its guardian-removal exception
contract GuardianCancellerTest is Test {
    TimelockController internal tl;
    GuardianCanceller internal c;
    address internal gov = makeAddr("governance-multisig");
    address internal guardian = makeAddr("guardian-timelock");
    bytes32 internal canceller;

    function setUp() public {
        address[] memory g = new address[](1);
        g[0] = gov;
        tl = new TimelockController(48 hours, g, g, address(0));
        c = new GuardianCanceller(address(tl), guardian);
        canceller = tl.CANCELLER_ROLE();
        vm.prank(address(tl));
        tl.grantRole(canceller, address(c));
    }

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

    function _refused(bytes32 id) internal {
        vm.expectRevert(abi.encodeWithSelector(GuardianCanceller.GuardianRemovalNotCancellable.selector, id));
    }

    function test_constructor_and_wiring() public {
        assertEq(c.governanceTimelock(), address(tl));
        assertEq(c.guardian(), guardian);
        assertEq(c.CANCELLER_ROLE(), canceller);
        vm.expectRevert(GuardianCanceller.TimelockHasNoCode.selector);
        new GuardianCanceller(makeAddr("eoa"), guardian);
        vm.expectRevert(InitialAdmin.InitialAdmin_Zero.selector);
        new GuardianCanceller(address(tl), address(0));
        vm.expectRevert(GuardianCanceller.GuardianIsTimelock.selector);
        new GuardianCanceller(address(tl), address(tl));
    }

    /// An ordinary operation: the guardian cancels it.
    function test_guardian_cancels_an_ordinary_operation() public {
        bytes memory data = abi.encodeCall(tl.updateDelay, (0));
        bytes32 id = _schedule(address(tl), data, 0);
        vm.prank(guardian);
        c.cancel(address(tl), 0, data, bytes32(0), 0);
        assertFalse(tl.isOperation(id));
    }

    /// Granting CANCELLER to someone, or revoking it from someone else, is ordinary governance.
    function test_other_canceller_role_changes_stay_cancellable() public {
        bytes memory grant = abi.encodeCall(tl.grantRole, (canceller, makeAddr("x")));
        bytes memory revokeGov = abi.encodeCall(tl.revokeRole, (canceller, gov));
        bytes memory revokeProposer = abi.encodeCall(tl.revokeRole, (tl.PROPOSER_ROLE(), address(c)));
        bytes[3] memory ops = [grant, revokeGov, revokeProposer];
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = _schedule(address(tl), ops[i], bytes32(i));
            vm.prank(guardian);
            c.cancel(address(tl), 0, ops[i], bytes32(0), bytes32(i));
            assertFalse(tl.isOperation(id));
        }
    }

    function test_only_the_guardian_cancels() public {
        bytes memory data = abi.encodeCall(tl.updateDelay, (0));
        _schedule(address(tl), data, 0);
        vm.prank(gov);
        vm.expectRevert(GuardianCanceller.NotGuardian.selector);
        c.cancel(address(tl), 0, data, bytes32(0), 0);
        vm.expectRevert(GuardianCanceller.NotGuardian.selector);
        c.cancelBatch(new address[](0), new uint256[](0), new bytes[](0), bytes32(0), 0);
    }

    /// Revoke and renounce of the guardian's CANCELLER, and setGuardian, single op: refused.
    function test_single_removal_ops_are_not_cancellable() public {
        bytes[3] memory ops = [
            abi.encodeCall(tl.revokeRole, (canceller, address(c))),
            abi.encodeCall(tl.renounceRole, (canceller, address(c))),
            abi.encodeCall(c.setGuardian, (makeAddr("new-guardian")))
        ];
        address[3] memory targets = [address(tl), address(tl), address(c)];
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = _schedule(targets[i], ops[i], bytes32(i));
            vm.prank(guardian);
            _refused(id);
            c.cancel(targets[i], 0, ops[i], bytes32(0), bytes32(i));
            assertTrue(tl.isOperationPending(id));
        }
    }

    /// The same calls inside a batch (removal-only, or removal + replacement grant): refused.
    function test_batch_removal_and_replacement_are_not_cancellable() public {
        address[] memory t = new address[](3);
        (t[0], t[1], t[2]) = (address(tl), address(tl), address(c));
        bytes[] memory p = new bytes[](3);
        p[0] = abi.encodeCall(tl.grantRole, (canceller, makeAddr("next")));
        p[1] = abi.encodeCall(tl.revokeRole, (canceller, address(c)));
        p[2] = abi.encodeCall(c.setGuardian, (makeAddr("new-guardian")));
        bytes32 id = _scheduleBatch(t, p, 0);
        uint256[] memory v = new uint256[](3);
        assertTrue(c.isGuardianRemoval(t, v, p));
        vm.prank(guardian);
        _refused(id);
        c.cancelBatch(t, v, p, bytes32(0), 0);
        assertTrue(tl.isOperationPending(id));
    }

    /// A removal cannot carry anything else past the veto: mixed batches, non-zero value and
    /// non-canonical encodings stay cancellable, as does a lone replacement grant.
    function test_mixed_or_irregular_ops_stay_cancellable() public {
        address[] memory t = new address[](2);
        (t[0], t[1]) = (address(tl), address(tl));
        uint256[] memory v = new uint256[](2);
        bytes[] memory p = new bytes[](2);
        p[0] = abi.encodeCall(tl.revokeRole, (canceller, address(c)));
        p[1] = abi.encodeCall(tl.updateDelay, (0));
        assertFalse(c.isGuardianRemoval(t, v, p), "removal + other call");
        bytes32 id = _scheduleBatch(t, p, 0);
        vm.prank(guardian);
        c.cancelBatch(t, v, p, bytes32(0), 0);
        assertFalse(tl.isOperation(id));

        // Only a replacement grant, no removal.
        address[] memory t1 = new address[](1);
        t1[0] = address(tl);
        uint256[] memory v1 = new uint256[](1);
        bytes[] memory p1 = new bytes[](1);
        p1[0] = abi.encodeCall(tl.grantRole, (canceller, makeAddr("next")));
        assertFalse(c.isGuardianRemoval(t1, v1, p1), "grant alone");
        // Value attached.
        p1[0] = abi.encodeCall(tl.revokeRole, (canceller, address(c)));
        v1[0] = 1;
        assertFalse(c.isGuardianRemoval(t1, v1, p1), "value attached");
        v1[0] = 0;
        assertTrue(c.isGuardianRemoval(t1, v1, p1), "canonical removal");
        // Trailing bytes, dirty address bits, another target.
        p1[0] = bytes.concat(abi.encodeCall(tl.revokeRole, (canceller, address(c))), hex"00");
        assertFalse(c.isGuardianRemoval(t1, v1, p1), "trailing bytes");
        p1[0] = abi.encodeWithSelector(tl.revokeRole.selector, canceller, uint256(uint160(address(c))) | (1 << 200));
        assertFalse(c.isGuardianRemoval(t1, v1, p1), "dirty address");
        p1[0] = abi.encodeCall(tl.revokeRole, (canceller, address(c)));
        t1[0] = makeAddr("other-timelock");
        assertFalse(c.isGuardianRemoval(t1, v1, p1), "another target");
        // Malformed batches.
        vm.expectRevert(GuardianCanceller.EmptyOperation.selector);
        c.isGuardianRemoval(new address[](0), new uint256[](0), new bytes[](0));
        vm.expectRevert(GuardianCanceller.LengthMismatch.selector);
        c.isGuardianRemoval(t1, new uint256[](2), p1);
    }

    /// A single op and a batch op with the same call hash differently: each path cancels only
    /// the operation whose preimage it was given.
    function test_preimage_binds_the_cancelled_id() public {
        bytes memory data = abi.encodeCall(tl.updateDelay, (0));
        bytes32 id = _schedule(address(tl), data, 0);
        address[] memory t = new address[](1);
        t[0] = address(tl);
        bytes[] memory p = new bytes[](1);
        p[0] = data;
        vm.prank(guardian);
        vm.expectRevert(); // the batch id is not pending
        c.cancelBatch(t, new uint256[](1), p, bytes32(0), 0);
        assertTrue(tl.isOperationPending(id));
    }

    function test_set_guardian_is_governance_only_and_moves_the_veto() public {
        address next = makeAddr("next-guardian");
        vm.prank(guardian);
        vm.expectRevert(GuardianCanceller.NotGovernance.selector);
        c.setGuardian(next);
        vm.prank(address(tl));
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        c.setGuardian(InitialAdmin.CREATE2_FACTORY);
        vm.prank(address(tl));
        c.setGuardian(next);
        assertEq(c.guardian(), next);

        bytes memory data = abi.encodeCall(tl.updateDelay, (0));
        _schedule(address(tl), data, 0);
        vm.prank(guardian);
        vm.expectRevert(GuardianCanceller.NotGuardian.selector);
        c.cancel(address(tl), 0, data, bytes32(0), 0);
        vm.prank(next);
        c.cancel(address(tl), 0, data, bytes32(0), 0);
    }

    /// The removal executes after the delay even though the guardian tried to cancel it.
    function test_removal_executes_after_the_delay() public {
        uint256 t0 = 1_000_000;
        vm.warp(t0);
        bytes memory removal = abi.encodeCall(tl.revokeRole, (canceller, address(c)));
        bytes32 id = _schedule(address(tl), removal, 0);
        vm.prank(guardian);
        _refused(id);
        c.cancel(address(tl), 0, removal, bytes32(0), 0);
        vm.warp(t0 + 48 hours);
        vm.prank(gov);
        tl.execute(address(tl), 0, removal, bytes32(0), 0);
        assertFalse(tl.hasRole(canceller, address(c)));
    }

    /// setGuardian(current guardian) is a no-op, not a removal: alone, or batched with an extra
    /// CANCELLER grant, the guardian can still cancel it (Codex P2 on #324 at e377bbd).
    function test_noop_set_guardian_is_not_a_removal() public {
        bytes memory noop = abi.encodeCall(c.setGuardian, (guardian));
        bytes32 id = _schedule(address(c), noop, "noop");
        vm.prank(guardian);
        c.cancel(address(c), 0, noop, bytes32(0), "noop");
        assertFalse(tl.isOperation(id));

        address[] memory t = new address[](2);
        bytes[] memory p = new bytes[](2);
        (t[0], p[0]) = (address(c), noop);
        (t[1], p[1]) = (address(tl), abi.encodeCall(tl.grantRole, (canceller, makeAddr("another-canceller"))));
        uint256[] memory v = new uint256[](2);
        assertFalse(c.isGuardianRemoval(t, v, p));
        bytes32 bid = _scheduleBatch(t, p, "noop-batch");
        vm.prank(guardian);
        c.cancelBatch(t, v, p, bytes32(0), "noop-batch");
        assertFalse(tl.isOperation(bid));
    }

    /// Batches that remove the guardian path and restore it (re-grant CANCELLER to this
    /// canceller, or set another guardian and then the current one back) change nothing, so
    /// an extra CANCELLER grant inside them stays cancellable.
    function test_restoring_batches_stay_cancellable() public {
        address extra = makeAddr("another-canceller");
        bytes memory grantExtra = abi.encodeCall(tl.grantRole, (canceller, extra));
        address[] memory t = new address[](3);
        bytes[] memory p = new bytes[](3);
        uint256[] memory v = new uint256[](3);
        (t[0], p[0]) = (address(tl), abi.encodeCall(tl.revokeRole, (canceller, address(c))));
        (t[1], p[1]) = (address(tl), abi.encodeCall(tl.grantRole, (canceller, address(c))));
        (t[2], p[2]) = (address(tl), grantExtra);
        assertFalse(c.isGuardianRemoval(t, v, p), "revoke + re-grant restores the role");
        bytes32 id = _scheduleBatch(t, p, "restore-role");
        vm.prank(guardian);
        c.cancelBatch(t, v, p, bytes32(0), "restore-role");
        assertFalse(tl.isOperation(id));

        (t[0], p[0]) = (address(c), abi.encodeCall(c.setGuardian, (makeAddr("interim"))));
        (t[1], p[1]) = (address(c), abi.encodeCall(c.setGuardian, (guardian)));
        (t[2], p[2]) = (address(tl), grantExtra);
        assertFalse(c.isGuardianRemoval(t, v, p), "set away and back restores the guardian");
        id = _scheduleBatch(t, p, "restore-guardian");
        vm.prank(guardian);
        c.cancelBatch(t, v, p, bytes32(0), "restore-guardian");
        assertFalse(tl.isOperation(id));

        // A real replacement (another guardian, plus the successor's CANCELLER) still is not.
        address[] memory t2 = new address[](2);
        bytes[] memory p2 = new bytes[](2);
        uint256[] memory v2 = new uint256[](2);
        (t2[0], p2[0]) = (address(c), abi.encodeCall(c.setGuardian, (makeAddr("successor"))));
        (t2[1], p2[1]) = (address(tl), grantExtra);
        assertTrue(c.isGuardianRemoval(t2, v2, p2));
    }
}
