// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";

/// @title MultisigProposer.t: m-of-n front for an OZ TimelockController (C2 D5 / G3)
/// @dev Every test runs against a real OZ v5.7.0 TimelockController wired the way
///      DeployGenesisGovernance wires it: the multisig is the only PROPOSER, EXECUTOR and
///      CANCELLER, and the timelock administers itself.
contract MultisigProposerTest is Test {
    uint256 internal constant DELAY = 2 days;
    uint256 internal constant TTL = 7 days;

    TimelockController internal tl;
    MultisigProposer internal ms;
    address[] internal owners;
    address internal stranger = makeAddr("stranger");

    function setUp() public {
        for (uint256 i = 0; i < 5; i++) {
            owners.push(makeAddr(string.concat("owner", vm.toString(i))));
        }
        (tl, ms) = _council(owners, 3);
    }

    // ── helpers ─────────────────────────────────────────────────────

    function _council(address[] memory o, uint256 m) internal returns (TimelockController t, MultisigProposer p) {
        address[] memory none = new address[](0);
        t = new TimelockController(DELAY, none, none, address(this));
        p = new MultisigProposer(address(t), o, m, TTL);
        t.grantRole(t.PROPOSER_ROLE(), address(p));
        t.grantRole(t.EXECUTOR_ROLE(), address(p));
        t.grantRole(t.CANCELLER_ROLE(), address(p));
        t.renounceRole(t.DEFAULT_ADMIN_ROLE(), address(this));
    }

    function _owners(uint256 n) internal pure returns (address[] memory o) {
        o = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            o[i] = address(uint160(0x1000 + i));
        }
    }

    function _propose(uint256 by, bytes memory data) internal returns (bytes32 id) {
        vm.prank(owners[by]);
        id = ms.propose(data);
    }

    function _approve(uint256 by, bytes32 id) internal {
        vm.prank(owners[by]);
        ms.approve(id);
    }

    function _exec(uint256 by, bytes32 id) internal {
        vm.prank(owners[by]);
        ms.execute(id);
    }

    /// Approve `id` up to the 3-of-5 threshold (proposer = owner 0) and run it.
    function _pass(bytes memory data) internal returns (bytes32 id) {
        id = _propose(0, data);
        _approve(1, id);
        _approve(2, id);
        _exec(0, id);
    }

    function _scheduleCall(address target, bytes memory payload, bytes32 salt) internal pure returns (bytes memory) {
        return abi.encodeCall(TimelockController.schedule, (target, 0, payload, bytes32(0), salt, DELAY));
    }

    function _executeCall(address target, bytes memory payload, bytes32 salt) internal pure returns (bytes memory) {
        return abi.encodeCall(TimelockController.execute, (target, 0, payload, bytes32(0), salt));
    }

    // ── constructor validation ──────────────────────────────────────

    function test_constructor_records_owners_threshold_timelock() public view {
        assertEq(ms.timelock(), address(tl));
        assertEq(ms.threshold(), 3);
        address[] memory o = ms.owners();
        assertEq(o.length, 5);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(o[i], owners[i]);
            assertTrue(ms.isOwner(owners[i]));
        }
        assertFalse(ms.isOwner(stranger));
    }

    function test_constructor_rejects_zero_owners() public {
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadOwnerCount.selector, 0));
        new MultisigProposer(address(tl), new address[](0), 1, TTL);
    }

    function test_constructor_rejects_eleven_owners() public {
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadOwnerCount.selector, 11));
        new MultisigProposer(address(tl), _owners(11), 1, TTL);
    }

    function test_constructor_accepts_ten_of_ten_and_one_of_one() public {
        MultisigProposer a = new MultisigProposer(address(tl), _owners(10), 10, TTL);
        assertEq(a.threshold(), 10);
        MultisigProposer b = new MultisigProposer(address(tl), _owners(1), 1, TTL);
        assertEq(b.threshold(), 1);
    }

    function test_constructor_rejects_threshold_zero() public {
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadThreshold.selector, 0, 3));
        new MultisigProposer(address(tl), _owners(3), 0, TTL);
    }

    function test_constructor_rejects_threshold_above_owner_count() public {
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadThreshold.selector, 4, 3));
        new MultisigProposer(address(tl), _owners(3), 4, TTL);
    }

    function test_constructor_rejects_duplicate_owner() public {
        address[] memory o = _owners(3);
        o[2] = o[0];
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.DuplicateOwner.selector, o[0]));
        new MultisigProposer(address(tl), o, 2, TTL);
    }

    function test_constructor_rejects_zero_owner() public {
        address[] memory o = _owners(3);
        o[1] = address(0);
        vm.expectRevert(InitialAdmin.InitialAdmin_Zero.selector);
        new MultisigProposer(address(tl), o, 2, TTL);
    }

    function test_constructor_rejects_create2_factory_owner() public {
        address[] memory o = _owners(3);
        o[1] = InitialAdmin.CREATE2_FACTORY;
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new MultisigProposer(address(tl), o, 2, TTL);
    }

    function test_constructor_rejects_timelock_as_owner() public {
        address[] memory o = _owners(3);
        o[1] = address(tl);
        vm.expectRevert(MultisigProposer.OwnerIsTimelock.selector);
        new MultisigProposer(address(tl), o, 2, TTL);
    }

    function test_constructor_rejects_codeless_timelock() public {
        vm.expectRevert(MultisigProposer.TimelockHasNoCode.selector);
        new MultisigProposer(makeAddr("not-a-timelock"), _owners(3), 2, TTL);
    }

    // ── access ──────────────────────────────────────────────────────

    function test_stranger_cannot_propose_approve_revoke_or_execute() public {
        bytes32 id = _propose(0, abi.encodeCall(TimelockController.updateDelay, (1 days)));
        vm.startPrank(stranger);
        vm.expectRevert(MultisigProposer.NotOwner.selector);
        ms.propose(hex"deadbeef");
        vm.expectRevert(MultisigProposer.NotOwner.selector);
        ms.approve(id);
        vm.expectRevert(MultisigProposer.NotOwner.selector);
        ms.revoke(id);
        vm.expectRevert(MultisigProposer.NotOwner.selector);
        ms.execute(id);
        vm.stopPrank();
    }

    function test_propose_rejects_call_without_selector() public {
        vm.prank(owners[0]);
        vm.expectRevert(MultisigProposer.EmptyCall.selector);
        ms.propose(hex"aabbcc");
    }

    function test_unknown_proposal_reverts() public {
        vm.prank(owners[0]);
        vm.expectRevert(MultisigProposer.UnknownProposal.selector);
        ms.approve(keccak256("nope"));
    }

    // ── threshold edges ─────────────────────────────────────────────

    function test_propose_counts_the_proposers_approval() public {
        bytes32 id = _propose(0, hex"deadbeef");
        (, uint256 approvals, bool exists, bool executed,) = ms.getProposal(id);
        assertEq(approvals, 1);
        assertTrue(exists);
        assertFalse(executed);
        assertTrue(ms.hasApproved(id, owners[0]));
    }

    function test_execute_one_below_threshold_reverts() public {
        bytes32 id = _propose(0, _scheduleCall(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), 0));
        _approve(1, id);
        vm.prank(owners[0]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BelowThreshold.selector, 2, 3));
        ms.execute(id);
    }

    function test_execute_exactly_at_threshold_schedules_on_the_timelock() public {
        bytes memory payload = abi.encodeCall(tl.updateDelay, (1 days));
        _pass(_scheduleCall(address(tl), payload, 0));
        bytes32 opId = tl.hashOperation(address(tl), 0, payload, bytes32(0), bytes32(0));
        assertTrue(tl.isOperationPending(opId));
        assertEq(tl.getTimestamp(opId), block.timestamp + DELAY);
    }

    function test_any_owner_may_execute_once_threshold_met() public {
        bytes32 id = _propose(0, _scheduleCall(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), 0));
        _approve(3, id);
        _approve(4, id);
        _exec(2, id); // owner 2 never approved, still may trigger
        (,,, bool executed,) = ms.getProposal(id);
        assertTrue(executed);
    }

    function test_one_of_one_executes_on_propose_plus_execute() public {
        address[] memory solo = _owners(1);
        (TimelockController t, MultisigProposer p) = _council(solo, 1);
        bytes memory payload = abi.encodeCall(t.updateDelay, (1 days));
        vm.startPrank(solo[0]);
        bytes32 id = p.propose(_scheduleCall(address(t), payload, 0));
        p.execute(id);
        vm.stopPrank();
        assertTrue(t.isOperationPending(t.hashOperation(address(t), 0, payload, bytes32(0), bytes32(0))));
    }

    function test_ten_of_ten_needs_every_owner() public {
        address[] memory o = _owners(10);
        (TimelockController t, MultisigProposer p) = _council(o, 10);
        bytes memory call_ = _scheduleCall(address(t), abi.encodeCall(t.updateDelay, (1 days)), 0);
        vm.prank(o[0]);
        bytes32 id = p.propose(call_);
        for (uint256 i = 1; i < 9; i++) {
            vm.prank(o[i]);
            p.approve(id);
        }
        vm.prank(o[0]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BelowThreshold.selector, 9, 10));
        p.execute(id);
        vm.prank(o[9]);
        p.approve(id);
        vm.prank(o[0]);
        p.execute(id);
    }

    // ── approvals, revocation, replay ───────────────────────────────

    function test_double_approve_reverts() public {
        bytes32 id = _propose(0, hex"deadbeef");
        vm.prank(owners[0]);
        vm.expectRevert(MultisigProposer.AlreadyApproved.selector);
        ms.approve(id);
        _approve(1, id);
        vm.prank(owners[1]);
        vm.expectRevert(MultisigProposer.AlreadyApproved.selector);
        ms.approve(id);
    }

    function test_revoke_drops_below_threshold() public {
        bytes32 id = _propose(0, _scheduleCall(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), 0));
        _approve(1, id);
        _approve(2, id);
        vm.prank(owners[2]);
        ms.revoke(id);
        assertFalse(ms.hasApproved(id, owners[2]));
        vm.prank(owners[0]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BelowThreshold.selector, 2, 3));
        ms.execute(id);
        _approve(2, id); // re-approval after revoke is allowed
        _exec(0, id);
    }

    function test_revoke_without_approval_reverts() public {
        bytes32 id = _propose(0, hex"deadbeef");
        vm.prank(owners[1]);
        vm.expectRevert(MultisigProposer.NotApproved.selector);
        ms.revoke(id);
    }

    function test_replay_execute_twice_reverts() public {
        bytes32 id = _pass(_scheduleCall(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), 0));
        vm.prank(owners[0]);
        vm.expectRevert(MultisigProposer.AlreadyExecuted.selector);
        ms.execute(id);
        vm.prank(owners[3]);
        vm.expectRevert(MultisigProposer.AlreadyExecuted.selector);
        ms.approve(id);
        vm.prank(owners[1]);
        vm.expectRevert(MultisigProposer.AlreadyExecuted.selector);
        ms.revoke(id);
    }

    function test_identical_proposals_get_distinct_ids() public {
        bytes memory data = hex"deadbeef";
        bytes32 a = _propose(0, data);
        bytes32 b = _propose(0, data);
        assertTrue(a != b);
        assertEq(ms.proposalCount(), 2);
        assertEq(a, keccak256(abi.encode(block.chainid, address(ms), uint256(0), data)));
    }

    function test_proposal_id_binds_chain_id() public {
        bytes memory data = hex"deadbeef";
        bytes32 here = keccak256(abi.encode(block.chainid, address(ms), uint256(0), data));
        vm.chainId(40204);
        bytes32 id = _propose(0, data);
        assertTrue(id != here);
        assertEq(id, keccak256(abi.encode(uint256(40204), address(ms), uint256(0), data)));
    }

    // ── end to end through the timelock ─────────────────────────────

    function test_schedule_then_execute_after_delay() public {
        bytes memory payload = abi.encodeCall(tl.updateDelay, (3 days));
        _pass(_scheduleCall(address(tl), payload, 0));

        bytes32 execId = _propose(1, _executeCall(address(tl), payload, 0));
        _approve(2, execId);
        _approve(3, execId);

        // Too early: the timelock reverts, the proposal stays pending and can be retried.
        vm.prank(owners[1]);
        vm.expectPartialRevert(MultisigProposer.ExecutionFailed.selector);
        ms.execute(execId);
        (,,, bool executed,) = ms.getProposal(execId);
        assertFalse(executed, "a failed call leaves the proposal pending");

        vm.warp(block.timestamp + DELAY);
        _exec(1, execId);
        assertEq(tl.getMinDelay(), 3 days);
    }

    function test_cancel_through_the_multisig() public {
        bytes memory payload = abi.encodeCall(tl.updateDelay, (3 days));
        _pass(_scheduleCall(address(tl), payload, 0));
        bytes32 opId = tl.hashOperation(address(tl), 0, payload, bytes32(0), bytes32(0));
        _pass(abi.encodeCall(TimelockController.cancel, (opId)));
        assertFalse(tl.isOperation(opId));
    }

    function test_owners_cannot_bypass_the_timelock() public {
        // Owners act only through the multisig; the timelock itself refuses them.
        bytes memory payload = abi.encodeCall(tl.updateDelay, (0));
        vm.prank(owners[0]);
        vm.expectRevert();
        tl.schedule(address(tl), 0, payload, bytes32(0), bytes32(0), DELAY);
        // And a direct updateDelay from the multisig (not a timelock self-call) fails.
        bytes32 id = _propose(0, payload);
        _approve(1, id);
        _approve(2, id);
        vm.prank(owners[0]);
        vm.expectPartialRevert(MultisigProposer.ExecutionFailed.selector);
        ms.execute(id);
        assertEq(tl.getMinDelay(), DELAY);
    }

    function test_rotation_via_timelock_role_swap() public {
        address[] memory next = _owners(3);
        MultisigProposer ms2 = new MultisigProposer(address(tl), next, 2, TTL);
        address[] memory targets = new address[](6);
        uint256[] memory values = new uint256[](6);
        bytes[] memory payloads = new bytes[](6);
        bytes32[3] memory roles = [tl.PROPOSER_ROLE(), tl.EXECUTOR_ROLE(), tl.CANCELLER_ROLE()];
        for (uint256 i = 0; i < 3; i++) {
            targets[i] = address(tl);
            payloads[i] = abi.encodeCall(tl.grantRole, (roles[i], address(ms2)));
            targets[i + 3] = address(tl);
            payloads[i + 3] = abi.encodeCall(tl.revokeRole, (roles[i], address(ms)));
        }
        _pass(abi.encodeCall(TimelockController.scheduleBatch, (targets, values, payloads, bytes32(0), 0, DELAY)));
        vm.warp(block.timestamp + DELAY);
        _pass(abi.encodeCall(TimelockController.executeBatch, (targets, values, payloads, bytes32(0), 0)));
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(tl.hasRole(roles[i], address(ms2)));
            assertFalse(tl.hasRole(roles[i], address(ms)));
        }
    }

    // ── fuzz ────────────────────────────────────────────────────────

    /// For any 1 <= m <= n <= 10 and any number k of distinct approvers, execute succeeds
    /// iff k >= m, and exactly once.
    function testFuzz_execute_iff_threshold_met(uint8 nSeed, uint8 mSeed, uint8 kSeed) public {
        uint256 n = bound(nSeed, 1, 10);
        uint256 m = bound(mSeed, 1, n);
        uint256 k = bound(kSeed, 1, n);
        address[] memory o = _owners(n);
        (TimelockController t, MultisigProposer p) = _council(o, m);
        bytes memory payload = abi.encodeCall(t.updateDelay, (1 days));

        vm.prank(o[0]);
        bytes32 id = p.propose(_scheduleCall(address(t), payload, 0));
        for (uint256 i = 1; i < k; i++) {
            vm.prank(o[i]);
            p.approve(id);
        }
        vm.prank(o[n - 1]);
        if (k < m) {
            vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BelowThreshold.selector, k, m));
            p.execute(id);
        } else {
            p.execute(id);
            assertTrue(t.isOperationPending(t.hashOperation(address(t), 0, payload, bytes32(0), bytes32(0))));
            vm.prank(o[0]);
            vm.expectRevert(MultisigProposer.AlreadyExecuted.selector);
            p.execute(id);
        }
    }

    /// Any owner list with a repeated address is refused, wherever the repeat sits.
    function testFuzz_constructor_rejects_any_duplicate(uint8 nSeed, uint8 iSeed, uint8 jSeed) public {
        uint256 n = bound(nSeed, 2, 10);
        uint256 i = bound(iSeed, 0, n - 1);
        uint256 j = bound(jSeed, 0, n - 1);
        vm.assume(i != j);
        address[] memory o = _owners(n);
        o[j] = o[i];
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.DuplicateOwner.selector, o[i]));
        new MultisigProposer(address(tl), o, 1, TTL);
    }

    /// Any threshold outside 1..n is refused.
    function testFuzz_constructor_rejects_bad_threshold(uint8 nSeed, uint256 m) public {
        uint256 n = bound(nSeed, 1, 10);
        vm.assume(m == 0 || m > n);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadThreshold.selector, m, n));
        new MultisigProposer(address(tl), _owners(n), m, TTL);
    }

    // ── proposal expiry ─────────────────────────────────────────────

    function test_constructor_records_ttl_and_rejects_out_of_bounds() public {
        assertEq(ms.proposalTtl(), TTL);
        uint256 lo = ms.MIN_PROPOSAL_TTL();
        uint256 hi = ms.MAX_PROPOSAL_TTL();
        assertEq(lo, 1 days);
        assertEq(hi, 30 days);
        new MultisigProposer(address(tl), _owners(3), 2, lo);
        new MultisigProposer(address(tl), _owners(3), 2, hi);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadProposalTtl.selector, lo - 1));
        new MultisigProposer(address(tl), _owners(3), 2, lo - 1);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadProposalTtl.selector, hi + 1));
        new MultisigProposer(address(tl), _owners(3), 2, hi + 1);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.BadProposalTtl.selector, 0));
        new MultisigProposer(address(tl), _owners(3), 2, 0);
    }

    function test_propose_records_expiry() public {
        bytes32 id = _propose(0, hex"deadbeef");
        (,,,, uint256 expiresAt) = ms.getProposal(id);
        assertEq(expiresAt, block.timestamp + TTL);
    }

    /// An approved-but-unexecuted proposal cannot run once expired, cannot gather or lose
    /// approvals either, and re-proposing the same call gives a fresh, runnable proposal.
    function test_expired_proposal_cannot_execute_and_can_be_reproposed() public {
        bytes memory payload = abi.encodeCall(tl.updateDelay, (3 days));
        bytes memory data = _scheduleCall(address(tl), payload, 0);
        bytes32 id = _propose(0, data);
        _approve(1, id);
        _approve(2, id);
        uint256 expiresAt = block.timestamp + TTL;
        vm.warp(expiresAt);

        vm.prank(owners[0]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.ProposalExpired.selector, expiresAt));
        ms.execute(id);
        vm.prank(owners[3]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.ProposalExpired.selector, expiresAt));
        ms.approve(id);
        vm.prank(owners[1]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.ProposalExpired.selector, expiresAt));
        ms.revoke(id);
        bytes32 opId = tl.hashOperation(address(tl), 0, payload, bytes32(0), bytes32(0));
        assertFalse(tl.isOperation(opId), "nothing reached the timelock");

        bytes32 again = _pass(data);
        assertTrue(again != id, "re-proposal gets a new id");
        assertTrue(tl.isOperationPending(opId));
        (,,, bool executed,) = ms.getProposal(id);
        assertFalse(executed, "the expired proposal stays unexecuted");
    }

    /// The expiry boundary for any TTL in bounds and any elapsed time: execute succeeds
    /// iff elapsed < ttl.
    function testFuzz_execute_iff_unexpired(uint256 ttlSeed, uint256 elapsedSeed) public {
        uint256 ttl = bound(ttlSeed, 1 days, 30 days);
        uint256 elapsed = bound(elapsedSeed, 0, 31 days);
        address[] memory none = new address[](0);
        TimelockController t = new TimelockController(DELAY, none, none, address(this));
        MultisigProposer p = new MultisigProposer(address(t), owners, 3, ttl);
        t.grantRole(t.PROPOSER_ROLE(), address(p));
        t.renounceRole(t.DEFAULT_ADMIN_ROLE(), address(this));

        bytes memory payload = abi.encodeCall(t.updateDelay, (1 days));
        vm.prank(owners[0]);
        bytes32 id = p.propose(_scheduleCall(address(t), payload, 0));
        vm.prank(owners[1]);
        p.approve(id);
        vm.prank(owners[2]);
        p.approve(id);
        uint256 expiresAt = block.timestamp + ttl;
        vm.warp(block.timestamp + elapsed);
        vm.prank(owners[0]);
        if (elapsed < ttl) {
            p.execute(id);
            assertTrue(t.isOperationPending(t.hashOperation(address(t), 0, payload, bytes32(0), bytes32(0))));
        } else {
            vm.expectRevert(abi.encodeWithSelector(MultisigProposer.ProposalExpired.selector, expiresAt));
            p.execute(id);
        }
    }

    /// Exact boundary: one second before expiry executes, at expiry reverts.
    function test_expiry_boundary_is_exclusive() public {
        // Fixed timestamps throughout: via-IR may reorder or reuse `block.timestamp` reads
        // around vm.warp, so the test never reads it.
        uint256 t0 = 1_000_000;
        vm.warp(t0);
        bytes memory data = _scheduleCall(address(tl), abi.encodeCall(tl.updateDelay, (3 days)), 0);
        bytes32 id = _propose(0, data);
        _approve(1, id);
        _approve(2, id);
        vm.warp(t0 + TTL - 1);
        _exec(0, id);
        bytes32 id2 = _propose(0, _scheduleCall(address(tl), abi.encodeCall(tl.updateDelay, (4 days)), 0));
        _approve(1, id2);
        _approve(2, id2);
        uint256 expires2 = t0 + TTL - 1 + TTL;
        (,,,, uint256 recorded) = ms.getProposal(id2);
        assertEq(recorded, expires2);
        vm.warp(expires2);
        vm.prank(owners[0]);
        vm.expectRevert(abi.encodeWithSelector(MultisigProposer.ProposalExpired.selector, expires2));
        ms.execute(id2);
    }
}
