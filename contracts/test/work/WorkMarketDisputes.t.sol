// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice 0.6.0 planset 06 §2.2: objective disputes (coordinator-signed receipt + tree proofs,
///         upheld automatically, bond slashed, offer runs again) and subjective TASK disputes.
contract WorkMarketDisputesTest is WorkMarketTestBase {
    address internal w4 = address(0x4004);

    function setUp() public override {
        super.setUp();
        vm.deal(w4, 100 ether);
    }

    function _ev(uint8 tag, bytes memory body) internal pure returns (bytes memory) {
        return abi.encode(tag, body);
    }

    /// Posts a tree over w1, w3 (w2 joined but omitted); depth 1, full.
    function _postedOmittingW2() internal returns (uint256 id, bytes32[] memory leaves, Entry[] memory e) {
        id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        e = new Entry[](2);
        e[0] = Entry(w1, 2);
        e[1] = Entry(w3, 1);
        (leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 3);
    }

    function _missingEvidence(
        uint256 id,
        address w,
        uint8 mode,
        WorkMarket.LeafOpening memory lo,
        WorkMarket.LeafOpening memory hi
    ) internal view returns (bytes memory) {
        return _ev(market.DISPUTE_MISSING_LEAF(), abi.encode(_receipt(id, w, keccak256("lease-1")), mode, lo, hi));
    }

    // ── missing leaf ───────────────────────────────────────────────

    function test_dispute_missing_leaf_between_is_upheld_and_slashes_bond() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOmittingW2();
        bytes memory ev = _missingEvidence(
            id, w2, market.ABSENT_BETWEEN(), _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2)
        );
        vm.prank(w2);
        market.dispute(id, ev);

        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Running));
        assertEq(o.payoutRoot, bytes32(0));
        assertFalse(o.coordinatorBondHeld);
        assertEq(market.balanceOf(w2), CBOND / 2);
        assertEq(market.balanceOf(poster), CBOND / 2);
        assertEq(market.owedOn(id), BUDGET);
    }

    function test_dispute_by_poster_gets_whole_bond() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOmittingW2();
        bytes memory ev = _missingEvidence(
            id, w2, market.ABSENT_BETWEEN(), _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2)
        );
        vm.prank(poster);
        market.dispute(id, ev);
        assertEq(market.balanceOf(poster), CBOND);
    }

    function test_after_upheld_dispute_a_new_root_pays() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOmittingW2();
        bytes memory ev = _missingEvidence(
            id, w2, market.ABSENT_BETWEEN(), _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2)
        );
        vm.prank(w2);
        market.dispute(id, ev);
        (bytes32[] memory l3,) = _leaves(id, _entries3(), _noOverride(), 2);
        _postTree(id, l3, 6);
        vm.warp(block.timestamp + WINDOW);
        _settle(id, l3, 1, _entries3()[1], 2);
        assertEq(market.balanceOf(w2), CBOND / 2 + 3 * PRICE);
    }

    function test_dispute_missing_before_first() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(w2, 1);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1); // [w2, pad]
        _postTree(id, leaves, 1);
        WorkMarket.LeafOpening memory none;
        bytes memory ev = _missingEvidence(id, w1, market.ABSENT_BEFORE_FIRST(), none, _opening(leaves, 0, e[0], 0));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_dispute_missing_after_last_padding_and_full_tree() public {
        // padded: [w1, pad], w3 missing
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w3);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(w1, 1);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 1);
        bytes memory ev =
            _missingEvidence(id, w3, market.ABSENT_AFTER_LAST(), _opening(leaves, 0, e[0], 0), _padding(leaves, 1));
        vm.prank(w3);
        market.dispute(id, ev);

        // full: [w1, w2], w3 missing; lo is the last slot
        uint256 id2 = _openFl();
        _join(id2, w1);
        _join(id2, w2);
        _join(id2, w3);
        verifier.setAccepted(id2, DIGEST);
        Entry[] memory f = new Entry[](2);
        f[0] = Entry(w1, 1);
        f[1] = Entry(w2, 1);
        (bytes32[] memory l2,) = _leaves(id2, f, _noOverride(), 1);
        _postTree(id2, l2, 2);
        WorkMarket.LeafOpening memory none;
        bytes memory ev2 = _missingEvidence(id2, w3, market.ABSENT_AFTER_LAST(), _opening(l2, 1, f[1], 1), none);
        vm.prank(w3);
        market.dispute(id2, ev2);
        assertEq(uint8(market.getOffer(id2).state), uint8(IWorkMarket.State.Running));
    }

    function test_dispute_missing_empty_tree() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        bytes32[] memory leaves = new bytes32[](2); // all padding
        _postTree(id, leaves, 1);
        WorkMarket.LeafOpening memory none;
        bytes memory ev = _missingEvidence(id, w1, market.ABSENT_EMPTY(), none, _padding(leaves, 0));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_dispute_missing_not_proven_when_worker_is_included() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        // w2 is at index 1: w1 < w2 < w3 is not a neighbour pair (indices 0 and 2)
        WorkMarket.LeafOpening memory lo = _opening(leaves, 0, e[0], 0);
        WorkMarket.LeafOpening memory hi = _opening(leaves, 2, e[2], 5);
        bytes memory ev = _missingEvidence(id, w2, market.ABSENT_BETWEEN(), lo, hi);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_dispute_missing_requires_coordinator_signature() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOmittingW2();
        WorkMarket.Receipt memory r = _receipt(id, w2, keccak256("lease-1"));
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(0xBEEF, keccak256("not the coordinator"));
        r.signature = abi.encodePacked(rr, s, v);
        bytes memory ev = _ev(
            market.DISPUTE_MISSING_LEAF(),
            abi.encode(r, market.ABSENT_BETWEEN(), _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2))
        );
        vm.prank(w2);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_dispute_missing_requires_joined_worker() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOmittingW2();
        // 0x2500 sits between w1 and w3 in the tree but never joined
        bytes memory ev = _missingEvidence(
            id, address(0x2500), market.ABSENT_BETWEEN(), _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2)
        );
        vm.prank(poster);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    // ── low units ──────────────────────────────────────────────────

    function test_dispute_low_units_upheld_with_more_receipts_than_units() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        // w3's leaf pays 1 unit; the coordinator signed 2 leases
        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](2);
        rs[0] = _receipt(id, w3, bytes32(uint256(1)));
        rs[1] = _receipt(id, w3, bytes32(uint256(2)));
        bytes memory ev = _ev(market.DISPUTE_LOW_UNITS(), abi.encode(_opening(leaves, 2, e[2], 5), rs));
        vm.prank(w3);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_dispute_low_units_rejects_duplicate_or_too_few_receipts() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        WorkMarket.Receipt[] memory dup = new WorkMarket.Receipt[](2);
        dup[0] = _receipt(id, w3, bytes32(uint256(1)));
        dup[1] = _receipt(id, w3, bytes32(uint256(1)));
        bytes memory ev = _ev(market.DISPUTE_LOW_UNITS(), abi.encode(_opening(leaves, 2, e[2], 5), dup));
        vm.prank(w3);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);

        WorkMarket.Receipt[] memory one = new WorkMarket.Receipt[](1);
        one[0] = _receipt(id, w3, bytes32(uint256(1)));
        ev = _ev(market.DISPUTE_LOW_UNITS(), abi.encode(_opening(leaves, 2, e[2], 5), one));
        vm.prank(w3);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    // ── tree shape ─────────────────────────────────────────────────

    function test_dispute_order_upheld_for_unsorted_tree() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w2, 1);
        e[1] = Entry(w1, 1); // descending
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 2);
        bytes memory ev =
            _ev(market.DISPUTE_ORDER(), abi.encode(_opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 1)));
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotDisputer.selector);
        market.dispute(id, ev);
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_dispute_order_upheld_for_overlapping_ranges() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, 4);
        e[1] = Entry(w2, 4);
        uint64[] memory cums = new uint64[](2);
        cums[0] = 0;
        cums[1] = 0; // both claim units [0,4): tree pays 8 against a posted 4
        (bytes32[] memory leaves,) = _leaves(id, e, cums, 1);
        _postTree(id, leaves, 4);
        bytes memory ev =
            _ev(market.DISPUTE_ORDER(), abi.encode(_opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 0)));
        vm.prank(w2);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_dispute_order_not_proven_for_well_formed_tree() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        bytes memory ev =
            _ev(market.DISPUTE_ORDER(), abi.encode(_opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2)));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
        // real leaf followed by padding is fine too
        ev = _ev(market.DISPUTE_ORDER(), abi.encode(_opening(leaves, 2, e[2], 5), _padding(leaves, 3)));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_dispute_first_leaf_must_start_at_zero() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(w1, 1);
        uint64[] memory cums = new uint64[](1);
        cums[0] = 3;
        (bytes32[] memory leaves,) = _leaves(id, e, cums, 1);
        _postTree(id, leaves, 4);
        bytes memory ev = _ev(market.DISPUTE_FIRST_LEAF(), abi.encode(_opening(leaves, 0, e[0], 3)));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    // ── window and parties ─────────────────────────────────────────

    function test_dispute_closed_after_window() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOmittingW2();
        vm.warp(block.timestamp + WINDOW);
        bytes memory ev = _missingEvidence(
            id, w2, market.ABSENT_BETWEEN(), _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2)
        );
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.dispute(id, ev);
    }

    function test_dispute_unknown_tag_reverts() public {
        (uint256 id,) = _postedFl3();
        vm.prank(w1);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.dispute(id, _ev(9, ""));
    }

    // ── subjective (TASK) ──────────────────────────────────────────

    function _postedTask(bool group) internal returns (uint256 id, bytes32[] memory leaves) {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.TASK);
        if (group) {
            p.groupHash = keccak256("group");
            p.disputeAdmin = admin;
        }
        id = _open(p, 3 * PRICE);
        _join(id, coordinator);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(coordinator, 1);
        (leaves,) = _leaves(id, e, _noOverride(), 0);
        _postTree(id, leaves, 1);
    }

    function _subjective(uint16 reason) internal pure returns (bytes memory) {
        return abi.encode(uint8(0), abi.encode(reason));
    }

    function test_subjective_dispute_freezes_settle_admin_upholds() public {
        (uint256 id,) = _postedTask(true);
        vm.prank(poster);
        market.dispute(id, _subjective(300));
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Disputed));
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.WrongState.selector);
        market.settle(id, coordinator, 1, 0, 0, new bytes32[](0));

        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotDisputeAdmin.selector);
        market.resolveDispute(id, true);
        vm.prank(admin);
        market.resolveDispute(id, true);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
        assertEq(market.balanceOf(coordinator), CBOND); // a bad result is not fraud: bond back
    }

    function test_subjective_dispute_rejected_payout_stands() public {
        (uint256 id,) = _postedTask(true);
        vm.prank(poster);
        market.dispute(id, _subjective(300));
        vm.prank(admin);
        market.resolveDispute(id, false);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // one subjective dispute per payout
        market.dispute(id, _subjective(301));
        vm.warp(block.timestamp + WINDOW);
        market.settle(id, coordinator, 1, 0, 0, new bytes32[](0));
        assertEq(market.balanceOf(coordinator), PRICE);
    }

    function test_subjective_open_task_refunds_after_timeout() public {
        (uint256 id,) = _postedTask(false);
        vm.prank(poster);
        market.dispute(id, _subjective(300));
        vm.prank(admin);
        vm.expectRevert(WorkMarket.NotDisputeAdmin.selector);
        market.resolveDispute(id, true);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.refund(id);
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        vm.prank(poster);
        market.refund(id);
        assertEq(market.balanceOf(poster), 3 * PRICE);
        assertEq(market.balanceOf(coordinator), CBOND);
        assertEq(market.owedOn(id), 0);
    }

    function test_subjective_dispute_rules() public {
        (uint256 id,) = _postedFl3();
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // FL has no subjective disputes
        market.dispute(id, _subjective(300));

        (uint256 t,) = _postedTask(true);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // only the requester
        market.dispute(t, _subjective(300));
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // codes below 256 are objective kinds
        market.dispute(t, _subjective(1));
    }
}
