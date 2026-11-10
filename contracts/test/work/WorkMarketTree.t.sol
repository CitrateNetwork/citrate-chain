// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Payout-tree integrity (chain #451 review): the tree depth is fixed per payout, every
///         index of the tree can be forced open (index challenge), and the order dispute takes
///         any two openable leaves, so no two leaves can claim overlapping unit ranges unseen.
contract WorkMarketTreeTest is WorkMarketTestBase {
    function _ev(uint8 tag, bytes memory body) internal pure returns (bytes memory) {
        return abi.encode(tag, body);
    }

    function _order(WorkMarket.LeafOpening memory a, WorkMarket.LeafOpening memory b)
        internal
        view
        returns (bytes memory)
    {
        return _ev(market.DISPUTE_ORDER(), abi.encode(a, b));
    }

    function _open3() internal returns (uint256 id) {
        id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
    }

    /// Reviewer attack A1: [w1 (0,2), garbage, w3 (0,2), pad], payoutUnits 2. w3 is a sybil whose
    /// range overlaps honest w1; the garbage separator keeps the two from being neighbours.
    function _postedA1() internal returns (uint256 id, bytes32[] memory leaves) {
        id = _open3();
        leaves = new bytes32[](4);
        leaves[0] = market.leafHash(0, market.leafPayload(id, w1, 2, 0));
        leaves[1] = keccak256("garbage separator, no preimage");
        leaves[2] = market.leafHash(2, market.leafPayload(id, w3, 2, 0));
        _postTree(id, leaves, 2);
    }

    /// Reviewer attack A2: depth-2 tree whose slot 1 holds a leaf hashed with index 5 (5 & 3 == 1)
    /// for sybil w3 overlapping honest w1 at slot 0.
    function _postedA2() internal returns (uint256 id, bytes32[] memory leaves) {
        id = _open3();
        leaves = new bytes32[](4);
        leaves[0] = market.leafHash(0, market.leafPayload(id, w1, 2, 0));
        leaves[1] = market.leafHash(5, market.leafPayload(id, w3, 2, 0));
        _postTree(id, leaves, 2);
    }

    function _real(bytes32[] memory leaves, uint256 index, address w, uint64 units, uint64 cum)
        internal
        pure
        returns (WorkMarket.LeafOpening memory)
    {
        return _opening(leaves, index, Entry(w, units), cum);
    }

    // ── A1: overlap across an unopenable separator ─────────────────

    function test_A1_order_dispute_takes_non_adjacent_overlapping_leaves() public {
        (uint256 id, bytes32[] memory leaves) = _postedA1();
        bytes memory ev = _order(_real(leaves, 0, w1, 2, 0), _real(leaves, 2, w3, 2, 0));
        vm.prank(w1);
        market.dispute(id, ev);
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Running));
        assertEq(o.payoutRoot, bytes32(0));
        assertEq(market.balanceOf(SINK), CBOND); // direct dispute: the whole slash to the sink
        // the sybil leaf no longer settles anything
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.WrongState.selector);
        _settle(id, leaves, 2, Entry(w3, 2), 0);
    }

    function test_A1_garbage_index_challenge_unanswered_is_upheld() public {
        (uint256 id, bytes32[] memory leaves) = _postedA1();
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 1);
        assertEq(market.getOffer(id).openChallenges, 1);

        // the garbage slot opens neither as padding nor as any real leaf
        vm.expectRevert(WorkMarket.BadAnswer.selector);
        market.answerIndexChallenge(id, _padding(leaves, 1));

        // the sybil cannot settle first while the challenge is open
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        _settle(id, leaves, 2, Entry(w3, 2), 0);

        vm.expectRevert(WorkMarket.AnswerTooEarly.selector); // answerBy is inclusive
        market.resolveIndexChallenge(id, 1);
        vm.warp(block.timestamp + 1);
        vm.prank(stranger);
        market.resolveIndexChallenge(id, 1);
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Running));
        assertEq(o.payoutRoot, bytes32(0));
        assertEq(o.openChallenges, 0);
        assertEq(market.balanceOf(w1), CBOND / 2 + CHBOND);
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), CBOND / 2);
    }

    /// A late answer reveals the sybil leaf; the window stays open for disputes long enough to use it.
    function test_A1_late_answer_keeps_disputes_open_and_settle_waits() public {
        (uint256 id, bytes32[] memory leaves) = _postedA1();
        uint256 windowEnd = uint256(market.getOffer(id).payoutPostedAt) + WINDOW;
        vm.warp(windowEnd - 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 2);
        vm.warp(windowEnd + market.CHALLENGE_RESPONSE_WINDOW() - 1);
        vm.prank(coordinator);
        market.answerIndexChallenge(id, _real(leaves, 2, w3, 2, 0));
        assertEq(market.getOffer(id).openChallenges, 0);

        // the revealed leaf can still be disputed, and nobody settles meanwhile
        vm.expectRevert(WorkMarket.WindowOpen.selector);
        _settle(id, leaves, 0, Entry(w1, 2), 0);
        vm.warp(block.timestamp + market.POST_ANSWER_DISPUTE_WINDOW() - 1);
        vm.expectRevert(WorkMarket.WindowOpen.selector);
        _settle(id, leaves, 2, Entry(w3, 2), 0);
        bytes memory ev = _order(_real(leaves, 0, w1, 2, 0), _real(leaves, 2, w3, 2, 0));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_answer_grace_closes_and_well_formed_tree_settles() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        uint256 windowEnd = uint256(market.getOffer(id).payoutPostedAt) + WINDOW;
        vm.warp(windowEnd - 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 3);
        vm.warp(windowEnd + 10);
        market.answerIndexChallenge(id, _padding(leaves, 3));
        uint256 graceEnd = windowEnd + 10 + market.POST_ANSWER_DISPUTE_WINDOW();
        vm.warp(graceEnd);
        bytes memory ev = _order(_real(leaves, 0, w1, 2, 0), _real(leaves, 1, w2, 3, 2));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.dispute(id, ev);
        _settle(id, leaves, 0, _entries3()[0], 0);
        assertEq(market.balanceOf(w1), 2 * PRICE);
    }

    // ── A2: index outside the tree ─────────────────────────────────

    function test_A2_out_of_range_index_cannot_settle() public {
        (uint256 id, bytes32[] memory leaves) = _postedA2();
        vm.warp(block.timestamp + WINDOW);
        bytes32[] memory path = _proof(leaves, 1); // the slot-1 path
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w3, 2, 0, 5, path);
        _settle(id, leaves, 0, Entry(w1, 2), 0); // the honest worker is paid
        assertEq(market.balanceOf(w1), 2 * PRICE);
    }

    function test_A2_out_of_range_slot_is_challengeable() public {
        (uint256 id, bytes32[] memory leaves) = _postedA2();
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 1);
        WorkMarket.LeafOpening memory l = _real(leaves, 1, w3, 2, 0);
        vm.expectRevert(WorkMarket.BadAnswer.selector); // slot 1 holds no index-1 leaf
        market.answerIndexChallenge(id, l);
        l.index = 5; // the index the leaf was hashed with names no slot
        vm.expectRevert(WorkMarket.NoOpenChallenge.selector);
        market.answerIndexChallenge(id, l);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveIndexChallenge(id, 1);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    // ── depth fixed per payout ─────────────────────────────────────

    function test_depth_is_stored_and_bounded_by_max_workers() public {
        (uint256 id,) = _postedFl3();
        assertEq(market.getOffer(id).payoutDepth, 2);

        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.maxWorkers = 5; // 8 slots at most: depth 3
        uint256 id2 = _open(p, BUDGET);
        _accept(id2);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.BadDepth.selector);
        market.postPayout{value: CBOND}(id2, keccak256("r"), 1, 4);
        vm.prank(coordinator);
        market.postPayout{value: CBOND}(id2, keccak256("r"), 1, 3);
        assertEq(market.getOffer(id2).payoutDepth, 3);
    }

    function test_settle_requires_proof_of_exactly_the_payout_depth() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        vm.warp(block.timestamp + WINDOW);
        bytes32[] memory p2 = _proof(leaves, 0);
        bytes32[] memory p3 = new bytes32[](3);
        p3[0] = p2[0];
        p3[1] = p2[1];
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w1, 2, 0, 0, p3);
        bytes32[] memory p1 = new bytes32[](1);
        p1[0] = p2[0];
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w1, 2, 0, 0, p1);
        market.settle(id, w1, 2, 0, 0, p2);
    }

    function test_openings_of_the_wrong_depth_do_not_count_in_disputes() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 0);
        WorkMarket.LeafOpening memory l = _real(leaves, 0, w1, 2, 0);
        bytes32[] memory longer = new bytes32[](3);
        longer[0] = l.path[0];
        longer[1] = l.path[1];
        l.path = longer;
        vm.expectRevert(WorkMarket.BadAnswer.selector);
        market.answerIndexChallenge(id, l);
    }

    // ── order dispute: any two openable leaves ─────────────────────

    function test_order_any_pair_padding_before_a_later_real_leaf() public {
        uint256 id = _open3();
        leavesBuf = new bytes32[](4); // [w1, pad, pad, w3]
        leavesBuf[0] = market.leafHash(0, market.leafPayload(id, w1, 1, 0));
        leavesBuf[3] = market.leafHash(3, market.leafPayload(id, w3, 1, 1));
        _postTree(id, leavesBuf, 2);
        bytes memory ev = _order(_padding(leavesBuf, 1), _real(leavesBuf, 3, w3, 1, 1));
        vm.prank(w2);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    bytes32[] internal leavesBuf;

    function test_order_any_pair_repeated_or_descending_worker() public {
        uint256 id = _open3();
        leavesBuf = new bytes32[](4); // [w1 (0,1), w2 (1,1), w1 (2,1), pad]
        leavesBuf[0] = market.leafHash(0, market.leafPayload(id, w1, 1, 0));
        leavesBuf[1] = market.leafHash(1, market.leafPayload(id, w2, 1, 1));
        leavesBuf[2] = market.leafHash(2, market.leafPayload(id, w1, 1, 2));
        _postTree(id, leavesBuf, 3);
        bytes memory ev = _order(_real(leavesBuf, 0, w1, 1, 0), _real(leavesBuf, 2, w1, 1, 2));
        vm.prank(w3);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_order_any_pair_not_proven_on_well_formed_tree() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        // non-adjacent real pair, real then later padding, reversed indices: none proves anything
        bytes memory ev = _order(_real(leaves, 0, w1, 2, 0), _real(leaves, 2, w3, 1, 5));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
        ev = _order(_real(leaves, 0, w1, 2, 0), _padding(leaves, 3));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
        ev = _order(_real(leaves, 2, e[2].worker, 1, 5), _real(leaves, 0, w1, 2, 0));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    // ── index challenge rules ──────────────────────────────────────

    function test_index_challenge_rules() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotDisputer.selector);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // 2^depth = 4 slots
        market.challengeIndex{value: CHBOND}(id, 4);

        vm.prank(poster);
        market.challengeIndex{value: CHBOND}(id, 1);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        market.challengeIndex{value: CHBOND}(id, 1);
        // an answer names its slot by index: an unchallenged slot is no answer, and the
        // challenged slot must open as what it holds (w2's leaf, not padding)
        vm.expectRevert(WorkMarket.NoOpenChallenge.selector);
        market.answerIndexChallenge(id, _real(leaves, 0, w1, 2, 0));
        vm.expectRevert(WorkMarket.BadAnswer.selector);
        market.answerIndexChallenge(id, _padding(leaves, 1));
        market.answerIndexChallenge(id, _real(leaves, 1, w2, 3, 2));
        vm.prank(w3);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // answered under this root: done
        market.challengeIndex{value: CHBOND}(id, 1);
        vm.expectRevert(WorkMarket.NoOpenChallenge.selector);
        market.resolveIndexChallenge(id, 1);

        vm.prank(w3);
        market.challengeIndex{value: CHBOND}(id, 3);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        vm.expectRevert(WorkMarket.AnswerTooLate.selector);
        market.answerIndexChallenge(id, _padding(leaves, 3));

        vm.warp(uint256(market.getOffer(id).payoutPostedAt) + WINDOW);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.challengeIndex{value: CHBOND}(id, 0);
    }

    function test_index_challenge_after_withdrawn_root_starts_fresh() public {
        (uint256 id, bytes32[] memory leaves) = _postedA1();
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 2);
        market.answerIndexChallenge(id, _real(leaves, 2, w3, 2, 0)); // slot 2 answered under root 1
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 1);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveIndexChallenge(id, 1);
        assertEq(market.getOffer(id).payoutDepth, 0); // cleared with the root

        (bytes32[] memory l3,) = _leaves(id, _entries3(), _noOverride(), 2);
        _postTree(id, l3, 6);
        assertEq(market.indexChallengeOf(id, 1).open, false);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 1);
        market.answerIndexChallenge(id, _real(l3, 1, w2, 3, 2));
        assertTrue(market.indexChallengeOf(id, 1).answered);
        // a slot answered under the withdrawn root can be challenged again under the new one
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 2);
        assertTrue(market.indexChallengeOf(id, 2).open);
    }

    // ── guards the mutation pass asked for ─────────────────────────

    function test_order_needs_two_distinct_slots() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        WorkMarket.LeafOpening memory a = _real(leaves, 1, w2, 3, 2);
        bytes memory ev = _order(a, a);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_order_non_adjacent_abutting_ranges_are_fine() public {
        uint256 id = _open3();
        leavesBuf = new bytes32[](4); // [w1 (0,2), w2 (2,0), w3 (2,1), pad]: a zero-unit leaf between
        leavesBuf[0] = market.leafHash(0, market.leafPayload(id, w1, 2, 0));
        leavesBuf[1] = market.leafHash(1, market.leafPayload(id, w2, 0, 2));
        leavesBuf[2] = market.leafHash(2, market.leafPayload(id, w3, 1, 2));
        _postTree(id, leavesBuf, 3);
        bytes memory ev = _order(_real(leavesBuf, 0, w1, 2, 0), _real(leavesBuf, 2, w3, 1, 2));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_order_neighbours_with_a_gap_are_disputable() public {
        uint256 id = _open3();
        leavesBuf = new bytes32[](2); // [w1 (0,1), w2 (3,1)]
        leavesBuf[0] = market.leafHash(0, market.leafPayload(id, w1, 1, 0));
        leavesBuf[1] = market.leafHash(1, market.leafPayload(id, w2, 1, 3));
        _postTree(id, leavesBuf, 4);
        bytes memory ev = _order(_real(leavesBuf, 0, w1, 1, 0), _real(leavesBuf, 1, w2, 1, 3));
        vm.prank(w3);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    /// A slot whose value is an internal node over two leaves hides those leaves one level below
    /// the posted depth. The depth rule keeps them from settling (and from opening as evidence).
    function test_leaves_nested_below_the_posted_depth_do_not_open() public {
        uint256 id = _open3();
        bytes32 la = market.leafHash(0, market.leafPayload(id, w1, 2, 0));
        bytes32 lb = market.leafHash(1, market.leafPayload(id, w3, 2, 0));
        leavesBuf = new bytes32[](4); // slot 0 = node(la, lb), posted at depth 2
        leavesBuf[0] = _node(la, lb);
        _postTree(id, leavesBuf, 2);
        vm.warp(block.timestamp + WINDOW);
        bytes32[] memory p2 = _proof(leavesBuf, 0);
        bytes32[] memory p3 = new bytes32[](3);
        p3[0] = lb;
        p3[1] = p2[0];
        p3[2] = p2[1];
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w1, 2, 0, 0, p3);
        p3[0] = la;
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w3, 2, 0, 1, p3);
    }

    /// Posted near the deadline, a late answer keeps the offer open past deadline + window: the
    /// refund and the coordinator bond wait until the post-answer window ends.
    function test_late_answer_holds_refund_and_coordinator_bond() public {
        uint256 id = _open3();
        uint64 deadline = market.getOffer(id).deadline;
        vm.warp(deadline);
        leavesBuf = new bytes32[](4);
        leavesBuf[0] = market.leafHash(0, market.leafPayload(id, w1, 2, 0));
        leavesBuf[2] = market.leafHash(2, market.leafPayload(id, w3, 2, 0));
        _postTree(id, leavesBuf, 2);
        uint256 windowEnd = uint256(deadline) + WINDOW;
        vm.warp(windowEnd - 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 2);
        vm.warp(windowEnd + 1 hours);
        market.answerIndexChallenge(id, _real(leavesBuf, 2, w3, 2, 0));
        vm.prank(poster);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.refund(id);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.claimBond(id);
        // the revealed overlap is still disputable, and the bond is still there to slash
        bytes memory ev = _order(_real(leavesBuf, 0, w1, 2, 0), _real(leavesBuf, 2, w3, 2, 0));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(market.balanceOf(SINK), CBOND); // the bond was still there to slash
    }
}
