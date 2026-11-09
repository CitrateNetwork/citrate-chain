// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Chain #451 round-2 review: a root's leaves must sum to exactly its posted units
///         (DISPUTE_TOTAL), only committed disputes earn the disputer's share, the reveal delay is
///         measured in time, and challenges carry a bond.
contract WorkMarketTotalsTest is WorkMarketTestBase {
    function _ev(uint8 tag, bytes memory body) internal pure returns (bytes memory) {
        return abi.encode(tag, body);
    }

    function _total(WorkMarket.LeafOpening memory leaf, WorkMarket.LeafOpening memory next)
        internal
        view
        returns (bytes memory)
    {
        return _ev(market.DISPUTE_TOTAL(), abi.encode(leaf, next));
    }

    function _none() internal pure returns (WorkMarket.LeafOpening memory n) {}

    function _commitReveal(uint256 id, address who, bytes memory ev) internal {
        bytes32 salt = keccak256(abi.encode("salt", who));
        bytes32 c = market.disputeCommitment(id, market.getOffer(id).payoutEpoch, who, ev, salt);
        vm.prank(who);
        market.commitDispute(id, c);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.prank(who);
        market.revealDispute(id, ev, salt);
    }

    /// [w1 (0,8), w3 (8,4)] posted as 10 units: the leaves sum past payoutUnits.
    function _postedOverTotal() internal returns (uint256 id, bytes32[] memory leaves, Entry[] memory e) {
        id = _openFl(); // budget 10 at price 1
        _join(id, w1);
        _join(id, w3);
        _accept(id);
        e = new Entry[](2);
        e[0] = Entry(w1, 8);
        e[1] = Entry(w3, 4);
        (leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 10);
    }

    // ── tree total must equal payoutUnits ──────────────────────────

    function test_leaf_past_payout_units_is_disputable() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOverTotal();
        bytes memory ev = _total(_opening(leaves, 1, e[1], 8), _none());
        _commitReveal(id, w3, ev);
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Running));
        assertEq(o.payoutRoot, bytes32(0));
        assertEq(market.balanceOf(w3), CBOND / 2);
        // the sybil leaf no longer pays
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.WrongState.selector);
        _settle(id, leaves, 0, e[0], 0);
    }

    function test_under_posted_payout_units_are_disputable_when_poster_coordinates() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinator = poster;
        uint256 id = _open(p, BUDGET);
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        (bytes32[] memory leaves,) = _leaves(id, _entries3(), _noOverride(), 2); // pays 6
        vm.prank(poster);
        market.postPayout{value: CBOND}(id, _rootOf(leaves), 1, 2); // posts 1
        bytes memory ev = _total(_opening(leaves, 0, _entries3()[0], 0), _none()); // w1 (0,2) > 1
        _commitReveal(id, w1, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
        // a coordinating poster forfeits the whole bond to the disputer, not half to itself
        assertEq(market.balanceOf(w1), CBOND);
        assertEq(market.balanceOf(poster), 0);
    }

    function test_payout_units_above_tree_total_are_disputable() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        (bytes32[] memory leaves,) = _leaves(id, _entries3(), _noOverride(), 2); // pays 6
        _postTree(id, leaves, 9);
        Entry[] memory e = _entries3();
        // w3 (5,1) ends at 6 < 9 and the next slot is padding: the tree pays less than posted
        bytes memory ev = _total(_opening(leaves, 2, e[2], 5), _padding(leaves, 3));
        vm.prank(poster);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
        assertEq(market.balanceOf(poster), CBOND);
    }

    function test_empty_tree_with_posted_units_is_disputable_as_under_total() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        bytes32[] memory leaves = new bytes32[](2);
        _postTree(id, leaves, 1);
        bytes memory tev = _total(_padding(leaves, 0), _none());
        vm.prank(w1);
        market.dispute(id, tev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_under_total_needs_the_last_real_leaf() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        (bytes32[] memory leaves,) = _leaves(id, _entries3(), _noOverride(), 2);
        _postTree(id, leaves, 9);
        Entry[] memory e = _entries3();
        // w2 (2,3) is not last: its neighbour is real
        bytes memory ev = _total(_opening(leaves, 1, e[1], 2), _opening(leaves, 2, e[2], 5));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
        // padding that is not the next slot proves nothing
        ev = _total(_opening(leaves, 1, e[1], 2), _padding(leaves, 3));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_total_not_proven_on_matching_tree() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3(); // pays 6, posted 6
        Entry[] memory e = _entries3();
        bytes memory ev = _total(_opening(leaves, 2, e[2], 5), _padding(leaves, 3));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
        ev = _total(_opening(leaves, 1, e[1], 2), _none());
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, ev);
    }

    function test_total_holds_on_a_full_tree_last_slot() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, 1);
        e[1] = Entry(w2, 1);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 3); // pays 2, posted 3; slot 1 is the last slot
        bytes memory tev = _total(_opening(leaves, 1, e[1], 1), _none());
        vm.prank(w1);
        market.dispute(id, tev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    // ── only committed disputes earn the disputer's share ──────────

    function test_direct_dispute_pays_no_disputer_share() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOverTotal();
        bytes memory ev = _total(_opening(leaves, 1, e[1], 8), _none());
        bytes32 salt = keccak256("s");
        bytes32 c = market.disputeCommitment(id, 0, w3, ev, salt);
        vm.prank(w3);
        market.commitDispute(id, c);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        // a copier who saw the reveal lands the same evidence first through dispute()
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(market.balanceOf(w1), 0, "an uncommitted dispute earns nothing");
        assertEq(market.balanceOf(poster), CBOND, "the poster keeps the whole slash");
        vm.prank(w3);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // the root it committed against is gone
        market.revealDispute(id, ev, salt);
    }

    function test_reveal_delay_is_measured_in_time_not_block_number() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _postedOverTotal();
        bytes memory ev = _total(_opening(leaves, 1, e[1], 8), _none());
        bytes32 salt = keccak256("s");
        bytes32 c = market.disputeCommitment(id, 0, w3, ev, salt);
        vm.prank(w3);
        market.commitDispute(id, c);
        vm.roll(block.number + 5); // later heights at the same time (merged parallel blocks)
        vm.prank(w3);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.revealDispute(id, ev, salt);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY() - 1);
        vm.prank(w3);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.revealDispute(id, ev, salt);
        vm.warp(block.timestamp + 1);
        vm.prank(w3);
        market.revealDispute(id, ev, salt);
        assertEq(market.balanceOf(w3), CBOND / 2);
    }

    // ── challenge bonds ────────────────────────────────────────────

    function test_challenge_needs_exact_bond() public {
        (uint256 id,) = _postedFl3();
        assertEq(market.challengeBondOf(id), CHBOND);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.WrongBond.selector);
        market.challengeIndex(id, 0);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.WrongBond.selector);
        market.challengeIndex{value: CHBOND - 1}(id, 0);
        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](1);
        rs[0] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WrongBond.selector);
        market.challengeInclusion(id, rs);
    }

    function test_answered_challenge_pays_its_bond_to_the_answerer() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 3);
        assertEq(market.owedOn(id), BUDGET + CBOND + CHBOND);
        vm.prank(stranger);
        market.answerIndexChallenge(id, _padding(leaves, 3));
        assertEq(market.balanceOf(stranger), CHBOND);
        assertEq(market.owedOn(id), BUDGET + CBOND);

        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](1);
        rs[0] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w2);
        market.challengeInclusion{value: CHBOND}(id, rs);
        vm.prank(coordinator);
        market.answerChallenge(id, _opening(leaves, 1, _entries3()[1], 2));
        assertEq(market.balanceOf(coordinator), CHBOND);
    }

    function test_upheld_challenge_returns_its_bond() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("no preimage");
        _postTree(id, leaves, 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveIndexChallenge(id, 0);
        assertEq(market.balanceOf(w1), CBOND / 2 + CHBOND);
        assertEq(market.owedOn(id), BUDGET);
    }

    function test_challenge_left_open_by_a_withdrawn_root_refunds_its_bond() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("no preimage");
        leaves[1] = keccak256("none either");
        _postTree(id, leaves, 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.prank(w2);
        market.challengeIndex{value: CHBOND}(id, 1);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveIndexChallenge(id, 0); // withdraws the root; w2's challenge is left open
        vm.expectRevert(WorkMarket.NoOpenChallenge.selector);
        market.resolveIndexChallenge(id, 1);
        market.reclaimIndexChallengeBond(id, 1);
        assertEq(market.balanceOf(w2), CHBOND);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.reclaimIndexChallengeBond(id, 1);
        assertEq(market.owedOn(id), BUDGET);

        // a worker challenge left open by an upheld dispute is reclaimable too
        (bytes32[] memory l2,) = _leaves(id, _twoEntries(), _noOverride(), 1);
        _postTree(id, l2, 2);
        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](1);
        rs[0] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w1);
        market.challengeInclusion{value: CHBOND}(id, rs);
        bytes memory tev = _total(_opening(l2, 1, Entry(w2, 5), 1), _none()); // w2 ends at 6 > 2
        vm.prank(w1);
        market.dispute(id, tev);
        vm.prank(w1);
        market.reclaimChallengeBond(id, w2);
        assertEq(market.balanceOf(w1), CHBOND);
        assertEq(market.owedOn(id), BUDGET);
    }

    function _twoEntries() internal view returns (Entry[] memory e) {
        e = new Entry[](2);
        e[0] = Entry(w1, 1);
        e[1] = Entry(w2, 5);
    }
}
