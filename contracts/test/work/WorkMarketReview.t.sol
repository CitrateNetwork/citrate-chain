// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Chain #451 review follow-ups: group tasks need a dispute admin, a TASK coordinator
///         must have joined, answered challenges record the leaf's units, a challenger's slash
///         share survives a refund or an upheld subjective dispute, and committed disputes keep
///         their reward with the disputer who found the evidence.
contract WorkMarketReviewTest is WorkMarketTestBase {
    function _ev(uint8 tag, bytes memory body) internal pure returns (bytes memory) {
        return abi.encode(tag, body);
    }

    function _receipts(uint256 id, address w, uint256 n) internal view returns (WorkMarket.Receipt[] memory rs) {
        rs = new WorkMarket.Receipt[](n);
        for (uint256 i = 0; i < n; i++) {
            rs[i] = _receipt(id, w, bytes32(i + 1));
        }
    }

    /// TASK offer; `w1` joins as a second worker so a non-poster party can challenge.
    function _postedTask(bool group) internal returns (uint256 id, bytes32[] memory leaves) {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.TASK);
        if (group) {
            p.groupHash = keccak256("group");
            p.disputeAdmin = admin;
        }
        id = _open(p, 3 * PRICE);
        _join(id, coordinator);
        _join(id, w1);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(coordinator, 1);
        (leaves,) = _leaves(id, e, _noOverride(), 0);
        _postTree(id, leaves, 1);
    }

    function _subjective() internal pure returns (bytes memory) {
        return abi.encode(uint8(0), abi.encode(uint16(300)));
    }

    // ── open / postPayout parties ──────────────────────────────────

    function test_group_task_requires_dispute_admin() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.TASK);
        p.groupHash = keccak256("group");
        vm.expectRevert(WorkMarket.BadParty.selector);
        _open(p, BUDGET);
        p.disputeAdmin = admin;
        _open(p, BUDGET);
        // an open task (no group) needs none
        _open(_params(IWorkMarket.Kind.TASK), BUDGET);
    }

    function test_task_payout_requires_joined_coordinator() public {
        uint256 id = _open(_params(IWorkMarket.Kind.TASK), BUDGET);
        _accept(id);
        vm.expectRevert(WorkMarket.NotJoined.selector);
        _post(id, keccak256("r"), 1);
        _join(id, coordinator);
        _post(id, keccak256("r"), 1);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.PayoutPosted));
    }

    // ── A3: answers record the leaf's units ────────────────────────

    function test_answer_records_leaf_units_and_stops_rechallenge_ladder() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3(); // w2's leaf pays 3
        WorkMarket.Receipt[] memory one = _receipts(id, w2, 1);
        vm.prank(w2);
        market.challengeInclusion{value: CHBOND}(id, one);
        market.answerChallenge(id, _opening(leaves, 1, e[1], 2));
        assertEq(market.challengeOf(id, w2).answeredUnits, 3);
        WorkMarket.Receipt[] memory two = _receipts(id, w2, 2);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.challengeInclusion{value: CHBOND}(id, two);
        WorkMarket.Receipt[] memory three = _receipts(id, w2, 3);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.challengeInclusion{value: CHBOND}(id, three);
    }

    // ── slash share survives a refund or an upheld subjective dispute

    function test_refund_of_disputed_task_waits_for_open_challenge_and_pays_challenger() public {
        (uint256 id,) = _postedTask(false);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.prank(poster);
        market.dispute(id, _subjective());
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        market.refund(id);

        market.resolveIndexChallenge(id, 0);
        assertEq(market.balanceOf(w1), CBOND / 2 + CHBOND);
        assertEq(market.balanceOf(poster), CBOND / 2);
        vm.prank(poster);
        market.refund(id);
        assertEq(market.balanceOf(poster), CBOND / 2 + 3 * PRICE);
        assertEq(market.owedOn(id), 0);
    }

    function test_upheld_subjective_dispute_waits_for_open_challenge() public {
        (uint256 id,) = _postedTask(true);
        WorkMarket.Receipt[] memory rs = _receipts(id, w1, 1);
        vm.prank(w1);
        market.challengeInclusion{value: CHBOND}(id, rs);
        vm.prank(poster);
        market.dispute(id, _subjective());
        vm.prank(admin);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        market.resolveDispute(id, true);
        // rejecting leaves the challenge running under the standing payout
        vm.prank(admin);
        market.resolveDispute(id, false);
        assertEq(market.getOffer(id).openChallenges, 1);
    }

    // ── committed disputes ─────────────────────────────────────────

    function _postedOmittingW2() internal returns (uint256 id, bytes memory ev) {
        id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, 2);
        e[1] = Entry(w3, 1);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 3);
        ev = _missingW2(id, _opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 2));
    }

    function _missingW2(uint256 id, WorkMarket.LeafOpening memory lo, WorkMarket.LeafOpening memory hi)
        internal
        view
        returns (bytes memory)
    {
        WorkMarket.Receipt memory r = _receipt(id, w2, keccak256("lease-1"));
        return _ev(market.DISPUTE_MISSING_LEAF(), abi.encode(r, market.ABSENT_BETWEEN(), lo, hi));
    }

    function test_committed_dispute_pays_the_committer_not_a_copier() public {
        (uint256 id, bytes memory ev) = _postedOmittingW2();
        bytes32 salt = keccak256("salt");
        uint32 epoch = market.getOffer(id).payoutEpoch;
        bytes32 c = market.disputeCommitment(id, epoch, w2, ev, salt);
        vm.prank(w2);
        market.commitDispute(id, c);

        vm.prank(w2);
        vm.expectRevert(WorkMarket.TooEarly.selector); // reveal after DISPUTE_REVEAL_DELAY
        market.revealDispute(id, ev, salt);

        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.prank(w3); // a copier holding the same evidence and salt has no commitment of its own
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.revealDispute(id, ev, salt);
        vm.prank(w2);
        market.revealDispute(id, ev, salt);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
        assertEq(market.balanceOf(w2), CBOND / 2);
        assertEq(market.balanceOf(w3), 0);
    }

    function test_committed_dispute_by_poster_sends_the_slash_to_the_sink() public {
        (uint256 id, bytes memory ev) = _postedOmittingW2();
        bytes32 c = market.disputeCommitment(id, market.getOffer(id).payoutEpoch, poster, ev, bytes32(uint256(7)));
        vm.prank(poster);
        market.commitDispute(id, c);
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotDisputer.selector);
        market.commitDispute(id, keccak256("x"));
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // one commitment, once
        market.commitDispute(id, c);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.prank(poster);
        market.revealDispute(id, ev, bytes32(uint256(7)));
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), CBOND);
    }

    function test_commitment_does_not_carry_to_a_new_root_or_past_the_window() public {
        (uint256 id, bytes memory ev) = _postedOmittingW2();
        bytes32 c = market.disputeCommitment(id, market.getOffer(id).payoutEpoch, w2, ev, bytes32(0));
        vm.prank(w2);
        market.commitDispute(id, c);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.warp(uint256(market.getOffer(id).payoutPostedAt) + WINDOW);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.revealDispute(id, ev, bytes32(0));
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.commitDispute(id, keccak256("late"));
    }
}
