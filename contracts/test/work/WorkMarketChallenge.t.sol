// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Owner decisions of 2026-11-09 on chain #451: Q11 inclusion challenge-response, Q1 default
///         coordinator bond, Q3 reserve sweep after the 180-day claim period.
contract WorkMarketChallengeTest is WorkMarketTestBase {
    function _receipts(uint256 id, address w, uint256 n) internal view returns (WorkMarket.Receipt[] memory rs) {
        rs = new WorkMarket.Receipt[](n);
        for (uint256 i = 0; i < n; i++) {
            rs[i] = _receipt(id, w, bytes32(i + 1));
        }
    }

    /// A tree with an unopenable "garbage" leaf where w2 belongs: [w1, garbage, w3, pad].
    function _postedWithGarbage() internal returns (uint256 id, bytes32[] memory leaves, Entry[] memory e) {
        id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        e = _entries3();
        (leaves,) = _leaves(id, e, _noOverride(), 2);
        leaves[1] = keccak256("garbage leaf, no preimage");
        _post(id, _rootOf(leaves), 6);
    }

    // ── Q11: challenge-response ────────────────────────────────────

    function test_unanswered_challenge_is_upheld_and_slashes_bond() public {
        (uint256 id,,) = _postedWithGarbage();
        WorkMarket.Receipt[] memory rs = _receipts(id, w2, 1);
        vm.prank(w2);
        market.challengeInclusion(id, rs);
        assertEq(market.getOffer(id).openChallenges, 1);

        vm.expectRevert(WorkMarket.AnswerTooEarly.selector);
        market.resolveChallenge(id, w2);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        vm.prank(stranger);
        market.resolveChallenge(id, w2);

        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Running));
        assertEq(o.payoutRoot, bytes32(0));
        assertEq(o.openChallenges, 0);
        assertEq(market.balanceOf(w2), CBOND / 2);
        assertEq(market.balanceOf(poster), CBOND / 2);
    }

    function test_answered_challenge_is_dismissed_and_settle_resumes() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        WorkMarket.Receipt[] memory rs = _receipts(id, w2, 3);
        vm.prank(w2);
        market.challengeInclusion(id, rs);

        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        _settle(id, leaves, 0, e[0], 0);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.claimBond(id);

        WorkMarket.LeafOpening memory l = _opening(leaves, 1, e[1], 2);
        vm.prank(stranger); // anyone holding the tree may answer
        market.answerChallenge(id, l);
        assertEq(market.getOffer(id).openChallenges, 0);
        vm.expectRevert(WorkMarket.NoOpenChallenge.selector);
        market.resolveChallenge(id, w2);

        _settle(id, leaves, 0, e[0], 0);
        assertEq(market.balanceOf(w1), 2 * PRICE);
        vm.prank(coordinator);
        market.claimBond(id);
    }

    function test_answer_needs_enough_units_and_a_real_leaf() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        WorkMarket.Receipt[] memory rs = _receipts(id, w3, 2); // w3's leaf pays 1
        vm.prank(w3);
        market.challengeInclusion(id, rs);
        WorkMarket.LeafOpening memory l = _opening(leaves, 2, e[2], 5);
        vm.expectRevert(WorkMarket.BadAnswer.selector);
        market.answerChallenge(id, l);
        l.units = 2; // does not open
        vm.expectRevert(WorkMarket.BadAnswer.selector);
        market.answerChallenge(id, l);
    }

    function test_answer_after_deadline_is_refused() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        WorkMarket.Receipt[] memory rs = _receipts(id, w2, 1);
        vm.prank(w2);
        market.challengeInclusion(id, rs);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        WorkMarket.LeafOpening memory l = _opening(leaves, 1, e[1], 2);
        vm.expectRevert(WorkMarket.AnswerTooLate.selector);
        market.answerChallenge(id, l);
    }

    function test_rechallenge_needs_more_receipts_than_answered() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        WorkMarket.Receipt[] memory one = _receipts(id, w2, 1);
        vm.prank(w2);
        market.challengeInclusion(id, one);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        market.challengeInclusion(id, one);
        WorkMarket.LeafOpening memory l = _opening(leaves, 1, e[1], 2);
        market.answerChallenge(id, l);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.BadEvidence.selector); // same claim again: griefing
        market.challengeInclusion(id, one);
        WorkMarket.Receipt[] memory four = _receipts(id, w2, 4); // leaf pays 3: a real claim
        vm.prank(w2);
        market.challengeInclusion(id, four);
        assertEq(market.getOffer(id).openChallenges, 1);
    }

    function test_challenge_rules() public {
        (uint256 id,) = _postedFl3();
        WorkMarket.Receipt[] memory rs = _receipts(id, w2, 1);
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotDisputer.selector);
        market.challengeInclusion(id, rs);

        WorkMarket.Receipt[] memory none = new WorkMarket.Receipt[](0);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.challengeInclusion(id, none);

        WorkMarket.Receipt[] memory bad = _receipts(id, w2, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, keccak256("x"));
        bad[0].signature = abi.encodePacked(r, s, v);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.challengeInclusion(id, bad);

        WorkMarket.Receipt[] memory dup = new WorkMarket.Receipt[](2);
        dup[0] = _receipt(id, w2, bytes32(uint256(1)));
        dup[1] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w2);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.challengeInclusion(id, dup);

        vm.warp(block.timestamp + WINDOW);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.challengeInclusion(id, rs);
    }

    function test_refund_waits_for_open_challenge() public {
        (uint256 id2,,) = _postedWithGarbage();
        WorkMarket.Receipt[] memory rs2 = _receipts(id2, w2, 1);
        vm.warp(uint256(market.getOffer(id2).payoutPostedAt) + WINDOW - 1);
        vm.prank(w2);
        market.challengeInclusion(id2, rs2);
        vm.warp(uint256(market.getOffer(id2).deadline) + WINDOW);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.ChallengeOpen.selector);
        market.refund(id2);
        market.resolveChallenge(id2, w2);
        vm.prank(poster);
        market.refund(id2); // Running past the deadline: Expired, full budget back
        assertEq(uint8(market.getOffer(id2).state), uint8(IWorkMarket.State.Expired));
    }

    // ── Q1: default coordinator bond ───────────────────────────────

    function test_zero_bond_at_open_takes_the_protocol_default() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinatorBond = 0;
        uint256 id = _open(p, BUDGET);
        assertEq(market.getOffer(id).coordinatorBond, market.defaultCoordinatorBond());
        assertGt(market.defaultCoordinatorBond(), 0);
        _accept(id);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.WrongBond.selector);
        market.postPayout(id, keccak256("r"), 1);
    }

    function test_constructor_refuses_zero_default_bond() public {
        vm.expectRevert(WorkMarket.BadDefaultBond.selector);
        new WorkMarket(governance, guardian, 0, new address[](0));
    }

    // ── Q3: reserve sweep after the claim period ───────────────────

    function test_sweep_reserve_after_claim_period_stops_settling() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        uint256 afterWindow = uint256(market.getOffer(id).deadline) + WINDOW;
        vm.warp(afterWindow);
        vm.prank(poster);
        market.refund(id); // 4 back, 6 reserved
        _settle(id, leaves, 0, e[0], 0); // w1 takes 2

        vm.warp(afterWindow + market.RESERVE_CLAIM_PERIOD() - 1);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.sweepReserve(id);
        vm.warp(afterWindow + market.RESERVE_CLAIM_PERIOD());
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotPoster.selector);
        market.sweepReserve(id);
        vm.prank(poster);
        market.sweepReserve(id);
        assertEq(market.balanceOf(poster), BUDGET - 2 * PRICE);

        vm.expectRevert(WorkMarket.ReserveGone.selector);
        _settle(id, leaves, 1, e[1], 2);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.WrongState.selector);
        market.sweepReserve(id);
        vm.prank(coordinator);
        market.claimBond(id);
        assertEq(market.owedOn(id), 0);
    }

    function test_sweep_requires_refund_first() public {
        (uint256 id,) = _postedFl3();
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW + market.RESERVE_CLAIM_PERIOD());
        vm.prank(poster);
        vm.expectRevert(WorkMarket.WrongState.selector);
        market.sweepReserve(id);
    }
}
