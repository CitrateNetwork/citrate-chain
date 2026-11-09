// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Chain #451 round-3 review: where a slashed coordinator bond goes (the poster never
///         takes back a slash it could have caused itself), when a dismissed challenge's bond is
///         paid, the commit deadline, and the minimum coordinator bond.
contract WorkMarketSlashTest is WorkMarketTestBase {
    function _ev(uint8 tag, bytes memory body) internal pure returns (bytes memory) {
        return abi.encode(tag, body);
    }

    function _commit(uint256 id, address who, bytes memory ev) internal returns (bytes32 salt) {
        salt = keccak256(abi.encode("salt", who));
        bytes32 c = market.disputeCommitment(id, market.getOffer(id).payoutEpoch, who, ev, salt);
        vm.prank(who);
        market.commitDispute(id, c);
    }

    function _reveal(uint256 id, address who, bytes memory ev, bytes32 salt) internal {
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.prank(who);
        market.revealDispute(id, ev, salt);
    }

    /// A further worker `_underPosted` joins before posting (a sybil), if set.
    address internal alsoJoins;

    /// Posts a correct 6-unit tree over w1..w3 posted as 9 units; returns the TOTAL evidence.
    function _underPosted(bool posterCoordinates) internal returns (uint256 id, bytes memory ev) {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        if (posterCoordinates) p.coordinator = poster;
        id = _open(p, BUDGET);
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        if (alsoJoins != address(0)) _join(id, alsoJoins);
        _accept(id);
        Entry[] memory e = _entries3();
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 2);
        address c = posterCoordinates ? poster : coordinator;
        vm.prank(c);
        market.postPayout{value: CBOND}(id, _rootOf(leaves), 9, 2);
        ev = _ev(6, abi.encode(_opening(leaves, 2, e[2], 5), _padding(leaves, 3)));
    }

    // ── slash destinations ─────────────────────────────────────────

    function test_coordinating_poster_self_dispute_sends_the_bond_to_the_sink() public {
        (uint256 id, bytes memory ev) = _underPosted(true);
        bytes32 salt = _commit(id, w3, ev);
        // the coordinating poster sees the commitment and disputes its own root at once
        vm.prank(poster);
        market.dispute(id, ev);
        assertEq(market.balanceOf(poster), 0, "the poster takes nothing back");
        assertEq(market.balanceOf(SINK), CBOND);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.prank(w3);
        vm.expectRevert(WorkMarket.BadEvidence.selector);
        market.revealDispute(id, ev, salt);
    }

    function test_uncommitted_copy_earns_nothing_when_the_poster_coordinates() public {
        (uint256 id, bytes memory ev) = _underPosted(true);
        _commit(id, w3, ev);
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        vm.prank(w1); // copies the reveal into dispute()
        market.dispute(id, ev);
        assertEq(market.balanceOf(w1), 0);
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), CBOND);
    }

    /// Owner 2026-11-09 (Q4 revised): every slash splits half to the rewarded disputer, half to
    /// the sink; the poster never receives any part, whoever coordinates.
    function test_committed_dispute_against_a_coordinating_poster_splits_with_the_sink() public {
        (uint256 id, bytes memory ev) = _underPosted(true);
        bytes32 salt = _commit(id, w3, ev);
        _reveal(id, w3, ev, salt);
        assertEq(market.balanceOf(w3), CBOND / 2);
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), CBOND - CBOND / 2);
    }

    /// A coordinating poster pre-commits through a joined sybil worker and reveals first: the
    /// colluding side recovers at most half of the slashed bond.
    function test_sybil_precommit_by_a_coordinating_poster_recovers_at_most_half() public {
        address sy = address(0x0A0A);
        alsoJoins = sy;
        (uint256 id, bytes memory ev) = _underPosted(true);
        bytes32 sSalt = _commit(id, sy, ev); // right after posting
        vm.warp(block.timestamp + 6 hours);
        _commit(id, w3, ev);
        vm.prank(sy);
        market.revealDispute(id, ev, sSalt);
        assertLe(market.balanceOf(sy) + market.balanceOf(poster), CBOND / 2, "colluders recover at most half");
        assertEq(market.balanceOf(SINK), CBOND - CBOND / 2);
    }

    /// The poster coordinates through a second address and keeps a sybil worker: still at most
    /// half comes back to the colluding side.
    function test_second_address_coordinator_and_sybil_recover_at_most_half() public {
        // `coordinator` stands for the poster's second address
        address sy = address(0x0A0A);
        alsoJoins = sy;
        (uint256 id, bytes memory ev) = _underPosted(false);
        bytes32 sSalt = _commit(id, sy, ev);
        _reveal(id, sy, ev, sSalt);
        assertLe(
            market.balanceOf(sy) + market.balanceOf(poster) + market.balanceOf(coordinator),
            CBOND / 2,
            "colluders recover at most half"
        );
        assertEq(market.balanceOf(SINK), CBOND - CBOND / 2);
    }

    function test_direct_dispute_slash_goes_to_the_sink() public {
        (uint256 id, bytes memory ev) = _underPosted(false);
        vm.prank(w2);
        market.dispute(id, ev);
        assertEq(market.balanceOf(w2), 0);
        assertEq(market.balanceOf(poster), 0, "a poster with a second-address coordinator recovers nothing");
        assertEq(market.balanceOf(SINK), CBOND);
    }

    function test_poster_disputes_send_the_slash_to_the_sink_committed_or_not() public {
        (uint256 id, bytes memory ev) = _underPosted(false);
        vm.prank(poster);
        market.dispute(id, ev);
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), CBOND);

        (uint256 id2, bytes memory ev2) = _underPosted(false);
        bytes32 salt = _commit(id2, poster, ev2);
        _reveal(id2, poster, ev2, salt);
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), 2 * CBOND);
    }

    function test_committed_worker_dispute_splits_with_the_sink_not_the_poster() public {
        (uint256 id, bytes memory ev) = _underPosted(false);
        bytes32 salt = _commit(id, w2, ev);
        _reveal(id, w2, ev, salt);
        assertEq(market.balanceOf(w2), CBOND / 2);
        assertEq(market.balanceOf(poster), 0);
        assertEq(market.balanceOf(SINK), CBOND - CBOND / 2);
    }

    function test_unanswered_poster_challenge_slash_goes_to_the_sink() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("no preimage");
        _postTree(id, leaves, 1);
        vm.prank(poster);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveIndexChallenge(id, 0);
        assertEq(market.balanceOf(poster), CHBOND, "only its challenge bond back");
        assertEq(market.balanceOf(SINK), CBOND);
    }

    // ── dismissed challenge bonds wait for the root to survive ─────

    function test_dismissed_bond_waits_for_the_root_and_goes_to_the_coordinator() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 3);
        vm.prank(stranger);
        market.answerIndexChallenge(id, _padding(leaves, 3));
        assertEq(market.balanceOf(stranger), 0, "nothing paid at answer time");
        assertEq(market.balanceOf(coordinator), 0);
        vm.expectRevert(WorkMarket.NothingToClaim.selector); // the root has not survived yet
        market.releaseIndexChallengeBond(id, 3);
        vm.warp(block.timestamp + market.POST_ANSWER_DISPUTE_WINDOW());
        market.releaseIndexChallengeBond(id, 3);
        assertEq(market.balanceOf(coordinator), CHBOND);
        assertEq(market.balanceOf(stranger), 0);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.releaseIndexChallengeBond(id, 3);
    }

    function test_self_answered_challenge_bond_goes_to_the_coordinator() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        uint256 end = uint256(market.getOffer(id).payoutPostedAt) + WINDOW;
        vm.warp(end - 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 3);
        vm.warp(end - 1 + 24 hours);
        vm.prank(w1); // answers its own challenge to delay settling
        market.answerIndexChallenge(id, _padding(leaves, 3));
        vm.warp(block.timestamp + market.POST_ANSWER_DISPUTE_WINDOW());
        market.releaseIndexChallengeBond(id, 3);
        assertEq(market.balanceOf(w1), 0, "the delay cost the challenger its bond");
        assertEq(market.balanceOf(coordinator), CHBOND);
    }

    function test_dismissed_bond_is_refunded_when_the_root_is_withdrawn() public {
        uint256 id = _openFl();
        address sy = address(0x0F00);
        _join(id, sy);
        _join(id, w3);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(sy, 4);
        e[1] = Entry(w3, 4);
        uint64[] memory cums = new uint64[](2); // both claim [0,4)
        (bytes32[] memory leaves,) = _leaves(id, e, cums, 1);
        _postTree(id, leaves, 4);
        vm.prank(w3);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.prank(coordinator);
        market.answerIndexChallenge(id, _opening(leaves, 0, e[0], 0));
        bytes memory ev = _ev(3, abi.encode(_opening(leaves, 0, e[0], 0), _opening(leaves, 1, e[1], 0)));
        vm.prank(sy);
        market.dispute(id, ev);
        market.releaseIndexChallengeBond(id, 0);
        assertEq(market.balanceOf(w3), CHBOND, "the finder gets its bond back");
        assertEq(market.balanceOf(coordinator), 0, "a withdrawn root earns its coordinator nothing");
        assertEq(market.owedOn(id), BUDGET);
    }

    function test_dismissed_worker_challenge_bond_follows_the_root() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](1);
        rs[0] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w2);
        market.challengeInclusion{value: CHBOND}(id, rs);
        market.answerChallenge(id, _opening(leaves, 1, _entries3()[1], 2));
        assertEq(market.balanceOf(coordinator), 0);
        vm.warp(block.timestamp + market.POST_ANSWER_DISPUTE_WINDOW());
        market.releaseChallengeBond(id, w2);
        assertEq(market.balanceOf(coordinator), CHBOND);
        vm.expectRevert(WorkMarket.NothingToClaim.selector); // paid once
        market.releaseChallengeBond(id, w2);
    }

    /// An answered challenge's root has not survived while another challenge is still open past
    /// the window; if that one is upheld, the answered challenger is refunded instead.
    function test_dismissed_bond_waits_for_open_challenges_too() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        uint256 windowEnd = uint256(market.getOffer(id).payoutPostedAt) + WINDOW;
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 3);
        market.answerIndexChallenge(id, _padding(leaves, 3)); // grace ends before the window does
        vm.warp(windowEnd - 1);
        vm.prank(w2);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.warp(windowEnd + 1); // past the dispute end, but slot 0 is still challenged
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.releaseIndexChallengeBond(id, 3);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW());
        market.resolveIndexChallenge(id, 0); // nobody answered slot 0: root withdrawn
        market.releaseIndexChallengeBond(id, 3);
        assertEq(market.balanceOf(w1), CHBOND, "refunded: the root it was dismissed under is gone");
        assertEq(market.balanceOf(coordinator), 0);
    }

    function test_upheld_challenges_pay_their_bond_once() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("no preimage");
        _postTree(id, leaves, 1);
        vm.prank(w1);
        market.challengeIndex{value: CHBOND}(id, 0);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveIndexChallenge(id, 0);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.releaseIndexChallengeBond(id, 0);

        bytes32[] memory l2 = new bytes32[](2);
        l2[0] = keccak256("still no preimage");
        _postTree(id, l2, 1);
        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](1);
        rs[0] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w1);
        market.challengeInclusion{value: CHBOND}(id, rs);
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveChallenge(id, w2);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.releaseChallengeBond(id, w2);
        assertEq(market.owedOn(id), BUDGET);
    }

    /// A same-root re-challenge with more receipts than the answered leaf pays proves the root
    /// faulty, so the earlier, dismissed challenger is refunded at once.
    function test_same_root_rechallenge_refunds_the_dismissed_challenger() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3(); // w2's leaf pays 3
        WorkMarket.Receipt[] memory one = new WorkMarket.Receipt[](1);
        one[0] = _receipt(id, w2, bytes32(uint256(1)));
        vm.prank(w1);
        market.challengeInclusion{value: CHBOND}(id, one);
        market.answerChallenge(id, _opening(leaves, 1, _entries3()[1], 2));
        WorkMarket.Receipt[] memory four = new WorkMarket.Receipt[](4);
        for (uint256 i = 0; i < 4; i++) {
            four[i] = _receipt(id, w2, bytes32(i + 1));
        }
        vm.prank(w2);
        market.challengeInclusion{value: CHBOND}(id, four);
        assertEq(market.balanceOf(w1), CHBOND);
        assertEq(market.owedOn(id), BUDGET + CBOND + CHBOND);
    }

    // ── commit deadline ────────────────────────────────────────────

    function test_commit_refused_when_the_reveal_cannot_fit() public {
        (uint256 id, bytes memory ev) = _underPosted(false);
        uint256 end = uint256(market.getOffer(id).payoutPostedAt) + WINDOW;
        vm.warp(end - market.DISPUTE_REVEAL_DELAY());
        bytes32 c = market.disputeCommitment(id, 0, w2, ev, bytes32(0));
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WindowClosed.selector);
        market.commitDispute(id, c);
        vm.warp(end - market.DISPUTE_REVEAL_DELAY() - 1);
        vm.prank(w2);
        market.commitDispute(id, c);
    }

    // ── minimum coordinator bond and the slash sink ────────────────

    function test_offer_bond_must_meet_the_minimum() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinatorBond = MINBOND - 1;
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BondBelowMinimum.selector);
        market.open{value: BUDGET}(p);
        p.coordinatorBond = MINBOND;
        uint256 id = _open(p, BUDGET);
        assertEq(market.getOffer(id).coordinatorBond, MINBOND);
    }

    function test_constructor_checks_minimum_and_sink() public {
        address[] memory none = new address[](0);
        vm.expectRevert(WorkMarket.BadMinBond.selector);
        new WorkMarket(governance, guardian, SINK, 1 ether, 0, none);
        vm.expectRevert(WorkMarket.BadDefaultBond.selector); // the default may not undercut the minimum
        new WorkMarket(governance, guardian, SINK, 1 ether, 2 ether, none);
        vm.expectRevert(InitialAdmin.InitialAdmin_Zero.selector);
        new WorkMarket(governance, guardian, address(0), 1 ether, MINBOND, none);
        assertEq(market.slashSink(), SINK);
        assertEq(market.minCoordinatorBond(), MINBOND);
    }
}
