// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Code that answers every EIP-1271 query with "not signed". Placed at a coordinator's
///         address (`vm.etch`) it stands for an address that gains code after it signed receipts
///         (a CREATE2 address deployed later, or a delegated key).
contract SignsNothing {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }

    receive() external payable {}
}

/// @notice GHSA-gh3c hardening: receipts, refunds and the Disputed refund path.
contract WorkMarketHardeningTest is WorkMarketTestBase {
    address internal w0 = address(0x0F00); // sorts before w1
    address internal w9 = address(0x5B11); // sorts after w3

    /// The receipt for `w`'s `n`-th verified lease: it proves `w` is owed at least `n` units.
    function _receipts(uint256 id, address w, uint256 n) internal view returns (WorkMarket.Receipt memory) {
        return _receiptN(id, w, bytes32(n), uint64(n));
    }

    /// w1 did `done` verified leases; the posted root pays it `paid` and gives the rest to w9.
    function _shortPaid(uint64 done, uint64 paid)
        internal
        returns (uint256 id, bytes32[] memory leaves, Entry[] memory e)
    {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.maxWorkers = 2;
        id = _open(p, uint256(done) * PRICE);
        _join(id, w1);
        vm.deal(w9, 100 ether);
        _join(id, w9);
        _accept(id);
        e = new Entry[](2);
        e[0] = Entry(w1, paid);
        e[1] = Entry(w9, done - paid);
        (leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, done);
    }

    // ── one receipt per lease proves what the worker is owed, at any unit count ──

    function test_receipts_prove_a_shortfall_at_any_unit_count() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _shortPaid(400, 256);
        WorkMarket.Receipt memory r = _receipts(id, w1, 400); // w1's 400th lease, one receipt
        bytes memory ev = abi.encode(uint8(2), abi.encode(_opening(leaves, 0, e[0], 0), r));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running), "the short root is withdrawn");
        assertEq(market.balanceOf(SINK), CBOND, "the coordinator bond is slashed");
    }

    /// The leaf itself pays more than 256 units (300 of 600 owed): one receipt still proves it.
    function test_a_leaf_paying_more_than_256_units_is_still_shown_short() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _shortPaid(600, 300);
        bytes memory ev = abi.encode(uint8(2), abi.encode(_opening(leaves, 0, e[0], 0), _receipts(id, w1, 600)));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running), "the short root is withdrawn");
        assertEq(market.balanceOf(SINK), CBOND);
    }

    function test_an_inclusion_challenge_holds_a_leaf_to_its_receipts_at_any_unit_count() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _shortPaid(400, 256);
        WorkMarket.Receipt memory r = _receipts(id, w1, 400);
        vm.prank(w1);
        market.challengeInclusion{value: CHBOND}(id, r);
        vm.expectRevert(WorkMarket.BadAnswer.selector); // the leaf pays 256 of 400
        market.answerChallenge(id, _opening(leaves, 0, e[0], 0));
        vm.warp(block.timestamp + market.CHALLENGE_RESPONSE_WINDOW() + 1);
        market.resolveChallenge(id, w1);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
        assertEq(market.balanceOf(w1), CBOND / 2 + CHBOND);
    }

    /// For any unit count and any shortfall, the receipt for the worker's last lease proves it,
    /// and the receipt for a lease the leaf does pay proves nothing.
    function testFuzz_one_receipt_proves_any_shortfall(uint64 done, uint64 paid) public {
        done = uint64(bound(done, 2, 5000));
        paid = uint64(bound(paid, 1, done - 1));
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _shortPaid(done, paid);
        WorkMarket.LeafOpening memory leaf = _opening(leaves, 0, e[0], 0);
        bytes memory paidInFull = abi.encode(uint8(2), abi.encode(leaf, _receipts(id, w1, paid)));
        bytes memory shortfall = abi.encode(uint8(2), abi.encode(leaf, _receipts(id, w1, done)));
        vm.prank(w1);
        vm.expectRevert(WorkMarket.DisputeNotProven.selector);
        market.dispute(id, paidInFull);
        vm.prank(w1);
        market.dispute(id, shortfall);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    // ── a signed receipt stays valid whatever code the coordinator's address later has ──

    /// The root pays only w9; w1 holds a receipt and is absent.
    function _omittingW1() internal returns (uint256 id, bytes32[] memory leaves, Entry[] memory e) {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.maxWorkers = 2;
        id = _open(p, BUDGET);
        _join(id, w1);
        vm.deal(w9, 100 ether);
        _join(id, w9);
        _accept(id);
        e = new Entry[](1);
        e[0] = Entry(w9, 5);
        (leaves,) = _leaves(id, e, _noOverride(), 1);
        _postTree(id, leaves, 5);
    }

    function test_a_receipt_still_proves_a_missing_leaf_after_the_coordinator_address_gains_code() public {
        (uint256 id, bytes32[] memory leaves, Entry[] memory e) = _omittingW1();
        WorkMarket.Receipt memory r = _receipt(id, w1, keccak256("lease-1"));
        vm.etch(coordinator, type(SignsNothing).runtimeCode);
        WorkMarket.LeafOpening memory none;
        bytes memory ev = abi.encode(uint8(1), abi.encode(r, uint8(1), none, _opening(leaves, 0, e[0], 0)));
        vm.prank(w1);
        market.dispute(id, ev);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
    }

    function test_a_receipt_still_raises_a_challenge_after_the_coordinator_address_gains_code() public {
        (uint256 id,,) = _omittingW1();
        WorkMarket.Receipt memory rs = _receipts(id, w1, 1);
        vm.etch(coordinator, type(SignsNothing).runtimeCode);
        vm.prank(w1);
        market.challengeInclusion{value: CHBOND}(id, rs);
        assertEq(market.getOffer(id).openChallenges, 1);
    }

    function test_an_fl_offer_refuses_a_coordinator_with_code() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinator = address(new SignsNothing());
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BadParty.selector);
        market.open{value: BUDGET}(p);
    }

    // ── refunds count what every root paid ──

    /// Executed time is monotone on Citrate (TIMESTAMP comes from the accepting block), so a root
    /// cannot be withdrawn after one of its leaves settled. The accounting must not depend on it:
    /// here time is moved back with vm.warp.
    function _paidThenWithdrawn() internal returns (uint256 id) {
        id = _paidThenWithdrawnBare();
        bytes32 leaf = market.leafHash(0, market.leafPayload(id, w3, 1, 0));
        vm.prank(coordinator);
        market.postPayout{value: CBOND}(id, leaf, 1, 0);
    }

    function _paidThenWithdrawnBare() internal returns (uint256 id) {
        bytes32[] memory leaves;
        (id, leaves) = _postedFl3(); // w1 2, w2 3, w3 1 of BUDGET 10
        uint256 postedAt = market.getOffer(id).payoutPostedAt;
        vm.warp(postedAt + WINDOW + 1);
        _settle(id, leaves, 0, Entry(w1, 2), 0); // paid = 2
        vm.warp(postedAt + 1);
        vm.prank(w2);
        market.challengeIndex{value: CHBOND}(id, 3);
        vm.warp(postedAt + 1 + 24 hours + 1);
        market.resolveIndexChallenge(id, 3); // root withdrawn; paid stays 2
        assertEq(market.getOffer(id).paid, 2 ether);
    }

    function test_refund_leaves_out_what_an_earlier_root_paid() public {
        uint256 other = _openFl();
        uint256 id = _paidThenWithdrawn();
        vm.warp(vm.getBlockTimestamp() + 8 days);
        vm.prank(poster);
        market.refund(id);
        market.settle(id, w3, 1, 0, 0, new bytes32[](0));
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(uint256(o.paid) + o.refunded, BUDGET, "paid plus refunded is the budget");
        assertEq(o.refunded, 7 ether);
        assertEq(market.owedOn(other), BUDGET, "the other offer stays fully backed");
    }

    function test_reserve_sweep_returns_only_the_unsettled_reserve() public {
        uint256 id = _paidThenWithdrawn();
        vm.warp(vm.getBlockTimestamp() + 8 days);
        vm.prank(poster);
        market.refund(id);
        WorkMarket.Offer memory o = market.getOffer(id);
        vm.warp(uint256(o.deadline) + o.disputeWindow + market.RESERVE_CLAIM_PERIOD());
        vm.prank(poster);
        market.sweepReserve(id);
        o = market.getOffer(id);
        assertEq(uint256(o.paid) + o.refunded, BUDGET);
    }

    /// A root may reserve only what the budget has not already paid.
    function test_a_root_may_not_reserve_more_than_the_unpaid_budget() public {
        uint256 id = _paidThenWithdrawnBare();
        bytes32 leaf = market.leafHash(0, market.leafPayload(id, w3, 9, 0));
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.BadUnits.selector); // 9 + 2 already paid > 10
        market.postPayout{value: CBOND}(id, leaf, 9, 0);
        leaf = market.leafHash(0, market.leafPayload(id, w3, 8, 0));
        vm.prank(coordinator);
        market.postPayout{value: CBOND}(id, leaf, 8, 0);
    }

    // ── a Disputed offer's refund does not wait on the poster ──

    function _disputedTask() internal returns (uint256 id) {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.TASK);
        p.coordinator = w1;
        id = _open(p, BUDGET);
        _join(id, w1);
        _accept(id);
        bytes32 leaf = market.leafHash(0, market.leafPayload(id, w1, 1, 0));
        vm.prank(w1);
        market.postPayout{value: CBOND}(id, leaf, 1, 0);
        vm.prank(poster);
        market.dispute(id, abi.encode(uint8(0), abi.encode(uint16(300))));
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Disputed));
    }

    function test_anyone_may_close_a_disputed_offer_and_the_refund_goes_to_its_poster() public {
        uint256 id = _disputedTask();
        WorkMarket.Offer memory o = market.getOffer(id);
        vm.warp(uint256(o.deadline) + o.disputeWindow);
        vm.prank(stranger);
        market.refund(id);
        assertEq(market.balanceOf(poster), BUDGET, "the refund is the poster's");
        assertEq(market.balanceOf(stranger), 0);
        assertEq(market.balanceOf(w1), CBOND, "the coordinator bond is released");
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Closed));
    }

    function test_only_the_poster_may_refund_an_offer_that_is_not_disputed() public {
        (uint256 id,) = _postedFl3();
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotPoster.selector);
        market.refund(id);
    }
}
