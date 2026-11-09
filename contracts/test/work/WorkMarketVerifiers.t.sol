// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {TaskVerifier} from "../../src/work/TaskVerifier.sol";
import {FLRoundVerifier, IFederatedRoundLedgerReads} from "../../src/work/FLRoundVerifier.sol";
import {FederatedRoundLedger} from "../../src/FederatedRoundLedger.sol";

/// @notice The two production verifiers, against the real FederatedRoundLedger and a real
///         WorkMarket (no test doubles on this path). 0.6.0 planset 06 §3, §4.
contract WorkMarketVerifiersTest is Test {
    WorkMarket internal market;
    TaskVerifier internal taskV;
    FLRoundVerifier internal flV;
    FederatedRoundLedger internal frl;

    address internal governance = makeAddr("governance");
    address internal poster = makeAddr("poster");
    address internal worker = makeAddr("worker");
    address internal flCoord = makeAddr("flCoord");
    address internal stranger = makeAddr("stranger");

    /// The genesis review window (owner 2026-11-09, Q7).
    uint64 internal constant REVIEW = 72 hours;
    uint128 internal bondNow;
    uint32 internal constant WINDOW = 24 hours;
    uint128 internal constant PRICE = 1 ether;
    bytes32 internal constant RESULT = keccak256("result");

    function setUp() public {
        vm.warp(1_000_000);
        frl = new FederatedRoundLedger();
        flV = new FLRoundVerifier(IFederatedRoundLedgerReads(address(frl)));
        taskV = new TaskVerifier(REVIEW);
        address[] memory vs = new address[](2);
        vs[0] = address(flV);
        vs[1] = address(taskV);
        market = new WorkMarket(governance, makeAddr("guardian"), makeAddr("slashSink"), 1 ether, 0.1 ether, vs);
        vm.deal(poster, 100 ether);
        vm.deal(worker, 10 ether);
        vm.deal(flCoord, 10 ether);
    }

    function _params(IWorkMarket.Kind kind, address v, bytes32 bind, address coord)
        internal
        view
        returns (WorkMarket.OpenParams memory p)
    {
        p = WorkMarket.OpenParams({
            kind: kind,
            verifier: v,
            bindRef: bind,
            jobSpecHash: keccak256("job"),
            requirementsHash: keccak256("req"),
            requirementsCid: "bafy-req",
            groupHash: bytes32(0),
            allowlistRoot: bytes32(0),
            pricePerUnit: PRICE,
            deadline: uint64(block.timestamp + 10 days),
            disputeWindow: WINDOW,
            maxWorkers: 8,
            joinBond: 0,
            coordinator: coord,
            coordinatorBond: 0,
            disputeAdmin: address(0)
        });
    }

    function _taskOffer() internal returns (uint256 id) {
        vm.prank(poster);
        id = market.open{value: 2 ether}(_params(IWorkMarket.Kind.TASK, address(taskV), keccak256("task"), worker));
        bytes32[] memory none;
        vm.prank(worker);
        market.join(id, PRICE, none);
    }

    function _leaf(uint256 id, address w, uint64 units) internal view returns (bytes32) {
        return market.leafHash(0, market.leafPayload(id, w, units, 0));
    }

    // ── TaskVerifier ───────────────────────────────────────────────

    function test_task_constructor_bounds_review_window() public {
        vm.expectRevert(TaskVerifier.BadReviewWindow.selector);
        new TaskVerifier(1 hours - 1);
        vm.expectRevert(TaskVerifier.BadReviewWindow.selector);
        new TaskVerifier(30 days + 1);
    }

    function test_task_not_accepted_before_submit_or_window() public {
        uint256 id = _taskOffer();
        (bool ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok);
        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        (ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok);
        vm.warp(block.timestamp + REVIEW - 1);
        (ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok);
    }

    function test_task_requester_accept_releases_payout_end_to_end() public {
        uint256 id = _taskOffer();
        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        vm.prank(stranger);
        vm.expectRevert(TaskVerifier.NotRequester.selector);
        taskV.accept(market, id, RESULT);
        vm.prank(poster);
        vm.expectRevert(TaskVerifier.BadResult.selector);
        taskV.accept(market, id, keccak256("other"));
        vm.prank(poster);
        taskV.accept(market, id, RESULT);

        bytes32 leaf = _leaf(id, worker, 1);
        bondNow = market.getOffer(id).coordinatorBond;
        vm.prank(worker);
        market.postPayout{value: bondNow}(id, leaf, 1, 0);
        assertEq(market.getOffer(id).digest, RESULT);
        vm.warp(block.timestamp + WINDOW);
        market.settle(id, worker, 1, 0, 0, new bytes32[](0));
        assertEq(market.balanceOf(worker), PRICE);
    }

    function test_task_auto_release_after_review_window() public {
        uint256 id = _taskOffer();
        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        bytes32 leaf = _leaf(id, worker, 1);
        bondNow = market.getOffer(id).coordinatorBond;
        vm.prank(worker);
        vm.expectRevert(WorkMarket.NotAccepted.selector);
        market.postPayout{value: bondNow}(id, leaf, 1, 0);
        vm.warp(block.timestamp + REVIEW);
        leaf = _leaf(id, worker, 1);
        bondNow = market.getOffer(id).coordinatorBond;
        vm.prank(worker);
        market.postPayout{value: bondNow}(id, leaf, 1, 0);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.PayoutPosted));
    }

    function test_task_only_selected_worker_submits_and_resubmit_restarts_window() public {
        uint256 id = _taskOffer();
        vm.prank(stranger);
        vm.expectRevert(TaskVerifier.NotWorker.selector);
        taskV.submit(market, id, RESULT);
        vm.prank(worker);
        vm.expectRevert(TaskVerifier.BadResult.selector);
        taskV.submit(market, id, bytes32(0));

        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        vm.warp(block.timestamp + REVIEW - 10);
        vm.prank(worker);
        taskV.submit(market, id, keccak256("v2"));
        vm.warp(block.timestamp + 10);
        (bool ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok);
        vm.prank(poster);
        taskV.accept(market, id, keccak256("v2"));
        vm.prank(worker);
        vm.expectRevert(TaskVerifier.AlreadyAccepted.selector);
        taskV.submit(market, id, RESULT);
    }

    function test_task_refuses_non_task_or_foreign_offers() public {
        vm.prank(poster);
        uint256 fl =
            market.open{value: 2 ether}(_params(IWorkMarket.Kind.FL_ROUND, address(flV), keccak256("x"), flCoord));
        vm.prank(flCoord);
        vm.expectRevert(TaskVerifier.NotTaskOffer.selector);
        taskV.submit(market, fl, RESULT);
        (bool ok,) = taskV.acceptedFor(market, fl, keccak256("x"));
        assertFalse(ok);
        (ok,) = taskV.acceptedFor(IWorkMarket(stranger), 1, keccak256("x")); // no code
        assertFalse(ok);
    }

    function test_task_bindRef_must_match() public {
        uint256 id = _taskOffer();
        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        vm.prank(poster);
        taskV.accept(market, id, RESULT);
        (bool ok,) = taskV.acceptedFor(market, id, keccak256("another-task"));
        assertFalse(ok);
    }

    // ── an upheld subjective dispute rejects the result (chain #451 review) ──

    address internal disputeAdmin = makeAddr("disputeAdmin");

    function _groupTaskPosted(bool requesterAccepts) internal returns (uint256 id) {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.TASK, address(taskV), keccak256("task"), worker);
        p.groupHash = keccak256("group");
        p.disputeAdmin = disputeAdmin;
        vm.prank(poster);
        id = market.open{value: 2 ether}(p);
        bytes32[] memory none;
        vm.prank(worker);
        market.join(id, PRICE, none);
        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        if (requesterAccepts) {
            vm.prank(poster);
            taskV.accept(market, id, RESULT);
        } else {
            vm.warp(block.timestamp + REVIEW);
        }
        bondNow = market.getOffer(id).coordinatorBond;
        bytes32 leaf = _leaf(id, worker, 1);
        vm.prank(worker);
        market.postPayout{value: bondNow}(id, leaf, 1, 0);
        vm.prank(poster);
        market.dispute(id, abi.encode(uint8(0), abi.encode(uint16(300))));
        vm.prank(disputeAdmin);
        market.resolveDispute(id, true);
    }

    function test_task_upheld_dispute_rejects_accepted_result_and_takes_a_corrected_one() public {
        uint256 id = _groupTaskPosted(true);
        (bool ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok, "the rejected result is no longer accepted");
        bondNow = market.getOffer(id).coordinatorBond;
        bytes32 leaf = _leaf(id, worker, 1);
        vm.prank(worker);
        vm.expectRevert(WorkMarket.NotAccepted.selector);
        market.postPayout{value: bondNow}(id, leaf, 1, 0);
        vm.prank(poster);
        vm.expectRevert(TaskVerifier.BadResult.selector); // nothing current to accept
        taskV.accept(market, id, RESULT);

        bytes32 v2 = keccak256("corrected");
        vm.prank(worker);
        taskV.submit(market, id, v2);
        vm.prank(poster);
        taskV.accept(market, id, v2);
        vm.prank(worker);
        market.postPayout{value: bondNow}(id, leaf, 1, 0);
        assertEq(market.getOffer(id).digest, v2);
        vm.warp(block.timestamp + WINDOW);
        market.settle(id, worker, 1, 0, 0, new bytes32[](0));
        assertEq(market.balanceOf(worker), PRICE + bondNow);
    }

    function test_task_upheld_dispute_rejects_auto_accepted_result() public {
        uint256 id = _groupTaskPosted(false);
        (bool ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok);
        // re-posting the same hash starts a fresh review window
        vm.prank(worker);
        taskV.submit(market, id, RESULT);
        (ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertFalse(ok);
        vm.warp(block.timestamp + REVIEW);
        (ok,) = taskV.acceptedFor(market, id, keccak256("task"));
        assertTrue(ok);
        assertEq(market.resultEpochOf(id), 1);
    }

    // ── FLRoundVerifier over the real FederatedRoundLedger ─────────

    function _cluster() internal returns (bytes32 clusterId) {
        FederatedRoundLedger.ClusterRules memory r = FederatedRoundLedger.ClusterRules({
            minParticipants: 3,
            chunkDim: 4,
            valueScaleLog2: 8,
            thresholdPos: 32768,
            thresholdNeg: -32768,
            confidenceRule: 1,
            weightRule: 1,
            challengeWindow: 20
        });
        vm.prank(flCoord);
        clusterId = frl.registerCluster(keccak256("c"), r);
    }

    function _commit(bytes32 clusterId) internal returns (bytes32 roundId) {
        FederatedRoundLedger.RoundCommit memory c = FederatedRoundLedger.RoundCommit({
            clusterId: clusterId,
            ordinal: 0,
            configHash: keccak256("cfg"),
            participantsRoot: keccak256("parts"),
            participants: 3,
            nValues: 4,
            inputRoot: keccak256("in"),
            outputRoot: keccak256("out"),
            chunks: 1,
            adapterHash: keccak256("adapter")
        });
        vm.prank(flCoord);
        roundId = frl.commitRound(c);
    }

    function test_fl_constructor_rejects_zero_ledger() public {
        vm.expectRevert(FLRoundVerifier.ZeroLedger.selector);
        new FLRoundVerifier(IFederatedRoundLedgerReads(address(0)));
    }

    function test_fl_bindRef_is_the_frl_round_id() public {
        bytes32 clusterId = _cluster();
        assertEq(flV.bindRefOf(clusterId, 0), frl.roundIdOf(clusterId, 0));
    }

    function test_fl_unknown_or_committed_round_not_accepted() public {
        bytes32 clusterId = _cluster();
        bytes32 bind = flV.bindRefOf(clusterId, 0);
        (bool ok, bytes32 d) = flV.accepted(1, bind);
        assertFalse(ok);
        assertEq(d, bytes32(0));
        _commit(clusterId);
        (ok,) = flV.accepted(1, bind);
        assertFalse(ok);
    }

    function test_fl_accepted_round_releases_payout_with_record_digest_end_to_end() public {
        bytes32 clusterId = _cluster();
        bytes32 bind = flV.bindRefOf(clusterId, 0);
        vm.prank(poster);
        uint256 id = market.open{value: 5 ether}(_params(IWorkMarket.Kind.FL_ROUND, address(flV), bind, flCoord));
        bytes32[] memory none;
        vm.prank(worker);
        market.join(id, PRICE, none);

        bytes32 roundId = _commit(clusterId);
        assertEq(roundId, bind);
        bytes32 leaf = _leaf(id, worker, 3);
        bondNow = market.getOffer(id).coordinatorBond;
        vm.prank(flCoord);
        vm.expectRevert(WorkMarket.NotAccepted.selector);
        market.postPayout{value: bondNow}(id, leaf, 3, 0);

        vm.roll(block.number + 21);
        frl.finalize(roundId);
        (bool ok, bytes32 d) = flV.accepted(id, bind);
        assertTrue(ok);
        assertEq(d, frl.recordDigest(roundId));

        leaf = _leaf(id, worker, 3);
        bondNow = market.getOffer(id).coordinatorBond;
        vm.prank(flCoord);
        market.postPayout{value: bondNow}(id, leaf, 3, 0);
        assertEq(market.getOffer(id).digest, frl.recordDigest(roundId));
        vm.warp(block.timestamp + WINDOW);
        market.settle(id, worker, 3, 0, 0, new bytes32[](0));
        assertEq(market.balanceOf(worker), 3 * PRICE);
    }
}
