// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {Governable} from "../../src/lib/Governable.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";
import {WorkMarketTestBase, ReenteringWorker} from "./WorkMarketTestBase.sol";

/// @notice 0.6.0 planset 06 §2.1 rules, one test (or more) per rule.
contract WorkMarketTest is WorkMarketTestBase {
    // ── open ───────────────────────────────────────────────────────

    function test_open_escrows_budget_and_fixes_terms() public {
        uint256 id = _openFl();
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(id, 1);
        assertEq(address(market).balance, BUDGET);
        assertEq(o.budget, BUDGET);
        assertEq(o.pricePerUnit, PRICE);
        assertEq(o.maxUnits, 10);
        assertEq(o.poster, poster);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Open));
        assertEq(market.owedOn(id), BUDGET);
    }

    function test_open_maxUnits_floors_and_remainder_is_refundable() public {
        uint256 id = _open(_params(IWorkMarket.Kind.FL_ROUND), 10.5 ether);
        assertEq(market.getOffer(id).maxUnits, 10);
        vm.warp(block.timestamp + 8 days);
        vm.prank(poster);
        market.refund(id);
        assertEq(market.balanceOf(poster), 10.5 ether);
    }

    function test_open_reverts_zero_price() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.pricePerUnit = 0;
        vm.expectRevert(WorkMarket.BadPrice.selector);
        _open(p, BUDGET);
    }

    function test_open_reverts_budget_below_price() public {
        vm.expectRevert(WorkMarket.BudgetBelowPrice.selector);
        _open(_params(IWorkMarket.Kind.FL_ROUND), PRICE - 1);
    }

    function test_open_reverts_verifier_not_allowed() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.verifier = stranger;
        vm.expectRevert(WorkMarket.VerifierNotAllowed.selector);
        _open(p, BUDGET);
    }

    function test_open_reverts_dispute_window_below_min() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.disputeWindow = 24 hours - 1;
        vm.expectRevert(WorkMarket.BadDisputeWindow.selector);
        _open(p, BUDGET);
    }

    function test_open_reverts_deadline_not_after_window() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.deadline = uint64(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.BadDeadline.selector);
        _open(p, BUDGET);
        p.deadline = uint64(block.timestamp + WINDOW + 1);
        _open(p, BUDGET);
    }

    function test_open_reverts_bad_max_workers() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.maxWorkers = 0;
        vm.expectRevert(WorkMarket.BadMaxWorkers.selector);
        _open(p, BUDGET);
        p.maxWorkers = 1025;
        vm.expectRevert(WorkMarket.BadMaxWorkers.selector);
        _open(p, BUDGET);
    }

    function test_open_reverts_zero_coordinator_or_bind() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinator = address(0);
        vm.expectRevert(WorkMarket.BadParty.selector);
        _open(p, BUDGET);
        p = _params(IWorkMarket.Kind.FL_ROUND);
        p.bindRef = bytes32(0);
        vm.expectRevert(WorkMarket.BadBindRef.selector);
        _open(p, BUDGET);
    }

    function test_open_reverts_dispute_admin_outside_group_tasks() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.disputeAdmin = admin;
        p.groupHash = keccak256("g");
        vm.expectRevert(WorkMarket.BadParty.selector);
        _open(p, BUDGET);
        p = _params(IWorkMarket.Kind.TASK);
        p.disputeAdmin = admin; // open task: no admin allowed
        vm.expectRevert(WorkMarket.BadParty.selector);
        _open(p, BUDGET);
        p.groupHash = keccak256("g");
        _open(p, BUDGET);
    }

    function test_open_reverts_when_new_offers_paused() public {
        vm.prank(guardian);
        market.setNewOffersPaused(true);
        vm.expectRevert(WorkMarket.NewOffersArePaused.selector);
        _openFl();
    }

    // ── join ───────────────────────────────────────────────────────

    function test_join_reverts_PriceBelowFloor() public {
        uint256 id = _openFl();
        bytes32[] memory none;
        vm.prank(w1);
        vm.expectRevert(abi.encodeWithSelector(WorkMarket.PriceBelowFloor.selector, PRICE, PRICE + 1));
        market.join(id, PRICE + 1, none);
    }

    function test_join_at_floor_moves_offer_to_running() public {
        uint256 id = _openFl();
        bytes32[] memory none;
        vm.prank(w1);
        market.join(id, PRICE, none);
        assertTrue(market.joined(id, w1));
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Running));
        assertEq(market.getOffer(id).workers, 1);
    }

    function test_join_reverts_twice() public {
        uint256 id = _openFl();
        _join(id, w1);
        bytes32[] memory none;
        vm.prank(w1);
        vm.expectRevert(WorkMarket.AlreadyJoined.selector);
        market.join(id, 0, none);
    }

    function test_join_reverts_when_full() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.maxWorkers = 2;
        uint256 id = _open(p, BUDGET);
        _join(id, w1);
        _join(id, w2);
        bytes32[] memory none;
        vm.prank(w3);
        vm.expectRevert(WorkMarket.OfferFull.selector);
        market.join(id, 0, none);
    }

    function test_join_requires_exact_join_bond() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.joinBond = 0.1 ether;
        uint256 id = _open(p, BUDGET);
        bytes32[] memory none;
        vm.prank(w1);
        vm.expectRevert(WorkMarket.WrongBond.selector);
        market.join{value: 0.09 ether}(id, 0, none);
        vm.prank(w1);
        market.join{value: 0.1 ether}(id, 0, none);
        assertEq(market.owedOn(id), BUDGET + 0.1 ether);
    }

    function test_join_allowlist_enforced() public {
        // Two-leaf OZ-standard tree over {w1, w2}.
        bytes32 l1 = keccak256(bytes.concat(keccak256(abi.encode(w1))));
        bytes32 l2 = keccak256(bytes.concat(keccak256(abi.encode(w2))));
        bytes32 root = l1 < l2 ? keccak256(abi.encode(l1, l2)) : keccak256(abi.encode(l2, l1));
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.allowlistRoot = root;
        uint256 id = _open(p, BUDGET);

        bytes32[] memory proof1 = new bytes32[](1);
        proof1[0] = l2;
        vm.prank(w1);
        market.join(id, 0, proof1);

        vm.prank(w3);
        vm.expectRevert(WorkMarket.NotAllowlisted.selector);
        market.join(id, 0, proof1);
    }

    function test_join_reverts_after_deadline_or_after_payout() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        _post(id, keccak256("r"), 1);
        bytes32[] memory none;
        vm.prank(w2);
        vm.expectRevert(WorkMarket.WrongState.selector);
        market.join(id, 0, none);

        uint256 id2 = _openFl();
        vm.warp(block.timestamp + 8 days);
        vm.prank(w2);
        vm.expectRevert(WorkMarket.PastDeadline.selector);
        market.join(id2, 0, none);
    }

    // ── postPayout ─────────────────────────────────────────────────

    function test_postPayout_only_coordinator() public {
        uint256 id = _openFl();
        _accept(id);
        vm.deal(stranger, 10 ether);
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotCoordinator.selector);
        market.postPayout{value: CBOND}(id, keccak256("r"), 1);
    }

    function test_postPayout_reverts_unless_verifier_accepted() public {
        uint256 id = _openFl();
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.NotAccepted.selector);
        market.postPayout{value: CBOND}(id, keccak256("r"), 1);
    }

    function test_postPayout_binds_digest_into_root() public {
        uint256 id = _openFl();
        _accept(id);
        bytes32 leavesRoot = keccak256("leaves");
        _post(id, leavesRoot, 4);
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(o.payoutRoot, keccak256(abi.encode(market.PAYOUT_TAG(), DIGEST, leavesRoot)));
        assertEq(o.digest, DIGEST);
        assertEq(o.payoutUnits, 4);
        assertEq(uint8(o.state), uint8(IWorkMarket.State.PayoutPosted));
        assertEq(market.owedOn(id), BUDGET + CBOND);
    }

    function test_postPayout_reverts_units_over_max_or_zero() public {
        uint256 id = _openFl();
        _accept(id);
        vm.startPrank(coordinator);
        vm.expectRevert(WorkMarket.BadUnits.selector);
        market.postPayout{value: CBOND}(id, keccak256("r"), 11);
        vm.expectRevert(WorkMarket.BadUnits.selector);
        market.postPayout{value: CBOND}(id, keccak256("r"), 0);
        vm.stopPrank();
    }

    function test_postPayout_requires_exact_bond_and_root() public {
        uint256 id = _openFl();
        _accept(id);
        vm.startPrank(coordinator);
        vm.expectRevert(WorkMarket.WrongBond.selector);
        market.postPayout{value: CBOND - 1}(id, keccak256("r"), 1);
        vm.expectRevert(WorkMarket.BadRoot.selector);
        market.postPayout{value: CBOND}(id, bytes32(0), 1);
        vm.stopPrank();
    }

    function test_postPayout_reverts_after_deadline() public {
        uint256 id = _openFl();
        _accept(id);
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.PastDeadline.selector);
        market.postPayout{value: CBOND}(id, keccak256("r"), 1);
    }

    function test_postPayout_task_must_be_one_unit() public {
        uint256 id = _open(_params(IWorkMarket.Kind.TASK), BUDGET);
        _accept(id);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.BadUnits.selector);
        market.postPayout{value: CBOND}(id, keccak256("r"), 2);
    }

    function test_verifier_denied_after_open_does_not_block_payout() public {
        uint256 id = _openFl();
        vm.prank(governance);
        market.setVerifierAllowed(address(verifier), false);
        _accept(id);
        _post(id, keccak256("r"), 1);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.PayoutPosted));
        vm.expectRevert(WorkMarket.VerifierNotAllowed.selector);
        _openFl();
    }

    // ── settle ─────────────────────────────────────────────────────

    function test_settle_pays_units_times_price_after_window() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        vm.expectRevert(WorkMarket.WindowOpen.selector);
        _settle(id, leaves, 1, e[1], 2);

        vm.warp(block.timestamp + WINDOW);
        vm.prank(stranger); // anyone may settle
        _settle(id, leaves, 1, e[1], 2);
        assertEq(market.balanceOf(w2), 3 * PRICE);
        assertTrue(market.settled(id, w2));
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(o.paid, 3 * PRICE);
        assertEq(o.settledUnits, 3);
    }

    function test_settle_once_per_worker() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        vm.warp(block.timestamp + WINDOW);
        _settle(id, leaves, 0, e[0], 0);
        vm.expectRevert(WorkMarket.AlreadySettled.selector);
        _settle(id, leaves, 0, e[0], 0);
    }

    function test_settle_rejects_bad_proof_and_inflated_units() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        vm.warp(block.timestamp + WINDOW);
        bytes32[] memory p = _proof(leaves, 0);
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w1, 5, 0, 0, p); // w1's leaf says 2
        vm.expectRevert(WorkMarket.BadProof.selector);
        market.settle(id, w1, 2, 0, 1, p); // wrong index
    }

    function test_settle_requires_joined_worker() public {
        uint256 id = _openFl();
        _join(id, w1);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, 1);
        e[1] = Entry(stranger, 1);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _post(id, _rootOf(leaves), 2);
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.NotJoined.selector);
        _settle(id, leaves, 1, e[1], 1);
    }

    function test_settle_leaf_beyond_posted_units_reverts() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, 3);
        e[1] = Entry(w2, 3);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _post(id, _rootOf(leaves), 4); // tree pays 6, posted 4
        vm.warp(block.timestamp + WINDOW);
        _settle(id, leaves, 0, e[0], 0);
        vm.expectRevert(WorkMarket.ExceedsPayout.selector);
        _settle(id, leaves, 1, e[1], 3);
    }

    /// The leaf whose range passes the posted units is refused even when it settles first, so an
    /// over-allocating tree cannot pay whoever races to settle.
    function test_settle_leaf_range_must_fit_posted_units_in_any_order() public {
        uint256 id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, 3);
        e[1] = Entry(w2, 3);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _post(id, _rootOf(leaves), 4);
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(WorkMarket.ExceedsPayout.selector);
        _settle(id, leaves, 1, e[1], 3);
        _settle(id, leaves, 0, e[0], 0);
        assertEq(market.balanceOf(w1), 3 * PRICE);
    }

    function test_settle_releases_join_bond() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.joinBond = 0.5 ether;
        uint256 id = _open(p, BUDGET);
        _join(id, w1);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(w1, 2);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 0);
        _post(id, _rootOf(leaves), 2);
        vm.warp(block.timestamp + WINDOW);
        market.settle(id, w1, 2, 0, 0, new bytes32[](0));
        assertEq(market.balanceOf(w1), 2 * PRICE + 0.5 ether);
        assertTrue(market.joinBondReleased(id, w1));
    }

    // ── refund ─────────────────────────────────────────────────────

    function test_refund_not_before_window() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        leaves;
        uint64 deadline = market.getOffer(id).deadline;
        vm.warp(deadline);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.refund(id);
        vm.warp(uint256(deadline) + WINDOW - 1);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.refund(id);
        vm.warp(uint256(deadline) + WINDOW);
        vm.prank(poster);
        market.refund(id);
        assertEq(market.balanceOf(poster), BUDGET - 6 * PRICE);
    }

    function test_refund_keeps_reserve_for_unsettled_workers() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        vm.prank(poster);
        market.refund(id);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Closed));
        // workers who had not settled still can, after the poster's refund
        _settle(id, leaves, 0, e[0], 0);
        _settle(id, leaves, 1, e[1], 2);
        _settle(id, leaves, 2, e[2], 5);
        assertEq(market.balanceOf(w1) + market.balanceOf(w2) + market.balanceOf(w3), 6 * PRICE);
        vm.prank(coordinator);
        market.claimBond(id);
        assertEq(market.owedOn(id), 0);
    }

    function test_refund_expired_when_no_payout_by_deadline() public {
        uint256 id = _openFl();
        _join(id, w1);
        vm.prank(poster);
        vm.expectRevert(WorkMarket.TooEarly.selector);
        market.refund(id);
        vm.warp(uint256(market.getOffer(id).deadline) + 1);
        vm.prank(poster);
        market.refund(id);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.Expired));
        assertEq(market.balanceOf(poster), BUDGET);
    }

    function test_refund_only_poster_and_once() public {
        uint256 id = _openFl();
        vm.warp(uint256(market.getOffer(id).deadline) + 1);
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotPoster.selector);
        market.refund(id);
        vm.startPrank(poster);
        market.refund(id);
        vm.expectRevert(WorkMarket.WrongState.selector);
        market.refund(id);
        vm.stopPrank();
    }

    // ── bonds ──────────────────────────────────────────────────────

    function test_coordinator_bond_released_after_undisputed_window() public {
        (uint256 id,) = _postedFl3();
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.claimBond(id);
        vm.warp(block.timestamp + WINDOW);
        vm.prank(coordinator);
        market.claimBond(id);
        assertEq(market.balanceOf(coordinator), CBOND);
        vm.prank(coordinator);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.claimBond(id);
    }

    function test_join_bond_released_to_unpaid_worker_after_offer_ends() public {
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.joinBond = 0.5 ether;
        uint256 id = _open(p, BUDGET);
        _join(id, w1);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.claimBond(id);
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        vm.prank(w1);
        market.claimBond(id);
        assertEq(market.balanceOf(w1), 0.5 ether);
    }

    // ── withdraw ───────────────────────────────────────────────────

    function test_withdraw_pays_out_and_zeroes() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        vm.warp(block.timestamp + WINDOW);
        _settle(id, leaves, 0, e[0], 0);
        uint256 before = w1.balance;
        vm.prank(w1);
        market.withdraw();
        assertEq(w1.balance, before + 2 * PRICE);
        assertEq(market.balanceOf(w1), 0);
        vm.prank(w1);
        vm.expectRevert(WorkMarket.NothingToClaim.selector);
        market.withdraw();
    }

    function test_withdraw_reentry_gets_nothing_extra() public {
        ReenteringWorker rw = new ReenteringWorker(market);
        uint256 id = _openFl();
        rw.joinOffer(id, 0);
        _accept(id);
        Entry[] memory e = new Entry[](1);
        e[0] = Entry(address(rw), 3);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 0);
        _post(id, _rootOf(leaves), 3);
        vm.warp(block.timestamp + WINDOW);
        market.settle(id, address(rw), 3, 0, 0, new bytes32[](0));
        uint256 marketBefore = address(market).balance;
        rw.pull();
        assertEq(address(rw).balance, 3 * PRICE);
        assertEq(address(market).balance, marketBefore - 3 * PRICE);
        assertEq(rw.reentries(), 1);
    }

    // ── governance, guardian, pause ────────────────────────────────

    function test_only_governance_allows_verifiers() public {
        vm.prank(stranger);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        market.setVerifierAllowed(stranger, true);
        vm.prank(guardian);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        market.setVerifierAllowed(stranger, true);
        vm.prank(governance);
        market.setVerifierAllowed(stranger, true);
        assertTrue(market.verifierAllowed(stranger));
    }

    function test_guardian_pauses_but_cannot_unpause() public {
        vm.prank(guardian);
        market.setNewOffersPaused(true);
        vm.prank(guardian);
        vm.expectRevert(WorkMarket.NotGuardianOrGovernance.selector);
        market.setNewOffersPaused(false);
        vm.prank(stranger);
        vm.expectRevert(WorkMarket.NotGuardianOrGovernance.selector);
        market.setNewOffersPaused(true);
        vm.prank(governance);
        market.setNewOffersPaused(false);
        assertFalse(market.newOffersPaused());
    }

    function test_pause_never_blocks_existing_offers() public {
        (uint256 id, bytes32[] memory leaves) = _postedFl3();
        Entry[] memory e = _entries3();
        vm.prank(guardian);
        market.setNewOffersPaused(true);
        vm.warp(block.timestamp + WINDOW);
        _settle(id, leaves, 0, e[0], 0);
        vm.prank(w1);
        market.withdraw();
        vm.prank(coordinator);
        market.claimBond(id);
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        vm.prank(poster);
        market.refund(id);
        assertEq(market.balanceOf(poster), BUDGET - 6 * PRICE);
    }

    function test_market_rejects_plain_value_transfers() public {
        vm.prank(stranger);
        (bool ok,) = address(market).call{value: 1 ether}("");
        assertFalse(ok);
    }

    function test_unknown_offer_reverts() public {
        vm.expectRevert(WorkMarket.UnknownOffer.selector);
        market.refund(42);
    }

    function test_constructor_rejects_zero_verifier_and_zero_governance() public {
        address[] memory vs = new address[](1);
        vm.expectRevert(WorkMarket.BadParty.selector);
        new WorkMarket(governance, guardian, 1 ether, vs);
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        new WorkMarket(address(0), guardian, 1 ether, new address[](0));
    }

    /// PBA-L2-002: a salted deploy runs the constructor from the CREATE2 factory, so no admin seat
    /// may be the factory (or zero) at construction.
    function test_constructor_guardian_goes_through_initial_admin_check() public {
        address factory = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new WorkMarket(governance, factory, 1 ether, new address[](0));
        vm.expectRevert(InitialAdmin.InitialAdmin_Zero.selector);
        new WorkMarket(governance, address(0), 1 ether, new address[](0));
    }

    function test_setGuardian_refuses_factory_but_may_clear() public {
        vm.startPrank(governance);
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        market.setGuardian(0x4e59b44847b379578588920cA78FbF26c0B4956C);
        market.setGuardian(address(0));
        vm.stopPrank();
        assertEq(market.guardian(), address(0));
        vm.prank(guardian);
        vm.expectRevert(WorkMarket.NotGuardianOrGovernance.selector);
        market.setNewOffersPaused(true);
    }

    // ── fuzz (10k runs, gate G-CON) ────────────────────────────────

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_join_floor(uint128 price, uint128 minPrice) public {
        price = uint128(bound(price, 1, 1_000 ether));
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.pricePerUnit = price;
        uint256 id = _open(p, price);
        bytes32[] memory none;
        vm.prank(w1);
        if (price < minPrice) {
            vm.expectRevert(abi.encodeWithSelector(WorkMarket.PriceBelowFloor.selector, price, minPrice));
            market.join(id, minPrice, none);
        } else {
            market.join(id, minPrice, none);
            assertTrue(market.joined(id, w1));
        }
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_settle_and_refund_conserve_budget(uint128 price, uint64 maxU, uint64 u1, uint64 u2) public {
        price = uint128(bound(price, 1, 1e24));
        maxU = uint64(bound(maxU, 2, 1e6));
        u1 = uint64(bound(u1, 1, maxU - 1));
        u2 = uint64(bound(u2, 1, maxU - u1));
        uint256 budget = uint256(price) * maxU + (price - 1);
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.pricePerUnit = price;
        vm.deal(poster, budget);
        uint256 id = _open(p, budget);
        _join(id, w1);
        _join(id, w2);
        _accept(id);
        Entry[] memory e = new Entry[](2);
        e[0] = Entry(w1, u1);
        e[1] = Entry(w2, u2);
        (bytes32[] memory leaves,) = _leaves(id, e, _noOverride(), 1);
        _post(id, _rootOf(leaves), u1 + u2);
        vm.warp(uint256(market.getOffer(id).deadline) + WINDOW);
        _settle(id, leaves, 0, e[0], 0);
        vm.prank(poster);
        market.refund(id);
        _settle(id, leaves, 1, e[1], u1);
        assertEq(market.balanceOf(w1), uint256(u1) * price);
        assertEq(market.balanceOf(w2), uint256(u2) * price);
        assertEq(market.balanceOf(w1) + market.balanceOf(w2) + market.balanceOf(poster), budget);
        assertEq(market.owedOn(id), CBOND);
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_refund_never_before_deadline_plus_window(uint256 t) public {
        (uint256 id,) = _postedFl3();
        uint64 deadline = market.getOffer(id).deadline;
        t = bound(t, block.timestamp, uint256(deadline) + 2 * WINDOW);
        vm.warp(t);
        vm.prank(poster);
        if (t < uint256(deadline) + WINDOW) {
            vm.expectRevert(WorkMarket.TooEarly.selector);
            market.refund(id);
        } else {
            market.refund(id);
        }
    }
}
