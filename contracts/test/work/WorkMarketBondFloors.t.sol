// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {Governable} from "../../src/lib/Governable.sol";
import {WorkMarketTestBase} from "./WorkMarketTestBase.sol";

/// @notice Governance-set bond floors (owner 2026-11-14): the least coordinator bond and the least
///         join bond a new offer may carry, each set by GOVERNANCE (the 48 h timelock) within
///         1 to 100,000 SALT. The genesis values (100 and 10 SALT) are constructor inputs; see
///         test/genesis for the deploy path.
contract WorkMarketBondFloorsTest is WorkMarketTestBase {
    event MinCoordinatorBondSet(uint128 previous, uint128 current);
    event MinJoinBondSet(uint128 previous, uint128 current);

    uint128 internal constant SALT = 1 ether;

    function _vs() internal view returns (address[] memory vs) {
        vs = new address[](1);
        vs[0] = address(verifier);
    }

    // ── construction ───────────────────────────────────────────────

    function test_constructor_sets_the_initial_floors_and_announces_them() public {
        vm.expectEmit(false, false, false, true);
        emit MinCoordinatorBondSet(0, 100 * SALT);
        vm.expectEmit(false, false, false, true);
        emit MinJoinBondSet(0, 10 * SALT);
        WorkMarket m = new WorkMarket(governance, guardian, SINK, 1000 * SALT, 100 * SALT, 10 * SALT, _vs());
        assertEq(m.minCoordinatorBond(), 100 * SALT);
        assertEq(m.minJoinBond(), 10 * SALT);
        assertEq(m.defaultCoordinatorBond(), 1000 * SALT);
        assertEq(m.MIN_BOND_FLOOR(), 1 * SALT);
        assertEq(m.MAX_BOND_FLOOR(), 100_000 * SALT);
    }

    function test_constructor_bounds_the_floors_and_the_default() public {
        address[] memory vs = _vs();
        vm.expectRevert(abi.encodeWithSelector(WorkMarket.BadBondFloor.selector, SALT - 1));
        new WorkMarket(governance, guardian, SINK, 1000 * SALT, SALT - 1, 10 * SALT, vs);
        vm.expectRevert(abi.encodeWithSelector(WorkMarket.BadBondFloor.selector, 100_000 * SALT + 1));
        new WorkMarket(governance, guardian, SINK, 1000 * SALT, 100 * SALT, 100_000 * SALT + 1, vs);
        vm.expectRevert(WorkMarket.BadDefaultBond.selector); // below the coordinator floor
        new WorkMarket(governance, guardian, SINK, 99 * SALT, 100 * SALT, 10 * SALT, vs);
        vm.expectRevert(WorkMarket.BadDefaultBond.selector); // above the bound
        new WorkMarket(governance, guardian, SINK, 100_000 * SALT + 1, 100 * SALT, 10 * SALT, vs);
    }

    // ── setters: governance only, bounded, announced ───────────────

    function test_only_governance_sets_the_floors() public {
        address[3] memory others = [guardian, poster, coordinator];
        for (uint256 i = 0; i < others.length; i++) {
            vm.startPrank(others[i]);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            market.setMinCoordinatorBond(5 * SALT);
            vm.expectRevert(Governable.Governable_NotGovernance.selector);
            market.setMinJoinBond(5 * SALT);
            vm.stopPrank();
        }
    }

    function test_governance_sets_each_floor_and_it_is_announced() public {
        uint128 before = market.minCoordinatorBond();
        vm.expectEmit(address(market));
        emit MinCoordinatorBondSet(before, 100 * SALT);
        vm.prank(governance);
        market.setMinCoordinatorBond(100 * SALT);
        assertEq(market.minCoordinatorBond(), 100 * SALT);

        before = market.minJoinBond();
        vm.expectEmit(address(market));
        emit MinJoinBondSet(before, 10 * SALT);
        vm.prank(governance);
        market.setMinJoinBond(10 * SALT);
        assertEq(market.minJoinBond(), 10 * SALT);
    }

    function testFuzz_a_floor_is_accepted_exactly_within_1_to_100000_salt(uint128 floor) public {
        bool inRange = floor >= SALT && floor <= 100_000 * SALT;
        vm.startPrank(governance);
        if (!inRange) {
            vm.expectRevert(abi.encodeWithSelector(WorkMarket.BadBondFloor.selector, floor));
            market.setMinCoordinatorBond(floor);
            vm.expectRevert(abi.encodeWithSelector(WorkMarket.BadBondFloor.selector, floor));
            market.setMinJoinBond(floor);
        } else {
            market.setMinCoordinatorBond(floor);
            market.setMinJoinBond(floor);
            assertEq(market.minCoordinatorBond(), floor);
            assertEq(market.minJoinBond(), floor);
        }
        vm.stopPrank();
    }

    function test_the_bounds_themselves_are_accepted() public {
        vm.startPrank(governance);
        market.setMinCoordinatorBond(SALT);
        market.setMinJoinBond(100_000 * SALT);
        assertEq(market.minCoordinatorBond(), SALT);
        assertEq(market.minJoinBond(), 100_000 * SALT);
        vm.stopPrank();
    }

    // ── what the floors govern ─────────────────────────────────────

    function test_open_refuses_a_join_bond_below_the_floor() public {
        vm.prank(governance);
        market.setMinJoinBond(10 * SALT);
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.joinBond = 10 * SALT - 1;
        vm.prank(poster);
        vm.expectRevert(WorkMarket.JoinBondBelowMinimum.selector);
        market.open{value: BUDGET}(p);
        p.joinBond = 10 * SALT;
        uint256 id = _open(p, BUDGET);
        assertEq(market.getOffer(id).joinBond, 10 * SALT);
    }

    function test_open_refuses_a_coordinator_bond_below_the_floor() public {
        vm.prank(governance);
        market.setMinCoordinatorBond(100 * SALT);
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinatorBond = 100 * SALT - 1;
        vm.prank(poster);
        vm.expectRevert(WorkMarket.BondBelowMinimum.selector);
        market.open{value: BUDGET}(p);
        p.coordinatorBond = 100 * SALT;
        uint256 id = _open(p, BUDGET);
        assertEq(market.getOffer(id).coordinatorBond, 100 * SALT);
    }

    /// A floor raised above the immutable default lifts what an offer opened with 0 carries.
    function test_a_zero_bond_offer_carries_at_least_the_floor() public {
        assertEq(market.defaultCoordinatorBond(), 1 * SALT);
        vm.prank(governance);
        market.setMinCoordinatorBond(100 * SALT);
        WorkMarket.OpenParams memory p = _params(IWorkMarket.Kind.FL_ROUND);
        p.coordinatorBond = 0;
        uint256 id = _open(p, BUDGET);
        assertEq(market.getOffer(id).coordinatorBond, 100 * SALT);
    }

    /// A floor change applies to new offers only: an open offer keeps the bonds it opened with,
    /// and its workers and coordinator can still join and post with them.
    function test_a_floor_change_leaves_open_offers_alone() public {
        uint256 id = _openFl(); // join bond JBOND, coordinator bond CBOND
        vm.startPrank(governance);
        market.setMinJoinBond(10 * SALT);
        market.setMinCoordinatorBond(100 * SALT);
        vm.stopPrank();
        WorkMarket.Offer memory o = market.getOffer(id);
        assertEq(o.joinBond, JBOND);
        assertEq(o.coordinatorBond, CBOND);
        _join(id, w1);
        _accept(id);
        _post(id, keccak256("root"), 1);
        assertEq(uint8(market.getOffer(id).state), uint8(IWorkMarket.State.PayoutPosted));
    }
}
