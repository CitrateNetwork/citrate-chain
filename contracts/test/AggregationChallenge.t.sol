// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {AggregationChallenge} from "../src/AggregationChallenge.sol";

/// @notice Mock NematocystSlashing — records (provider, tier) for assertions.
contract MockSlashing {
    address[] internal _addrs;
    uint8[] internal _tiers;

    function slash(address provider, uint8 tier, bytes calldata) external {
        _addrs.push(provider);
        _tiers.push(tier);
    }

    function count() external view returns (uint256) {
        return _addrs.length;
    }

    function last() external view returns (address provider, uint8 tier) {
        uint256 i = _addrs.length - 1;
        return (_addrs[i], _tiers[i]);
    }
}

contract AggregationChallengeTest is Test {
    AggregationChallenge internal ac;
    MockSlashing internal slashing;

    address internal coordinator = address(0xC001);
    address internal challenger = address(0xCA11);

    uint256 internal constant BOND = 1 ether;
    uint256 internal constant WINDOW = 50;

    // A 2-coordinate aggregate (dim=2 => 64 bytes) and its keccak digest.
    bytes internal aggregate = abi.encodePacked(uint256(10), uint256(20));
    bytes32 internal digest = keccak256(abi.encodePacked(uint256(10), uint256(20)));
    bytes32 internal constant ROUND = keccak256("round-1");

    function setUp() public {
        ac = new AggregationChallenge(BOND, WINDOW); // governance = this
        slashing = new MockSlashing();
        ac.setSlashingContract(address(slashing));
        vm.deal(challenger, 100 ether);
    }

    function _commit() internal {
        vm.prank(coordinator);
        ac.commitAggregate(ROUND, digest, 2);
    }

    // ── default-accept ───────────────────────────────────────────────

    function test_uncontested_round_is_default_accepted() public {
        _commit();
        vm.roll(block.number + WINDOW + 1);
        ac.finalize(ROUND);
        assertTrue(ac.isAccepted(ROUND));
    }

    function test_cannot_finalize_before_window() public {
        _commit();
        vm.expectRevert("Window open");
        ac.finalize(ROUND);
    }

    // ── honest defense → wrong challenge funds coordinator (grief-unprofitable) ──

    function test_frivolous_challenge_forfeits_bond_to_coordinator() public {
        _commit();
        uint256 coordBefore = coordinator.balance;

        vm.prank(challenger);
        ac.challenge{value: BOND}(ROUND, 0);

        vm.prank(coordinator);
        ac.defend(ROUND, aggregate);

        // Referee finds the aggregate correct → challenger loses, bond funds coordinator.
        ac.resolve(ROUND, false);

        assertTrue(ac.isAccepted(ROUND));
        assertEq(slashing.count(), 0, "no slash on honest aggregate");
        assertEq(coordinator.balance, coordBefore + BOND, "frivolous bond funds coordinator");
    }

    // ── proven-wrong aggregate → coordinator slashed Byzantine, challenger refunded ──

    function test_proven_wrong_aggregate_slashes_coordinator() public {
        _commit();
        uint256 challBefore = challenger.balance;

        vm.prank(challenger);
        ac.challenge{value: BOND}(ROUND, 1);

        vm.prank(coordinator);
        ac.defend(ROUND, aggregate);

        // Referee's deterministic recompute shows the committed aggregate is wrong.
        ac.resolve(ROUND, true);

        assertEq(uint8(ac.statusOf(ROUND)), uint8(AggregationChallenge.Status.Slashed));
        assertEq(slashing.count(), 1);
        (address who, uint8 tier) = slashing.last();
        assertEq(who, coordinator);
        assertEq(tier, ac.TIER_BYZANTINE()); // 100% + ban
        assertEq(challenger.balance, challBefore, "challenger recovers its bond");
    }

    // ── coordinator that won't reveal loses by timeout ───────────────

    function test_timeout_when_coordinator_does_not_defend() public {
        _commit();
        vm.prank(challenger);
        ac.challenge{value: BOND}(ROUND, 0);

        vm.roll(block.number + WINDOW + 1);
        ac.timeoutChallenge(ROUND);

        assertEq(slashing.count(), 1);
        (address who,) = slashing.last();
        assertEq(who, coordinator);
    }

    // ── guards ───────────────────────────────────────────────────────

    function test_reveal_must_match_commit() public {
        _commit();
        vm.prank(challenger);
        ac.challenge{value: BOND}(ROUND, 0);
        vm.prank(coordinator);
        vm.expectRevert("Reveal != commit");
        ac.defend(ROUND, abi.encodePacked(uint256(99), uint256(20))); // tampered
    }

    function test_cannot_challenge_after_window() public {
        _commit();
        vm.roll(block.number + WINDOW + 1);
        vm.prank(challenger);
        vm.expectRevert("Window closed");
        ac.challenge{value: BOND}(ROUND, 0);
    }

    function test_challenge_requires_bond() public {
        _commit();
        vm.prank(challenger);
        vm.expectRevert("Insufficient bond");
        ac.challenge{value: BOND - 1}(ROUND, 0);
    }

    function test_only_governance_resolves() public {
        _commit();
        vm.prank(challenger);
        ac.challenge{value: BOND}(ROUND, 0);
        vm.prank(challenger);
        vm.expectRevert();
        ac.resolve(ROUND, true);
    }

    function test_coordinator_cannot_challenge_self() public {
        _commit();
        vm.deal(coordinator, 10 ether);
        vm.prank(coordinator);
        vm.expectRevert("Cannot challenge self");
        ac.challenge{value: BOND}(ROUND, 0);
    }

    function test_coord_index_must_be_in_range() public {
        _commit();
        vm.prank(challenger);
        vm.expectRevert("coord out of range");
        ac.challenge{value: BOND}(ROUND, 2); // dim = 2, valid indices 0..1
    }
}
