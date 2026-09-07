// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {VoteAllowance} from "../../src/quorum/VoteAllowance.sol";

/// @title CHAIN-B-C034 — `VoteAllowance.decrease` must only narrow.
/// @notice Pre-fix, `decrease(id, to)` wrote `weightCap = to` with only a
///         `to >= spent` guard, so it could RAISE the cap — past the
///         `type(uint64).max` bound that `grant`/`increase` enforce for the
///         `quorum-policy` u64 mirror. This asserts the fixed behaviour.
contract VoteAllowanceC034Test is Test {
    VoteAllowance va;
    address constant PRINCIPAL = address(0xA11CE);
    address constant CASTER = address(0xCA5);
    uint256 constant AGENT = 42;
    bytes32 constant SCOPE = keccak256("Citrate");
    bytes32 constant CLASS = keccak256("proposal.budget");
    uint256 constant CAP = 100;
    uint64 constant START_SEC = 1_700_000_000;

    function setUp() public {
        va = new VoteAllowance();
        vm.warp(START_SEC);
    }

    function _grant() internal returns (bytes32) {
        bytes32[] memory c = new bytes32[](1);
        c[0] = CLASS;
        vm.prank(PRINCIPAL);
        return va.grant(AGENT, CASTER, SCOPE, c, CAP, (START_SEC + 1 days) * 1000, keccak256("g"));
    }

    /// RED (pre-fix): `decrease(id, type(uint64).max + 1)` succeeded and set the
    /// cap far above the u64 bound. GREEN: it reverts DecreaseWouldWiden.
    function test_C034_decreaseCannotWidenPastUint64() public {
        bytes32 id = _grant();
        uint256 huge = uint256(type(uint64).max) + 1;
        vm.prank(PRINCIPAL);
        vm.expectRevert(
            abi.encodeWithSelector(VoteAllowance.DecreaseWouldWiden.selector, id, huge, CAP)
        );
        va.decrease(id, huge);
    }

    /// RED (pre-fix): decreasing to any value above the current cap widened it.
    /// GREEN: even a modest widening is refused.
    function test_C034_decreaseCannotRaiseAboveCurrentCap() public {
        bytes32 id = _grant();
        vm.prank(PRINCIPAL);
        vm.expectRevert(
            abi.encodeWithSelector(VoteAllowance.DecreaseWouldWiden.selector, id, CAP + 1, CAP)
        );
        va.decrease(id, CAP + 1);
    }

    /// The legitimate direction still works.
    function test_C034_decreaseStillNarrows() public {
        bytes32 id = _grant();
        vm.prank(PRINCIPAL);
        va.decrease(id, 40);
        assertEq(va.remaining(id), 40, "narrowing must still succeed");
    }
}
