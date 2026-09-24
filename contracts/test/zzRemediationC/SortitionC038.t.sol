// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Sortition} from "../../src/quorum/Sortition.sol";

/// @title CHAIN-B-C038 — `Sortition` draw-grinding via caller-chosen drawId.
/// @notice Pre-fix the seed mixed in `drawId`, which the opener picks freely at
///         `openDraw`. So an opener could open M draws over one pool with
///         different ids and finalize only the favourable committee. Post-fix
///         the seed depends solely on the chain anchor, the revealed entropy and
///         the committed pool root — distinct ids over the same pool/target/
///         anchor yield the SAME committee, so the id is no longer a knob.
contract SortitionC038Test is Test {
    Sortition s;

    bytes32 constant POOL_ROOT = keccak256("pool");
    uint32 constant POOL = 64;
    uint32 constant K = 5;
    uint64 constant START = 1000;
    uint64 constant TARGET = 1100; // START + MIN_DELTA

    function setUp() public {
        s = new Sortition();
    }

    /// RED (pre-fix): two draws over identical pool/target/anchor but with
    /// different ids produced DIFFERENT committees, so the opener could grind
    /// the id to pick a favourable one. GREEN: they are identical.
    function test_C038_drawIdDoesNotSteerCommittee() public {
        bytes32 anchor = keccak256("anchor");

        vm.roll(START);
        bytes32 a = keccak256("draw-A");
        bytes32 b = keccak256("draw-B");
        s.openDraw(a, POOL_ROOT, POOL, K, TARGET);
        s.openDraw(b, POOL_ROOT, POOL, K, TARGET);

        vm.roll(TARGET + s.FINALITY_DELAY());
        vm.setBlockhash(TARGET, anchor);

        s.finalize(a);
        s.finalize(b);

        uint32[] memory picksA = s.selection(a);
        uint32[] memory picksB = s.selection(b);
        assertEq(picksA.length, picksB.length, "same committee size");
        for (uint256 i = 0; i < picksA.length; i++) {
            assertEq(picksA[i], picksB[i], "drawId must not change the committee");
        }
    }
}
