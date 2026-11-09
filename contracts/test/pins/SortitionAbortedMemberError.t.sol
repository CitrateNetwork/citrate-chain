// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Sortition} from "../../src/quorum/Sortition.sol";

/// A member that withheld its reveal on a voided draw is refused on the re-run
/// with `AbortedMemberExcluded`, which is distinct from the
/// `OutstandingCommitment` a member gets while its earlier draw is still open.
/// Callers can tell an exclusion from a pending reveal.
contract SortitionAbortedMemberErrorTest is Test {
    Sortition internal s;
    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant CAROL = address(0xCA401);
    address internal constant DUMMY = address(0xD00D);
    bytes32 internal root;
    bytes32 internal n23;

    function setUp() public {
        vm.roll(1000);
        s = new Sortition();
        bytes32 n01 = keccak256(abi.encode(_leaf(ALICE), _leaf(BOB)));
        n23 = keccak256(abi.encode(_leaf(CAROL), _leaf(DUMMY)));
        root = keccak256(abi.encode(n01, n23));
    }

    function _leaf(address w) internal pure returns (bytes32) {
        return keccak256(abi.encode(w));
    }

    function _proof(address w) internal view returns (uint32 i, bytes32[] memory p) {
        p = new bytes32[](2);
        if (w == ALICE) {
            i = 0;
            p[0] = _leaf(BOB);
        } else {
            i = 1;
            p[0] = _leaf(ALICE);
        }
        p[1] = n23;
    }

    function _commit(bytes32 d, address w, bytes32 r) internal {
        (uint32 i, bytes32[] memory p) = _proof(w);
        vm.prank(w);
        s.commit(d, keccak256(abi.encode(r, bytes32("salt"))), i, p);
    }

    function test_withholderOfVoidedDrawGetsAbortedMemberExcluded() public {
        bytes32 d1 = keccak256("draw-1");
        uint64 t1 = uint64(vm.getBlockNumber()) + s.MIN_DELTA();
        s.openDraw(d1, root, 12, 2, t1);
        _commit(d1, ALICE, bytes32("a"));
        _commit(d1, BOB, bytes32("b"));
        vm.roll(t1 + 1);
        vm.prank(ALICE);
        s.reveal(d1, bytes32("a"), bytes32("salt"));
        vm.roll(t1 + s.BLOCKHASH_HORIZON() + 1);
        s.void(d1);

        bytes32 d2 = keccak256("draw-2");
        s.openDraw(d2, root, 12, 2, uint64(vm.getBlockNumber()) + s.MIN_DELTA());
        (uint32 i, bytes32[] memory p) = _proof(BOB);
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Sortition.AbortedMemberExcluded.selector, root, BOB, d1));
        s.commit(d2, keccak256(abi.encode(bytes32("b2"), bytes32("salt"))), i, p);
    }

    function test_memberWithAnOpenDrawGetsOutstandingCommitment() public {
        bytes32 d1 = keccak256("draw-1");
        s.openDraw(d1, root, 12, 2, uint64(vm.getBlockNumber()) + s.MIN_DELTA());
        _commit(d1, BOB, bytes32("b"));

        bytes32 d2 = keccak256("draw-2");
        s.openDraw(d2, root, 12, 2, uint64(vm.getBlockNumber()) + s.MIN_DELTA());
        (uint32 i, bytes32[] memory p) = _proof(BOB);
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Sortition.OutstandingCommitment.selector, root, BOB, d1));
        s.commit(d2, keccak256(abi.encode(bytes32("b2"), bytes32("salt"))), i, p);
    }
}
