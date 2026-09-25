// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Sortition} from "../../src/quorum/Sortition.sol";

/// PBA-L2-055: a member that withholds its reveal (voiding the draw) cannot
/// contribute entropy to a re-run over the same pool.
contract PBA_L2_055_SortitionRegression is Test {
    Sortition s;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA401);
    address constant DUMMY = address(0xD00D);
    bytes32 root;
    bytes32 n01;
    bytes32 n23;

    function setUp() public {
        vm.roll(1000);
        s = new Sortition();
        n01 = keccak256(abi.encode(_leaf(ALICE), _leaf(BOB)));
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
            p[1] = n23;
        } else {
            i = 1;
            p[0] = _leaf(ALICE);
            p[1] = n23;
        }
    }

    function _commit(bytes32 d, address w, bytes32 r) internal returns (bool ok) {
        (uint32 i, bytes32[] memory p) = _proof(w);
        vm.prank(w);
        try s.commit(d, keccak256(abi.encode(r, bytes32("salt"))), i, p) {
            ok = true;
        } catch {}
    }

    function test_L2_055_abortingMemberExcludedFromRerun() public {
        bytes32 d1 = keccak256("draw-1");
        uint64 t1 = uint64(vm.getBlockNumber()) + s.MIN_DELTA();
        s.openDraw(d1, root, 12, 2, t1);
        _commit(d1, ALICE, bytes32("a"));
        _commit(d1, BOB, bytes32("b"));
        vm.roll(t1 + 1);
        vm.prank(ALICE);
        s.reveal(d1, bytes32("a"), bytes32("salt"));
        // BOB (last revealer) dislikes the outcome and withholds; draw voids.
        vm.roll(t1 + s.BLOCKHASH_HORIZON() + 1);
        s.void(d1);

        bytes32 d2 = keccak256("draw-2");
        s.openDraw(d2, root, 12, 2, uint64(vm.getBlockNumber()) + s.MIN_DELTA());
        assertTrue(_commit(d2, ALICE, bytes32("a2")), "an honest revealer may re-run");
        assertFalse(_commit(d2, BOB, bytes32("b2")), "the aborting member must be excluded from the re-run");
    }
}
