// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {MultisigTimelock2of3} from "../../src/cit_agent/MultisigTimelock2of3.sol";

/// @title CHAIN-B-C044(a) — MultisigTimelock2of3 constructor hardening.
/// @notice `replaceOwner` documents the zero-owner and duplicate-owner checks as
///         load-bearing (a duplicate collapses 2-of-3 into 1-of-1), but the
///         constructor applied neither and imposed no floor on `minDelay` — a
///         zero delay makes the timelock an immediate executor.
contract MultisigTimelock2of3C044Test is Test {
    address constant A = address(0xA);
    address constant B = address(0xB);
    address constant C = address(0xC);

    /// RED (pre-fix): a zero owner was accepted. GREEN: reverts ZeroOwner.
    function test_C044_rejectsZeroOwner() public {
        vm.expectRevert(MultisigTimelock2of3.ZeroOwner.selector);
        new MultisigTimelock2of3([A, address(0), C], 1 hours);
    }

    /// RED (pre-fix): a duplicate owner was accepted, collapsing 2-of-3.
    /// GREEN: reverts DuplicateOwner.
    function test_C044_rejectsDuplicateOwner() public {
        vm.expectRevert(abi.encodeWithSelector(MultisigTimelock2of3.DuplicateOwner.selector, A));
        new MultisigTimelock2of3([A, B, A], 1 hours);
    }

    /// RED (pre-fix): minDelay == 0 produced a no-delay 2-of-3 executor.
    /// GREEN: reverts DelayTooShort.
    function test_C044_rejectsZeroDelay() public {
        vm.expectRevert(abi.encodeWithSelector(MultisigTimelock2of3.DelayTooShort.selector, uint256(0), uint256(1 hours)));
        new MultisigTimelock2of3([A, B, C], 0);
    }

    /// A well-formed deployment still works.
    function test_C044_validConstructionSucceeds() public {
        MultisigTimelock2of3 tl = new MultisigTimelock2of3([A, B, C], 2 days);
        assertEq(tl.minDelay(), 2 days);
        assertTrue(tl.isOwner(A));
    }
}
