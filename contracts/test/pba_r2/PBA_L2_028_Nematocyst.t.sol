// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {NematocystSlashing} from "../../src/NematocystSlashing.sol";

/// Regression for PBA-L2-028 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_028_Regression is Test {
    /// Finding trace, inverted: a provider that sees `slash()` coming and
    /// calls `unstake()` first does not walk away with its stake.
    function test_L2_028_unstakeCannotEvadePendingSlash() public {
        NematocystSlashing ns = new NematocystSlashing(address(this));
        address p = makeAddr("provider");
        vm.deal(p, 200 ether);
        vm.prank(p);
        ns.stake{value: 200 ether}();
        vm.prank(p);
        ns.unstake(); // front-runs governance's slash
        try ns.slash(p, NematocystSlashing.SlashTier.Inconsistency, hex"01") {} catch {}
        assertEq(p.balance, 0, "stake was not paid out instantly");
        (bool ok, bytes memory ret) = address(ns).staticcall(abi.encodeWithSignature("pendingUnstake(address)", p));
        assertTrue(ok && ret.length == 32, "unbonding queue exists");
        assertEq(abi.decode(ret, (uint256)), 160 ether, "20% slash reached the unbonding stake");
    }
}
