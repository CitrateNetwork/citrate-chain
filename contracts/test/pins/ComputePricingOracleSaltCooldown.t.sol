// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePricingOracle} from "../../src/ComputePricingOracle.sol";

/// The per-update 10% cap only bounds price movement if two finalized updates
/// of the SAME track cannot land inside `MIN_UPDATE_INTERVAL`. The compute
/// track already has a same-block test; this pins the SALT track, which reads
/// its own `lastSaltUpdateBlock` and is consumed by the marketplace's
/// SALT-to-credits conversion.
contract ComputePricingOracleSaltCooldownTest is Test {
    ComputePricingOracle internal oracle;
    address internal constant O1 = address(0x5A171);
    address internal constant O2 = address(0x5A172);
    address internal constant O3 = address(0x5A173);

    function setUp() public {
        oracle = new ComputePricingOracle(13, 100, address(this));
        oracle.addOracleMember(O1);
        oracle.addOracleMember(O2);
        oracle.addOracleMember(O3);
    }

    function _vote(address who, uint256 p) internal {
        vm.prank(who);
        oracle.proposeSaltPrice(p);
    }

    function _reachSalt(uint256 p) internal {
        _vote(O1, p);
        _vote(O2, p);
        _vote(O3, p);
    }

    function test_saltSecondUpdateInsideIntervalReverts() public {
        _reachSalt(110);
        assertEq(oracle.saltPriceUsdCents(), 110);

        _vote(O1, 121);
        _vote(O2, 121);
        vm.prank(O3);
        vm.expectRevert("ComputePricingOracle: update cooldown");
        oracle.proposeSaltPrice(121);
        assertEq(oracle.saltPriceUsdCents(), 110, "price must not compound inside the interval");
    }

    function test_saltVoteStaysOpenUntilIntervalElapses() public {
        _reachSalt(110);
        _vote(O1, 121);
        _vote(O2, 121);
        vm.roll(block.number + oracle.MIN_UPDATE_INTERVAL() - 1);
        vm.prank(O3);
        vm.expectRevert("ComputePricingOracle: update cooldown");
        oracle.proposeSaltPrice(121);
        vm.roll(block.number + 1);
        _vote(O3, 121);
        assertEq(oracle.saltPriceUsdCents(), 121, "the held vote finalizes once the interval elapses");
    }

    function test_saltUpdateAllowedOnceIntervalElapses() public {
        _reachSalt(110);
        vm.roll(block.number + oracle.MIN_UPDATE_INTERVAL());
        _reachSalt(121);
        assertEq(oracle.saltPriceUsdCents(), 121);
    }

    function test_computeUpdateDoesNotConsumeTheSaltInterval() public {
        vm.prank(O1);
        oracle.proposeComputePrice(14);
        vm.prank(O2);
        oracle.proposeComputePrice(14);
        vm.prank(O3);
        oracle.proposeComputePrice(14);
        // First-ever SALT update is unconstrained even in the same block.
        _reachSalt(110);
        assertEq(oracle.saltPriceUsdCents(), 110);
    }
}
