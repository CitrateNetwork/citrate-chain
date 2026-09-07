// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePricingOracle} from "../../src/ComputePricingOracle.sol";

/// @title CHAIN-B-C037 — pricing oracle: update cooldown + salt-nonce bump.
/// @notice (a) Without a cooldown the 10% cap is per-update and the nonce
///         reopens a fresh vote in the same block, so N sequential proposals
///         compound to 1.1^N in one block. (b) Membership changes bumped only
///         `computePriceNonce`, leaving a live salt-price vote to finalize
///         against a shrunken quorum with votes from removed members.
contract ComputePricingOracleC037Test is Test {
    ComputePricingOracle oracle;
    address constant O1 = address(0x0AC1E1);
    address constant O2 = address(0x0AC1E2);
    address constant O3 = address(0x0AC1E3);

    function setUp() public {
        oracle = new ComputePricingOracle(13, 100);
        oracle.addOracleMember(O1);
        oracle.addOracleMember(O2);
        oracle.addOracleMember(O3);
    }

    function _reachCompute(uint256 p) internal {
        vm.prank(O1);
        oracle.proposeComputePrice(p);
        vm.prank(O2);
        oracle.proposeComputePrice(p);
        vm.prank(O3);
        oracle.proposeComputePrice(p);
    }

    /// C037(b): every membership change bumps BOTH nonces. RED (pre-fix):
    /// `saltPriceNonce` stayed 0 across membership changes.
    function test_C037_membershipBumpsSaltNonce() public {
        uint256 before = oracle.saltPriceNonce();
        oracle.removeOracleMember(O3);
        assertEq(oracle.saltPriceNonce(), before + 1, "salt nonce must bump on removal");
        oracle.addOracleMember(O3);
        assertEq(oracle.saltPriceNonce(), before + 2, "salt nonce must bump on add");
    }

    /// C037(a): two finalized compute updates cannot land in the same block.
    /// RED (pre-fix): the second finalize succeeded, compounding the price.
    function test_C037_secondUpdateInSameBlockRevertsOnCooldown() public {
        _reachCompute(14);
        assertEq(oracle.computePriceUsdCents(), 14);

        // Second update, same block → cooldown revert on the quorum-reaching vote.
        vm.prank(O1);
        oracle.proposeComputePrice(15);
        vm.prank(O2);
        oracle.proposeComputePrice(15);
        vm.prank(O3);
        vm.expectRevert("ComputePricingOracle: update cooldown");
        oracle.proposeComputePrice(15);
    }

    /// After the cooldown elapses, the next update proceeds.
    function test_C037_updateAllowedAfterCooldown() public {
        _reachCompute(14);
        vm.roll(block.number + oracle.MIN_UPDATE_INTERVAL());
        _reachCompute(15);
        assertEq(oracle.computePriceUsdCents(), 15, "update proceeds after cooldown");
    }
}
