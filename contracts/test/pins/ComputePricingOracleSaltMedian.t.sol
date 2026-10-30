// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePricingOracle} from "../../src/ComputePricingOracle.sol";

/// The SALT track finalizes at the MEDIAN of the quorum's submissions, like the
/// compute track (which has its own test). One member's outlier, submitted
/// first or last, must not become the price.
contract ComputePricingOracleSaltMedianTest is Test {
    ComputePricingOracle internal o;
    address internal constant A = address(0x01);
    address internal constant B = address(0x02);
    address internal constant C = address(0x03);

    function setUp() public {
        o = new ComputePricingOracle(100, 100, address(this));
        o.addOracleMember(A);
        o.addOracleMember(B);
        o.addOracleMember(C);
    }

    function _salt(address who, uint256 p) internal {
        vm.prank(who);
        o.proposeSaltPrice(p);
    }

    function test_saltFinalizesAtMedianWhenOutlierIsLast() public {
        _salt(A, 102);
        _salt(B, 105);
        _salt(C, 109);
        assertEq(o.saltPriceUsdCents(), 105, "median of the quorum, not the last vote");
    }

    function test_saltFinalizesAtMedianWhenOutlierIsFirst() public {
        _salt(A, 91);
        _salt(B, 104);
        _salt(C, 103);
        assertEq(o.saltPriceUsdCents(), 103, "median of the quorum, not the first or last vote");
    }

    function test_saltMedianDoesNotMoveComputePrice() public {
        _salt(A, 102);
        _salt(B, 105);
        _salt(C, 109);
        assertEq(o.computePriceUsdCents(), 100, "compute track untouched");
    }
}
