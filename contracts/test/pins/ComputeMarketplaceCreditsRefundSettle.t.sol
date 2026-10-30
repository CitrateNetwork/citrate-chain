// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";
import {MockBulkGateway, MockOracle, MockVerifier} from "../zzRmQ/RmQ_C014_C015_ComputeMarketplace.t.sol";

/// A credit-path refund is recorded in `creditsRefundOwed`; governance settles
/// it (credits re-issued off-native), and settling must actually reduce what is
/// owed, never beyond the recorded amount.
contract ComputeMarketplaceCreditsRefundSettleTest is Test {
    ComputeMarketplace internal market;
    MockBulkGateway internal bulk;
    address internal buyer = makeAddr("buyer");

    function setUp() public {
        market = new ComputeMarketplace(address(new MockVerifier()), makeAddr("treasury"), address(this));
        bulk = new MockBulkGateway();
        market.setBulkGateway(address(bulk));
        market.setPricingOracle(address(new MockOracle()));
        bulk.authorize(address(market));
        bulk.setCredits(buyer, 1000 ether);

        vm.prank(buyer);
        uint256 jobId = market.postJobWithMethod(
            bytes32(uint256(0xC1)),
            hex"deadbeef",
            1 ether,
            ComputeVerifier.VerificationTier.Commitment,
            ComputeMarketplace.PaymentMethod.BulkCredits,
            10,
            100
        );
        vm.roll(block.number + 11);
        market.expireJob(jobId);
        assertEq(market.creditsRefundOwed(buyer), 1 ether);
    }

    function test_settlingReducesTheOwedAmount() public {
        market.settleCreditsRefund(buyer, 0.4 ether);
        assertEq(market.creditsRefundOwed(buyer), 0.6 ether, "settled part is no longer owed");
        market.settleCreditsRefund(buyer, 0.6 ether);
        assertEq(market.creditsRefundOwed(buyer), 0, "fully settled");
    }

    function test_cannotSettleMoreThanOwed() public {
        market.settleCreditsRefund(buyer, 0.7 ether);
        vm.expectRevert(bytes("ComputeMarketplace: exceeds owed"));
        market.settleCreditsRefund(buyer, 0.7 ether);
        assertEq(market.creditsRefundOwed(buyer), 0.3 ether);
    }

    function test_onlyGovernanceSettles() public {
        vm.prank(buyer);
        vm.expectRevert();
        market.settleCreditsRefund(buyer, 1 ether);
        assertEq(market.creditsRefundOwed(buyer), 1 ether);
    }
}
