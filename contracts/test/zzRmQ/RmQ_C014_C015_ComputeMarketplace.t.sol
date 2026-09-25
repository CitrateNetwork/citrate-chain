// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";

// ── Minimal mocks (mirror ComputeMarketplaceCreditPath.t.sol) ──────────

contract MockBulkGateway {
    mapping(address => uint256) public credits;
    mapping(address => bool) public authorized;

    function setCredits(address who, uint256 amt) external { credits[who] = amt; }
    function authorize(address spender) external { authorized[spender] = true; }

    function spendCredits(address who, uint256 amt) external returns (bool) {
        require(authorized[msg.sender], "not authorized");
        require(amt > 0, "zero");
        require(credits[who] >= amt, "insufficient");
        credits[who] -= amt;
        return true;
    }

    function getCreditBalance(address who) external view returns (uint256) { return credits[who]; }
}

contract MockOracle {
    function isPriceStale() external pure returns (bool) { return false; }
    function saltPerPflopHour() external pure returns (uint256) { return 13e16; } // $0.13/$1
}

contract MockVerifier {
    function configureJob(uint256, uint256, ComputeVerifier.VerificationTier) external {}
    function bindJob(uint256, bytes32, bytes32) external {} // PBA-L2-004
}

/// @title RmQ_C014_C015 — ComputeMarketplace phantom credits + conscription
contract RmQ_C014_C015_ComputeMarketplace is Test {
    ComputeMarketplace internal market;
    MockBulkGateway internal bulk;
    MockOracle internal oracle;
    MockVerifier internal verifier;

    address internal treasury = makeAddr("treasury");
    address internal buyer = makeAddr("buyer");
    address internal provider = makeAddr("provider");
    address internal attacker = makeAddr("attacker");

    bytes32 internal constant MODEL = bytes32(uint256(0xC1));

    function setUp() public {
        verifier = new MockVerifier();
        market = new ComputeMarketplace(address(verifier), treasury, address(this));
        bulk = new MockBulkGateway();
        oracle = new MockOracle();
        market.setBulkGateway(address(bulk));
        market.setPricingOracle(address(oracle));
        bulk.authorize(address(market));

        vm.deal(buyer, 1000 ether);
        vm.deal(provider, 2000 ether);
        vm.deal(attacker, 100 ether);
    }

    // ================= C014: phantom credits =================

    /// GREEN: a credit-path job's escrow is a NON-native liability, so
    /// `expireJob` moves no SALT out of the contract — it records a credit
    /// refund instead. The 100 ether of other users' escrow is untouched.
    /// RED (pre-fix): `expireJob` pays the buyer 1 ether of native SALT it
    /// never deposited, draining the contract that holds other users' funds
    /// (buyer.balance += 1 ether; market.balance -= 1 ether).
    function test_C014_credit_job_expiry_does_not_drain_native() public {
        // Stand in for other SALT-path requesters' escrow held by the market.
        vm.deal(address(market), 100 ether);

        bulk.setCredits(buyer, 1000 ether);

        // Post a credits job (msg.value == 0) with a 1 ether maxPrice.
        vm.prank(buyer);
        uint256 jobId = market.postJobWithMethod(
            MODEL, hex"deadbeef", 1 ether,
            ComputeVerifier.VerificationTier.Commitment,
            ComputeMarketplace.PaymentMethod.BulkCredits,
            10, 100
        );

        uint256 buyerBefore = buyer.balance;
        uint256 marketBefore = address(market).balance;

        vm.roll(block.number + 11); // past bidDeadline (bidWindow == 10)
        market.expireJob(jobId);

        assertEq(buyer.balance, buyerBefore, "C014: no native SALT paid to buyer");
        assertEq(address(market).balance, marketBefore, "C014: contract not drained");
        assertEq(market.creditsRefundOwed(buyer), 1 ether, "C014: refund recorded as credits");
    }

    /// The native (SALT) path still refunds native on expiry — no regression.
    function test_C014_salt_job_expiry_refunds_native() public {
        vm.prank(buyer);
        uint256 jobId = market.postJob{value: 1 ether}(
            MODEL, hex"deadbeef", 1 ether,
            ComputeVerifier.VerificationTier.Commitment, 10, 100
        );
        uint256 buyerBefore = buyer.balance;
        vm.roll(block.number + 11);
        market.expireJob(jobId);
        assertEq(buyer.balance, buyerBefore + 1 ether, "SALT path refunds native");
    }

    // ================= C015: non-consensual conscription =================

    function _registerProvider() internal {
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(provider);
        market.registerProvider{value: 1000 ether}(models);
    }

    /// GREEN: a provider who never opted in cannot be conscripted by
    /// `autoAssignJob`, so their stake can never be slashed by a griefing
    /// timeout. The attacker's call reverts and the stake is intact.
    /// RED (pre-fix): `autoAssignJob` conscripts the provider (no revert);
    /// after the deadline `timeoutJob` slashes 5% of their stake while
    /// refunding the attacker in full.
    function test_C015_unconsented_provider_cannot_be_conscripted() public {
        _registerProvider();
        uint256 stakeBefore = market.getProvider(provider).stake;

        vm.prank(attacker);
        vm.expectRevert("ComputeMarketplace: no available provider");
        market.autoAssignJob{value: 0.01 ether}(MODEL, hex"aa", ComputeVerifier.VerificationTier.Commitment);

        assertEq(market.getProvider(provider).stake, stakeBefore, "C015: stake untouched");
    }

    /// A provider that DOES opt in can still be auto-assigned — the feature is
    /// preserved for consenting providers.
    function test_C015_opted_in_provider_can_be_auto_assigned() public {
        _registerProvider();
        vm.prank(provider);
        market.setAutoAssignOptIn(true);

        vm.prank(attacker);
        uint256 jobId = market.autoAssignJob{value: 0.01 ether}(
            MODEL, hex"aa", ComputeVerifier.VerificationTier.Commitment
        );
        assertEq(market.getJob(jobId).assignedProvider, provider, "opted-in provider assigned");
    }

    receive() external payable {}
}
