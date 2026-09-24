// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../src/ComputeVerifier.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @title ComputeMarketplaceCreditPath.t.sol — CM-06 WP-06.1
/// @notice Tests for the dual-payment-path (SALT vs BulkCredits)
///         extension to ComputeMarketplace.postJob. Written FIRST per
///         the spec-first discipline.
///
/// Acceptance criteria from
/// .agentile/planset/compute-marketplace-buildout/CM-06-gateway-credit-billing.md
/// (WP-06.1):
///   - test_post_job_with_salt                       (no regression)
///   - test_post_job_with_credits_happy_path
///   - test_post_job_with_credits_insufficient_fails
///   - test_post_job_with_credits_stale_oracle_reverts
///   - test_post_job_with_value_in_credits_mode_reverts (no mixed)
///
/// Plus:
///   - test_legacy_postJob_signature_unchanged
///   - test_credits_path_reverts_when_marketplace_unauthorized
///   - test_setBulkGateway_only_governance
///   - test_governance_can_set_zero_to_disable
///
/// Mirrors invariants from
/// .agentile/formal/specs/compute/CreditBilling.tla
///   - NoMixedPayment        — `test_post_job_with_value_in_credits_mode_reverts`
///   - PostJobCredits precondition (`marketplace ∈ authorizedSpenders`)
///                            — `test_credits_path_reverts_when_marketplace_unauthorized`
///   - CreditConservation    — happy-path test asserts pre/post balances

// ── Mock BulkComputeGateway ────────────────────────────────────

/// Tracks credit balances + authorization, mimics the real
/// BulkComputeGateway's `spendCredits` + `getCreditBalance` surface.
contract MockBulkGateway {
    mapping(address => uint256) public credits;
    mapping(address => bool) public authorized;

    function setCredits(address institution, uint256 amount) external {
        credits[institution] = amount;
    }

    function authorize(address spender) external {
        authorized[spender] = true;
    }

    function spendCredits(
        address institution,
        uint256 amount
    ) external returns (bool) {
        require(authorized[msg.sender], "MockBulkGateway: not authorized");
        require(amount > 0, "MockBulkGateway: zero credits");
        require(credits[institution] >= amount, "MockBulkGateway: insufficient credits");
        credits[institution] -= amount;
        return true;
    }

    function getCreditBalance(address institution) external view returns (uint256) {
        return credits[institution];
    }
}

// ── Mock ComputePricingOracle ──────────────────────────────────

contract MockOracle {
    bool public stale;
    uint256 public computePriceUsdCents = 13;   // $0.13 per PFLOP-hour
    uint256 public saltPriceUsdCents = 100;     // $1.00 per SALT

    function setStale(bool s) external { stale = s; }

    function isPriceStale() external view returns (bool) {
        return stale;
    }

    /// SALT/PFLOP-hour = computePrice * 1e18 / saltPrice
    function saltPerPflopHour() external view returns (uint256) {
        return (computePriceUsdCents * 1e18) / saltPriceUsdCents;
    }
}

// ── Mock ComputeVerifier ───────────────────────────────────────
// Minimal stub to satisfy the marketplace's `verifier.configureJob`
// call inside postJob — we don't exercise the verifier path here.

contract MockVerifier {
    function configureJob(
        uint256,
        uint256,
        ComputeVerifier.VerificationTier
    ) external {}
}

contract ComputeMarketplaceCreditPathTest is Test {
    ComputeMarketplace internal market;
    MockBulkGateway internal bulk;
    MockOracle internal oracle;
    MockVerifier internal verifier;

    address internal governance = address(this);
    address internal buyer = address(0xB001);
    address internal treasury = address(0xC0FFEE);

    bytes32 internal constant MODEL_HASH = bytes32(uint256(0xab));

    function setUp() public {
        verifier = new MockVerifier();
        market = new ComputeMarketplace(address(verifier), treasury);
        bulk = new MockBulkGateway();
        oracle = new MockOracle();

        vm.deal(buyer, 1000 ether);

        // Wire bulk gateway + oracle into the marketplace via
        // governance (msg.sender = address(this) = governance).
        market.setBulkGateway(address(bulk));
        market.setPricingOracle(address(oracle));

        // Governance authorizes the marketplace to spend credits on
        // behalf of buyers.
        bulk.authorize(address(market));
    }

    // ── Helpers ────────────────────────────────────────────────

    function _spec()
        internal
        pure
        returns (bytes memory inputHash, ComputeVerifier.VerificationTier tier)
    {
        inputHash = hex"deadbeef";
        tier = ComputeVerifier.VerificationTier.Commitment;
    }

    function _postWithSalt(uint256 maxPrice) internal returns (uint256) {
        (bytes memory ih, ComputeVerifier.VerificationTier tier) = _spec();
        vm.prank(buyer);
        return market.postJob{value: maxPrice}(
            MODEL_HASH,
            ih,
            maxPrice,
            tier,
            10,
            100
        );
    }

    function _postWithCredits(uint256 maxPrice, uint256 valueSent) internal returns (uint256) {
        (bytes memory ih, ComputeVerifier.VerificationTier tier) = _spec();
        vm.prank(buyer);
        return market.postJobWithMethod{value: valueSent}(
            MODEL_HASH,
            ih,
            maxPrice,
            tier,
            ComputeMarketplace.PaymentMethod.BulkCredits,
            10,
            100
        );
    }

    // ── No-regression on the SALT path ─────────────────────────

    /// AC: existing SALT-only postJob still works.
    function test_post_job_with_salt() public {
        uint256 jobId = _postWithSalt(1 ether);
        ComputeMarketplace.Job memory j = market.getJob(jobId);
        assertEq(j.requester, buyer);
        assertEq(j.maxPrice, 1 ether);
        assertEq(j.escrow, 1 ether);
    }

    /// AC: legacy 6-arg postJob signature is unchanged.
    function test_legacy_postJob_signature_unchanged() public {
        // The legacy postJob (no PaymentMethod arg) defaults to SALT.
        uint256 jobId = _postWithSalt(2 ether);
        ComputeMarketplace.Job memory j = market.getJob(jobId);
        assertEq(j.escrow, 2 ether);
    }

    // ── Credits happy path ─────────────────────────────────────

    /// AC: post a job paid from credits — buyer's credit balance
    /// drops by the SALT-converted credit amount; no SALT leaves
    /// the buyer's wallet.
    function test_post_job_with_credits_happy_path() public {
        // Give buyer 1000 credits worth (more than enough for a
        // 1 SALT job at the mock oracle's $0.13/PFLOP-h × $1/SALT
        // rates: 1 SALT = ~7.69 PFLOP-hours).
        bulk.setCredits(buyer, 1000 ether);
        uint256 buyerSaltBefore = buyer.balance;
        uint256 buyerCreditsBefore = bulk.getCreditBalance(buyer);

        uint256 jobId = _postWithCredits(1 ether, 0);

        // Job is posted in Bidding state with full SALT-denominated
        // escrow recorded (the marketplace owes that SALT to the
        // eventual provider; treasury replenishment is operational).
        ComputeMarketplace.Job memory j = market.getJob(jobId);
        assertEq(j.requester, buyer);
        assertEq(j.escrow, 1 ether);
        assertEq(
            uint8(market.jobPaymentMethod(jobId)),
            uint8(ComputeMarketplace.PaymentMethod.BulkCredits)
        );

        // No SALT changed hands.
        assertEq(buyer.balance, buyerSaltBefore);

        // Credits debited per oracle conversion: SALT/PFLOP-h =
        // 13 * 1e18 / 100 = 1.3e17. credits = 1e18 * 1e18 / 1.3e17 ≈
        // 7.692e18 (≈7.69 PFLOP-h).
        uint256 expectedCredits = (1 ether * 1e18) / oracle.saltPerPflopHour();
        assertEq(
            buyerCreditsBefore - bulk.getCreditBalance(buyer),
            expectedCredits,
            "credit debit doesn't match oracle conversion"
        );
    }

    /// AC: insufficient credits → revert with clear message.
    function test_post_job_with_credits_insufficient_fails() public {
        bulk.setCredits(buyer, 1); // way too few credits
        vm.expectRevert(bytes("MockBulkGateway: insufficient credits"));
        _postWithCredits(1 ether, 0);
    }

    /// AC: stale oracle → revert before any credit debit.
    function test_post_job_with_credits_stale_oracle_reverts() public {
        bulk.setCredits(buyer, 1000 ether);
        oracle.setStale(true);
        vm.expectRevert(bytes("ComputeMarketplace: oracle price stale"));
        _postWithCredits(1 ether, 0);
    }

    /// AC: msg.value > 0 in credits mode → revert (no mixed payment).
    /// Mirrors NoMixedPayment invariant in CreditBilling.tla.
    function test_post_job_with_value_in_credits_mode_reverts() public {
        bulk.setCredits(buyer, 1000 ether);
        vm.expectRevert(bytes("ComputeMarketplace: credits path accepts no value"));
        _postWithCredits(1 ether, 1); // 1 wei sent alongside credits
    }

    /// Marketplace not authorized to spend on the gateway → revert.
    /// Mirrors PostJobCredits precondition (marketplace ∈
    /// authorizedSpenders) in CreditBilling.tla.
    function test_credits_path_reverts_when_marketplace_unauthorized() public {
        // Wire a fresh gateway that does NOT authorize the marketplace.
        MockBulkGateway fresh = new MockBulkGateway();
        market.setBulkGateway(address(fresh));
        fresh.setCredits(buyer, 1000 ether);
        vm.expectRevert(bytes("MockBulkGateway: not authorized"));
        _postWithCredits(1 ether, 0);
    }

    // ── Governance gates ───────────────────────────────────────

    /// Only governance can call setBulkGateway.
    function test_setBulkGateway_only_governance() public {
        address attacker = address(0xBAD1);
        vm.prank(attacker);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        market.setBulkGateway(address(bulk));
    }

    /// Governance can set bulk gateway to address(0) to disable
    /// the credits path entirely. Subsequent credits-mode posts
    /// revert with a clear message.
    function test_governance_can_set_zero_to_disable() public {
        market.setBulkGateway(address(0));
        bulk.setCredits(buyer, 1000 ether);
        vm.expectRevert(bytes("ComputeMarketplace: bulk gateway not set"));
        _postWithCredits(1 ether, 0);
    }

    /// Only governance can call setPricingOracle.
    function test_setPricingOracle_only_governance() public {
        address attacker = address(0xBAD2);
        vm.prank(attacker);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        market.setPricingOracle(address(oracle));
    }
}
