// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BulkComputeGateway} from "../src/BulkComputeGateway.sol";
import {ComputePricingOracle} from "../src/ComputePricingOracle.sol";
import {StablecoinTreasury} from "../src/StablecoinTreasury.sol";

/// @title BulkGatewayAuthorization.t.sol — CM-06 WP-06.2
/// @notice Verifies the on-chain effect of
///         `script/AuthorizeSpenders.s.sol`: after governance calls
///         authorizeSpender(marketplace), authorizedSpenders[marketplace]
///         is true; outsiders cannot grant; revokes work; marketplace
///         can then call spendCredits while non-authorized addresses
///         cannot.
///
/// The script itself uses vm.startBroadcast — these tests exercise
/// the same code path against the real BulkComputeGateway state
/// machine.
contract BulkGatewayAuthorizationTest is Test {
    BulkComputeGateway internal gateway;
    ComputePricingOracle internal oracle;
    StablecoinTreasury internal treasury;

    address internal governance = address(this);
    address internal marketplace = address(0xB001);
    address internal extra = address(0xB002);
    address internal outsider = address(0xBAD1);

    function setUp() public {
        oracle = new ComputePricingOracle(13, 100);  // $0.13/PFLOP-h, $1/SALT
        treasury = new StablecoinTreasury(governance);
        gateway = new BulkComputeGateway(
            address(treasury),
            address(oracle),
            governance
        );
    }

    function test_authorize_then_check_returns_true() public {
        assertEq(gateway.authorizedSpenders(marketplace), false);
        gateway.authorizeSpender(marketplace);
        assertEq(gateway.authorizedSpenders(marketplace), true);
    }

    function test_authorize_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit SpenderAuthorized(marketplace);
        gateway.authorizeSpender(marketplace);
    }

    function test_outsider_cannot_authorize() public {
        vm.prank(outsider);
        vm.expectRevert();
        gateway.authorizeSpender(marketplace);
    }

    function test_double_authorize_idempotent() public {
        gateway.authorizeSpender(marketplace);
        // Re-authorising shouldn't revert; the script's
        // _authorizeIfNeeded gates this, but the contract itself
        // also handles it gracefully.
        // (We don't assert no-event here — the contract emits each
        // time. The script SKIPS rather than re-emitting.)
        gateway.authorizeSpender(marketplace);
        assertEq(gateway.authorizedSpenders(marketplace), true);
    }

    function test_revoke_flips_back_to_false() public {
        gateway.authorizeSpender(marketplace);
        gateway.revokeSpender(marketplace);
        assertEq(gateway.authorizedSpenders(marketplace), false);
    }

    function test_authorized_spender_can_spend_credits() public {
        gateway.authorizeSpender(marketplace);

        // Seed credits into a buyer's account by going through the
        // purchase path. Easier path: we use the spendCredits-only
        // flow with a synthetic balance via storage slot tweaks…
        // Actually, we can't easily inject credits without going
        // through purchaseComputeCredits, which needs USDC + treasury
        // wiring. Instead, this test asserts the access-control side
        // (authorized → no AccessControl revert; non-authorized →
        // revert), which is the script's invariant.
        address buyer = address(0xBEEF);

        // Even with zero balance, an unauthorized caller hits the
        // onlyAuthorizedSpender modifier first. Confirm.
        vm.prank(outsider);
        vm.expectRevert();
        gateway.spendCredits(buyer, 1);

        // An authorized caller passes the modifier; the call still
        // reverts on insufficient credits, but that's the BUYER's
        // balance check, not access control. Assert the revert
        // reason is the credit-balance one, not the auth one.
        vm.prank(marketplace);
        vm.expectRevert(bytes("BulkComputeGateway: insufficient credits"));
        gateway.spendCredits(buyer, 1);
    }

    function test_extra_spender_can_be_added_alongside() public {
        gateway.authorizeSpender(marketplace);
        gateway.authorizeSpender(extra);
        assertEq(gateway.authorizedSpenders(marketplace), true);
        assertEq(gateway.authorizedSpenders(extra), true);
    }

    /// Mirror of the script's post-broadcast assertion. Catches any
    /// future change that breaks the public getter shape.
    function test_authorizedSpenders_getter_shape() public {
        gateway.authorizeSpender(marketplace);
        bool flag = gateway.authorizedSpenders(marketplace);
        assertTrue(flag);
    }

    // Re-declare the event signature so vm.expectEmit can match it.
    event SpenderAuthorized(address indexed spender);
}
