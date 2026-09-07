// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {X402Paywall} from "../../src/X402Paywall.sol";
import {WrappedSALT} from "../../src/WrappedSALT.sol";

/// @title CHAIN-B-C047 — X402Paywall resourceId not bound to the authorization.
/// @notice The EIP-3009 authorization signs only (from, to, value, validAfter,
///         validBefore, nonce) — NOT `resourceId`. Pre-fix `verifyAndGrant` did
///         not bind them, so an observer could front-run with a different
///         `resourceId`, consuming the one-shot nonce and paying the provider
///         while granting access to the wrong resource; the payer's own call
///         then reverted "authorization already used". Post-fix the nonce must
///         equal keccak256(resourceId, salt).
contract X402PaywallC047Test is Test {
    WrappedSALT wSALT;
    X402Paywall paywall;
    address provider;
    address payer;
    uint256 payerPk;
    uint256 constant PRICE = 1 ether;

    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    function setUp() public {
        provider = makeAddr("provider");
        (payer, payerPk) = makeAddrAndKey("payer");
        wSALT = new WrappedSALT();
        vm.prank(provider);
        paywall = new X402Paywall(address(wSALT), PRICE);
        vm.deal(payer, 100 ether);
        vm.prank(payer);
        wSALT.deposit{value: 50 ether}();
    }

    function _sign(uint256 value, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, payer, provider, value, uint256(0), validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash));
        (v, r, s) = vm.sign(payerPk, digest);
    }

    /// RED (pre-fix): a front-runner replays the payer's authorization against a
    /// DIFFERENT resourceId, burning the nonce. GREEN: the mismatch reverts
    /// before the nonce is consumed, so the payer's legitimate grant still works.
    function test_C047_frontRunWithDifferentResourceIsRejected() public {
        bytes32 intendedResource = keccak256("premium-article");
        bytes32 salt = keccak256("purchase-1");
        bytes32 nonce = keccak256(abi.encode(intendedResource, salt));
        (uint8 v, bytes32 r, bytes32 s) = _sign(PRICE, block.timestamp + 1 hours, nonce);

        // Attacker front-runs pointing the same authorization at a different id.
        bytes32 attackerResource = keccak256("cheap-junk");
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert("Paywall: nonce not bound to resource");
        paywall.verifyAndGrant(attackerResource, payer, PRICE, 0, block.timestamp + 1 hours, nonce, salt, v, r, s);

        // The payer's legitimate call is untouched: nonce not yet consumed.
        paywall.verifyAndGrant(intendedResource, payer, PRICE, 0, block.timestamp + 1 hours, nonce, salt, v, r, s);
        assertTrue(paywall.hasAccess(payer, intendedResource), "legit grant must still work");
    }

    /// A correctly-bound authorization grants access.
    function test_C047_boundAuthorizationGrantsAccess() public {
        bytes32 resource = keccak256("resource");
        bytes32 salt = keccak256("s");
        bytes32 nonce = keccak256(abi.encode(resource, salt));
        (uint8 v, bytes32 r, bytes32 s) = _sign(PRICE, block.timestamp + 1 hours, nonce);
        paywall.verifyAndGrant(resource, payer, PRICE, 0, block.timestamp + 1 hours, nonce, salt, v, r, s);
        assertTrue(paywall.hasAccess(payer, resource));
    }
}
