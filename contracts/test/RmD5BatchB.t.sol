// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/X402Paywall.sol";
import "../src/WrappedSALT.sol";

/// Aggregate regression tests for RM-D5 batch B audit findings:
///   SOL-12 (MEDIUM) — Paywall TTL: re-purchase after expiry
///   SOL-16 (MEDIUM) — LiquidStakingPool dead-shares + receive() block (covered by LiquidStakingPool.t.sol)
///   SOL-10 (MEDIUM) — Oracle BFT lock on membership change (covered by ComputePricingOracle.t.sol)
///   SOL-09 (HIGH)   — Pipeline submitDeadline (covered by ComputePoolPipeline.t.sol structurally)

contract RmD5BatchBTest is Test {
    WrappedSALT public wSALT;
    X402Paywall public paywall;
    address public provider;
    address public payer;
    uint256 public payerPk;
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
        vm.startPrank(payer);
        wSALT.deposit{value: 50 ether}();
        vm.stopPrank();
    }

    /// SOL-12.1: re-purchase after TTL expires must succeed.
    /// Pre-fix `accessGranted` was a permanent boolean; second
    /// purchase reverted with "Paywall: already granted".
    function test_sol12_repurchase_after_expiry_works() public {
        bytes32 resourceId = keccak256("test-resource");

        // First purchase. C047: the nonce is now bound to the resource.
        bytes32 salt1 = keccak256("nonce-1");
        bytes32 nonce1 = keccak256(abi.encode(resourceId, salt1));
        (uint8 v1, bytes32 r1, bytes32 s1) = _sign(payer, payerPk, provider, PRICE, 0, block.timestamp + 1 hours, nonce1);
        paywall.verifyAndGrant(resourceId, payer, PRICE, 0, block.timestamp + 1 hours, nonce1, salt1, v1, r1, s1);

        assertTrue(paywall.hasAccess(payer, resourceId), "first purchase grants access");

        // Advance past default 24h TTL. Use absolute timestamp
        // values so the validBefore math is unambiguous.
        uint256 t2 = 200_000;
        vm.warp(t2);
        assertFalse(paywall.hasAccess(payer, resourceId), "access expired");

        // Re-purchase. Sign with an auth window valid at t2.
        bytes32 salt2 = keccak256("nonce-2");
        bytes32 nonce2 = keccak256(abi.encode(resourceId, salt2));
        uint256 newValidBefore = t2 + 3600;
        (uint8 v2, bytes32 r2, bytes32 s2) = _sign(payer, payerPk, provider, PRICE, 0, newValidBefore, nonce2);
        paywall.verifyAndGrant(resourceId, payer, PRICE, 0, newValidBefore, nonce2, salt2, v2, r2, s2);

        assertTrue(paywall.hasAccess(payer, resourceId), "SOL-12: re-purchase after expiry must work");
    }

    /// SOL-12.2: re-purchase BEFORE expiry is rejected (no double-grant).
    function test_sol12_repurchase_before_expiry_rejected() public {
        bytes32 resourceId = keccak256("test-resource");

        bytes32 salt1 = keccak256("nonce-1");
        bytes32 nonce1 = keccak256(abi.encode(resourceId, salt1));
        (uint8 v1, bytes32 r1, bytes32 s1) = _sign(payer, payerPk, provider, PRICE, 0, block.timestamp + 1 hours, nonce1);
        paywall.verifyAndGrant(resourceId, payer, PRICE, 0, block.timestamp + 1 hours, nonce1, salt1, v1, r1, s1);

        bytes32 salt2 = keccak256("nonce-2");
        bytes32 nonce2 = keccak256(abi.encode(resourceId, salt2));
        (uint8 v2, bytes32 r2, bytes32 s2) = _sign(payer, payerPk, provider, PRICE, 0, block.timestamp + 1 hours, nonce2);
        vm.expectRevert("Paywall: access still active");
        paywall.verifyAndGrant(resourceId, payer, PRICE, 0, block.timestamp + 1 hours, nonce2, salt2, v2, r2, s2);
    }

    /// SOL-12.3: setAccessTTL is provider-only.
    function test_sol12_setAccessTTL_provider_only() public {
        vm.prank(provider);
        paywall.setAccessTTL(7 days);
        assertEq(paywall.accessTTL(), 7 days);

        vm.prank(payer);
        vm.expectRevert("Paywall: not provider");
        paywall.setAccessTTL(1 days);
    }

    function _sign(
        address /* from */,
        uint256 signerPk,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_TYPEHASH,
            payer, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }
}
