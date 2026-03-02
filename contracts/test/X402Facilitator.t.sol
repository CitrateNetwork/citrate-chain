// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WrappedSALT.sol";
import "../src/X402Facilitator.sol";

contract X402FacilitatorTest is Test {
    WrappedSALT public wSALT;
    X402Facilitator public facilitator;

    address public admin;
    uint256 public adminPk;
    address public alice;
    uint256 public alicePk;
    address public bob;
    address public treasury;

    uint256 constant FEE_BPS = 50; // 0.5%

    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    function setUp() public {
        (admin, adminPk) = makeAddrAndKey("admin");
        (alice, alicePk) = makeAddrAndKey("alice");
        bob = makeAddr("bob");
        treasury = makeAddr("treasury");

        vm.deal(alice, 100 ether);

        wSALT = new WrappedSALT();

        vm.prank(admin);
        facilitator = new X402Facilitator(address(wSALT), treasury, FEE_BPS);

        // Alice deposits and approves facilitator for fee deductions
        vm.startPrank(alice);
        wSALT.deposit{value: 50 ether}();
        wSALT.approve(address(facilitator), type(uint256).max);
        vm.stopPrank();
    }

    // ============================================================
    // settlePayment Tests
    // ============================================================

    function test_settlePayment_valid() public {
        uint256 value = 10 ether;
        uint256 fee = (value * FEE_BPS) / 10000; // 0.05 ether
        uint256 netValue = value - fee;

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("settle-1");

        // Alice signs authorization for netValue to bob (facilitator adjusts)
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, netValue, validAfter, validBefore, nonce
        );

        vm.prank(admin);
        facilitator.settlePayment(alice, bob, value, validAfter, validBefore, nonce, v, r, s);

        assertEq(wSALT.balanceOf(bob), netValue);
        assertEq(wSALT.balanceOf(treasury), fee);
    }

    function test_settlePayment_zero_value_reverts() public {
        bytes32 nonce = keccak256("settle-zero");
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 0, 0, block.timestamp + 1 hours, nonce
        );

        vm.prank(admin);
        vm.expectRevert("X402: zero value");
        facilitator.settlePayment(alice, bob, 0, 0, block.timestamp + 1 hours, nonce, v, r, s);
    }

    function test_settlePayment_non_facilitator_reverts() public {
        bytes32 nonce = keccak256("settle-unauth");
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 1 ether, 0, block.timestamp + 1 hours, nonce
        );

        vm.prank(bob); // bob is not a facilitator
        vm.expectRevert("AccessControl: account missing role");
        facilitator.settlePayment(alice, bob, 1 ether, 0, block.timestamp + 1 hours, nonce, v, r, s);
    }

    // ============================================================
    // batchSettle Tests
    // ============================================================

    function test_batchSettle() public {
        X402Facilitator.PaymentAuthorization[] memory payments = new X402Facilitator.PaymentAuthorization[](2);

        // Payment 1
        {
            uint256 value1 = 2 ether;
            uint256 net1 = value1 - (value1 * FEE_BPS) / 10000;
            bytes32 nonce1 = keccak256("batch-1");
            (uint8 v1, bytes32 r1, bytes32 s1) = _signTransferAuth(
                alicePk, alice, bob, net1, 0, block.timestamp + 1 hours, nonce1
            );
            payments[0] = X402Facilitator.PaymentAuthorization({
                from: alice, to: bob, value: value1,
                validAfter: 0, validBefore: block.timestamp + 1 hours,
                nonce: nonce1, v: v1, r: r1, s: s1
            });
        }

        // Payment 2
        {
            uint256 value2 = 3 ether;
            uint256 net2 = value2 - (value2 * FEE_BPS) / 10000;
            bytes32 nonce2 = keccak256("batch-2");
            (uint8 v2, bytes32 r2, bytes32 s2) = _signTransferAuth(
                alicePk, alice, bob, net2, 0, block.timestamp + 1 hours, nonce2
            );
            payments[1] = X402Facilitator.PaymentAuthorization({
                from: alice, to: bob, value: value2,
                validAfter: 0, validBefore: block.timestamp + 1 hours,
                nonce: nonce2, v: v2, r: r2, s: s2
            });
        }

        vm.prank(admin);
        facilitator.batchSettle(payments);

        // Bob got net values, treasury got fees
        uint256 totalNet = (2 ether - (2 ether * FEE_BPS) / 10000) + (3 ether - (3 ether * FEE_BPS) / 10000);
        uint256 totalFees = (2 ether * FEE_BPS) / 10000 + (3 ether * FEE_BPS) / 10000;
        assertEq(wSALT.balanceOf(bob), totalNet);
        assertEq(wSALT.balanceOf(treasury), totalFees);
    }

    // ============================================================
    // Fee Configuration Tests
    // ============================================================

    function test_setFacilitatorFee_admin() public {
        vm.prank(admin);
        facilitator.setFacilitatorFee(100); // 1%

        assertEq(facilitator.feeBps(), 100);
    }

    function test_setFacilitatorFee_exceeds_max_reverts() public {
        vm.prank(admin);
        vm.expectRevert("X402: fee exceeds 10%");
        facilitator.setFacilitatorFee(1001);
    }

    function test_setFacilitatorFee_non_admin_reverts() public {
        vm.prank(bob);
        vm.expectRevert("AccessControl: account missing role");
        facilitator.setFacilitatorFee(100);
    }

    // ============================================================
    // Treasury Tests
    // ============================================================

    function test_setTreasury() public {
        address newTreasury = makeAddr("newTreasury");
        vm.prank(admin);
        facilitator.setTreasury(newTreasury);

        assertEq(facilitator.treasury(), newTreasury);
    }

    function test_setTreasury_zero_reverts() public {
        vm.prank(admin);
        vm.expectRevert("X402: zero treasury address");
        facilitator.setTreasury(address(0));
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _signTransferAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_TYPEHASH,
            from, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }
}
