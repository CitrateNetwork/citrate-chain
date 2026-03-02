// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WrappedSALT.sol";

contract WrappedSALTTest is Test {
    WrappedSALT public wSALT;

    address public alice;
    uint256 public alicePk;
    address public bob;
    uint256 public bobPk;

    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    bytes32 constant CANCEL_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    function setUp() public {
        wSALT = new WrappedSALT();

        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");

        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ============================================================
    // Deposit / Withdraw Tests
    // ============================================================

    function test_deposit() public {
        vm.prank(alice);
        wSALT.deposit{value: 1 ether}();

        assertEq(wSALT.balanceOf(alice), 1 ether);
        assertEq(wSALT.totalSupply(), 1 ether);
    }

    function test_deposit_zero_reverts() public {
        vm.prank(alice);
        vm.expectRevert("wSALT: zero deposit");
        wSALT.deposit{value: 0}();
    }

    function test_withdraw() public {
        vm.startPrank(alice);
        wSALT.deposit{value: 5 ether}();
        uint256 balBefore = alice.balance;
        wSALT.withdraw(2 ether);
        vm.stopPrank();

        assertEq(wSALT.balanceOf(alice), 3 ether);
        assertEq(alice.balance, balBefore + 2 ether);
    }

    function test_withdraw_insufficient_reverts() public {
        vm.startPrank(alice);
        wSALT.deposit{value: 1 ether}();
        vm.expectRevert("wSALT: insufficient balance");
        wSALT.withdraw(2 ether);
        vm.stopPrank();
    }

    function test_receive_ether() public {
        vm.prank(alice);
        (bool ok,) = address(wSALT).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(wSALT.balanceOf(alice), 1 ether);
    }

    // ============================================================
    // ERC-20 Tests
    // ============================================================

    function test_transfer() public {
        vm.prank(alice);
        wSALT.deposit{value: 5 ether}();

        vm.prank(alice);
        wSALT.transfer(bob, 2 ether);

        assertEq(wSALT.balanceOf(alice), 3 ether);
        assertEq(wSALT.balanceOf(bob), 2 ether);
    }

    function test_approve_and_transferFrom() public {
        vm.prank(alice);
        wSALT.deposit{value: 5 ether}();

        vm.prank(alice);
        wSALT.approve(bob, 3 ether);

        vm.prank(bob);
        wSALT.transferFrom(alice, bob, 2 ether);

        assertEq(wSALT.balanceOf(bob), 2 ether);
        assertEq(wSALT.allowance(alice, bob), 1 ether);
    }

    // ============================================================
    // TransferWithAuthorization Tests
    // ============================================================

    function test_transferWithAuthorization_valid() public {
        // Alice deposits wSALT
        vm.prank(alice);
        wSALT.deposit{value: 10 ether}();

        uint256 value = 1 ether;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        // Sign the authorization
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, value, validAfter, validBefore, nonce
        );

        // Anyone can submit the authorization
        wSALT.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);

        assertEq(wSALT.balanceOf(alice), 9 ether);
        assertEq(wSALT.balanceOf(bob), 1 ether);
        assertTrue(wSALT.authorizationState(alice, nonce));
    }

    function test_transferWithAuthorization_expired() public {
        vm.prank(alice);
        wSALT.deposit{value: 10 ether}();

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp - 1; // Already expired
        bytes32 nonce = keccak256("nonce-expired");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 1 ether, validAfter, validBefore, nonce
        );

        vm.expectRevert("wSALT: authorization expired");
        wSALT.transferWithAuthorization(alice, bob, 1 ether, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_not_yet_valid() public {
        vm.prank(alice);
        wSALT.deposit{value: 10 ether}();

        uint256 validAfter = block.timestamp + 1 hours; // Not yet valid
        uint256 validBefore = block.timestamp + 2 hours;
        bytes32 nonce = keccak256("nonce-early");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 1 ether, validAfter, validBefore, nonce
        );

        vm.expectRevert("wSALT: authorization not yet valid");
        wSALT.transferWithAuthorization(alice, bob, 1 ether, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_replayed() public {
        vm.prank(alice);
        wSALT.deposit{value: 10 ether}();

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce-replay");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 1 ether, validAfter, validBefore, nonce
        );

        // First call succeeds
        wSALT.transferWithAuthorization(alice, bob, 1 ether, validAfter, validBefore, nonce, v, r, s);

        // Replay reverts
        vm.expectRevert("wSALT: authorization already used");
        wSALT.transferWithAuthorization(alice, bob, 1 ether, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_wrong_signer() public {
        vm.prank(alice);
        wSALT.deposit{value: 10 ether}();

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce-wrong");

        // Sign with bob's key but claim from=alice
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            bobPk, alice, bob, 1 ether, validAfter, validBefore, nonce
        );

        vm.expectRevert("wSALT: invalid signature");
        wSALT.transferWithAuthorization(alice, bob, 1 ether, validAfter, validBefore, nonce, v, r, s);
    }

    // ============================================================
    // CancelAuthorization Tests
    // ============================================================

    function test_cancelAuthorization() public {
        bytes32 nonce = keccak256("nonce-cancel");

        (uint8 v, bytes32 r, bytes32 s) = _signCancelAuth(alicePk, alice, nonce);

        wSALT.cancelAuthorization(alice, nonce, v, r, s);

        assertTrue(wSALT.authorizationState(alice, nonce));
    }

    function test_cancelAuthorization_prevents_transfer() public {
        vm.prank(alice);
        wSALT.deposit{value: 10 ether}();

        bytes32 nonce = keccak256("nonce-cancel2");

        // Cancel first
        (uint8 cv, bytes32 cr, bytes32 cs) = _signCancelAuth(alicePk, alice, nonce);
        wSALT.cancelAuthorization(alice, nonce, cv, cr, cs);

        // Try to use same nonce for transfer
        (uint8 tv, bytes32 tr, bytes32 ts) = _signTransferAuth(
            alicePk, alice, bob, 1 ether, 0, block.timestamp + 1 hours, nonce
        );

        vm.expectRevert("wSALT: authorization already used");
        wSALT.transferWithAuthorization(alice, bob, 1 ether, 0, block.timestamp + 1 hours, nonce, tv, tr, ts);
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

    function _signCancelAuth(
        uint256 signerPk,
        address authorizer,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            CANCEL_TYPEHASH,
            authorizer, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }
}
