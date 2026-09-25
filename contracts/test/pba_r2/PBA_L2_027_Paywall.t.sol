// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {X402Paywall} from "../../src/X402Paywall.sol";
import {WrappedSALT} from "../../src/WrappedSALT.sol";

/// PBA-L2-027: the payer's authorization cannot be redeemed by anyone but the
/// paywall, so a front-run can no longer take payment without granting access.
contract PBA_L2_027_PaywallRegression is Test {
    bytes32 constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    function test_L2_027_frontRunCannotPayWithoutAccess() public {
        WrappedSALT w = new WrappedSALT();
        address provider = makeAddr("provider");
        X402Paywall pw = new X402Paywall(address(w), 1 ether, provider);
        (address user, uint256 pk) = makeAddrAndKey("user");
        vm.deal(user, 5 ether);
        vm.prank(user);
        w.deposit{value: 5 ether}();

        bytes32 resourceId = keccak256("res");
        bytes32 salt = keccak256("s");
        bytes32 nonce = keccak256(abi.encode(resourceId, salt));
        uint256 vb = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(RECEIVE_TYPEHASH, user, address(pw), 1 ether, uint256(0), vb, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", w.DOMAIN_SEPARATOR(), sh)));

        // Mempool observer replays the signature directly on wSALT, both ways.
        vm.startPrank(makeAddr("griefer"));
        try w.receiveWithAuthorization(user, address(pw), 1 ether, 0, vb, nonce, v, r, s) {} catch {}
        try w.transferWithAuthorization(user, address(pw), 1 ether, 0, vb, nonce, v, r, s) {} catch {}
        vm.stopPrank();
        assertEq(w.balanceOf(user), 5 ether, "front-run moved nothing");

        pw.verifyAndGrant(resourceId, user, 1 ether, 0, vb, nonce, salt, v, r, s);
        assertTrue(pw.hasAccess(user, resourceId), "user paid AND got access");
        assertEq(w.balanceOf(provider), 1 ether, "provider paid via the paywall");
        assertEq(w.balanceOf(address(pw)), 0, "paywall forwards everything");
    }
}
