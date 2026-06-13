// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

contract KYCRegistryTest is Test {
    KYCRegistry internal kyc;
    address internal updater = address(0xDD);
    address internal user = address(0xBEEF);

    function setUp() public {
        kyc = new KYCRegistry(updater);
    }

    function test_constructorGrantsUpdater() public view {
        assertTrue(kyc.hasRole(kyc.KYC_UPDATER_ROLE(), updater));
        assertTrue(kyc.hasRole(kyc.KYC_UPDATER_ROLE(), address(this)));
        assertTrue(kyc.hasRole(kyc.DEFAULT_ADMIN_ROLE(), address(this)));
    }

    function test_setVerified_thenIsVerified() public {
        assertFalse(kyc.isVerified(user));
        vm.prank(updater);
        kyc.setVerified(user);
        assertTrue(kyc.isVerified(user));
    }

    function test_revoke_clearsVerification() public {
        vm.prank(updater);
        kyc.setVerified(user);
        vm.prank(updater);
        kyc.revoke(user);
        assertFalse(kyc.isVerified(user));
    }

    function test_setVerified_revertsForNonUpdater() public {
        vm.prank(user);
        vm.expectRevert("AccessControl: account missing role");
        kyc.setVerified(user);
    }

    function test_setVerified_revertsZeroAddress() public {
        vm.prank(updater);
        vm.expectRevert("KYC: zero address");
        kyc.setVerified(address(0));
    }

    function test_setVerified_idempotent() public {
        vm.startPrank(updater);
        kyc.setVerified(user);
        kyc.setVerified(user); // no revert, no double event semantics
        vm.stopPrank();
        assertTrue(kyc.isVerified(user));
    }

    // ───────────────────────── PIN-S4 identity binding ─────────────────────

    function test_setVerified_bindsProvisionalSelfIdentity() public {
        vm.prank(updater);
        kyc.setVerified(user);
        // Provisional: each address is its own distinct identity until linked.
        assertEq(kyc.identityOf(user), keccak256(abi.encode("PIN-self", user)));
        address other = address(0xC0FFEE);
        vm.prank(updater);
        kyc.setVerified(other);
        assertTrue(kyc.identityOf(user) != kyc.identityOf(other), "self-identities distinct");
    }

    function test_setVerifiedWithIdentity_linksAddresses() public {
        bytes32 sub = keccak256("sub:alice");
        address w1 = address(0x1111);
        address w2 = address(0x2222);
        vm.startPrank(updater);
        kyc.setVerifiedWithIdentity(w1, sub);
        kyc.setVerifiedWithIdentity(w2, sub); // same person, two wallets
        vm.stopPrank();
        assertTrue(kyc.isVerified(w1) && kyc.isVerified(w2));
        assertEq(kyc.identityOf(w1), sub);
        assertEq(kyc.identityOf(w2), kyc.identityOf(w1), "linked addresses share one identity");
    }

    function test_setVerifiedWithIdentity_revertsZeroIdentity() public {
        vm.prank(updater);
        vm.expectRevert("KYC: zero identity");
        kyc.setVerifiedWithIdentity(user, bytes32(0));
    }

    function test_realIdentity_notOverwrittenBySelfDefault() public {
        bytes32 sub = keccak256("sub:bob");
        vm.startPrank(updater);
        kyc.setVerifiedWithIdentity(user, sub);
        kyc.setVerified(user); // must NOT clobber the real identity with self
        vm.stopPrank();
        assertEq(kyc.identityOf(user), sub);
    }
}
