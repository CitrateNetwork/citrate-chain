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
}
