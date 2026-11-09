// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";

/// The verifier's provisional caller may hand the marketplace role to the
/// deployed marketplace exactly once, and only before using it.
contract ComputeVerifierHandOverTest is Test {
    address deployer = makeAddr("deployer");
    address gov = makeAddr("gov");
    address treasury = makeAddr("treasury");
    ComputeVerifier v;
    ComputeMarketplace cm;

    function setUp() public {
        v = new ComputeVerifier(deployer, gov);
        cm = new ComputeMarketplace(address(v), treasury, gov);
    }

    function test_handOver_bindsAndLocks() public {
        assertFalse(v.marketplaceLocked());
        vm.prank(deployer);
        v.handOverMarketplace(address(cm));
        assertEq(v.marketplace(), address(cm));
        assertTrue(v.marketplaceLocked());
    }

    function test_handOver_onlyByTheCurrentHolder() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(bytes("ComputeVerifier: caller is not marketplace"));
        v.handOverMarketplace(address(cm));
        vm.prank(gov); // governance uses setMarketplace, not the hand-over
        vm.expectRevert(bytes("ComputeVerifier: caller is not marketplace"));
        v.handOverMarketplace(address(cm));
    }

    function test_handOver_onlyOnce() public {
        vm.prank(deployer);
        v.handOverMarketplace(address(cm));
        ComputeMarketplace cm2 = new ComputeMarketplace(address(v), treasury, gov);
        vm.prank(address(cm));
        vm.expectRevert(bytes("ComputeVerifier: marketplace locked"));
        v.handOverMarketplace(address(cm2));
    }

    function test_handOver_refusedOnceTheRoleWasUsed() public {
        vm.prank(deployer);
        v.configureJob(7, 1 ether, ComputeVerifier.VerificationTier.Commitment);
        assertTrue(v.marketplaceLocked(), "using the role locks it");
        vm.prank(deployer);
        vm.expectRevert(bytes("ComputeVerifier: marketplace locked"));
        v.handOverMarketplace(address(cm));
    }

    function test_handOver_toAnAccountWithoutCode_isRefused() public {
        vm.prank(deployer);
        vm.expectRevert(bytes("ComputeVerifier: marketplace has no code"));
        v.handOverMarketplace(makeAddr("eoa"));
    }

    function test_handOver_toItself_isRefused() public {
        vm.prank(deployer);
        vm.expectRevert(bytes("ComputeVerifier: same marketplace"));
        v.handOverMarketplace(deployer);
    }

    function test_governanceSet_locksTheHandOver() public {
        vm.prank(gov);
        v.setMarketplace(address(cm));
        assertTrue(v.marketplaceLocked());
        vm.prank(address(cm));
        vm.expectRevert(bytes("ComputeVerifier: marketplace locked"));
        v.handOverMarketplace(address(this));
    }

    function test_governanceCanStillRewireAfterTheHandOver() public {
        vm.prank(deployer);
        v.handOverMarketplace(address(cm));
        address next = address(new ComputeMarketplace(address(v), treasury, gov));
        vm.prank(gov);
        v.setMarketplace(next);
        assertEq(v.marketplace(), next);
    }
}
