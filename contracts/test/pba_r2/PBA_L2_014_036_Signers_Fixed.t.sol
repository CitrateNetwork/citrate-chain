// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TinaWorkpaperRegistry} from "../../src/defense_prime/TinaWorkpaperRegistry.sol";
import {CrossOrgEnvelope} from "../../src/defense_prime/CrossOrgEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";

/// Mutation hardening (PBA-L2-014 / -036) through the fixed API.
contract PBA_L2_014_036_Fixed is Test {
    function _one(bytes32 x) internal pure returns (bytes32[] memory a) {
        a = new bytes32[](1);
        a[0] = x;
    }

    function test_L2_014_signatureAfterExpiryRefused() public {
        TinaWorkpaperRegistry tina = new TinaWorkpaperRegistry(address(0x60));
        address rec = address(0xEC1);
        address cfo = address(0xCF0);
        vm.prank(address(0x60));
        tina.setRecorder(rec, true);
        bytes32 wp = keccak256("wp");
        bytes32 me = QuorumIdentity.subjectKey(cfo);
        uint256 deadline = vm.getBlockNumber() + 5;
        vm.prank(rec);
        tina.draftWorkpaper(wp, keccak256("po"), bytes32(0), bytes32(0), keccak256("t"), 1, deadline, _one(me));
        vm.roll(deadline + 1);
        vm.prank(cfo);
        vm.expectRevert(
            abi.encodeWithSelector(TinaWorkpaperRegistry.WorkpaperLapsed.selector, wp, deadline, deadline + 1)
        );
        tina.addSignature(wp, me);
    }

    function test_L2_014_signerMustBeRequired() public {
        TinaWorkpaperRegistry tina = new TinaWorkpaperRegistry(address(0x60));
        address rec = address(0xEC1);
        vm.prank(address(0x60));
        tina.setRecorder(rec, true);
        bytes32 wp = keccak256("wp");
        vm.prank(rec);
        tina.draftWorkpaper(
            wp, keccak256("po"), bytes32(0), bytes32(0), keccak256("t"), 1, vm.getBlockNumber() + 5,
            _one(QuorumIdentity.subjectKey(address(0xCF0)))
        );
        address stranger = address(0x5A);
        bytes32 sk = QuorumIdentity.subjectKey(stranger);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(TinaWorkpaperRegistry.NotRequiredSigner.selector, wp, sk));
        tina.addSignature(wp, sk);
    }

    function test_L2_036_drafterCannotAcceptItsOwnEnvelope() public {
        address gov = address(0x60);
        CrossOrgEnvelope c = new CrossOrgEnvelope(gov);
        address recA = address(0xAAA1);
        address sa = address(0x5AA);
        bytes32 orgA = keccak256("orgA");
        vm.startPrank(gov);
        c.setRecorder(recA, true);
        c.setOrgRecorder(orgA, recA, true);
        c.setOrgRecorder(orgA, sa, true);
        vm.stopPrank();
        uint8[] memory th = new uint8[](1);
        th[0] = 1;
        bytes32[][] memory sig = new bytes32[][](1);
        sig[0] = _one(QuorumIdentity.subjectKey(sa));
        vm.prank(recA);
        c.draft(keccak256("e"), bytes32(uint256(1)), bytes32(uint256(2)), _one(orgA), th, sig, 0, keccak256("t"), 0);
        vm.prank(sa);
        c.sign(keccak256("e"), orgA, QuorumIdentity.subjectKey(sa));
        vm.prank(recA);
        c.markDelivered(keccak256("e"));
        vm.prank(recA);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgEnvelope.NotCounterpartyOrgRecorder.selector, keccak256("e"), recA));
        c.accept(keccak256("e"));
    }
}
