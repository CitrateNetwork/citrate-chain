// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TinaWorkpaperRegistry} from "../../src/defense_prime/TinaWorkpaperRegistry.sol";
import {CrossOrgEnvelope} from "../../src/defense_prime/CrossOrgEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";

/// PBA-L2-014 / PBA-L2-036 regressions (pre-bounty audit 2026-09-24): lane PoCs
/// `test_F4_04_tina_single_recorder_forges_threshold` and
/// `test_F4_05_crossorg_recorder_rejects_in_other_orgs_name`, inverted.
/// Uses call shapes valid before and after the fix (low-level draft with the
/// new trailing arg, falling back to the old shape) so the revert check can
/// replay it on the vulnerable source.
contract PBA_L2_014_036_Regression is Test {
    bytes32 constant TENANT = keccak256("tenant-A");
    address gov = address(0x60);

    function _one(bytes32 x) internal pure returns (bytes32[] memory a) {
        a = new bytes32[](1);
        a[0] = x;
    }

    /// F4-04 inverted: one recorder names CFO/DCAA/CO; the workpaper must not
    /// become Signed.
    function test_L2_014_singleRecorder_cannotForgeTinaThreshold() public {
        TinaWorkpaperRegistry tina = new TinaWorkpaperRegistry(gov);
        address recorder = address(0xEC1);
        vm.prank(gov);
        tina.setRecorder(recorder, true);
        bytes32 wp = keccak256("wp");
        bytes32[] memory req = new bytes32[](3);
        req[0] = keccak256("CFO");
        req[1] = keccak256("DCAA");
        req[2] = keccak256("ContractingOfficer");

        vm.startPrank(recorder);
        (bool ok,) = address(tina).call(
            abi.encodeWithSignature(
                "draftWorkpaper(bytes32,bytes32,bytes32,bytes32,bytes32,uint16,uint256,bytes32[])",
                wp, keccak256("po"), bytes32(0), bytes32(0), TENANT, uint16(3), block.number + 10, req
            )
        );
        if (!ok) {
            (ok,) = address(tina).call(
                abi.encodeWithSignature(
                    "draftWorkpaper(bytes32,bytes32,bytes32,bytes32,bytes32,uint16,uint256)",
                    wp, keccak256("po"), bytes32(0), bytes32(0), TENANT, uint16(3), block.number + 10
                )
            );
        }
        require(ok, "draft");
        try tina.addSignature(wp, req[0]) {} catch {}
        try tina.addSignature(wp, req[1]) {} catch {}
        try tina.addSignature(wp, req[2]) {} catch {}
        vm.stopPrank();
        try tina.signWorkpaper(wp) {} catch {}
        assertTrue(tina.getWorkpaper(wp).state != 2, "one recorder must not satisfy a 3-signer workpaper");
        assertEq(tina.getWorkpaper(wp).sig_count, 0, "the recorder cannot sign as anyone");
    }

    /// F4-05 inverted: org A's recorder rejects "in org B's name"; the record
    /// must not attribute a rejection to org B.
    function test_L2_036_orgARecorder_cannotRejectAsOrgB() public {
        CrossOrgEnvelope c = new CrossOrgEnvelope(gov);
        address recA = address(0xAAA1);
        bytes32 orgA = keccak256("orgA");
        bytes32 orgB = keccak256("orgB");
        vm.startPrank(gov);
        c.setRecorder(recA, true);
        c.setOrgRecorder(orgA, recA, true);
        vm.stopPrank();

        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = orgA;
        orgs[1] = orgB;
        uint8[] memory th = new uint8[](2);
        th[0] = 1;
        th[1] = 1;
        bytes32[][] memory sig = new bytes32[][](2);
        sig[0] = _one(keccak256("alice"));
        sig[1] = _one(keccak256("bob"));
        vm.prank(recA);
        c.draft(keccak256("e"), bytes32(uint256(1)), bytes32(uint256(2)), orgs, th, sig, 0, TENANT, 0);

        vm.prank(recA);
        try c.reject(keccak256("e"), orgB, "org B says no (it did not)") {} catch {}
        assertTrue(c.getEnvelope(keccak256("e")).rejected_by_org != orgB, "rejection falsely attributed to org B");
    }

    /// F4-05 (within one org): one org-recorder key names both of its org's
    /// required signers; the org's 2-of-2 must not be met.
    function test_L2_036_oneOrgKey_cannotSatisfyOrgMofN() public {
        CrossOrgEnvelope c = new CrossOrgEnvelope(gov);
        address recB = address(0xBBB1);
        bytes32 orgB = keccak256("orgB");
        vm.startPrank(gov);
        c.setRecorder(recB, true);
        c.setOrgRecorder(orgB, recB, true);
        vm.stopPrank();
        bytes32[] memory orgs = _one(orgB);
        uint8[] memory th = new uint8[](1);
        th[0] = 2;
        bytes32[][] memory sig = new bytes32[][](1);
        sig[0] = new bytes32[](2);
        sig[0][0] = keccak256("bob");
        sig[0][1] = keccak256("carol");
        vm.startPrank(recB);
        c.draft(keccak256("e2"), bytes32(uint256(1)), bytes32(uint256(2)), orgs, th, sig, 0, TENANT, 0);
        try c.sign(keccak256("e2"), orgB, sig[0][0]) {} catch {}
        try c.sign(keccak256("e2"), orgB, sig[0][1]) {} catch {}
        vm.stopPrank();
        assertFalse(c.isOrgThresholdMet(keccak256("e2"), orgB), "one key must not meet a 2-of-2");
    }
}
