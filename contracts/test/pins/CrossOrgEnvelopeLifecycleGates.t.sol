// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {CrossOrgEnvelope} from "../../src/defense_prime/CrossOrgEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";

/// Lifecycle transitions of a CrossOrgEnvelope after signing: delivery is the
/// drafting recorder's act, not any global recorder's.
contract CrossOrgEnvelopeLifecycleGatesTest is Test {
    CrossOrgEnvelope internal c;
    address internal constant GOV = address(0x60);
    address internal constant REC_A = address(0xAAA1);
    address internal constant REC_OTHER = address(0xCCC1);
    address internal constant SA = address(0x5AA);
    bytes32 internal constant ORG_A = keccak256("orgA");
    bytes32 internal constant EID = keccak256("e");

    function _one(bytes32 x) internal pure returns (bytes32[] memory a) {
        a = new bytes32[](1);
        a[0] = x;
    }

    function setUp() public {
        c = new CrossOrgEnvelope(GOV);
        vm.startPrank(GOV);
        c.setRecorder(REC_A, true);
        c.setRecorder(REC_OTHER, true);
        c.setOrgRecorder(ORG_A, REC_A, true);
        c.setOrgRecorder(ORG_A, SA, true);
        vm.stopPrank();
        uint8[] memory th = new uint8[](1);
        th[0] = 1;
        bytes32[][] memory sig = new bytes32[][](1);
        sig[0] = _one(QuorumIdentity.subjectKey(SA));
        vm.prank(REC_A);
        c.draft(EID, bytes32(uint256(1)), bytes32(uint256(2)), _one(ORG_A), th, sig, 0, keccak256("t"), 0);
        vm.prank(SA);
        c.sign(EID, ORG_A, QuorumIdentity.subjectKey(SA));
    }

    function test_onlyTheDrafterMarksDelivered() public {
        vm.prank(REC_OTHER);
        vm.expectRevert(abi.encodeWithSelector(CrossOrgEnvelope.NotDrafter.selector, EID, REC_OTHER));
        c.markDelivered(EID);

        vm.prank(REC_A);
        c.markDelivered(EID);
        assertEq(c.getEnvelope(EID).state, 4, "drafter delivers");
    }
}
