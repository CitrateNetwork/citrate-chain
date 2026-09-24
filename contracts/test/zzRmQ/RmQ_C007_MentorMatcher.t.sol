// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MentorMatcher} from "../../src/MentorMatcher.sol";

/// @title RM-Q · CHAIN-B-C007 — permissionless assignMentees
/// @notice RED→GREEN tripwire. Before the fix, `assignMentees` had no
///         access control and read both accuracy operands from calldata,
///         so any outsider could forge pairings for any mentor, saturate
///         a mentor to capacity and front-run the honest matcher. After
///         the fix it is gated to governance or an authorized matcher.
contract RmQ_C007 is Test {
    MentorMatcher internal mm;
    address internal governance = address(0x6007);
    address internal attacker = address(0xBAD);
    address internal matcher = address(0x777);

    address internal victimMentor = address(0x1E7);
    uint32 internal constant Q16_ONE = 65536;

    function q16(uint256 cents) internal pure returns (uint32) {
        return uint32((cents * Q16_ONE) / 100);
    }

    function setUp() public {
        mm = new MentorMatcher(governance);
    }

    /// RED: an outsider forges pairings and saturates a mentor. The
    /// expectRevert is the assertion that fails pre-fix (the call
    /// SUCCEEDS pre-fix and the mentor's load is corrupted).
    function test_C007_outsider_cannot_forge_pairings() public {
        address[] memory mentees = new address[](1);
        mentees[0] = address(0xB0B);
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(MentorMatcher.NotAuthorizedMatcher.selector, attacker)
        );
        mm.assignMentees(victimMentor, mentees, q16(85), accs, keccak256("finance"));

        // GREEN: no pairing was created by the outsider.
        assertEq(mm.mentorLoad(victimMentor), 0);
        assertFalse(mm.isPaired(victimMentor, address(0xB0B)));
    }

    /// The authorized matcher path still commits pairings.
    function test_C007_authorized_matcher_can_assign() public {
        vm.prank(governance);
        mm.setMatcher(matcher, true);

        address[] memory mentees = new address[](1);
        mentees[0] = address(0xB0B);
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);

        vm.prank(matcher);
        mm.assignMentees(victimMentor, mentees, q16(85), accs, keccak256("finance"));
        assertEq(mm.mentorLoad(victimMentor), 1);
        assertTrue(mm.isPaired(victimMentor, address(0xB0B)));
    }
}
