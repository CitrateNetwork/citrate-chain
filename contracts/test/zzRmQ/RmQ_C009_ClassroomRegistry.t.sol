// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ClassroomRegistry} from "../../src/ClassroomRegistry.sol";

/// @title RM-Q · CHAIN-B-C009 — public invite HASH used as the credential
/// @notice RED→GREEN tripwire. Before the fix, `enrollWithCode` took the
///         invite-code HASH as its credential — and that hash is public
///         chain state (public mappings + `ClassroomCreated` event), so
///         any observer could enrol. After the fix the function takes the
///         RAW code (secret preimage) and hashes it internally.
contract RmQ_C009 is Test {
    ClassroomRegistry internal cr;
    address internal teacher = address(0x7EAC);
    address internal attacker = address(0xBAD);
    address internal student = address(0x57D);

    string internal constant SECRET = "STEM-2026-SECRET";
    bytes32 internal codeHash;

    function setUp() public {
        cr = new ClassroomRegistry();
        codeHash = keccak256(bytes(SECRET));
        vm.prank(teacher);
        cr.createClassroom("AP CS", 20, codeHash);
    }

    /// RED: the attacker knows only the PUBLIC hash (from the getter /
    /// event), not the secret. Presenting the hash bytes no longer
    /// authenticates. Pre-fix, calling enrollWithCode(codeHash) SUCCEEDED
    /// (the hash WAS the credential); post-fix it reverts because
    /// keccak256(hashBytes) != codeHash.
    function test_C009_public_hash_is_not_the_credential() public {
        // The attacker reads the public commitment...
        assertEq(cr.codeToTeacher(codeHash), teacher);
        // ...and tries to present it directly.
        vm.prank(attacker);
        vm.expectRevert("Invalid invite code");
        cr.enrollWithCode(bytes(abi.encodePacked(codeHash)));
        assertFalse(cr.isEnrolled(teacher, attacker));
    }

    /// GREEN: a student who actually possesses the raw secret enrols.
    function test_C009_secret_preimage_enrolls() public {
        vm.prank(student);
        cr.enrollWithCode(bytes(SECRET));
        assertTrue(cr.isEnrolled(teacher, student));
        assertEq(cr.studentTeacher(student), teacher);
    }
}
