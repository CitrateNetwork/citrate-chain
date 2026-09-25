// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ClassroomRegistry} from "../../src/ClassroomRegistry.sol";

/// @title RM-Q · CHAIN-B-C009 — public invite HASH used as the credential
/// @notice RED→GREEN tripwire. Before the C009 fix, `enrollWithCode` took the
///         invite-code HASH as its credential — and that hash is public chain
///         state, so any observer could enrol. The C009 fix switched to the raw
///         code, which PBA-L2-010 showed is replayable from calldata. Since
///         PBA-L2-010 the credential is a signature by the invite secret over
///         (teacher, msg.sender, commitment): neither the public hash nor any
///         value seen on chain lets an observer enrol.
contract RmQ_C009 is Test {
    ClassroomRegistry internal cr;
    address internal teacher = address(0x7EAC);
    address internal attacker = address(0xBAD);
    address internal student = address(0x57D);

    uint256 internal constant SECRET_PK = 0x57E3202653C2E7;
    bytes32 internal codeHash;

    function setUp() public {
        cr = new ClassroomRegistry();
        codeHash = keccak256(abi.encodePacked(vm.addr(SECRET_PK)));
        vm.prank(teacher);
        cr.createClassroom("AP CS", 20, codeHash);
    }

    function _sig(address who) internal view returns (bytes memory) {
        bytes32 d = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", cr.enrollmentDigest(teacher, who, codeHash))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SECRET_PK, d);
        return abi.encodePacked(r, s, v);
    }

    /// RED: the attacker knows the PUBLIC commitment and even the public key
    /// address, but not the secret; a self-made proof does not authenticate.
    function test_C009_public_hash_is_not_the_credential() public {
        assertEq(cr.codeToTeacher(codeHash), teacher);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, keccak256("x"));
        vm.prank(attacker);
        vm.expectRevert("Invalid invite proof");
        cr.enrollWithInvite(vm.addr(SECRET_PK), abi.encodePacked(r, s, v));
        assertFalse(cr.isEnrolled(teacher, attacker));
    }

    /// GREEN: a student who possesses the secret enrols.
    function test_C009_secret_holder_enrolls() public {
        bytes memory sig = _sig(student);
        vm.prank(student);
        cr.enrollWithInvite(vm.addr(SECRET_PK), sig);
        assertTrue(cr.isEnrolled(teacher, student));
        assertEq(cr.studentTeacher(student), teacher);
    }
}
