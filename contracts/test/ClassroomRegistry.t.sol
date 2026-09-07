// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ClassroomRegistry} from "../src/ClassroomRegistry.sol";

contract ClassroomRegistryTest is Test {
    ClassroomRegistry public cr;

    address public teacher1;
    address public teacher2;
    address public student1;
    address public student2;
    address public student3;
    address public outsider;

    // CHAIN-B-C009 RC-8: enrollWithCode now authenticates on the RAW
    // invite code (secret preimage), not its public hash. The teacher
    // still commits the hash at creation; students present the secret.
    string internal constant CODE1 = "STEM-2026-ALPHA";
    string internal constant CODE2 = "MATH-2026-BETA";
    string internal constant CODE3 = "ART-2026-GAMMA";

    bytes32 public code1Hash;
    bytes32 public code2Hash;
    bytes32 public code3Hash;
    bytes32 public model1Hash;
    bytes32 public model2Hash;
    bytes32 public model3Hash;

    function setUp() public {
        cr = new ClassroomRegistry();

        teacher1 = address(0x1001);
        teacher2 = address(0x1002);
        student1 = address(0x2001);
        student2 = address(0x2002);
        student3 = address(0x2003);
        outsider = address(0xBAD);

        code1Hash = keccak256(abi.encodePacked("STEM-2026-ALPHA"));
        code2Hash = keccak256(abi.encodePacked("MATH-2026-BETA"));
        code3Hash = keccak256(abi.encodePacked("ART-2026-GAMMA"));
        model1Hash = keccak256("STEM-tutor-v2");
        model2Hash = keccak256("essay-reviewer-v1");
        model3Hash = keccak256("math-helper-v3");
    }

    // ============================================================
    // Classroom Creation Tests
    // ============================================================

    function test_create_classroom() public {
        vm.prank(teacher1);
        cr.createClassroom("AP Computer Science", 20, code1Hash);

        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher1);
        assertEq(room.teacher, teacher1);
        assertEq(room.name, "AP Computer Science");
        assertEq(room.maxStudents, 20);
        assertEq(room.studentCount, 0);
        assertTrue(room.exists);
        assertEq(room.createdAt, block.timestamp);

        // Invite code mappings set correctly
        assertEq(cr.activeInviteCode(teacher1), code1Hash);
        assertEq(cr.codeToTeacher(code1Hash), teacher1);
    }

    function test_create_classroom_emits_event() public {
        vm.expectEmit(true, false, false, true);
        emit ClassroomRegistry.ClassroomCreated(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.createClassroom("AP CS", 20, code1Hash);
    }

    function test_create_classroom_empty_name_reverts() public {
        vm.prank(teacher1);
        vm.expectRevert("Empty name");
        cr.createClassroom("", 20, code1Hash);
    }

    function test_create_classroom_zero_max_students_reverts() public {
        vm.prank(teacher1);
        vm.expectRevert("Max students must be >= 1");
        cr.createClassroom("Class", 0, code1Hash);
    }

    function test_create_classroom_duplicate_reverts() public {
        vm.prank(teacher1);
        cr.createClassroom("Class A", 20, code1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Classroom already exists");
        cr.createClassroom("Class B", 30, code2Hash);
    }

    function test_create_classroom_zero_code_hash_reverts() public {
        vm.prank(teacher1);
        vm.expectRevert("Invalid invite code hash");
        cr.createClassroom("Class", 20, bytes32(0));
    }

    function test_create_classroom_duplicate_code_reverts() public {
        vm.prank(teacher1);
        cr.createClassroom("Class A", 20, code1Hash);

        // teacher2 tries to create with the same invite code
        vm.prank(teacher2);
        vm.expectRevert("Invite code already in use");
        cr.createClassroom("Class B", 20, code1Hash);
    }

    // ============================================================
    // Student Enrollment Tests
    // ============================================================

    function test_enroll_with_valid_code() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(student1);
        cr.enrollWithCode(bytes(CODE1));

        assertTrue(cr.isEnrolled(teacher1, student1));
        assertEq(cr.studentTeacher(student1), teacher1);

        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 1);
    }

    function test_enroll_emits_event() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.expectEmit(true, true, false, true);
        emit ClassroomRegistry.StudentEnrolled(teacher1, student1, code1Hash);

        vm.prank(student1);
        cr.enrollWithCode(bytes(CODE1));
    }

    function test_enroll_invalid_code_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(student1);
        vm.expectRevert("Invalid invite code");
        cr.enrollWithCode(bytes("wrong-code"));
    }

    function test_enroll_empty_code_reverts() public {
        vm.prank(student1);
        vm.expectRevert("Empty invite code");
        cr.enrollWithCode(bytes(""));
    }

    function test_teacher_cannot_self_enroll() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Teacher cannot enroll as student");
        cr.enrollWithCode(bytes(CODE1));
    }

    // ============================================================
    // Student Unenrollment Tests
    // ============================================================

    function test_student_unenroll() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _enrollStudent(student1, CODE1);

        vm.prank(student1);
        cr.unenroll();

        assertFalse(cr.isEnrolled(teacher1, student1));
        assertEq(cr.studentTeacher(student1), address(0));

        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 0);
    }

    function test_unenroll_emits_event() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _enrollStudent(student1, CODE1);

        vm.expectEmit(true, true, false, false);
        emit ClassroomRegistry.StudentUnenrolled(teacher1, student1);

        vm.prank(student1);
        cr.unenroll();
    }

    function test_unenroll_not_enrolled_reverts() public {
        vm.prank(student1);
        vm.expectRevert("Not enrolled in any classroom");
        cr.unenroll();
    }

    function test_teacher_remove_student() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _enrollStudent(student1, CODE1);

        vm.prank(teacher1);
        cr.removeStudent(student1);

        assertFalse(cr.isEnrolled(teacher1, student1));
        assertEq(cr.studentTeacher(student1), address(0));

        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 0);
    }

    function test_teacher_remove_student_not_enrolled_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Student not in your classroom");
        cr.removeStudent(student1);
    }

    function test_non_teacher_cannot_remove_student() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _enrollStudent(student1, CODE1);

        vm.prank(outsider);
        vm.expectRevert("Not a teacher with a classroom");
        cr.removeStudent(student1);
    }

    // ============================================================
    // Model Whitelist Tests
    // ============================================================

    function test_whitelist_model() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        assertTrue(cr.whitelistedModels(teacher1, model1Hash));
        assertEq(cr.whitelistCount(teacher1), 1);
    }

    function test_whitelist_model_emits_event() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.expectEmit(true, false, false, true);
        emit ClassroomRegistry.ModelWhitelisted(teacher1, model1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);
    }

    function test_whitelist_duplicate_model_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Model already whitelisted");
        cr.whitelistModel(model1Hash);
    }

    function test_whitelist_zero_hash_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Invalid model hash");
        cr.whitelistModel(bytes32(0));
    }

    function test_remove_model() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        vm.prank(teacher1);
        cr.removeModel(model1Hash);

        assertFalse(cr.whitelistedModels(teacher1, model1Hash));
        assertEq(cr.whitelistCount(teacher1), 0);
    }

    function test_remove_model_emits_event() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        vm.expectEmit(true, false, false, true);
        emit ClassroomRegistry.ModelRemoved(teacher1, model1Hash);

        vm.prank(teacher1);
        cr.removeModel(model1Hash);
    }

    function test_remove_non_whitelisted_model_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Model not whitelisted");
        cr.removeModel(model1Hash);
    }

    function test_non_teacher_cannot_whitelist() public {
        vm.prank(outsider);
        vm.expectRevert("Not a teacher with a classroom");
        cr.whitelistModel(model1Hash);
    }

    function test_non_teacher_cannot_remove_model() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        vm.prank(outsider);
        vm.expectRevert("Not a teacher with a classroom");
        cr.removeModel(model1Hash);
    }

    // ============================================================
    // Invite Code Rotation Tests
    // ============================================================

    function test_rotate_invite_code() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.rotateInviteCode(code2Hash);

        // New code is active
        assertEq(cr.activeInviteCode(teacher1), code2Hash);
        assertEq(cr.codeToTeacher(code2Hash), teacher1);

        // Old code is freed
        assertEq(cr.codeToTeacher(code1Hash), address(0));
    }

    function test_rotate_invite_code_emits_event() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.expectEmit(true, false, false, true);
        emit ClassroomRegistry.InviteCodeRotated(teacher1, code1Hash, code2Hash);

        vm.prank(teacher1);
        cr.rotateInviteCode(code2Hash);
    }

    function test_rotate_to_in_use_code_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _createClassroom(teacher2, "Art History", 15, code2Hash);

        // teacher1 tries to rotate to teacher2's code
        vm.prank(teacher1);
        vm.expectRevert("Invite code already in use");
        cr.rotateInviteCode(code2Hash);
    }

    function test_rotate_zero_code_hash_reverts() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        vm.expectRevert("Invalid invite code hash");
        cr.rotateInviteCode(bytes32(0));
    }

    function test_enroll_after_code_rotation() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.rotateInviteCode(code2Hash);

        // Old code no longer works
        vm.prank(student1);
        vm.expectRevert("Invalid invite code");
        cr.enrollWithCode(bytes(CODE1));

        // New code works
        vm.prank(student1);
        cr.enrollWithCode(bytes(CODE2));

        assertTrue(cr.isEnrolled(teacher1, student1));
        assertEq(cr.studentTeacher(student1), teacher1);
    }

    // ============================================================
    // View Function Tests
    // ============================================================

    function test_can_student_access_model() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _enrollStudent(student1, CODE1);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        // Enrolled student can access whitelisted model
        assertTrue(cr.canStudentAccessModel(student1, model1Hash));

        // Enrolled student cannot access non-whitelisted model
        assertFalse(cr.canStudentAccessModel(student1, model2Hash));

        // Unenrolled student cannot access any model
        assertFalse(cr.canStudentAccessModel(student2, model1Hash));
    }

    function test_classroom_exists_view() public {
        assertFalse(cr.classroomExists(teacher1));

        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        assertTrue(cr.classroomExists(teacher1));
    }

    function test_get_student_teacher_view() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        assertEq(cr.getStudentTeacher(student1), address(0));

        _enrollStudent(student1, CODE1);
        assertEq(cr.getStudentTeacher(student1), teacher1);
    }

    function test_is_model_whitelisted_for() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        assertFalse(cr.isModelWhitelistedFor(teacher1, model1Hash));

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);

        assertTrue(cr.isModelWhitelistedFor(teacher1, model1Hash));
        assertFalse(cr.isModelWhitelistedFor(teacher1, model2Hash));
    }

    // ============================================================
    // TLA+ Invariant Verification Tests
    // ============================================================

    /// @dev INV-2: EnrollmentBounded — no classroom exceeds maxStudents.
    function test_inv2_enrollment_bounded() public {
        _createClassroom(teacher1, "Small Class", 2, code1Hash);

        _enrollStudent(student1, CODE1);
        _enrollStudent(student2, CODE1);

        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 2);
        assertEq(room.maxStudents, 2);

        // Third student should be rejected
        vm.prank(student3);
        vm.expectRevert("Classroom is full");
        cr.enrollWithCode(bytes(CODE1));

        // Count still 2
        room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 2, "INV-2: Count must not exceed maxStudents");
    }

    /// @dev INV-3: StudentInOneClass — each student enrolled in at most one classroom.
    function test_inv3_student_in_one_class() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _createClassroom(teacher2, "Art History", 20, code2Hash);

        _enrollStudent(student1, CODE1);

        // student1 tries to enroll in second classroom
        vm.prank(student1);
        vm.expectRevert("Already enrolled in a classroom");
        cr.enrollWithCode(bytes(CODE2));

        // student1 is still only with teacher1
        assertEq(cr.studentTeacher(student1), teacher1, "INV-3: Student in at most one classroom");
        assertTrue(cr.isEnrolled(teacher1, student1));
        assertFalse(cr.isEnrolled(teacher2, student1));
    }

    /// @dev INV-3 continued: After unenrolling, student can enroll elsewhere.
    function test_inv3_student_can_switch_classrooms() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _createClassroom(teacher2, "Art History", 20, code2Hash);

        _enrollStudent(student1, CODE1);

        // Unenroll from teacher1
        vm.prank(student1);
        cr.unenroll();
        assertEq(cr.studentTeacher(student1), address(0));

        // Enroll with teacher2
        vm.prank(student1);
        cr.enrollWithCode(bytes(CODE2));

        assertEq(cr.studentTeacher(student1), teacher2);
        assertFalse(cr.isEnrolled(teacher1, student1));
        assertTrue(cr.isEnrolled(teacher2, student1));
    }

    /// @dev INV-4: WhitelistOnlyByTeacher — only active classrooms have whitelists.
    ///      Teachers without classrooms cannot whitelist.
    function test_inv4_whitelist_only_by_teacher() public {
        // outsider has no classroom
        vm.prank(outsider);
        vm.expectRevert("Not a teacher with a classroom");
        cr.whitelistModel(model1Hash);

        // After creating classroom, whitelisting works
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);
        assertTrue(cr.whitelistedModels(teacher1, model1Hash), "INV-4: Teacher with classroom can whitelist");
    }

    /// @dev INV-5: InviteCodeUnique — no two teachers share an invite code.
    function test_inv5_invite_code_unique() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        // teacher2 cannot use same code
        vm.prank(teacher2);
        vm.expectRevert("Invite code already in use");
        cr.createClassroom("Art", 20, code1Hash);

        // After teacher1 rotates away from code1, teacher2 can use it
        vm.prank(teacher1);
        cr.rotateInviteCode(code3Hash);

        vm.prank(teacher2);
        cr.createClassroom("Art", 20, code1Hash);

        // Both teachers have different active codes
        assertEq(cr.activeInviteCode(teacher1), code3Hash);
        assertEq(cr.activeInviteCode(teacher2), code1Hash);
        assertTrue(
            cr.activeInviteCode(teacher1) != cr.activeInviteCode(teacher2),
            "INV-5: No two teachers share an invite code"
        );
    }

    /// @dev INV-6: StudentAccessOnlyWhitelisted — students can only use models
    ///      in their teacher's whitelist.
    function test_inv6_student_access_only_whitelisted() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _createClassroom(teacher2, "Art", 20, code2Hash);

        // teacher1 whitelists model1, teacher2 whitelists model2
        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);
        vm.prank(teacher2);
        cr.whitelistModel(model2Hash);

        // student1 enrolls with teacher1
        _enrollStudent(student1, CODE1);

        // student1 can access model1 (teacher1's whitelist) but NOT model2
        assertTrue(
            cr.canStudentAccessModel(student1, model1Hash),
            "INV-6: Student can access teacher's whitelisted model"
        );
        assertFalse(
            cr.canStudentAccessModel(student1, model2Hash),
            "INV-6: Student cannot access another teacher's model"
        );

        // Unenrolled student cannot access anything
        assertFalse(
            cr.canStudentAccessModel(student2, model1Hash),
            "INV-6: Unenrolled student has no access"
        );
    }

    /// @dev INV-7: CodeToTeacherConsistent — reverse index matches forward mapping.
    function test_inv7_code_to_teacher_consistent() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        // Forward: teacher1's code is code1Hash
        bytes32 teacherCode = cr.activeInviteCode(teacher1);
        assertEq(teacherCode, code1Hash);

        // Reverse: code1Hash points to teacher1
        address resolvedTeacher = cr.codeToTeacher(code1Hash);
        assertEq(resolvedTeacher, teacher1, "INV-7: Forward-reverse consistency");

        // After rotation, both directions update
        vm.prank(teacher1);
        cr.rotateInviteCode(code2Hash);

        // Forward: teacher1's code is now code2Hash
        assertEq(cr.activeInviteCode(teacher1), code2Hash);
        // Reverse: code2Hash -> teacher1, code1Hash -> address(0)
        assertEq(cr.codeToTeacher(code2Hash), teacher1, "INV-7: New code -> teacher");
        assertEq(cr.codeToTeacher(code1Hash), address(0), "INV-7: Old code freed");
    }

    /// @dev INV-8: NoClassroomNoEnrollments — teachers without classrooms have no students.
    function test_inv8_no_classroom_no_enrollments() public {
        // teacher2 has no classroom
        assertFalse(cr.classroomExists(teacher2));

        // Cannot enroll students in a non-existent classroom
        // (there is no valid invite code pointing to teacher2)
        assertEq(cr.codeToTeacher(code2Hash), address(0));

        // student1 cannot join teacher2
        vm.prank(student1);
        vm.expectRevert("Invalid invite code");
        cr.enrollWithCode(bytes(CODE2));

        // Teacher2's enrollment count is 0
        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher2);
        assertEq(room.studentCount, 0, "INV-8: No classroom => zero enrollments");
    }

    // ============================================================
    // Multi-Classroom Isolation Tests
    // ============================================================

    function test_two_classrooms_independent() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);
        _createClassroom(teacher2, "Art History", 15, code2Hash);

        _enrollStudent(student1, CODE1);
        _enrollStudent(student2, CODE2);

        // Each student is in exactly one classroom
        assertEq(cr.studentTeacher(student1), teacher1);
        assertEq(cr.studentTeacher(student2), teacher2);

        // Enrollment counts are independent
        ClassroomRegistry.Classroom memory room1 = cr.getClassroom(teacher1);
        ClassroomRegistry.Classroom memory room2 = cr.getClassroom(teacher2);
        assertEq(room1.studentCount, 1);
        assertEq(room2.studentCount, 1);

        // Whitelists are independent
        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);
        vm.prank(teacher2);
        cr.whitelistModel(model2Hash);

        assertTrue(cr.canStudentAccessModel(student1, model1Hash));
        assertFalse(cr.canStudentAccessModel(student1, model2Hash));
        assertFalse(cr.canStudentAccessModel(student2, model1Hash));
        assertTrue(cr.canStudentAccessModel(student2, model2Hash));
    }

    // ============================================================
    // Full Lifecycle Test
    // ============================================================

    function test_full_lifecycle() public {
        // 1. Teacher creates classroom
        _createClassroom(teacher1, "AP CS", 3, code1Hash);

        // 2. Teacher whitelists models
        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);
        vm.prank(teacher1);
        cr.whitelistModel(model2Hash);

        // 3. Students enroll
        _enrollStudent(student1, CODE1);
        _enrollStudent(student2, CODE1);

        ClassroomRegistry.Classroom memory room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 2);

        // 4. Students can access whitelisted models
        assertTrue(cr.canStudentAccessModel(student1, model1Hash));
        assertTrue(cr.canStudentAccessModel(student2, model2Hash));
        assertFalse(cr.canStudentAccessModel(student1, model3Hash));

        // 5. Teacher removes a model
        vm.prank(teacher1);
        cr.removeModel(model2Hash);
        assertFalse(cr.canStudentAccessModel(student1, model2Hash));

        // 6. Teacher rotates invite code
        vm.prank(teacher1);
        cr.rotateInviteCode(code3Hash);

        // 7. New student enrolls with new code
        _enrollStudent(student3, CODE3);
        room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 3);

        // 8. Classroom is now full (maxStudents=3)
        address student4 = address(0x54);
        vm.prank(student4);
        vm.expectRevert("Classroom is full");
        cr.enrollWithCode(bytes(CODE3));

        // 9. Teacher removes a student, freeing a slot
        vm.prank(teacher1);
        cr.removeStudent(student2);
        room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 2);

        // 10. New student can now enroll
        vm.prank(student4);
        cr.enrollWithCode(bytes(CODE3));
        room = cr.getClassroom(teacher1);
        assertEq(room.studentCount, 3);

        // 11. Student unenrolls themselves
        vm.prank(student1);
        cr.unenroll();
        assertEq(cr.studentTeacher(student1), address(0));
        assertFalse(cr.canStudentAccessModel(student1, model1Hash));
    }

    // ============================================================
    // Edge Case: Multiple Whitelists
    // ============================================================

    function test_multiple_models_whitelisted() public {
        _createClassroom(teacher1, "AP CS", 20, code1Hash);

        vm.prank(teacher1);
        cr.whitelistModel(model1Hash);
        vm.prank(teacher1);
        cr.whitelistModel(model2Hash);
        vm.prank(teacher1);
        cr.whitelistModel(model3Hash);

        assertEq(cr.whitelistCount(teacher1), 3);

        _enrollStudent(student1, CODE1);
        assertTrue(cr.canStudentAccessModel(student1, model1Hash));
        assertTrue(cr.canStudentAccessModel(student1, model2Hash));
        assertTrue(cr.canStudentAccessModel(student1, model3Hash));

        // Remove middle model
        vm.prank(teacher1);
        cr.removeModel(model2Hash);
        assertEq(cr.whitelistCount(teacher1), 2);
        assertTrue(cr.canStudentAccessModel(student1, model1Hash));
        assertFalse(cr.canStudentAccessModel(student1, model2Hash));
        assertTrue(cr.canStudentAccessModel(student1, model3Hash));
    }

    // ============================================================
    // Edge Case: Max Students = 1
    // ============================================================

    function test_classroom_with_one_student_max() public {
        _createClassroom(teacher1, "Tutorial", 1, code1Hash);

        _enrollStudent(student1, CODE1);

        // INV-2: Second student rejected
        vm.prank(student2);
        vm.expectRevert("Classroom is full");
        cr.enrollWithCode(bytes(CODE1));

        // After first student leaves, another can join
        vm.prank(student1);
        cr.unenroll();

        _enrollStudent(student2, CODE1);
        assertTrue(cr.isEnrolled(teacher1, student2));
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _createClassroom(
        address teacher,
        string memory name,
        uint256 maxStudents,
        bytes32 codeHash
    ) internal {
        vm.prank(teacher);
        cr.createClassroom(name, maxStudents, codeHash);
    }

    function _enrollStudent(address student, string memory rawCode) internal {
        vm.prank(student);
        cr.enrollWithCode(bytes(rawCode));
    }
}
