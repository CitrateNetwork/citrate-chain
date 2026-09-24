// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ClassroomClusterV1} from "../../src/edu/ClassroomClusterV1.sol";
import {IClassroomCluster} from "../../src/edu/interfaces/IClassroomCluster.sol";

contract ClassroomClusterV1Test is Test {
    ClassroomClusterV1 cluster;

    address governance = address(0x1000);
    address admin = address(0x1);
    address itAdmin = address(0x2);
    address teacher1 = address(0x3);
    address teacher2 = address(0x4);
    address student1 = address(0x10);
    address student2 = address(0x11);
    address student3 = address(0x12);
    address ta1 = address(0x20);
    address nobody = address(0xBEEF);

    bytes32 device1 = keccak256("device-001");
    bytes32 device2 = keccak256("device-002");
    bytes32 device3 = keccak256("device-003");

    function setUp() public {
        cluster = new ClassroomClusterV1(governance);

        // Set up org roles
        vm.startPrank(governance);
        cluster.grantOrgRole(admin, IClassroomCluster.OrgRole.Admin);
        cluster.grantOrgRole(itAdmin, IClassroomCluster.OrgRole.IT);
        vm.stopPrank();

        // Create a classroom
        vm.prank(admin);
        cluster.createClassroom("Biology 101", teacher1, 0, 0, "");
    }

    // ===================================================================
    // CONSTRUCTOR + SETUP
    // ===================================================================

    function test_constructor_sets_governance() public view {
        assertEq(uint256(cluster.getOrgRole(governance)), uint256(IClassroomCluster.OrgRole.SuperAdmin));
    }

    function test_setup_admin_role() public view {
        assertEq(uint256(cluster.getOrgRole(admin)), uint256(IClassroomCluster.OrgRole.Admin));
    }

    function test_setup_it_role() public view {
        assertEq(uint256(cluster.getOrgRole(itAdmin)), uint256(IClassroomCluster.OrgRole.IT));
    }

    function test_setup_classroom_created() public view {
        assertEq(cluster.getClassroomName(0), "Biology 101");
        assertEq(cluster.getClassroomTeacher(0), teacher1);
    }

    function test_teacher_has_classroom_role() public view {
        assertEq(uint256(cluster.getClassroomRole(0, teacher1)), uint256(IClassroomCluster.ClassroomRole.Teacher));
    }

    // ===================================================================
    // ORG ROLE MANAGEMENT
    // ===================================================================

    function test_admin_can_grant_admin() public {
        vm.prank(admin);
        cluster.grantOrgRole(address(0x99), IClassroomCluster.OrgRole.Admin);
        assertEq(uint256(cluster.getOrgRole(address(0x99))), uint256(IClassroomCluster.OrgRole.Admin));
    }

    function test_admin_can_grant_it() public {
        vm.prank(admin);
        cluster.grantOrgRole(address(0x99), IClassroomCluster.OrgRole.IT);
        assertEq(uint256(cluster.getOrgRole(address(0x99))), uint256(IClassroomCluster.OrgRole.IT));
    }

    function test_non_admin_cannot_grant_roles() public {
        vm.prank(nobody);
        vm.expectRevert();
        cluster.grantOrgRole(address(0x99), IClassroomCluster.OrgRole.Admin);
    }

    function test_revoke_org_role() public {
        vm.prank(admin);
        cluster.revokeOrgRole(itAdmin);
        assertEq(uint256(cluster.getOrgRole(itAdmin)), uint256(IClassroomCluster.OrgRole.None));
    }

    function test_revoked_user_can_get_new_role_if_not_expelled() public {
        // With the new AccountStatus state machine, revokeOrgRole sets Inactive (reversible),
        // not permanent revocation. Admin can re-enroll the user.
        vm.prank(admin);
        cluster.revokeOrgRole(itAdmin);

        // Status is now Inactive — re-grant is allowed (not expelled)
        vm.prank(admin);
        cluster.grantOrgRole(itAdmin, IClassroomCluster.OrgRole.IT);
        assertEq(uint256(cluster.getOrgRole(itAdmin)), uint256(IClassroomCluster.OrgRole.IT));
    }

    // ===================================================================
    // INVARIANT TESTS — Q-005 TLA+ MAPPING
    // ===================================================================

    // Invariant 1: RoleHierarchyAcyclic
    function test_invariant_hierarchy_acyclic() public {
        // Governance grants admin, admin cannot grant governance/SuperAdmin back
        vm.prank(admin);
        vm.expectRevert(); // SuperAdminRequiresGovernance
        cluster.grantOrgRole(nobody, IClassroomCluster.OrgRole.SuperAdmin);
    }

    // Invariant 2: SuperAdminRequiresMultiSig
    function test_invariant_superadmin_requires_governance() public {
        // Only governance can grant SuperAdmin
        vm.prank(governance);
        cluster.grantOrgRole(address(0x99), IClassroomCluster.OrgRole.SuperAdmin);
        assertEq(uint256(cluster.getOrgRole(address(0x99))), uint256(IClassroomCluster.OrgRole.SuperAdmin));

        // Admin cannot grant SuperAdmin
        vm.prank(admin);
        vm.expectRevert();
        cluster.grantOrgRole(address(0x88), IClassroomCluster.OrgRole.SuperAdmin);
    }

    // Invariant 3: ImmediateRevocation
    function test_invariant_immediate_revocation() public {
        // Give teacher1 an admin role too
        vm.prank(admin);
        cluster.grantOrgRole(teacher1, IClassroomCluster.OrgRole.Admin);

        // Revoke — should lose all org permissions immediately
        vm.prank(governance);
        cluster.revokeOrgRole(teacher1);
        assertEq(uint256(cluster.getOrgRole(teacher1)), uint256(IClassroomCluster.OrgRole.None));

        // Cannot act as admin anymore
        vm.prank(teacher1);
        vm.expectRevert();
        cluster.createClassroom("Denied", address(0x77), 0, 0, "");
    }

    // Invariant 4: MultiRoleConsistency
    function test_invariant_multi_role_consistency() public {
        // teacher1 is Teacher in classroom 0
        // Give teacher1 Admin org role too
        vm.prank(admin);
        cluster.grantOrgRole(teacher1, IClassroomCluster.OrgRole.Admin);

        // teacher1 should have both: OrgRole=Admin AND ClassroomRole=Teacher
        assertEq(uint256(cluster.getOrgRole(teacher1)), uint256(IClassroomCluster.OrgRole.Admin));
        assertEq(uint256(cluster.getClassroomRole(0, teacher1)), uint256(IClassroomCluster.ClassroomRole.Teacher));

        // teacher1 can now create classrooms (Admin privilege) AND manage students (Teacher privilege)
        vm.prank(teacher1);
        cluster.createClassroom("Chemistry 201", teacher2, 0, 0, "");

        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);
    }

    // Invariant 5: SharedDeviceIsolation
    function test_invariant_shared_device_isolation() public {
        // Register device for student1
        vm.prank(itAdmin);
        cluster.registerDevice(device1, student1);

        assertEq(cluster.getDeviceUser(device1), student1);
        assertTrue(cluster.isDeviceActive(device1));

        // Revoke device — user data should be inaccessible via device
        vm.prank(itAdmin);
        cluster.revokeDevice(device1);
        assertFalse(cluster.isDeviceActive(device1));
    }

    // Invariant 6: ClassroomTransferAtomicity
    function test_invariant_transfer_atomicity() public {
        // Create second classroom
        vm.prank(admin);
        uint256 classroomB = cluster.createClassroom("Chemistry 201", teacher2, 0, 0, "");

        // Add student to classroom 0
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);
        assertEq(cluster.getStudentCount(0), 1);

        // Transfer student from 0 to classroomB.
        // FWA-C3-14: a cross-classroom transfer where the caller does not
        // teach BOTH ends is now an admin-only operation (teacher1 teaches
        // classroom 0 but not classroomB, which teacher2 teaches). Use the
        // org admin — the legitimate cross-classroom authority — so the
        // atomicity invariant is still exercised on a permitted transfer.
        vm.prank(admin);
        cluster.transferStudent(student1, 0, classroomB);

        // Atomic: removed from 0, added to B
        assertEq(uint256(cluster.getClassroomRole(0, student1)), uint256(IClassroomCluster.ClassroomRole.None));
        assertEq(uint256(cluster.getClassroomRole(classroomB, student1)), uint256(IClassroomCluster.ClassroomRole.Student));
        assertEq(cluster.getStudentCount(0), 0);
        assertEq(cluster.getStudentCount(classroomB), 1);
    }

    // FWA-C3-14: cross-classroom roster injection.
    // Pre-fix: a teacher of the SOURCE classroom could inject a student into
    // ANY destination classroom they don't control. Post-fix: a teacher must
    // control BOTH ends (or be an admin).
    function test_C3_14_teacher_cannot_inject_into_foreign_classroom() public {
        // teacher2 owns classroomB; teacher1 owns classroom 0.
        vm.prank(admin);
        uint256 classroomB = cluster.createClassroom("Chemistry 201", teacher2, 0, 0, "");

        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        // teacher1 (teacher of source only) tries to push the student into
        // teacher2's classroom → must revert.
        vm.prank(teacher1);
        vm.expectRevert(); // NotTeacherOf
        cluster.transferStudent(student1, 0, classroomB);

        // Student was NOT injected into classroomB.
        assertEq(
            uint256(cluster.getClassroomRole(classroomB, student1)),
            uint256(IClassroomCluster.ClassroomRole.None),
            "no cross-classroom injection"
        );
        assertEq(cluster.getStudentCount(classroomB), 0);
    }

    function test_C3_14_teacher_of_both_ends_can_transfer() public {
        // teacher1 teaches BOTH classrooms.
        vm.prank(admin);
        uint256 classroomB = cluster.createClassroom("Chemistry 201", teacher1, 0, 0, "");

        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        vm.prank(teacher1);
        cluster.transferStudent(student1, 0, classroomB);
        assertEq(
            uint256(cluster.getClassroomRole(classroomB, student1)),
            uint256(IClassroomCluster.ClassroomRole.Student),
            "teacher of both ends may transfer"
        );
    }

    // Invariant 7: NoPrivilegeEscalation
    function test_invariant_no_privilege_escalation() public {
        // Add student
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        // Student cannot grant themselves Teacher role
        vm.prank(student1);
        vm.expectRevert();
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Teacher);

        // Student cannot create classrooms
        vm.prank(student1);
        vm.expectRevert();
        cluster.createClassroom("Hacked", student1, 0, 0, "");

        // Student cannot grant org roles
        vm.prank(student1);
        vm.expectRevert();
        cluster.grantOrgRole(student1, IClassroomCluster.OrgRole.Admin);
    }

    // ===================================================================
    // CLASSROOM OPERATIONS
    // ===================================================================

    function test_add_student_to_classroom() public {
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        assertEq(uint256(cluster.getClassroomRole(0, student1)), uint256(IClassroomCluster.ClassroomRole.Student));
        assertEq(cluster.getStudentCount(0), 1);
    }

    function test_add_ta_to_classroom() public {
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, ta1, IClassroomCluster.ClassroomRole.TA);

        assertEq(uint256(cluster.getClassroomRole(0, ta1)), uint256(IClassroomCluster.ClassroomRole.TA));
    }

    function test_remove_student_from_classroom() public {
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        vm.prank(teacher1);
        cluster.revokeClassroomRole(0, student1);

        assertEq(uint256(cluster.getClassroomRole(0, student1)), uint256(IClassroomCluster.ClassroomRole.None));
        assertEq(cluster.getStudentCount(0), 0);
    }

    function test_teacher_cannot_assign_teacher_role() public {
        // Teacher trying to make another user a Teacher — requires Admin
        vm.prank(teacher1);
        vm.expectRevert(); // NotAdminOrAbove
        cluster.grantClassroomRole(0, nobody, IClassroomCluster.ClassroomRole.Teacher);
    }

    function test_admin_can_assign_teacher_role() public {
        vm.prank(admin);
        cluster.grantClassroomRole(0, teacher2, IClassroomCluster.ClassroomRole.Teacher);
        assertEq(uint256(cluster.getClassroomRole(0, teacher2)), uint256(IClassroomCluster.ClassroomRole.Teacher));
    }

    function test_multi_classroom_per_teacher() public {
        // teacher1 teaches Bio 101 (classroom 0)
        // Create another classroom for same teacher
        vm.prank(admin);
        uint256 chem = cluster.createClassroom("Chemistry 301", teacher1, 0, 0, "");

        // teacher1 is Teacher in both
        assertEq(uint256(cluster.getClassroomRole(0, teacher1)), uint256(IClassroomCluster.ClassroomRole.Teacher));
        assertEq(uint256(cluster.getClassroomRole(chem, teacher1)), uint256(IClassroomCluster.ClassroomRole.Teacher));
    }

    // ===================================================================
    // DEVICE MANAGEMENT
    // ===================================================================

    function test_register_device() public {
        vm.prank(itAdmin);
        cluster.registerDevice(device1, student1);

        assertTrue(cluster.isDeviceActive(device1));
        assertEq(cluster.getDeviceUser(device1), student1);
    }

    function test_revoke_device() public {
        vm.prank(itAdmin);
        cluster.registerDevice(device1, student1);

        vm.prank(itAdmin);
        cluster.revokeDevice(device1);

        assertFalse(cluster.isDeviceActive(device1));
    }

    function test_non_it_cannot_register_device() public {
        vm.prank(teacher1);
        vm.expectRevert();
        cluster.registerDevice(device1, student1);
    }

    function test_duplicate_device_reverts() public {
        vm.prank(itAdmin);
        cluster.registerDevice(device1, student1);

        vm.prank(itAdmin);
        vm.expectRevert(); // DeviceAlreadyRegistered
        cluster.registerDevice(device1, student2);
    }

    // ===================================================================
    // ADVERSARIAL TESTS
    // ===================================================================

    // Student tries to become SuperAdmin through role chain
    function test_adversarial_student_to_superadmin() public {
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        // Student tries every escalation path
        vm.startPrank(student1);

        vm.expectRevert();
        cluster.grantOrgRole(student1, IClassroomCluster.OrgRole.SuperAdmin);

        vm.expectRevert();
        cluster.grantOrgRole(student1, IClassroomCluster.OrgRole.Admin);

        vm.expectRevert();
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Teacher);

        vm.expectRevert();
        cluster.createClassroom("Hacked", student1, 0, 0, "");

        vm.stopPrank();
    }

    // Teacher tries to self-promote to Admin
    function test_adversarial_teacher_self_promote() public {
        vm.prank(teacher1);
        vm.expectRevert();
        cluster.grantOrgRole(teacher1, IClassroomCluster.OrgRole.Admin);
    }

    // Revoked user tries to act
    function test_adversarial_revoked_user_acts() public {
        vm.prank(admin);
        cluster.grantOrgRole(teacher2, IClassroomCluster.OrgRole.Admin);

        // Revoke
        vm.prank(governance);
        cluster.revokeOrgRole(teacher2);

        // Try to act as admin
        vm.prank(teacher2);
        vm.expectRevert();
        cluster.createClassroom("Denied", address(0x77), 0, 0, "");
    }

    // Transfer student who isn't in source classroom
    function test_adversarial_invalid_transfer() public {
        vm.prank(admin);
        uint256 classroomB = cluster.createClassroom("Chem", teacher2, 0, 0, "");

        // student1 is NOT in classroom 0
        vm.prank(teacher1);
        vm.expectRevert(); // InvalidTransfer
        cluster.transferStudent(student1, 0, classroomB);
    }

    // ===================================================================
    // FUZZ TESTS
    // ===================================================================

    function testFuzz_create_classroom(string calldata name) public {
        vm.assume(bytes(name).length > 0 && bytes(name).length < 256);
        vm.prank(admin);
        uint256 id = cluster.createClassroom(name, teacher2, 0, 0, "");
        assertEq(cluster.getClassroomName(id), name);
    }

    function testFuzz_grant_revoke_student(address student) public {
        vm.assume(student != address(0) && student != teacher1 && student != admin && student != governance);

        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student, IClassroomCluster.ClassroomRole.Student);
        assertEq(uint256(cluster.getClassroomRole(0, student)), uint256(IClassroomCluster.ClassroomRole.Student));

        vm.prank(teacher1);
        cluster.revokeClassroomRole(0, student);
        assertEq(uint256(cluster.getClassroomRole(0, student)), uint256(IClassroomCluster.ClassroomRole.None));
    }

    // ===================================================================
    // EDGE CASES
    // ===================================================================

    function test_nonexistent_classroom_reverts() public {
        vm.expectRevert(); // ClassroomNotFound
        cluster.getClassroomName(999);
    }

    function test_revoke_nonexistent_role_reverts() public {
        vm.prank(teacher1);
        vm.expectRevert(); // NoRole
        cluster.revokeClassroomRole(0, nobody);
    }

    function test_grant_zero_address_reverts() public {
        vm.prank(teacher1);
        vm.expectRevert(); // ZeroAddress
        cluster.grantClassroomRole(0, address(0), IClassroomCluster.ClassroomRole.Student);
    }

    // ===================================================================
    // ACCOUNT STATUS TESTS — FERPA-aligned state machine
    // ===================================================================

    /// @dev New user (fresh address) has default Active status (zero value = Active).
    function test_status_default_is_active() public {
        // Grant a fresh address a role; default status is Active (enum value 0)
        address freshUser = address(0xAAAA);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);
        assertEq(
            uint256(cluster.getAccountStatus(freshUser)),
            uint256(IClassroomCluster.AccountStatus.Active)
        );
    }

    /// @dev IT can set a user from Active to Inactive (non-disciplinary).
    function test_it_can_set_inactive() public {
        address freshUser = address(0xBBBB);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Active));

        vm.prank(itAdmin);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Inactive);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Inactive));
    }

    /// @dev IT cannot set Suspended (disciplinary); reverts with InsufficientPrivilege.
    function test_it_cannot_set_suspended() public {
        address freshUser = address(0xCCCC);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(itAdmin);
        vm.expectRevert(ClassroomClusterV1.InsufficientPrivilege.selector);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Suspended);
    }

    /// @dev Admin can set Active→Suspended (disciplinary action).
    function test_admin_can_set_suspended() public {
        address freshUser = address(0xDDDD);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(admin);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Suspended);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Suspended));
    }

    /// @dev Admin can reinstate a Suspended user back to Active.
    function test_admin_can_reinstate_from_suspended() public {
        address freshUser = address(0xEEEE);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(admin);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Suspended);

        vm.prank(admin);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Active);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Active));
    }

    /// @dev SuperAdmin (governance) can set Expelled on a user.
    function test_superadmin_can_expel() public {
        address freshUser = address(0xFF00);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(governance);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Expelled);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Expelled));
    }

    /// @dev Expelled user cannot be granted an org role (AccountExpelled).
    function test_expelled_user_cannot_be_granted_role() public {
        address freshUser = address(0xFF11);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(governance);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Expelled);

        vm.prank(admin);
        vm.expectRevert(ClassroomClusterV1.AccountExpelled.selector);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);
    }

    /// @dev Expelled status is permanent — setAccountStatus reverts with AccountExpelled.
    function test_expelled_user_cannot_change_status() public {
        address freshUser = address(0xFF22);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(governance);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Expelled);

        // Even governance cannot change an expelled status
        vm.prank(governance);
        vm.expectRevert(ClassroomClusterV1.AccountExpelled.selector);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Active);
    }

    /// @dev Graduated status is permanent — setAccountStatus reverts with InvalidStatusTransition.
    function test_graduated_user_is_final() public {
        address freshUser = address(0xFF33);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(governance);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Graduated);

        vm.prank(governance);
        vm.expectRevert(ClassroomClusterV1.InvalidStatusTransition.selector);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Active);
    }

    /// @dev Inactive user can be reactivated by IT or above.
    function test_inactive_user_can_be_reactivated() public {
        address freshUser = address(0xFF44);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        vm.prank(itAdmin);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Inactive);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Inactive));

        vm.prank(itAdmin);
        cluster.setAccountStatus(freshUser, IClassroomCluster.AccountStatus.Active);
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Active));
    }

    /// @dev revokeOrgRole sets Inactive (not permanent), so grantOrgRole succeeds afterward.
    function test_revoke_org_role_sets_inactive_not_permanent() public {
        address freshUser = address(0xFF55);
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);

        // Revoke — should set to Inactive
        vm.prank(admin);
        cluster.revokeOrgRole(freshUser);

        assertEq(uint256(cluster.getOrgRole(freshUser)), uint256(IClassroomCluster.OrgRole.None));
        assertEq(uint256(cluster.getAccountStatus(freshUser)), uint256(IClassroomCluster.AccountStatus.Inactive));

        // Re-enroll — should work because Inactive is reversible
        vm.prank(admin);
        cluster.grantOrgRole(freshUser, IClassroomCluster.OrgRole.IT);
        assertEq(uint256(cluster.getOrgRole(freshUser)), uint256(IClassroomCluster.OrgRole.IT));
    }

    /// @dev Classroom created with grade=5, year=2026, section="A" stores the metadata correctly.
    function test_classroom_includes_grade_and_year() public {
        vm.prank(admin);
        uint256 cid = cluster.createClassroom("5th Grade Math", teacher2, 5, 2026, "A");

        (
            string memory name,
            address teacher,
            uint256 studentCount,
            uint8 gradeLevel,
            uint16 academicYear,
            string memory section
        ) = cluster.getClassroomInfo(cid);

        assertEq(name, "5th Grade Math");
        assertEq(teacher, teacher2);
        assertEq(studentCount, 0);
        assertEq(gradeLevel, 5);
        assertEq(academicYear, 2026);
        assertEq(section, "A");
    }

    /// @dev gradeLevel=13 (college/university) is accepted without revert.
    function test_college_grade_level_above_12() public {
        vm.prank(admin);
        uint256 cid = cluster.createClassroom("Intro to CS", teacher2, 13, 2026, "Honors");

        (,,,uint8 gradeLevel,,) = cluster.getClassroomInfo(cid);
        assertEq(gradeLevel, 13);
    }

    /// @dev Bulk: set 5 users to Inactive, then reactivate them all.
    function test_bulk_status_operations() public {
        address[5] memory users = [
            address(0xA001),
            address(0xA002),
            address(0xA003),
            address(0xA004),
            address(0xA005)
        ];

        // Grant roles to all users
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(admin);
            cluster.grantOrgRole(users[i], IClassroomCluster.OrgRole.IT);
        }

        // Set all to Inactive
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(itAdmin);
            cluster.setAccountStatus(users[i], IClassroomCluster.AccountStatus.Inactive);
            assertEq(
                uint256(cluster.getAccountStatus(users[i])),
                uint256(IClassroomCluster.AccountStatus.Inactive)
            );
        }

        // Reactivate all
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(itAdmin);
            cluster.setAccountStatus(users[i], IClassroomCluster.AccountStatus.Active);
            assertEq(
                uint256(cluster.getAccountStatus(users[i])),
                uint256(IClassroomCluster.AccountStatus.Active)
            );
        }
    }

    // ===================================================================
    // RM-L / WP-L1.1 — two-step governance transfer
    // ===================================================================

    function test_l1_1_transferGovernance_is_two_step() public {
        address newGov = address(0xABCD);

        // Step 1: current governance proposes.
        vm.prank(governance);
        cluster.transferGovernance(newGov);

        // Pre-accept: pending is set, but governance() unchanged.
        assertEq(cluster.pendingGovernance(), newGov);
        assertEq(cluster.governance(), governance);

        // Step 2: pending account accepts.
        vm.prank(newGov);
        cluster.acceptGovernance();

        // Post-accept: governance moved, pending cleared, role
        // transferred.
        assertEq(cluster.governance(), newGov);
        assertEq(cluster.pendingGovernance(), address(0));
        assertEq(
            uint256(cluster.getOrgRole(newGov)),
            uint256(IClassroomCluster.OrgRole.SuperAdmin),
            "L1.1: new governance becomes SuperAdmin"
        );
        // Old governance demoted to None — no implicit lingering authority.
        assertEq(
            uint256(cluster.getOrgRole(governance)),
            uint256(IClassroomCluster.OrgRole.None),
            "L1.1: old governance demoted on accept"
        );
    }

    function test_l1_1_only_pending_can_accept() public {
        address newGov = address(0xABCD);
        address other = address(0xDEAD);

        vm.prank(governance);
        cluster.transferGovernance(newGov);

        // Random non-pending address cannot accept.
        vm.prank(other);
        vm.expectRevert(ClassroomClusterV1.NotPendingGovernance.selector);
        cluster.acceptGovernance();

        assertEq(cluster.governance(), governance);
    }

    function test_l1_1_cancel_governance_transfer() public {
        address newGov = address(0xABCD);

        vm.prank(governance);
        cluster.transferGovernance(newGov);
        assertEq(cluster.pendingGovernance(), newGov);

        vm.prank(governance);
        cluster.cancelGovernanceTransfer();
        assertEq(cluster.pendingGovernance(), address(0));

        // Now the pending address cannot accept.
        vm.prank(newGov);
        vm.expectRevert(ClassroomClusterV1.NotPendingGovernance.selector);
        cluster.acceptGovernance();
    }

    function test_l1_1_only_governance_can_propose() public {
        vm.prank(admin);
        vm.expectRevert(ClassroomClusterV1.NotGovernance.selector);
        cluster.transferGovernance(address(0xABCD));
    }

    function test_l1_1_only_governance_can_cancel() public {
        vm.prank(governance);
        cluster.transferGovernance(address(0xABCD));

        vm.prank(admin);
        vm.expectRevert(ClassroomClusterV1.NotGovernance.selector);
        cluster.cancelGovernanceTransfer();
    }

    function test_l1_1_cannotTransferToZero() public {
        vm.prank(governance);
        vm.expectRevert(ClassroomClusterV1.ZeroAddress.selector);
        cluster.transferGovernance(address(0));
    }

    function test_l1_1_cancel_with_no_pending_reverts() public {
        vm.prank(governance);
        vm.expectRevert(ClassroomClusterV1.NoPendingTransfer.selector);
        cluster.cancelGovernanceTransfer();
    }

    function test_l1_1_old_governance_loses_authority_post_accept() public {
        address newGov = address(0xABCD);
        vm.prank(governance);
        cluster.transferGovernance(newGov);
        vm.prank(newGov);
        cluster.acceptGovernance();

        // The old governance address should no longer be able to
        // grant SuperAdmin (which requires the governance modifier).
        vm.prank(governance);
        vm.expectRevert(ClassroomClusterV1.SuperAdminRequiresGovernance.selector);
        cluster.grantOrgRole(address(0xCAFE), IClassroomCluster.OrgRole.SuperAdmin);

        // The new governance can.
        vm.prank(newGov);
        cluster.grantOrgRole(address(0xCAFE), IClassroomCluster.OrgRole.SuperAdmin);
        assertEq(
            uint256(cluster.getOrgRole(address(0xCAFE))),
            uint256(IClassroomCluster.OrgRole.SuperAdmin)
        );
    }
}
