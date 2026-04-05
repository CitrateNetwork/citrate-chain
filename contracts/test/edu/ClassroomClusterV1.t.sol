// SPDX-License-Identifier: BUSL-1.1
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
        cluster.createClassroom("Biology 101", teacher1);
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

    function test_revoked_user_cannot_get_new_role() public {
        vm.prank(admin);
        cluster.revokeOrgRole(itAdmin);

        vm.prank(admin);
        vm.expectRevert(); // UserRevoked
        cluster.grantOrgRole(itAdmin, IClassroomCluster.OrgRole.IT);
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
        cluster.createClassroom("Denied", address(0x77));
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
        cluster.createClassroom("Chemistry 201", teacher2);

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
        uint256 classroomB = cluster.createClassroom("Chemistry 201", teacher2);

        // Add student to classroom 0
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);
        assertEq(cluster.getStudentCount(0), 1);

        // Transfer student from 0 to classroomB
        vm.prank(teacher1);
        cluster.transferStudent(student1, 0, classroomB);

        // Atomic: removed from 0, added to B
        assertEq(uint256(cluster.getClassroomRole(0, student1)), uint256(IClassroomCluster.ClassroomRole.None));
        assertEq(uint256(cluster.getClassroomRole(classroomB, student1)), uint256(IClassroomCluster.ClassroomRole.Student));
        assertEq(cluster.getStudentCount(0), 0);
        assertEq(cluster.getStudentCount(classroomB), 1);
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
        cluster.createClassroom("Hacked", student1);

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
        uint256 chem = cluster.createClassroom("Chemistry 301", teacher1);

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
        cluster.createClassroom("Hacked", student1);

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
        cluster.createClassroom("Denied", address(0x77));
    }

    // Transfer student who isn't in source classroom
    function test_adversarial_invalid_transfer() public {
        vm.prank(admin);
        uint256 classroomB = cluster.createClassroom("Chem", teacher2);

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
        uint256 id = cluster.createClassroom(name, teacher2);
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
}
