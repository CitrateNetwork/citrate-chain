// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title IClassroomCluster
/// @notice Scoped multi-role RBAC for institutions, classrooms, and devices.
/// @dev Implements invariants from Q-005 ScopedRoleTree.tla:
///   1. RoleHierarchyAcyclic
///   2. SuperAdminRequiresMultiSig
///   3. ImmediateRevocation
///   4. MultiRoleConsistency
///   5. SharedDeviceIsolation
///   6. ClassroomTransferAtomicity
///   7. NoPrivilegeEscalation
///
/// Replaces ClassroomRegistry.sol (versioned migration per LC-8).
/// Supports multiple classrooms per teacher and org-scoped roles.
interface IClassroomCluster {
    // ── Enums ──

    enum OrgRole { None, Admin, IT, SuperAdmin }
    enum ClassroomRole { None, Student, TA, Teacher }

    // ── Events ──

    event OrgRoleGranted(address indexed user, OrgRole role, address indexed grantedBy);
    event OrgRoleRevoked(address indexed user, OrgRole previousRole, address indexed revokedBy);
    event ClassroomCreated(uint256 indexed classroomId, string name, address indexed teacher);
    event ClassroomRoleGranted(uint256 indexed classroomId, address indexed user, ClassroomRole role);
    event ClassroomRoleRevoked(uint256 indexed classroomId, address indexed user, ClassroomRole previousRole);
    event DeviceRegistered(bytes32 indexed deviceCertHash, address indexed user);
    event DeviceRevoked(bytes32 indexed deviceCertHash);
    event StudentTransferred(address indexed student, uint256 indexed fromClassroom, uint256 indexed toClassroom);

    // ── Views ──

    /// @notice Get a user's org-level role.
    function getOrgRole(address user) external view returns (OrgRole);

    /// @notice Get a user's role in a specific classroom.
    function getClassroomRole(uint256 classroomId, address user) external view returns (ClassroomRole);

    /// @notice Check if a user has any active role in the organization.
    function isActiveMember(address user) external view returns (bool);

    /// @notice Check if a device certificate is registered and not revoked.
    function isDeviceActive(bytes32 deviceCertHash) external view returns (bool);

    /// @notice Get the user associated with a device certificate.
    function getDeviceUser(bytes32 deviceCertHash) external view returns (address);

    /// @notice Get classroom details.
    function getClassroomName(uint256 classroomId) external view returns (string memory);

    /// @notice Get the teacher of a classroom.
    function getClassroomTeacher(uint256 classroomId) external view returns (address);

    /// @notice Get student count in a classroom.
    function getStudentCount(uint256 classroomId) external view returns (uint256);

    // ── Org Role Management ──

    /// @notice Grant an org-level role (Admin or SuperAdmin only).
    /// @dev SuperAdmin requires multi-sig via vault approval (invariant 2).
    function grantOrgRole(address user, OrgRole role) external;

    /// @notice Revoke an org-level role.
    /// @dev Invariant: ImmediateRevocation — all derived permissions lost immediately.
    function revokeOrgRole(address user) external;

    // ── Classroom Management ──

    /// @notice Create a new classroom (Admin only).
    function createClassroom(string calldata name, address teacher) external returns (uint256 classroomId);

    /// @notice Grant a classroom role (Teacher of that classroom, or Admin).
    function grantClassroomRole(uint256 classroomId, address user, ClassroomRole role) external;

    /// @notice Revoke a classroom role.
    function revokeClassroomRole(uint256 classroomId, address user) external;

    /// @notice Transfer a student between classrooms atomically.
    /// @dev Invariant: ClassroomTransferAtomicity — no moment with roles in both or neither.
    function transferStudent(address student, uint256 fromClassroom, uint256 toClassroom) external;

    // ── Device Management (IT only) ──

    /// @notice Register a device certificate for a user.
    function registerDevice(bytes32 deviceCertHash, address user) external;

    /// @notice Revoke a device certificate (immediate effect).
    function revokeDevice(bytes32 deviceCertHash) external;

    // ── Migration ──

    /// @notice Claim an existing classroom from the legacy ClassroomRegistry.
    /// @param legacyRegistry Address of the old ClassroomRegistry contract
    /// @param legacyClassroomId The teacher's classroom ID in the old registry
    function claimClassroom(address legacyRegistry, uint256 legacyClassroomId) external returns (uint256 newClassroomId);
}
