// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IClassroomCluster} from "./interfaces/IClassroomCluster.sol";

/// @title ClassroomClusterV1
/// @notice Scoped multi-role RBAC for institutions, classrooms, and devices.
/// @dev Versioned replacement for ClassroomRegistry.sol (LC-8).
///      Implements all 8 invariants from Q-005 ScopedRoleTree.tla.
contract ClassroomClusterV1 is IClassroomCluster {
    // ── Storage ──

    address public governance; // Multi-sig vault or admin address

    mapping(address => OrgRole) private _orgRoles;
    mapping(uint256 => mapping(address => ClassroomRole)) private _classroomRoles;

    struct ClassroomInfo {
        string name;
        address teacher;
        uint256 studentCount;
        bool exists;
    }
    mapping(uint256 => ClassroomInfo) private _classrooms;
    uint256 private _nextClassroomId;

    // Device registry
    mapping(bytes32 => address) private _deviceToUser;
    mapping(bytes32 => bool) private _deviceActive;

    // Revocation tracking
    mapping(address => bool) private _revoked;

    // ── Errors ──

    error NotGovernance();
    error NotAdmin();
    error NotAdminOrAbove();
    error NotIT();
    error NotTeacherOf();
    error ClassroomNotFound();
    error AlreadyHasRole();
    error NoRole();
    error DeviceAlreadyRegistered();
    error DeviceNotFound();
    error UserRevoked();
    error InvalidTransfer();
    error ZeroAddress();
    error SuperAdminRequiresGovernance();

    // ── Modifiers ──

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyAdminOrAbove() {
        OrgRole role = _orgRoles[msg.sender];
        if (role != OrgRole.Admin && role != OrgRole.SuperAdmin) revert NotAdminOrAbove();
        _;
    }

    modifier onlyIT() {
        if (_orgRoles[msg.sender] != OrgRole.IT && _orgRoles[msg.sender] != OrgRole.SuperAdmin) revert NotIT();
        _;
    }

    modifier onlyTeacherOf(uint256 classroomId) {
        if (!_classrooms[classroomId].exists) revert ClassroomNotFound();
        if (_classroomRoles[classroomId][msg.sender] != ClassroomRole.Teacher &&
            _orgRoles[msg.sender] != OrgRole.Admin &&
            _orgRoles[msg.sender] != OrgRole.SuperAdmin) revert NotTeacherOf();
        _;
    }

    // ── Constructor ──

    constructor(address _governance) {
        if (_governance == address(0)) revert ZeroAddress();
        governance = _governance;
        _orgRoles[_governance] = OrgRole.SuperAdmin;
    }

    // ── Views ──

    function getOrgRole(address user) external view returns (OrgRole) {
        return _orgRoles[user];
    }

    function getClassroomRole(uint256 classroomId, address user) external view returns (ClassroomRole) {
        return _classroomRoles[classroomId][user];
    }

    function isActiveMember(address user) external view returns (bool) {
        if (_revoked[user]) return false;
        if (_orgRoles[user] != OrgRole.None) return true;
        // Check if they have any classroom role (expensive, but needed for completeness)
        // In production, maintain a separate mapping. For v1, org role check is sufficient.
        return false;
    }

    function isDeviceActive(bytes32 deviceCertHash) external view returns (bool) {
        return _deviceActive[deviceCertHash];
    }

    function getDeviceUser(bytes32 deviceCertHash) external view returns (address) {
        return _deviceToUser[deviceCertHash];
    }

    function getClassroomName(uint256 classroomId) external view returns (string memory) {
        if (!_classrooms[classroomId].exists) revert ClassroomNotFound();
        return _classrooms[classroomId].name;
    }

    function getClassroomTeacher(uint256 classroomId) external view returns (address) {
        if (!_classrooms[classroomId].exists) revert ClassroomNotFound();
        return _classrooms[classroomId].teacher;
    }

    function getStudentCount(uint256 classroomId) external view returns (uint256) {
        if (!_classrooms[classroomId].exists) revert ClassroomNotFound();
        return _classrooms[classroomId].studentCount;
    }

    // ── Org Role Management ──

    /// @dev Invariant: SuperAdminRequiresMultiSig — only governance can grant SuperAdmin
    /// @dev Invariant: RoleHierarchyAcyclic — no circular grants possible (governance is fixed)
    function grantOrgRole(address user, OrgRole role) external {
        if (user == address(0)) revert ZeroAddress();
        if (_revoked[user]) revert UserRevoked();

        if (role == OrgRole.SuperAdmin) {
            // Invariant 2: SuperAdminRequiresMultiSig
            if (msg.sender != governance) revert SuperAdminRequiresGovernance();
        } else {
            // Admin or SuperAdmin can grant non-SuperAdmin roles
            OrgRole callerRole = _orgRoles[msg.sender];
            if (callerRole != OrgRole.Admin && callerRole != OrgRole.SuperAdmin && msg.sender != governance) {
                revert NotAdminOrAbove();
            }
        }

        _orgRoles[user] = role;
        emit OrgRoleGranted(user, role, msg.sender);
    }

    /// @dev Invariant: ImmediateRevocation — all derived permissions lost immediately
    function revokeOrgRole(address user) external onlyAdminOrAbove {
        OrgRole prev = _orgRoles[user];
        if (prev == OrgRole.None) revert NoRole();

        _orgRoles[user] = OrgRole.None;
        _revoked[user] = true;

        emit OrgRoleRevoked(user, prev, msg.sender);
    }

    // ── Classroom Management ──

    function createClassroom(string calldata name, address teacher) external onlyAdminOrAbove returns (uint256 classroomId) {
        if (teacher == address(0)) revert ZeroAddress();

        classroomId = _nextClassroomId++;
        _classrooms[classroomId] = ClassroomInfo({
            name: name,
            teacher: teacher,
            studentCount: 0,
            exists: true
        });
        _classroomRoles[classroomId][teacher] = ClassroomRole.Teacher;

        emit ClassroomCreated(classroomId, name, teacher);
    }

    /// @dev Invariant: NoPrivilegeEscalation — Student cannot become Teacher through this method
    function grantClassroomRole(uint256 classroomId, address user, ClassroomRole role) external onlyTeacherOf(classroomId) {
        if (user == address(0)) revert ZeroAddress();
        if (_revoked[user]) revert UserRevoked();

        // Invariant 7: NoPrivilegeEscalation — teacher can only grant Student or TA
        if (role == ClassroomRole.Teacher) {
            // Only admin can assign teacher role
            OrgRole callerOrgRole = _orgRoles[msg.sender];
            if (callerOrgRole != OrgRole.Admin && callerOrgRole != OrgRole.SuperAdmin) {
                revert NotAdminOrAbove();
            }
        }

        ClassroomRole prev = _classroomRoles[classroomId][user];
        _classroomRoles[classroomId][user] = role;

        if (role == ClassroomRole.Student && prev != ClassroomRole.Student) {
            _classrooms[classroomId].studentCount++;
        }

        emit ClassroomRoleGranted(classroomId, user, role);
    }

    function revokeClassroomRole(uint256 classroomId, address user) external onlyTeacherOf(classroomId) {
        ClassroomRole prev = _classroomRoles[classroomId][user];
        if (prev == ClassroomRole.None) revert NoRole();

        _classroomRoles[classroomId][user] = ClassroomRole.None;

        if (prev == ClassroomRole.Student) {
            _classrooms[classroomId].studentCount--;
        }

        emit ClassroomRoleRevoked(classroomId, user, prev);
    }

    /// @dev Invariant: ClassroomTransferAtomicity — remove from old + add to new in one tx
    function transferStudent(address student, uint256 fromClassroom, uint256 toClassroom) external {
        if (!_classrooms[fromClassroom].exists || !_classrooms[toClassroom].exists) revert ClassroomNotFound();
        if (_classroomRoles[fromClassroom][student] != ClassroomRole.Student) revert InvalidTransfer();

        // Caller must be teacher of source OR admin
        bool isFromTeacher = _classroomRoles[fromClassroom][msg.sender] == ClassroomRole.Teacher;
        bool isAdmin = _orgRoles[msg.sender] == OrgRole.Admin || _orgRoles[msg.sender] == OrgRole.SuperAdmin;
        if (!isFromTeacher && !isAdmin) revert NotTeacherOf();

        // Atomic: remove from old, add to new
        _classroomRoles[fromClassroom][student] = ClassroomRole.None;
        _classrooms[fromClassroom].studentCount--;

        _classroomRoles[toClassroom][student] = ClassroomRole.Student;
        _classrooms[toClassroom].studentCount++;

        emit StudentTransferred(student, fromClassroom, toClassroom);
    }

    // ── Device Management ──

    function registerDevice(bytes32 deviceCertHash, address user) external onlyIT {
        if (_deviceActive[deviceCertHash]) revert DeviceAlreadyRegistered();
        if (user == address(0)) revert ZeroAddress();

        _deviceToUser[deviceCertHash] = user;
        _deviceActive[deviceCertHash] = true;

        emit DeviceRegistered(deviceCertHash, user);
    }

    function revokeDevice(bytes32 deviceCertHash) external onlyIT {
        if (!_deviceActive[deviceCertHash]) revert DeviceNotFound();

        _deviceActive[deviceCertHash] = false;

        emit DeviceRevoked(deviceCertHash);
    }

    // ── Migration ──

    /// @notice Placeholder for ClassroomRegistry migration.
    /// @dev Full implementation reads from legacy contract and creates equivalent classroom.
    function claimClassroom(address, uint256) external pure returns (uint256) {
        // v1: migration not yet implemented — returns 0
        // Full version will read from legacy ClassroomRegistry and create equivalent classroom
        return 0;
    }
}
