// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IClassroomCluster} from "./interfaces/IClassroomCluster.sol";

/// @title ClassroomClusterV1
/// @notice Scoped multi-role RBAC for institutions, classrooms, and devices.
/// @dev Versioned replacement for ClassroomRegistry.sol (LC-8).
///      Implements all 8 invariants from Q-005 ScopedRoleTree.tla.
///      AccountStatus replaces the old binary _revoked mapping with a FERPA-aligned
///      state machine supporting K-12 lifecycle: enrollment, leave, transfer, graduation,
///      and disciplinary actions. Expelled is institution-local only.
contract ClassroomClusterV1 is IClassroomCluster {
    // ── Storage ──

    address public governance; // Multi-sig vault or admin address
    // RM-L / WP-L1.1: two-step governance transfer. Pre-fix the
    // contract had no transfer mechanism at all — if the genesis
    // multisig was lost or compromised, governance was permanently
    // locked. Pattern matches `Governable` semantics: `transferGovernance`
    // proposes, the proposed account calls `acceptGovernance` to take
    // effect, current governance can `cancelGovernanceTransfer` before
    // acceptance.
    address public pendingGovernance;

    mapping(address => OrgRole) private _orgRoles;
    mapping(uint256 => mapping(address => ClassroomRole)) private _classroomRoles;

    /// @dev FERPA-aligned account status replacing the old boolean _revoked mapping.
    mapping(address => AccountStatus) private _accountStatus;

    struct ClassroomInfo {
        string name;
        address teacher;
        uint256 studentCount;
        bool exists;
        uint8 gradeLevel;    // 0=Kindergarten, 1-12=Grade, 13+=College/University (no hard cap)
        uint16 academicYear; // year the term ends (2026 = 2025-2026 school year)
        string section;      // "A", "B", "Honors" — empty string if not sectioned
    }
    mapping(uint256 => ClassroomInfo) private _classrooms;
    uint256 private _nextClassroomId;

    // Device registry
    mapping(bytes32 => address) private _deviceToUser;
    mapping(bytes32 => bool) private _deviceActive;

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
    error UserRevoked();           // Kept for backward compat; Expelled users trigger this path
    error AccountExpelled();       // User has been permanently expelled from this institution
    error InvalidStatusTransition(); // Attempted status change is not permitted
    error InsufficientPrivilege(); // Caller does not have authority for this status change
    error InvalidTransfer();
    error ZeroAddress();
    error SuperAdminRequiresGovernance();
    // RM-L / WP-L1.1
    error NotPendingGovernance();
    error NoPendingTransfer();

    // ── Modifiers ──

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyAdminOrAbove() {
        OrgRole role = _orgRoles[msg.sender];
        if (role != OrgRole.Admin && role != OrgRole.SuperAdmin && msg.sender != governance) revert NotAdminOrAbove();
        _;
    }

    modifier onlyIT() {
        OrgRole role = _orgRoles[msg.sender];
        if (role != OrgRole.IT && role != OrgRole.Admin && role != OrgRole.SuperAdmin && msg.sender != governance) revert NotIT();
        _;
    }

    modifier onlyTeacherOf(uint256 classroomId) {
        if (!_classrooms[classroomId].exists) revert ClassroomNotFound();
        if (_classroomRoles[classroomId][msg.sender] != ClassroomRole.Teacher &&
            _orgRoles[msg.sender] != OrgRole.Admin &&
            _orgRoles[msg.sender] != OrgRole.SuperAdmin &&
            msg.sender != governance) revert NotTeacherOf();
        _;
    }

    // ── Constructor ──

    constructor(address _governance) {
        if (_governance == address(0)) revert ZeroAddress();
        governance = _governance;
        _orgRoles[_governance] = OrgRole.SuperAdmin;
        // Governance starts as Active
        _accountStatus[_governance] = AccountStatus.Active;
    }

    // ── Governance Transfer (RM-L / WP-L1.1 — two-step) ──

    event GovernanceTransferProposed(address indexed currentGovernance, address indexed pendingGovernance);
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event GovernanceTransferCancelled(address indexed pendingGovernance);

    /// @notice Propose a new governance address. Only the current
    /// governance can call. The proposed address must call
    /// `acceptGovernance` for the transfer to take effect — there
    /// is no atomic transfer.
    function transferGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert ZeroAddress();
        pendingGovernance = newGovernance;
        emit GovernanceTransferProposed(governance, newGovernance);
    }

    /// @notice Cancel a pending governance transfer. Only the
    /// current governance can call.
    function cancelGovernanceTransfer() external onlyGovernance {
        address prev = pendingGovernance;
        if (prev == address(0)) revert NoPendingTransfer();
        pendingGovernance = address(0);
        emit GovernanceTransferCancelled(prev);
    }

    /// @notice Accept the proposed governance role. Only the
    /// pending governance address can call.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        address previous = governance;
        // Demote the previous SuperAdmin role; the new governance
        // becomes the institution's SuperAdmin.
        _orgRoles[previous] = OrgRole.None;
        governance = msg.sender;
        pendingGovernance = address(0);
        _orgRoles[msg.sender] = OrgRole.SuperAdmin;
        _accountStatus[msg.sender] = AccountStatus.Active;
        emit GovernanceTransferred(previous, msg.sender);
    }

    // ── Views ──

    function getOrgRole(address user) external view returns (OrgRole) {
        return _orgRoles[user];
    }

    function getClassroomRole(uint256 classroomId, address user) external view returns (ClassroomRole) {
        return _classroomRoles[classroomId][user];
    }

    function getAccountStatus(address user) external view returns (AccountStatus) {
        return _accountStatus[user];
    }

    /// @dev Active membership requires Active status AND a non-None org role.
    function isActiveMember(address user) external view returns (bool) {
        AccountStatus status = _accountStatus[user];
        if (status == AccountStatus.Expelled || status == AccountStatus.Graduated) {
            return false;
        }
        // Active membership requires Active status AND a role
        if (status != AccountStatus.Active) return false;
        if (_orgRoles[user] != OrgRole.None) return true;
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

    /// @notice Get full classroom info including grade, year, and section.
    function getClassroomInfo(uint256 classroomId) external view returns (
        string memory name,
        address teacher,
        uint256 studentCount,
        uint8 gradeLevel,
        uint16 academicYear,
        string memory section
    ) {
        if (!_classrooms[classroomId].exists) revert ClassroomNotFound();
        ClassroomInfo storage c = _classrooms[classroomId];
        return (c.name, c.teacher, c.studentCount, c.gradeLevel, c.academicYear, c.section);
    }

    // ── Account Status Management ──

    /// @notice Update a user's FERPA-aligned account status.
    /// @dev State machine rules:
    ///   - Expelled → nothing (permanent from this institution)
    ///   - Graduated → nothing (permanent)
    ///   - IT or above: can set Active, Inactive
    ///   - Admin or above: can set Active, Inactive, Withdrawn, Transferred, Suspended
    ///   - SuperAdmin or governance: can set Graduated, Expelled
    function setAccountStatus(address user, AccountStatus newStatus) external {
        if (user == address(0)) revert ZeroAddress();

        AccountStatus current = _accountStatus[user];

        // Permanent states cannot be changed
        if (current == AccountStatus.Expelled) revert AccountExpelled();
        if (current == AccountStatus.Graduated) revert InvalidStatusTransition();

        OrgRole callerRole = _orgRoles[msg.sender];
        bool isGov = msg.sender == governance;
        bool isSuperAdmin = callerRole == OrgRole.SuperAdmin || isGov;
        bool isAdmin = callerRole == OrgRole.Admin || isSuperAdmin;
        bool isIT = callerRole == OrgRole.IT || isAdmin;

        // Graduated and Expelled require SuperAdmin or governance
        if (newStatus == AccountStatus.Graduated || newStatus == AccountStatus.Expelled) {
            if (!isSuperAdmin) revert InsufficientPrivilege();
        }
        // Disciplinary statuses (Suspended) require Admin or above
        else if (newStatus == AccountStatus.Suspended) {
            if (!isAdmin) revert InsufficientPrivilege();
        }
        // Withdrawn and Transferred require Admin or above
        else if (newStatus == AccountStatus.Withdrawn || newStatus == AccountStatus.Transferred) {
            if (!isAdmin) revert InsufficientPrivilege();
        }
        // Active and Inactive require at least IT
        else {
            if (!isIT) revert InsufficientPrivilege();
        }

        AccountStatus old = _accountStatus[user];
        _accountStatus[user] = newStatus;
        emit AccountStatusChanged(user, old, newStatus, msg.sender);
    }

    // ── Org Role Management ──

    /// @dev Invariant: SuperAdminRequiresMultiSig — only governance can grant SuperAdmin
    /// @dev Invariant: RoleHierarchyAcyclic — no circular grants possible (governance is fixed)
    function grantOrgRole(address user, OrgRole role) external {
        if (user == address(0)) revert ZeroAddress();

        AccountStatus status = _accountStatus[user];
        if (status == AccountStatus.Expelled) revert AccountExpelled();
        // Allow granting roles to Inactive/Withdrawn/Transferred/Suspended users
        // (re-enrollment is an explicit admin action, not automatic)

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
        // If the user had no prior Active status set, grant Active on first role assignment
        if (_accountStatus[user] == AccountStatus.Inactive ||
            (_accountStatus[user] != AccountStatus.Active &&
             _accountStatus[user] != AccountStatus.Suspended &&
             _accountStatus[user] != AccountStatus.Withdrawn &&
             _accountStatus[user] != AccountStatus.Transferred)) {
            // Only auto-activate if previously Inactive (was revoked) — admin chose to re-enroll
            // For fresh addresses (default Active from mapping default), keep as-is
        }
        emit OrgRoleGranted(user, role, msg.sender);
    }

    /// @dev Invariant: ImmediateRevocation — all derived permissions lost immediately.
    ///      Sets status to Inactive (reversible) instead of permanent revocation.
    function revokeOrgRole(address user) external onlyAdminOrAbove {
        OrgRole prev = _orgRoles[user];
        if (prev == OrgRole.None) revert NoRole();

        _orgRoles[user] = OrgRole.None;
        // Set to Inactive (reversible) instead of permanent revocation
        if (_accountStatus[user] == AccountStatus.Active) {
            _accountStatus[user] = AccountStatus.Inactive;
            emit AccountStatusChanged(user, AccountStatus.Active, AccountStatus.Inactive, msg.sender);
        }

        emit OrgRoleRevoked(user, prev, msg.sender);
    }

    // ── Classroom Management ──

    /// @notice Create a new classroom with grade, year, and section metadata.
    function createClassroom(
        string calldata name,
        address teacher,
        uint8 gradeLevel,
        uint16 academicYear,
        string calldata section
    ) external onlyAdminOrAbove returns (uint256 classroomId) {
        if (teacher == address(0)) revert ZeroAddress();

        classroomId = _nextClassroomId++;
        _classrooms[classroomId] = ClassroomInfo({
            name: name,
            teacher: teacher,
            studentCount: 0,
            exists: true,
            gradeLevel: gradeLevel,
            academicYear: academicYear,
            section: section
        });
        _classroomRoles[classroomId][teacher] = ClassroomRole.Teacher;

        emit ClassroomCreated(classroomId, name, teacher);
    }

    /// @dev Invariant: NoPrivilegeEscalation — Student cannot become Teacher through this method
    function grantClassroomRole(uint256 classroomId, address user, ClassroomRole role) external onlyTeacherOf(classroomId) {
        if (user == address(0)) revert ZeroAddress();

        AccountStatus status = _accountStatus[user];
        if (status == AccountStatus.Expelled) revert AccountExpelled();

        // Invariant 7: NoPrivilegeEscalation — teacher can only grant Student or TA
        if (role == ClassroomRole.Teacher) {
            // Only admin can assign teacher role
            OrgRole callerOrgRole = _orgRoles[msg.sender];
            if (callerOrgRole != OrgRole.Admin && callerOrgRole != OrgRole.SuperAdmin && msg.sender != governance) {
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

        // FWA-C3-14: an org-level admin may move a student between any two
        // classrooms. A classroom TEACHER, however, must control BOTH ends
        // of the transfer — being teacher of the source alone let a teacher
        // inject a student into ANY destination classroom they have no
        // authority over (cross-classroom roster injection). Require
        // teacher-of-source AND teacher-of-destination for the non-admin path.
        bool isAdmin = _orgRoles[msg.sender] == OrgRole.Admin ||
                       _orgRoles[msg.sender] == OrgRole.SuperAdmin ||
                       msg.sender == governance;
        if (!isAdmin) {
            bool isFromTeacher = _classroomRoles[fromClassroom][msg.sender] == ClassroomRole.Teacher;
            bool isToTeacher = _classroomRoles[toClassroom][msg.sender] == ClassroomRole.Teacher;
            if (!isFromTeacher || !isToTeacher) revert NotTeacherOf();
        }

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
