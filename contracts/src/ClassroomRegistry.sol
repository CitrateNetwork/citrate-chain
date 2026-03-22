// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ClassroomRegistry — Teacher-Student Classroom Management
/// @notice Teachers create classrooms, generate invite codes, enroll students,
///         and manage model whitelists. Students can only access whitelisted models.
///         Satisfies ClassroomRegistry.tla invariants INV-1 through INV-8:
///           EnrollmentBounded, StudentInOneClass, WhitelistOnlyByTeacher,
///           InviteCodeUnique, StudentAccessOnlyWhitelisted,
///           CodeToTeacherConsistent, NoClassroomNoEnrollments.
/// @dev WP-LC.3.1 — backbone for the Learning Center "Classroom" screen.
contract ClassroomRegistry {
    // ============================================================
    // Types
    // ============================================================

    struct Classroom {
        address teacher;
        string name;
        uint256 maxStudents;
        uint256 studentCount;
        uint256 createdAt;
        bool exists;
    }

    // ============================================================
    // State
    // ============================================================

    /// @notice Classroom data keyed by teacher address.
    /// TLA+ variable: classrooms (set of teachers who have a classroom).
    mapping(address => Classroom) public classrooms;

    /// @notice Whether a student is enrolled with a given teacher.
    /// TLA+ variable: enrollments (teacher -> set of students).
    mapping(address => mapping(address => bool)) public isEnrolled;

    /// @notice Reverse mapping: student -> teacher they are enrolled with (or address(0)).
    /// Enforces INV-3: StudentInOneClass — each student in at most one classroom.
    mapping(address => address) public studentTeacher;

    /// @notice Model whitelist per teacher classroom.
    /// TLA+ variable: whitelists (teacher -> set of models).
    mapping(address => mapping(bytes32 => bool)) public whitelistedModels;

    /// @notice The active invite code hash for each teacher (or bytes32(0) if none).
    /// TLA+ variable: inviteCodes (teacher -> code or "none").
    mapping(address => bytes32) public activeInviteCode;

    /// @notice Reverse index: invite code hash -> teacher address (or address(0)).
    /// TLA+ variable: codeToTeacher (code -> teacher or "none").
    mapping(bytes32 => address) public codeToTeacher;

    /// @notice Count of whitelisted models per teacher (for cleanup tracking).
    mapping(address => uint256) public whitelistCount;

    // ============================================================
    // Events
    // ============================================================

    event ClassroomCreated(
        address indexed teacher,
        string name,
        uint256 maxStudents,
        bytes32 inviteCodeHash
    );
    event StudentEnrolled(address indexed teacher, address indexed student, bytes32 inviteCodeHash);
    event StudentUnenrolled(address indexed teacher, address indexed student);
    event ModelWhitelisted(address indexed teacher, bytes32 modelHash);
    event ModelRemoved(address indexed teacher, bytes32 modelHash);
    event InviteCodeRotated(address indexed teacher, bytes32 oldCodeHash, bytes32 newCodeHash);

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyTeacher() {
        require(classrooms[msg.sender].exists, "Not a teacher with a classroom");
        _;
    }

    // ============================================================
    // Core: Classroom Creation
    // ============================================================

    /// @notice Create a classroom with a name, max student limit, and initial invite code.
    /// @dev Satisfies TLA+ CreateClassroom: teacher not in classrooms, code not in use,
    ///      classrooms' = classrooms ∪ {teacher}, codeToTeacher updated.
    ///      INV-5 (InviteCodeUnique) enforced by requiring codeToTeacher[codeHash] == address(0).
    ///      INV-8 (NoClassroomNoEnrollments) trivially holds: new classroom has 0 students.
    /// @param name Classroom display name (non-empty)
    /// @param maxStudents Maximum enrollment capacity (>= 1)
    /// @param inviteCodeHash keccak256 of the initial invite code
    function createClassroom(
        string calldata name,
        uint256 maxStudents,
        bytes32 inviteCodeHash
    ) external {
        require(bytes(name).length > 0, "Empty name");
        require(maxStudents >= 1, "Max students must be >= 1");
        require(!classrooms[msg.sender].exists, "Classroom already exists");
        require(inviteCodeHash != bytes32(0), "Invalid invite code hash");
        require(codeToTeacher[inviteCodeHash] == address(0), "Invite code already in use");

        classrooms[msg.sender] = Classroom({
            teacher: msg.sender,
            name: name,
            maxStudents: maxStudents,
            studentCount: 0,
            createdAt: block.timestamp,
            exists: true
        });

        activeInviteCode[msg.sender] = inviteCodeHash;
        codeToTeacher[inviteCodeHash] = msg.sender;

        emit ClassroomCreated(msg.sender, name, maxStudents, inviteCodeHash);
    }

    // ============================================================
    // Core: Student Enrollment
    // ============================================================

    /// @notice Enroll in a classroom by providing the invite code.
    /// @dev Satisfies TLA+ EnrollStudent:
    ///      - codeToTeacher[code] != "none" (code resolves to a teacher)
    ///      - teacher in classrooms
    ///      - student not enrolled anywhere (INV-3: StudentInOneClass)
    ///      - enrollment count < maxStudents (INV-2: EnrollmentBounded)
    ///      INV-6 (StudentAccessOnlyWhitelisted): enrollment links student to teacher
    ///      who controls the whitelist.
    /// @param inviteCodeHash keccak256 of the invite code provided by teacher
    function enrollWithCode(bytes32 inviteCodeHash) external {
        require(inviteCodeHash != bytes32(0), "Invalid invite code hash");
        address teacher = codeToTeacher[inviteCodeHash];
        require(teacher != address(0), "Invalid invite code");
        require(classrooms[teacher].exists, "Classroom does not exist");
        require(msg.sender != teacher, "Teacher cannot enroll as student");
        require(studentTeacher[msg.sender] == address(0), "Already enrolled in a classroom");
        require(
            classrooms[teacher].studentCount < classrooms[teacher].maxStudents,
            "Classroom is full"
        );

        isEnrolled[teacher][msg.sender] = true;
        studentTeacher[msg.sender] = teacher;
        classrooms[teacher].studentCount++;

        emit StudentEnrolled(teacher, msg.sender, inviteCodeHash);
    }

    /// @notice Unenroll from current classroom (called by student).
    /// @dev Satisfies TLA+ UnenrollStudent: student enrolled somewhere,
    ///      enrollment removed, count decremented.
    function unenroll() external {
        address teacher = studentTeacher[msg.sender];
        require(teacher != address(0), "Not enrolled in any classroom");

        isEnrolled[teacher][msg.sender] = false;
        studentTeacher[msg.sender] = address(0);
        classrooms[teacher].studentCount--;

        emit StudentUnenrolled(teacher, msg.sender);
    }

    /// @notice Remove a student from the classroom (called by teacher).
    /// @dev Teacher-initiated unenrollment. Same invariants as unenroll.
    /// @param student Address of the student to remove
    function removeStudent(address student) external onlyTeacher {
        require(isEnrolled[msg.sender][student], "Student not in your classroom");

        isEnrolled[msg.sender][student] = false;
        studentTeacher[student] = address(0);
        classrooms[msg.sender].studentCount--;

        emit StudentUnenrolled(msg.sender, student);
    }

    // ============================================================
    // Model Whitelist Management
    // ============================================================

    /// @notice Whitelist a model for this classroom (teacher only).
    /// @dev Satisfies TLA+ AddToWhitelist: teacher in classrooms, model added.
    ///      INV-4 (WhitelistOnlyByTeacher) enforced by onlyTeacher modifier.
    /// @param modelHash Hash identifying the model
    function whitelistModel(bytes32 modelHash) external onlyTeacher {
        require(modelHash != bytes32(0), "Invalid model hash");
        require(!whitelistedModels[msg.sender][modelHash], "Model already whitelisted");

        whitelistedModels[msg.sender][modelHash] = true;
        whitelistCount[msg.sender]++;

        emit ModelWhitelisted(msg.sender, modelHash);
    }

    /// @notice Remove a model from the whitelist (teacher only).
    /// @dev Satisfies TLA+ RemoveFromWhitelist: teacher in classrooms, model removed.
    /// @param modelHash Hash identifying the model
    function removeModel(bytes32 modelHash) external onlyTeacher {
        require(whitelistedModels[msg.sender][modelHash], "Model not whitelisted");

        whitelistedModels[msg.sender][modelHash] = false;
        whitelistCount[msg.sender]--;

        emit ModelRemoved(msg.sender, modelHash);
    }

    // ============================================================
    // Invite Code Management
    // ============================================================

    /// @notice Rotate the invite code (teacher only). Invalidates old code,
    ///         sets new one.
    /// @dev Satisfies TLA+ RotateCode: teacher in classrooms, old code freed,
    ///      new code assigned. INV-5 (InviteCodeUnique) enforced by checking
    ///      codeToTeacher[newCodeHash] == address(0).
    ///      INV-7 (CodeToTeacherConsistent) maintained: old bidirectional
    ///      mapping cleared, new one established.
    /// @param newCodeHash keccak256 of the new invite code
    function rotateInviteCode(bytes32 newCodeHash) external onlyTeacher {
        require(newCodeHash != bytes32(0), "Invalid invite code hash");
        require(codeToTeacher[newCodeHash] == address(0), "Invite code already in use");

        bytes32 oldCodeHash = activeInviteCode[msg.sender];

        // Clear old mapping
        if (oldCodeHash != bytes32(0)) {
            codeToTeacher[oldCodeHash] = address(0);
        }

        // Set new mapping
        activeInviteCode[msg.sender] = newCodeHash;
        codeToTeacher[newCodeHash] = msg.sender;

        emit InviteCodeRotated(msg.sender, oldCodeHash, newCodeHash);
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get full classroom info for a teacher.
    /// @param teacher The teacher address
    /// @return Classroom struct
    function getClassroom(address teacher) external view returns (Classroom memory) {
        return classrooms[teacher];
    }

    /// @notice Check if a student is enrolled in a specific teacher's classroom.
    /// @param teacher The teacher address
    /// @param student The student address
    /// @return True if enrolled
    function isStudentEnrolled(address teacher, address student) external view returns (bool) {
        return isEnrolled[teacher][student];
    }

    /// @notice Get the teacher a student is enrolled with (address(0) if none).
    /// @param student The student address
    /// @return Teacher address or address(0)
    function getStudentTeacher(address student) external view returns (address) {
        return studentTeacher[student];
    }

    /// @notice Check if a model is whitelisted for a teacher's classroom.
    /// @param teacher The teacher address
    /// @param modelHash The model hash
    /// @return True if whitelisted
    function isModelWhitelistedFor(address teacher, bytes32 modelHash) external view returns (bool) {
        return whitelistedModels[teacher][modelHash];
    }

    /// @notice Check if a student can access a specific model (enrolled + model whitelisted).
    /// @dev Structural enforcement of INV-6 (StudentAccessOnlyWhitelisted):
    ///      A student can only access models whitelisted by their teacher.
    /// @param student The student address
    /// @param modelHash The model hash
    /// @return True if the student can access the model
    function canStudentAccessModel(address student, bytes32 modelHash) external view returns (bool) {
        address teacher = studentTeacher[student];
        if (teacher == address(0)) return false;
        return whitelistedModels[teacher][modelHash];
    }

    /// @notice Get the active invite code hash for a teacher.
    /// @param teacher The teacher address
    /// @return The invite code hash (bytes32(0) if none)
    function getActiveInviteCode(address teacher) external view returns (bytes32) {
        return activeInviteCode[teacher];
    }

    /// @notice Check if a classroom exists for the given teacher.
    /// @param teacher The teacher address
    /// @return True if classroom exists
    function classroomExists(address teacher) external view returns (bool) {
        return classrooms[teacher].exists;
    }
}
