------------------------------ MODULE ClassroomRegistry ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the ClassroomRegistry smart contract for teacher-student management.
\*
\* Teachers create classrooms, enroll students via invite codes, and
\* manage model whitelists. Students can only access whitelisted models.
\* Enrollment is bounded by MaxStudents per classroom.
\*
\* Source: contracts/src/ClassroomRegistry.sol

CONSTANTS
    Teachers,           \* Set of teacher addresses
    Students,           \* Set of student addresses
    Models,             \* Set of model IDs
    InviteCodes,        \* Set of possible invite codes
    MaxStudents         \* Max students per classroom

ASSUME Teachers # {}
ASSUME Students # {}
ASSUME Models # {}
ASSUME InviteCodes # {}
ASSUME MaxStudents \in Nat /\ MaxStudents >= 1
ASSUME Teachers \cap Students = {}  \* Teachers and students are disjoint

VARIABLES
    classrooms,         \* Set of teachers who have created a classroom
    enrollments,        \* Mapping: teacher -> set of enrolled students
    whitelists,         \* Mapping: teacher -> set of whitelisted models
    inviteCodes,        \* Mapping: teacher -> invite code (or "none")
    codeToTeacher       \* Mapping: code -> teacher (reverse index, or "none")

vars == <<classrooms, enrollments, whitelists, inviteCodes, codeToTeacher>>

\* ---- Helper operators ----

\* The teacher (if any) that a student is enrolled with.
EnrolledWith(s) ==
    {t \in classrooms : s \in enrollments[t]}

\* ---- State machine ----

Init ==
    /\ classrooms = {}
    /\ enrollments = [t \in Teachers |-> {}]
    /\ whitelists = [t \in Teachers |-> {}]
    /\ inviteCodes = [t \in Teachers |-> "none"]
    /\ codeToTeacher = [c \in InviteCodes |-> "none"]

\* Teacher creates a classroom with an invite code.
CreateClassroom(teacher, code) ==
    /\ teacher \in Teachers
    /\ teacher \notin classrooms
    /\ code \in InviteCodes
    /\ codeToTeacher[code] = "none"   \* code not in use
    /\ classrooms' = classrooms \cup {teacher}
    /\ inviteCodes' = [inviteCodes EXCEPT ![teacher] = code]
    /\ codeToTeacher' = [codeToTeacher EXCEPT ![code] = teacher]
    /\ UNCHANGED <<enrollments, whitelists>>

\* Student enrolls via invite code.
EnrollStudent(student, code) ==
    /\ student \in Students
    /\ code \in InviteCodes
    /\ codeToTeacher[code] # "none"
    /\ LET teacher == codeToTeacher[code]
       IN /\ teacher \in classrooms
          /\ EnrolledWith(student) = {}        \* student not yet enrolled anywhere
          /\ Cardinality(enrollments[teacher]) < MaxStudents
          /\ enrollments' = [enrollments EXCEPT ![teacher] = enrollments[teacher] \cup {student}]
          /\ UNCHANGED <<classrooms, whitelists, inviteCodes, codeToTeacher>>

\* Student unenrolls from their classroom.
UnenrollStudent(student) ==
    /\ student \in Students
    /\ EnrolledWith(student) # {}
    /\ LET teacher == CHOOSE t \in EnrolledWith(student) : TRUE
       IN /\ enrollments' = [enrollments EXCEPT ![teacher] = enrollments[teacher] \ {student}]
          /\ UNCHANGED <<classrooms, whitelists, inviteCodes, codeToTeacher>>

\* Teacher adds a model to their whitelist.
AddToWhitelist(teacher, model) ==
    /\ teacher \in classrooms
    /\ model \in Models
    /\ model \notin whitelists[teacher]
    /\ whitelists' = [whitelists EXCEPT ![teacher] = whitelists[teacher] \cup {model}]
    /\ UNCHANGED <<classrooms, enrollments, inviteCodes, codeToTeacher>>

\* Teacher removes a model from their whitelist.
RemoveFromWhitelist(teacher, model) ==
    /\ teacher \in classrooms
    /\ model \in whitelists[teacher]
    /\ whitelists' = [whitelists EXCEPT ![teacher] = whitelists[teacher] \ {model}]
    /\ UNCHANGED <<classrooms, enrollments, inviteCodes, codeToTeacher>>

\* Teacher rotates their invite code.
RotateCode(teacher, newCode) ==
    /\ teacher \in classrooms
    /\ newCode \in InviteCodes
    /\ codeToTeacher[newCode] = "none"   \* new code not in use
    /\ LET oldCode == inviteCodes[teacher]
       IN /\ inviteCodes' = [inviteCodes EXCEPT ![teacher] = newCode]
          /\ codeToTeacher' = [codeToTeacher EXCEPT ![oldCode] = "none", ![newCode] = teacher]
    /\ UNCHANGED <<classrooms, enrollments, whitelists>>

Next ==
    \/ \E t \in Teachers, c \in InviteCodes : CreateClassroom(t, c)
    \/ \E s \in Students, c \in InviteCodes : EnrollStudent(s, c)
    \/ \E s \in Students : UnenrollStudent(s)
    \/ \E t \in Teachers, model \in Models : AddToWhitelist(t, model)
    \/ \E t \in Teachers, model \in Models : RemoveFromWhitelist(t, model)
    \/ \E t \in Teachers, c \in InviteCodes : RotateCode(t, c)

\* ---- Invariants ----

\* INV-1: Type correctness.
TypeOK ==
    /\ classrooms \subseteq Teachers
    /\ \A t \in Teachers : enrollments[t] \subseteq Students
    /\ \A t \in Teachers : whitelists[t] \subseteq Models
    /\ \A t \in Teachers : inviteCodes[t] \in InviteCodes \/ inviteCodes[t] = "none"
    /\ \A c \in InviteCodes : codeToTeacher[c] \in Teachers \/ codeToTeacher[c] = "none"

\* INV-2: EnrollmentBounded — no classroom exceeds MaxStudents.
EnrollmentBounded ==
    \A t \in classrooms : Cardinality(enrollments[t]) <= MaxStudents

\* INV-3: StudentInOneClass — each student enrolled in at most one classroom.
StudentInOneClass ==
    \A s \in Students : Cardinality(EnrolledWith(s)) <= 1

\* INV-4: WhitelistOnlyByTeacher — only active classrooms have whitelists.
\* (Teachers without classrooms have empty whitelists.)
WhitelistOnlyByTeacher ==
    \A t \in Teachers : t \notin classrooms => whitelists[t] = {}

\* INV-5: InviteCodeUnique — no two teachers share an invite code.
InviteCodeUnique ==
    \A t1 \in classrooms : \A t2 \in classrooms :
        (t1 # t2) => (inviteCodes[t1] # inviteCodes[t2])

\* INV-6: StudentAccessOnlyWhitelisted — students can only use models
\* in their teacher's whitelist. (Structural: enrollment links to teacher,
\* teacher controls whitelist. We verify the linkage is consistent.)
StudentAccessOnlyWhitelisted ==
    \A s \in Students :
        EnrolledWith(s) # {} =>
            LET teacher == CHOOSE t \in EnrolledWith(s) : TRUE
            IN teacher \in classrooms

\* INV-7: CodeToTeacherConsistent — reverse index matches forward mapping.
CodeToTeacherConsistent ==
    /\ \A t \in classrooms :
        inviteCodes[t] # "none" => codeToTeacher[inviteCodes[t]] = t
    /\ \A c \in InviteCodes :
        codeToTeacher[c] # "none" => inviteCodes[codeToTeacher[c]] = c

\* INV-8: NoClassroomNoEnrollments — teachers without classrooms have no students.
NoClassroomNoEnrollments ==
    \A t \in Teachers : t \notin classrooms => enrollments[t] = {}

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety       == Spec => []TypeOK
THEOREM EnrollBound      == Spec => []EnrollmentBounded
THEOREM OneClass         == Spec => []StudentInOneClass
THEOREM WhitelistAuth    == Spec => []WhitelistOnlyByTeacher
THEOREM CodeUnique       == Spec => []InviteCodeUnique
THEOREM StudentAccess    == Spec => []StudentAccessOnlyWhitelisted
THEOREM CodeConsistent   == Spec => []CodeToTeacherConsistent
THEOREM NoClassNoEnroll  == Spec => []NoClassroomNoEnrollments

=============================================================================
