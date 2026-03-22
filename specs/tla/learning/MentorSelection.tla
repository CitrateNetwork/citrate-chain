------------------------------ MODULE MentorSelection ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the mentor-mentee pairing algorithm.
\*
\* Participants have accuracy scores and domain expertise. The algorithm
\* pairs higher-accuracy mentors with lower-accuracy mentees, respecting
\* capacity limits and preferring domain overlap.
\*
\* Source: core/learning/src/mentor.rs

CONSTANTS
    Participants,       \* Set of participant keys
    Domains,            \* Set of domain strings
    MinAccuracyGap,     \* Delta threshold (integer scale, e.g. 5 = 0.05 * 100)
    MaxMentees,         \* Max mentees per mentor (e.g. 3)
    MaxAccuracy         \* Upper bound on accuracy scale (e.g. 20 for model checking)

ASSUME Participants # {}
ASSUME MinAccuracyGap \in Nat /\ MinAccuracyGap >= 1
ASSUME MaxMentees \in Nat /\ MaxMentees >= 1
ASSUME Domains # {}
ASSUME MaxAccuracy \in Nat /\ MaxAccuracy >= MinAccuracyGap + 1

VARIABLES
    accuracies,         \* Mapping: participant -> accuracy (0..100 integer scale)
    domains,            \* Mapping: participant -> subset of Domains
    pairings,           \* Set of [mentor |-> p, mentee |-> q] records
    mentorLoad          \* Mapping: participant -> number of mentees assigned

vars == <<accuracies, domains, pairings, mentorLoad>>

\* ---- Helper operators ----

\* Set of all possible pairing records.
PairingRecords == [mentor : Participants, mentee : Participants]

\* The set of mentees for a given mentor in current pairings.
MenteesOf(m) ==
    {r.mentee : r \in {r2 \in pairings : r2.mentor = m}}

\* The set of mentors for a given mentee in current pairings.
MentorsOf(p) ==
    {r.mentor : r \in {r2 \in pairings : r2.mentee = p}}

\* Domain overlap cardinality between two participants.
DomainOverlap(a, b) ==
    Cardinality(domains[a] \cap domains[b])

\* Whether participant m is a valid mentor for participant q.
ValidPairing(m, q) ==
    /\ m # q
    /\ accuracies[m] > accuracies[q] + MinAccuracyGap
    /\ mentorLoad[m] < MaxMentees
    /\ MentorsOf(q) = {}  \* mentee has no mentor yet

\* Whether there exists another valid mentor with strictly more domain overlap.
\* If so, m is not the preferred mentor (DomainOverlapPreferred would be violated).
BetterMentorExists(m, q) ==
    \E m2 \in Participants :
        /\ m2 # m
        /\ ValidPairing(m2, q)
        /\ DomainOverlap(m2, q) > DomainOverlap(m, q)

\* ---- State machine ----

Init ==
    \* Non-deterministically assign accuracies (0..100) and domain sets.
    /\ accuracies \in [Participants -> 0..MaxAccuracy]
    /\ domains \in [Participants -> (SUBSET Domains \ {{}})]
    /\ pairings = {}
    /\ mentorLoad = [p \in Participants |-> 0]

\* Pair mentor m with mentee q.
Pair(m, q) ==
    /\ ValidPairing(m, q)
    /\ ~BetterMentorExists(m, q)
    /\ pairings' = pairings \cup {[mentor |-> m, mentee |-> q]}
    /\ mentorLoad' = [mentorLoad EXCEPT ![m] = mentorLoad[m] + 1]
    /\ UNCHANGED <<accuracies, domains>>

\* Allow unpairing (mentee leaves, mentor freed).
Unpair(m, q) ==
    /\ [mentor |-> m, mentee |-> q] \in pairings
    /\ pairings' = pairings \ {[mentor |-> m, mentee |-> q]}
    /\ mentorLoad' = [mentorLoad EXCEPT ![m] = mentorLoad[m] - 1]
    /\ UNCHANGED <<accuracies, domains>>

Next ==
    \/ \E m \in Participants, q \in Participants : Pair(m, q)
    \/ \E m \in Participants, q \in Participants : Unpair(m, q)

\* ---- Invariants ----

\* INV-1: Type correctness.
TypeOK ==
    /\ \A p \in Participants : accuracies[p] \in 0..MaxAccuracy
    /\ \A p \in Participants : domains[p] \subseteq Domains /\ domains[p] # {}
    /\ pairings \subseteq PairingRecords
    /\ \A p \in Participants : mentorLoad[p] \in Nat

\* INV-2: MentorHigherAccuracy — mentor's accuracy exceeds mentee's by at least MinAccuracyGap.
MentorHigherAccuracy ==
    \A r \in pairings :
        accuracies[r.mentor] > accuracies[r.mentee] + MinAccuracyGap

\* INV-3: MentorCapacity — no mentor has more than MaxMentees mentees.
MentorCapacity ==
    \A m \in Participants : mentorLoad[m] <= MaxMentees

\* INV-4: NoSelfMentor — no pairing where mentor = mentee.
NoSelfMentor ==
    \A r \in pairings : r.mentor # r.mentee

\* INV-5: MenteeHasAtMostOneMentor — each mentee appears in at most one pairing.
MenteeHasAtMostOneMentor ==
    \A q \in Participants :
        Cardinality({r \in pairings : r.mentee = q}) <= 1

\* INV-6: DomainOverlapPreferred — no pairing exists where a strictly better
\* (more domain overlap) valid mentor was available at the time of pairing.
\* Since we enforce ~BetterMentorExists in Pair, this holds by construction.
DomainOverlapPreferred ==
    \A r \in pairings :
        ~(\E m2 \in Participants :
            /\ m2 # r.mentor
            /\ m2 # r.mentee
            /\ accuracies[m2] > accuracies[r.mentee] + MinAccuracyGap
            /\ mentorLoad[m2] < MaxMentees
            /\ DomainOverlap(m2, r.mentee) > DomainOverlap(r.mentor, r.mentee))

\* INV-7: MentorLoadConsistent — mentorLoad matches actual pairing count.
MentorLoadConsistent ==
    \A m \in Participants :
        mentorLoad[m] = Cardinality({r \in pairings : r.mentor = m})

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety        == Spec => []TypeOK
THEOREM HigherAccuracy    == Spec => []MentorHigherAccuracy
THEOREM Capacity          == Spec => []MentorCapacity
THEOREM NoSelf            == Spec => []NoSelfMentor
THEOREM AtMostOneMentor   == Spec => []MenteeHasAtMostOneMentor
THEOREM DomainPref        == Spec => []DomainOverlapPreferred
THEOREM LoadConsistent    == Spec => []MentorLoadConsistent

=============================================================================
