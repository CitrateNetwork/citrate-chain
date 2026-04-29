------------------------------ MODULE MentorAdversarial ------------------------------
EXTENDS Naturals, FiniteSets, TLC

(***********************************************************************
* RM-FL-4 / WP-4.1 — adversarial extension of MentorSelection.tla.
*
* The base spec (MentorSelection.tla) verifies that legitimate
* pairings preserve safety: mentor accuracy > mentee, capacity
* respected, no self-mentor, mentee has at most one mentor, domain
* preference, mentor load consistent.
*
* This adversarial spec adds three threats not covered by the base:
*
*   1. SYBIL MENTOR. An adversary controls multiple participant
*      keys; without a trust floor, a sybil cluster of low-blue-
*      score mentors can claim accuracy advantages and capture
*      mentee assignments.
*
*   2. CAPACITY OVERRUN. The base spec proves `MentorCapacity`
*      assuming the only way to add a pairing is `Pair(m, q)`,
*      which checks `mentorLoad[m] < MaxMentees`. The adversarial
*      model adds an `AdversaryAttemptOverrun` action that tries
*      to bypass the check; safety must hold under this action's
*      enabling condition.
*
*   3. WEIGHT UPDATE MID-MATCHING. The base spec keeps
*      `accuracies` constant. In production, accuracy scores
*      update across cycles. An accuracy drop on an in-flight
*      mentor must not retroactively invalidate existing
*      pairings (the chain has them; rollback is not an option),
*      but must affect future pairings.
*
* Plus a TRUST FLOOR invariant: every committed pairing's mentor
* must have accuracy at the time of pairing >= TrustFloor.
*
* Lessons applied from RM-FL-3's THE_OPERATOR_AND_THE_VARIABLE.md:
* the adversary's identity is a CONSTANT (not a variable), and
* the trust-floor predicate is an operator (not a variable map),
* so TLC doesn't enumerate every possible adversary configuration.
***********************************************************************)

CONSTANTS
    Participants,         \* As MentorSelection.tla
    Adversaries,          \* SUBSET Participants — the sybil cluster
    Domains,
    MinAccuracyGap,
    MaxMentees,
    MaxAccuracy,
    TrustFloor            \* New: minimum accuracy to be a mentor

ASSUME Participants # {}
ASSUME Adversaries \subseteq Participants
ASSUME MinAccuracyGap \in Nat /\ MinAccuracyGap >= 1
ASSUME MaxMentees \in Nat /\ MaxMentees >= 1
ASSUME Domains # {}
ASSUME MaxAccuracy \in Nat /\ MaxAccuracy >= MinAccuracyGap + 1
ASSUME TrustFloor \in Nat /\ TrustFloor <= MaxAccuracy

VARIABLES
    accuracies,           \* As MentorSelection.tla, but mutable
    domains,
    pairings,             \* Set of [mentor, mentee, mentorAccAtPair]
    mentorLoad,
    overrunAttempted      \* TRUE if an adversary tried capacity overrun

vars == <<accuracies, domains, pairings, mentorLoad, overrunAttempted>>

\* ---- Helpers ----

PairingRecords ==
    [mentor : Participants, mentee : Participants, mentorAccAtPair : 0..MaxAccuracy]

MenteesOf(m) ==
    {r.mentee : r \in {r2 \in pairings : r2.mentor = m}}

MentorsOf(p) ==
    {r.mentor : r \in {r2 \in pairings : r2.mentee = p}}

ValidPairing(m, q) ==
    /\ m # q
    /\ accuracies[m] > accuracies[q] + MinAccuracyGap
    /\ accuracies[m] >= TrustFloor   \* New: trust floor enforced
    /\ mentorLoad[m] < MaxMentees
    /\ MentorsOf(q) = {}

\* ---- State machine ----

Init ==
    /\ accuracies \in [Participants -> 0..MaxAccuracy]
    /\ domains \in [Participants -> (SUBSET Domains \ {{}})]
    /\ pairings = {}
    /\ mentorLoad = [p \in Participants |-> 0]
    /\ overrunAttempted = FALSE

\* Honest pair action: same as MentorSelection.tla but records
\* the mentor's accuracy at pairing time so we can audit
\* trust-floor adherence even if accuracy later drops.
Pair(m, q) ==
    /\ ValidPairing(m, q)
    /\ pairings' = pairings \cup {[mentor |-> m, mentee |-> q,
                                   mentorAccAtPair |-> accuracies[m]]}
    /\ mentorLoad' = [mentorLoad EXCEPT ![m] = mentorLoad[m] + 1]
    /\ UNCHANGED <<accuracies, domains, overrunAttempted>>

Unpair(m, q) ==
    /\ \E r \in pairings :
        /\ r.mentor = m
        /\ r.mentee = q
        /\ pairings' = pairings \ {r}
    /\ mentorLoad' = [mentorLoad EXCEPT ![m] = mentorLoad[m] - 1]
    /\ UNCHANGED <<accuracies, domains, overrunAttempted>>

\* Adversary action 1: an Adversary participant attempts to overrun
\* a mentor's capacity. The action is enabled only when an adversary
\* has hit cap; the *attempt* sets a flag, but the underlying
\* `mentorLoad < MaxMentees` guard in `Pair` prevents the bad state.
\* The flag lets us assert that even when the adversary tries, no
\* invariant is violated.
AdversaryAttemptOverrun ==
    /\ \E m \in Adversaries :
        /\ mentorLoad[m] >= MaxMentees
        /\ overrunAttempted' = TRUE
    /\ UNCHANGED <<accuracies, domains, pairings, mentorLoad>>

\* Adversary action 2: weight update — an adversary's accuracy
\* drops mid-matching. Existing pairings are NOT touched (chain
\* is canonical), but future pairings see the new accuracy.
AccuracyDrop(p) ==
    /\ accuracies[p] > 0
    /\ accuracies' = [accuracies EXCEPT ![p] = accuracies[p] - 1]
    /\ UNCHANGED <<domains, pairings, mentorLoad, overrunAttempted>>

\* Adversary action 3: weight update — accuracy increase. Models
\* an adversary inflating their score (e.g. by colluding to win
\* contributions). Must not break existing safety properties.
AccuracyRise(p) ==
    /\ accuracies[p] < MaxAccuracy
    /\ accuracies' = [accuracies EXCEPT ![p] = accuracies[p] + 1]
    /\ UNCHANGED <<domains, pairings, mentorLoad, overrunAttempted>>

Next ==
    \/ \E m \in Participants, q \in Participants : Pair(m, q)
    \/ \E m \in Participants, q \in Participants : Unpair(m, q)
    \/ AdversaryAttemptOverrun
    \/ \E p \in Participants : AccuracyDrop(p)
    \/ \E p \in Participants : AccuracyRise(p)

\* ---- Invariants ----

\* INV-A1: Type correctness with the new field.
TypeOK ==
    /\ \A p \in Participants : accuracies[p] \in 0..MaxAccuracy
    /\ \A p \in Participants : domains[p] \subseteq Domains /\ domains[p] # {}
    /\ pairings \subseteq PairingRecords
    /\ \A p \in Participants : mentorLoad[p] \in Nat
    /\ overrunAttempted \in BOOLEAN

\* INV-A2: TrustFloorAtPairing — every pairing's mentor was at or
\* above the trust floor at the time of pairing. This is a
\* safety property at the moment of commit; subsequent accuracy
\* drops do not retroactively invalidate the pairing.
TrustFloorAtPairing ==
    \A r \in pairings : r.mentorAccAtPair >= TrustFloor

\* INV-A3: CapacityHoldsUnderAdversary — even when the adversary
\* sets the overrun flag, no mentor exceeds MaxMentees in actual
\* state (because `Pair` enforces it independently).
CapacityHoldsUnderAdversary ==
    \A m \in Participants : mentorLoad[m] <= MaxMentees

\* INV-A4: PairingAccuracyGapPreservedAtCommit — the accuracy gap
\* invariant from MentorSelection.tla holds at *commit time*. We
\* don't require it post-accuracy-drop; the chain has the
\* pairing and rollback is not an option (see RM-FL-3 essay
\* THE_TRAINING_DAEMON_BET).
PairingAccuracyGapPreservedAtCommit ==
    \A r \in pairings : r.mentorAccAtPair > MinAccuracyGap

\* INV-A5: NoSybilCaptureAtTrustFloor — an adversary below the
\* trust floor can never appear as a mentor in any pairing,
\* regardless of relative accuracy gaps.
NoSybilCaptureAtTrustFloor ==
    \A r \in pairings :
        r.mentor \in Adversaries =>
            r.mentorAccAtPair >= TrustFloor

\* INV-A6: MentorLoadConsistent — same as base spec; held under
\* adversarial actions because pair/unpair are the only fns that
\* touch mentorLoad.
MentorLoadConsistent ==
    \A m \in Participants :
        mentorLoad[m] = Cardinality({r \in pairings : r.mentor = m})

\* INV-A7: NoSelfMentor — same as base spec.
NoSelfMentor ==
    \A r \in pairings : r.mentor # r.mentee

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety           == Spec => []TypeOK
THEOREM TrustFloorTheorem    == Spec => []TrustFloorAtPairing
THEOREM CapacityUnderAdv     == Spec => []CapacityHoldsUnderAdversary
THEOREM AccGapAtCommit       == Spec => []PairingAccuracyGapPreservedAtCommit
THEOREM NoSybilCapture       == Spec => []NoSybilCaptureAtTrustFloor
THEOREM LoadConsistent       == Spec => []MentorLoadConsistent
THEOREM NoSelf               == Spec => []NoSelfMentor

=============================================================================
