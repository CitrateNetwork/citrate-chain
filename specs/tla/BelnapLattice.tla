------------------------------ MODULE BelnapLattice ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the four-valued Belnap logic lattice used in paraconsensus.
\* Exhaustively verifies all lattice axioms across the 4x4 = 16 element combinations.
\* Source: core/learning/src/belnap.rs — BelnapValue, join(), meet(), negation()

CONSTANTS
    BelnapValues    \* The four values: {Neither, True, False, Both}

ASSUME BelnapValues = {"Neither", "True", "False", "Both"}

VARIABLES
    checked     \* Monotonically increasing set of checked pairs (for liveness / progress)

vars == <<checked>>

\* ---- Lattice operators ----

\* Knowledge-ordering join (least upper bound under ≤k).
\* Combines information: the result knows at least as much as either input.
\* Corresponds to BelnapValue::join() in belnap.rs.
Join(a, b) ==
    IF a = b THEN a
    ELSE IF a = "Neither" THEN b
    ELSE IF b = "Neither" THEN a
    ELSE IF a = "Both" THEN "Both"
    ELSE IF b = "Both" THEN "Both"
    ELSE "Both"   \* True+False => Both (disagreement)

\* Knowledge-ordering meet (greatest lower bound under ≤k).
\* Consensus: the result knows only what both inputs agree on.
\* Corresponds to BelnapValue::meet() in belnap.rs.
Meet(a, b) ==
    IF a = b THEN a
    ELSE IF a = "Both" THEN b
    ELSE IF b = "Both" THEN a
    ELSE IF a = "Neither" THEN "Neither"
    ELSE IF b = "Neither" THEN "Neither"
    ELSE "Neither"  \* True+False => Neither (no consensus)

\* Negation: swaps True <-> False, Both and Neither are self-dual.
\* Corresponds to BelnapValue::negation() in belnap.rs.
Negation(a) ==
    IF a = "True" THEN "False"
    ELSE IF a = "False" THEN "True"
    ELSE a    \* Both and Neither are fixed points

\* Knowledge ordering level: Neither=0, True=1, False=1, Both=2
KLevel(a) ==
    IF a = "Neither" THEN 0
    ELSE IF a = "Both" THEN 2
    ELSE 1

\* Knowledge ordering: a ≤k b
KLeq(a, b) ==
    \/ a = b
    \/ a = "Neither"
    \/ b = "Both"

\* ---- State machine ----

\* The state space is trivial — we use a single step to mark completion.
\* All properties are checked as state invariants over the constant domain.

Init ==
    /\ checked = {}

\* Non-deterministically check a pair to allow TLC to explore
CheckPair(a, b) ==
    /\ <<a, b>> \notin checked
    /\ checked' = checked \cup {<<a, b>>}

Next ==
    \E a \in BelnapValues, b \in BelnapValues : CheckPair(a, b)

\* ---- Invariants (lattice axioms) ----

\* All invariants are universally quantified over the constant set BelnapValues,
\* so TLC checks them exhaustively on every reachable state.

\* INV-1: Join is commutative
JoinCommutative ==
    \A a \in BelnapValues : \A b \in BelnapValues :
        Join(a, b) = Join(b, a)

\* INV-2: Join is associative
JoinAssociative ==
    \A a \in BelnapValues : \A b \in BelnapValues : \A c \in BelnapValues :
        Join(Join(a, b), c) = Join(a, Join(b, c))

\* INV-3: Join is idempotent
JoinIdempotent ==
    \A a \in BelnapValues :
        Join(a, a) = a

\* INV-4: Meet is commutative
MeetCommutative ==
    \A a \in BelnapValues : \A b \in BelnapValues :
        Meet(a, b) = Meet(b, a)

\* INV-5: Meet is associative
MeetAssociative ==
    \A a \in BelnapValues : \A b \in BelnapValues : \A c \in BelnapValues :
        Meet(Meet(a, b), c) = Meet(a, Meet(b, c))

\* INV-6: Meet is idempotent
MeetIdempotent ==
    \A a \in BelnapValues :
        Meet(a, a) = a

\* INV-7: Negation is an involution (double negation = identity)
NegationInvolution ==
    \A a \in BelnapValues :
        Negation(Negation(a)) = a

\* INV-8: Knowledge ordering — join only increases information.
\* Join(a, b) ≥k a AND Join(a, b) ≥k b
KnowledgeOrdering ==
    \A a \in BelnapValues : \A b \in BelnapValues :
        /\ KLeq(a, Join(a, b))
        /\ KLeq(b, Join(a, b))

\* INV-9: Absorption law 1 — Join(a, Meet(a, b)) = a
AbsorptionJoinMeet ==
    \A a \in BelnapValues : \A b \in BelnapValues :
        Join(a, Meet(a, b)) = a

\* INV-10: Absorption law 2 — Meet(a, Join(a, b)) = a
AbsorptionMeetJoin ==
    \A a \in BelnapValues : \A b \in BelnapValues :
        Meet(a, Join(a, b)) = a

\* INV-11: Neither is the identity for Join (bottom of knowledge ordering)
JoinIdentity ==
    \A a \in BelnapValues :
        Join(a, "Neither") = a

\* INV-12: Both is the identity for Meet (top of knowledge ordering)
MeetIdentity ==
    \A a \in BelnapValues :
        Meet(a, "Both") = a

\* INV-13: Join and Meet produce valid Belnap values
ClosedUnderOps ==
    \A a \in BelnapValues : \A b \in BelnapValues :
        /\ Join(a, b) \in BelnapValues
        /\ Meet(a, b) \in BelnapValues
        /\ Negation(a) \in BelnapValues

\* INV-14: Type invariant
TypeOK ==
    checked \subseteq (BelnapValues \X BelnapValues)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM Types == Spec => []TypeOK
THEOREM JoinComm == Spec => []JoinCommutative
THEOREM JoinAssoc == Spec => []JoinAssociative
THEOREM JoinIdem == Spec => []JoinIdempotent
THEOREM MeetComm == Spec => []MeetCommutative
THEOREM MeetAssoc == Spec => []MeetAssociative
THEOREM MeetIdem == Spec => []MeetIdempotent
THEOREM NegInvol == Spec => []NegationInvolution
THEOREM KnowledgeOrder == Spec => []KnowledgeOrdering
THEOREM AbsJM == Spec => []AbsorptionJoinMeet
THEOREM AbsMJ == Spec => []AbsorptionMeetJoin
THEOREM JoinId == Spec => []JoinIdentity
THEOREM MeetId == Spec => []MeetIdentity
THEOREM Closed == Spec => []ClosedUnderOps

=============================================================================
