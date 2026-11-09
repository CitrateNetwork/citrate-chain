------------------------------ MODULE negative ------------------------------
\* Fixture (tla-frame, negative): frames that are correct, and text that only looks like a
\* clash. Nothing here may be reported.
VARIABLES x, y, mode
vars == <<x, y, mode>>

Open == /\ mode' = "Open" /\ UNCHANGED <<x, y>>

Clean ==
    /\ x' = 1
    /\ UNCHANGED <<y, mode>>

\* disjuncts are alternatives, never siblings
Alternatives ==
    \/ /\ x' = 1
       /\ UNCHANGED <<y, mode>>
    \/ /\ y' = 1
       /\ UNCHANGED <<x, mode>>

\* THEN and ELSE arms are separate conjunction lists
Branches ==
    /\ IF x = 0
       THEN /\ x' = 1
            /\ UNCHANGED <<y, mode>>
       ELSE /\ y' = 1
            /\ UNCHANGED <<x, mode>>

\* a string equal to an operator name ("Open") is not a call of that operator
GuardOnString ==
    /\ mode = "Open"
    /\ UNCHANGED vars

\* commented-out frames do not count:  /\ x' = 2  /\ UNCHANGED x
(* Block == /\ x' = 3
            /\ UNCHANGED <<x>> *)

Stutter == UNCHANGED vars

Spec == x = 0 /\ [][Clean \/ Alternatives \/ Branches]_vars
=============================================================================
