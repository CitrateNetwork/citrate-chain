------------------------------ MODULE positive ------------------------------
\* Fixture (tla-frame, positive): every marked line keeps a variable UNCHANGED that a
\* sibling conjunct of the same action assigns, so the action only fires when the new value
\* equals the old one. Each marked line must be reported.
VARIABLES x, y, mode
vars == <<x, y, mode>>
pair == <<x, y>>

Helper == x' = x + 1

AssignBesideUnchanged ==
    /\ x' = 0
    /\ UNCHANGED <<x, y, mode>>                \* FLAG

ThroughAlias ==
    /\ y' = 1
    /\ mode' = "on"
    /\ UNCHANGED pair                          \* FLAG

NestedAlias ==
    /\ mode' = "off"
    /\ UNCHANGED vars                          \* FLAG

ThroughHelper(i) ==
    /\ Helper
    /\ y' = i
    /\ UNCHANGED <<x, mode>>                   \* FLAG

MultiLine ==
    /\ y' = 2
    /\ UNCHANGED <<x,                          \* FLAG
                  y, mode>>

NestedBranch ==
    /\ x' = 1
    /\ IF y = 0                              \* FLAG
       THEN UNCHANGED <<x, y, mode>>
       ELSE /\ y' = 1
            /\ UNCHANGED mode
=============================================================================
