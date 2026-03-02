------------------------------ MODULE GhostDAGConsensus ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models GhostDAG consensus: block addition, blue set calculation (k-cluster rule),
\* tip selection, and merge-parent classification.
\* Source: core/consensus/src/ghostdag.rs

CONSTANTS
    Blocks,       \* Set of possible block IDs (including "genesis")
    K,            \* GhostDAG k-cluster parameter
    MaxParents    \* Maximum number of parents per block

ASSUME "genesis" \in Blocks
ASSUME K \in Nat /\ K >= 1
ASSUME MaxParents \in Nat /\ MaxParents >= 1

VARIABLES
    addedBlocks,      \* Set of blocks currently in the DAG
    parents,          \* Function: block -> set of parent blocks (selected + merge)
    selectedParent,   \* Function: block -> selected parent block
    blueSet,          \* Function: block -> set of blocks considered blue relative to it
    blueScore,        \* Function: block -> blue score (|blueSet|)
    tips              \* Set of current tip blocks (no children)

vars == <<addedBlocks, parents, selectedParent, blueSet, blueScore, tips>>

\* ---- Helper operators ----

\* Past set: all ancestors of a block (transitive closure of parents)
RECURSIVE PastOf(_, _)
PastOf(b, depth) ==
    IF depth = 0 \/ b = "genesis" \/ b \notin addedBlocks
    THEN {}
    ELSE
        LET ps == IF b \in DOMAIN parents THEN parents[b] ELSE {} IN
        ps \cup UNION { PastOf(p, depth - 1) : p \in ps }

Past(b) == PastOf(b, Cardinality(Blocks))

\* Anticone: blocks not in past of b and b not in their past
Anticone(b) ==
    { x \in addedBlocks : x # b /\ x \notin Past(b) /\ b \notin Past(x) }

\* Blue anticone: anticone members that are blue relative to some context
BlueAnticone(candidate, contextBlue) ==
    Anticone(candidate) \cap contextBlue

\* K-cluster check: a candidate is blue if its anticone overlap with existing blue set <= K
IsBlueCandidate(candidate, contextBlue) ==
    Cardinality(BlueAnticone(candidate, contextBlue)) <= K

\* ---- State machine ----

Init ==
    /\ addedBlocks = {"genesis"}
    /\ parents = [b \in {"genesis"} |-> {}]
    /\ selectedParent = [b \in {"genesis"} |-> "genesis"]
    /\ blueSet = [b \in {"genesis"} |-> {"genesis"}]
    /\ blueScore = [b \in {"genesis"} |-> 1]
    /\ tips = {"genesis"}

\* Add a new block to the DAG
AddBlock(b) ==
    /\ b \notin addedBlocks                       \* Not already added
    /\ b # "genesis"                               \* Genesis is pre-added
    /\ \E ps \in SUBSET addedBlocks :             \* Choose parent set from existing blocks
        /\ ps # {}                                 \* At least one parent
        /\ Cardinality(ps) <= MaxParents           \* Respect max parents
        /\ \E sp \in ps :                          \* Choose selected parent (highest blue score)
            /\ \A other \in ps : blueScore[sp] >= blueScore[other]
            \* Compute blue set for new block
            /\ LET
                spBlue == blueSet[sp]
                \* Check which merge parents (ps \ {sp}) are blue candidates
                mergeParents == ps \ {sp}
                \* For simplicity in bounded model: merge parents that pass k-cluster
                blueMerge == { mp \in mergeParents : IsBlueCandidate(mp, spBlue) }
                \* New blue set = selected parent's blue set + blue merge parents' blue sets + self
                newBlue == spBlue \cup blueMerge \cup {b}
               IN
                /\ addedBlocks' = addedBlocks \cup {b}
                /\ parents' = [x \in DOMAIN parents \cup {b} |->
                    IF x = b THEN ps ELSE parents[x]]
                /\ selectedParent' = [x \in DOMAIN selectedParent \cup {b} |->
                    IF x = b THEN sp ELSE selectedParent[x]]
                /\ blueSet' = [x \in DOMAIN blueSet \cup {b} |->
                    IF x = b THEN newBlue ELSE blueSet[x]]
                /\ blueScore' = [x \in DOMAIN blueScore \cup {b} |->
                    IF x = b THEN Cardinality(newBlue) ELSE blueScore[x]]
                \* Update tips: new block is a tip; its parents are no longer tips
                /\ tips' = (tips \ ps) \cup {b}

Next == \E b \in Blocks : AddBlock(b)

\* ---- Invariants ----

\* INV-1: No cycles — a block is never in its own past
NoCycles ==
    \A b \in addedBlocks : b \notin Past(b)

\* INV-2: Blue score monotonicity along selected-parent chain
\* A block's blue score is always >= its selected parent's blue score
BlueScoreMonotonicity ==
    \A b \in addedBlocks :
        b # "genesis" /\ b \in DOMAIN selectedParent =>
            blueScore[b] >= blueScore[selectedParent[b]]

\* INV-3: Tip consistency — tips have no children in the DAG
TipConsistency ==
    \A t \in tips :
        ~(\E b \in addedBlocks : b # t /\ t \in parents[b])

\* INV-4: Genesis is always blue in every block's blue set
GenesisAlwaysBlue ==
    \A b \in addedBlocks : "genesis" \in blueSet[b]

\* INV-5: Blue score equals blue set cardinality
BlueScoreCorrectness ==
    \A b \in addedBlocks : blueScore[b] = Cardinality(blueSet[b])

\* ---- Type invariant ----

TypeInv ==
    /\ addedBlocks \subseteq Blocks
    /\ "genesis" \in addedBlocks
    /\ tips \subseteq addedBlocks
    /\ \A b \in addedBlocks : b \in DOMAIN blueSet
    /\ \A b \in addedBlocks : b \in DOMAIN blueScore
    /\ \A b \in addedBlocks : blueSet[b] \subseteq addedBlocks
    /\ \A b \in addedBlocks : blueScore[b] \in Nat

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeInv
THEOREM CycleFreedom == Spec => []NoCycles
THEOREM Monotonicity == Spec => []BlueScoreMonotonicity
THEOREM TipCorrectness == Spec => []TipConsistency
THEOREM GenesisBlue == Spec => []GenesisAlwaysBlue
THEOREM ScoreCorrectness == Spec => []BlueScoreCorrectness

=============================================================================
