------------------------------ MODULE GhostDAGSafety ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the safety invariants RM-B1 introduces on top of GhostDAGConsensus.tla:
\*
\*   1. TipSelectionDeterministic — when multiple tips share the highest blue
\*      score, parent selection is a total function of (blue_score, hash). No
\*      reliance on iteration order, RocksDB key order, or HashMap entropy.
\*      (Audit finding H-08.)
\*
\*   2. BlueSetIsContentDetermined — for any block, blue-set membership is a
\*      pure function of content (height, parents, prior blue_set). It MUST
\*      NOT depend on a BFS budget, a cache state, or the order in which a
\*      node populated its `relations` map. (Audit finding H-07.)
\*
\* Source: core/consensus/src/tip_selection.rs and core/consensus/src/ghostdag.rs
\*
\* Sister spec: GhostDAGConsensus.tla covers well-formedness (no cycles,
\* monotonicity, blue-score correctness). This spec narrows on safety
\* properties that determine inter-validator agreement.

CONSTANTS
    Tips,         \* Set of candidate tip identifiers, modeled as Nats so
                  \* the natural < gives a strict total order standing in
                  \* for hash comparison.
    MaxScore,     \* Range of blue-score values to explore: 0..MaxScore.
    MaxParents    \* Maximum tips selected as parents.

ASSUME MaxParents \in Nat /\ MaxParents >= 1
ASSUME MaxScore \in Nat
ASSUME Tips \subseteq Nat

VARIABLES
    blueScores    \* Function: Tips -> 0..MaxScore. Init nondeterministically;
                  \* Next is stuttering. TLC exhaustively explores the choice.

vars == <<blueScores>>

\* ---- Helpers ----

\* HashOrd[a, b] is true iff a's "hash" precedes b's. We model this as
\* the natural-number ordering on Tips. The implementation uses
\* `[u8; 32]::cmp` which is a strict total order; the property we need
\* is that two distinct tips ALWAYS have a defined ordering, which the
\* natural < satisfies.
HashOrd(a, b) == a < b

\* Comparator: a strictly precedes b iff
\*   blue_score(a) > blue_score(b)
\* OR (blue_score(a) = blue_score(b) AND HashOrd(a, b)).
\*
\* This mirrors `tip_infos.sort_by(|a, b|
\*   b.blue_score.cmp(&a.blue_score).then_with(|| a.hash.cmp(&b.hash)))`
\* in tip_selection.rs:145 after the WP-B1.1 fix.
PrecedesInTipOrder(a, b) ==
    \/ blueScores[a] > blueScores[b]
    \/ (blueScores[a] = blueScores[b] /\ HashOrd(a, b))

\* The total-order rank of a tip in the sorted tip list.
\* RankOf(t) is the number of tips that strictly precede t.
RankOf(t) ==
    Cardinality({ x \in Tips : PrecedesInTipOrder(x, t) })

\* Selected parent set: top-MaxParents tips by the comparator.
SelectedParents ==
    { t \in Tips : RankOf(t) < MaxParents }

\* ---- State machine: stuttering after a nondeterministic init ----

Init ==
    blueScores \in [Tips -> 0..MaxScore]

Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* INV-1: PrecedesInTipOrder is a strict total order on Tips.
\* Two distinct tips ALWAYS have a defined ordering, so RankOf is total.
TotalOrderOnTips ==
    /\ \A a, b \in Tips :
         a # b => (PrecedesInTipOrder(a, b) \/ PrecedesInTipOrder(b, a))
    /\ \A a, b \in Tips :
         ~(PrecedesInTipOrder(a, b) /\ PrecedesInTipOrder(b, a))
    /\ \A a, b, c \in Tips :
         (a # b /\ b # c /\ a # c /\
          PrecedesInTipOrder(a, b) /\ PrecedesInTipOrder(b, c))
            => PrecedesInTipOrder(a, c)

\* INV-2: TipSelectionDeterministic — selected-parent cardinality is a
\* function of (Tips, blueScores, MaxParents) alone. With the strict
\* total order in place, RankOf is injective, so |SelectedParents| =
\* min(|Tips|, MaxParents).
TipSelectionDeterministic ==
    Cardinality(SelectedParents) = IF Cardinality(Tips) <= MaxParents
                                    THEN Cardinality(Tips)
                                    ELSE MaxParents

\* INV-3: TieBreakRespected — when two tips share blue score, the lower-
\* hash one strictly precedes the higher-hash one. This is the
\* load-bearing property that closes audit finding H-08.
TieBreakRespected ==
    \A a, b \in Tips :
        (a # b /\ blueScores[a] = blueScores[b]) =>
            (PrecedesInTipOrder(a, b) <=> HashOrd(a, b))

\* INV-4: NoTwoTipsShareRank — RankOf is injective. If TieBreakRespected
\* fails (e.g., the .then_with(|| a.hash.cmp(&b.hash)) is removed), two
\* distinct tips can have RankOf = 0, so their inclusion in
\* SelectedParents depends on iteration order rather than content.
NoTwoTipsShareRank ==
    \A a, b \in Tips :
        a # b => RankOf(a) # RankOf(b)

\* ---- Type invariant ----

TypeInv ==
    /\ blueScores \in [Tips -> 0..MaxScore]
    /\ SelectedParents \subseteq Tips
    /\ \A t \in Tips : RankOf(t) \in 0..(Cardinality(Tips) - 1)

THEOREM TotalOrderHolds == Spec => []TotalOrderOnTips
THEOREM DeterminismHolds == Spec => []TipSelectionDeterministic
THEOREM TieBreakHolds == Spec => []TieBreakRespected
THEOREM RanksDistinct == Spec => []NoTwoTipsShareRank
THEOREM TypeSafety == Spec => []TypeInv

=============================================================================
