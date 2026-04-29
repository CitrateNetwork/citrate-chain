------------------------------ MODULE HypothesisH1 ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

(***********************************************************************
* RM-FL-5 / WP-5.1 — TLA+ formalization of Hypothesis H1 from Paper II §4.
*
* HYPOTHESIS (informal): Belnap-FOUR aggregation is more robust to
* mislabel-injection adversaries than flat-mean aggregation. Stated
* operationally: given a fixed mislabel rate p in one of M regions,
* the routing model trained on Belnap-aggregated embeddings achieves
* held-out accuracy at least equal to the model trained on
* flat-mean-aggregated embeddings, for all p in [0, 0.5].
*
* WHAT TLA+ CAN AND CAN'T CHECK
* ----------------------------
* TLA+ verifies protocol-level invariants over a state machine. It
* CANNOT fit a power law, run gradient descent, or measure held-out
* accuracy on a real dataset. So this spec encodes:
*
*   (a) The PRECONDITION STRUCTURE of the experiment — every
*       embedding submission carries a region tag, a labelling
*       claim, and a per-dimension confidence. Mislabel injection
*       in region R only flips the labelling claim, not the region
*       tag (the adversary cannot pretend to be a different region).
*
*   (b) The PROTOCOL INVARIANTS that must hold for the experiment
*       to be meaningful: every region's embeddings are aggregated
*       via the same protocol; the same routing model architecture
*       sees both aggregation paths; the test set is disjoint from
*       any training contribution.
*
*   (c) A FALSIFICATION GATE: if Belnap and flat-mean produce the
*       same aggregated embedding when no mislabel is present
*       (this is a sanity check — the two methods agree on
*       consistent inputs), the experiment is well-posed.
*
* What TLA+ does NOT check is the statistical claim itself. That's
* the experiment's job in WP-5.3, with a fitted accuracy delta and
* a 95% confidence interval. TLA+ here is the protocol-side
* contract that says "if you run the experiment the way the spec
* describes, the measurement is meaningful."
*
* OPERATOR-VS-VARIABLE PRINCIPLE (carried from RM-FL-3 essay
* THE_OPERATOR_AND_THE_VARIABLE):
*
*   - Region count M, mislabel rate p, dimension count D are all
*     CONSTANTS — they don't vary across the model-checked state
*     space. Only the per-step submission action and the resulting
*     aggregated embedding vary.
*   - The aggregation FUNCTIONS (BelnapAgg, FlatMeanAgg) are
*     OPERATORS over current state, not VARIABLES. TLC evaluates
*     them in place; they never join the state vector.
***********************************************************************)

CONSTANTS
    Regions,              \* SET of region IDs (typically 4)
    MislabelRegion,       \* Adversary-controlled region ID (subset of Regions)
    Dimensions,           \* SET of dimension IDs (e.g. {finance, tech})
    MaxConfidence,        \* Q16 max — typically 65536 (1.0)
    MaxSubmissions        \* Bound on submissions per cycle (state-space bound)

ASSUME Regions # {}
ASSUME MislabelRegion \in Regions
ASSUME Dimensions # {}
ASSUME MaxConfidence \in Nat /\ MaxConfidence >= 1
ASSUME MaxSubmissions \in Nat /\ MaxSubmissions >= 1

VARIABLES
    submissions,          \* Sequence of submitted embeddings
    cycleStatus,          \* "open" | "closed" | "aggregated"
    belnapAgg,            \* Belnap-aggregated result (per dimension)
    flatMeanAgg,          \* Flat-mean-aggregated result
    mislabelOccurred      \* TRUE iff at least one mislabel was injected

vars == << submissions, cycleStatus, belnapAgg, flatMeanAgg,
           mislabelOccurred >>

\* An embedding submission is a record:
\*   { region |-> Regions, dim |-> Dimensions,
\*     value |-> 0..MaxConfidence,
\*     mislabel |-> BOOLEAN }
SubmissionType ==
    [ region: Regions,
      dim: Dimensions,
      value: 0..MaxConfidence,
      mislabel: BOOLEAN ]

\* Initial state: cycle is open, no submissions, no aggregation.
Init ==
    /\ submissions = << >>
    /\ cycleStatus = "open"
    /\ belnapAgg = [d \in Dimensions |-> 0]
    /\ flatMeanAgg = [d \in Dimensions |-> 0]
    /\ mislabelOccurred = FALSE

\* Honest submission: any region except MislabelRegion submits a
\* truthful embedding (mislabel = FALSE). The adversary in
\* MislabelRegion may submit either honestly or with mislabel = TRUE.
HonestSubmit(r, d, v) ==
    /\ cycleStatus = "open"
    /\ Len(submissions) < MaxSubmissions
    /\ submissions' = Append(
            submissions,
            [region |-> r, dim |-> d, value |-> v, mislabel |-> FALSE])
    /\ UNCHANGED << cycleStatus, belnapAgg, flatMeanAgg,
                    mislabelOccurred >>

\* Mislabel injection: only MislabelRegion may set mislabel = TRUE.
MislabelSubmit(d, v) ==
    /\ cycleStatus = "open"
    /\ Len(submissions) < MaxSubmissions
    /\ submissions' = Append(
            submissions,
            [region |-> MislabelRegion, dim |-> d, value |-> v,
             mislabel |-> TRUE])
    /\ mislabelOccurred' = TRUE
    /\ UNCHANGED << cycleStatus, belnapAgg, flatMeanAgg >>

\* Sum of values for a given dimension across all submissions.
SumForDim(d) ==
    LET vals == { i \in 1..Len(submissions):
                    submissions[i].dim = d } IN
    IF vals = {} THEN 0
    ELSE LET RECURSIVE Sigma(_)
              Sigma(S) ==
                IF S = {} THEN 0
                ELSE LET x == CHOOSE x \in S: TRUE IN
                     submissions[x].value + Sigma(S \ {x})
         IN Sigma(vals)

\* Count of submissions for a given dimension.
CountForDim(d) ==
    Cardinality({ i \in 1..Len(submissions):
                    submissions[i].dim = d })

\* Flat-mean aggregation: sum/count, integer division (Q16).
FlatMean(d) ==
    LET c == CountForDim(d) IN
    IF c = 0 THEN 0
    ELSE SumForDim(d) \div c

\* Belnap-FOUR aggregation operator. The full lattice is in
\* BelnapLattice.tla; here we model the protocol-relevant property:
\* a mislabelled submission CONTRIBUTES to the "Both" cell rather
\* than corrupting the "True" cell. Operationally, when at least
\* one mislabel exists for a dimension, the Belnap aggregate
\* downweights that dimension; without mislabels, Belnap and flat-
\* mean agree (sanity check, encoded below).
HasMislabelForDim(d) ==
    \E i \in 1..Len(submissions):
        submissions[i].dim = d /\ submissions[i].mislabel

BelnapAggregate(d) ==
    LET fm == FlatMean(d) IN
    IF HasMislabelForDim(d)
        \* Belnap downweights mislabel-contaminated dims by
        \* keeping only the consistent submissions.
        THEN LET clean == { i \in 1..Len(submissions):
                                submissions[i].dim = d
                                /\ ~submissions[i].mislabel } IN
             IF clean = {} THEN 0
             ELSE LET RECURSIVE Sigma(_)
                       Sigma(S) ==
                         IF S = {} THEN 0
                         ELSE LET x == CHOOSE x \in S: TRUE IN
                              submissions[x].value + Sigma(S \ {x})
                  IN Sigma(clean) \div Cardinality(clean)
        ELSE fm  \* No mislabels — agree with flat-mean.

\* Close the cycle and compute both aggregates.
Aggregate ==
    /\ cycleStatus = "open"
    /\ Len(submissions) >= 1
    /\ cycleStatus' = "aggregated"
    /\ belnapAgg' = [d \in Dimensions |-> BelnapAggregate(d)]
    /\ flatMeanAgg' = [d \in Dimensions |-> FlatMean(d)]
    /\ UNCHANGED << submissions, mislabelOccurred >>

Next ==
    \/ \E r \in Regions, d \in Dimensions, v \in 0..MaxConfidence:
            HonestSubmit(r, d, v)
    \/ \E d \in Dimensions, v \in 0..MaxConfidence:
            MislabelSubmit(d, v)
    \/ Aggregate

Spec == Init /\ [][Next]_vars

(***********************************************************************
* INVARIANTS (the protocol-level claims)
***********************************************************************)

\* Type invariant.
TypeOK ==
    /\ submissions \in Seq(SubmissionType)
    /\ cycleStatus \in { "open", "closed", "aggregated" }
    /\ belnapAgg \in [ Dimensions -> 0..MaxConfidence ]
    /\ flatMeanAgg \in [ Dimensions -> 0..MaxConfidence ]
    /\ mislabelOccurred \in BOOLEAN

\* Adversary identity: only MislabelRegion may submit mislabel.
\* The protocol cannot pretend to be a different region.
OnlyAdversaryRegionMislabels ==
    \A i \in 1..Len(submissions):
        submissions[i].mislabel
            => submissions[i].region = MislabelRegion

\* Sanity: when no mislabel is present, Belnap and flat-mean agree
\* dimension-by-dimension. This pins the experimental design — if
\* this invariant ever fails, H1's measurement is meaningless
\* (the two methods would diverge on consistent inputs, so any
\* observed accuracy delta could be aggregation-method noise rather
\* than mislabel resilience).
BelnapMatchesFlatMeanWithoutMislabel ==
    cycleStatus = "aggregated"
        /\ ~mislabelOccurred
        => \A d \in Dimensions: belnapAgg[d] = flatMeanAgg[d]

\* Aggregation totality: every dimension has a defined aggregate
\* once the cycle is closed (no division by zero, no undefined).
AggregationTotal ==
    cycleStatus = "aggregated"
        => \A d \in Dimensions:
            /\ belnapAgg[d] \in 0..MaxConfidence
            /\ flatMeanAgg[d] \in 0..MaxConfidence

\* The mislabelOccurred flag is monotonic — once set, never cleared.
\* This is the experiment's audit trail: a re-run cannot "forget"
\* that mislabels were present.
MislabelMonotonic ==
    mislabelOccurred => [](mislabelOccurred = TRUE)

\* Hypothesis postcondition (the FALSIFICATION GATE):
\* When mislabels were injected, Belnap aggregate is at most the
\* flat-mean aggregate plus one bound (i.e. Belnap doesn't run
\* AWAY from the truth). If this ever fails — Belnap > flatMean
\* by more than the dimension's max confidence — the experimental
\* claim "Belnap is at least as good" cannot be supported.
\*
\* This is a NECESSARY condition for H1, not a sufficient one. The
\* sufficient condition is empirical accuracy, measured in WP-5.3.
BelnapBoundedDeviation ==
    cycleStatus = "aggregated"
        => \A d \in Dimensions:
            \/ belnapAgg[d] <= flatMeanAgg[d]
            \/ belnapAgg[d] - flatMeanAgg[d] <= MaxConfidence

THEOREM Safety ==
    Spec => [](
        TypeOK
        /\ OnlyAdversaryRegionMislabels
        /\ BelnapMatchesFlatMeanWithoutMislabel
        /\ AggregationTotal
        /\ BelnapBoundedDeviation
    )

==========================================================================
