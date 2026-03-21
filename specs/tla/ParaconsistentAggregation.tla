--------------------- MODULE ParaconsistentAggregation ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models dual-output paraconsistent aggregation from
\* core/learning/src/aggregation.rs.
\*
\* The ParaconsistentAggregator produces two independent outputs:
\*   1. An aggregated embedding (confidence-and-trust-weighted mean)
\*   2. A Belnap state vector capturing epistemic agreement structure
\*
\* Belnap four-valued logic: {True, False, Both, Neither}
\*   - True: confident agreement among participants
\*   - False: confident agreement on opposite direction
\*   - Both: paraconsistent disagreement (conflicting high-confidence)
\*   - Neither: insufficient evidence (low confidence)
\*
\* Source: core/learning/src/aggregation.rs
\*   - ParaconsistentAggregator::aggregate_paraconsistent
\*   - AggregationResult, AggregationInput
\*   - belnap::classify_belnap, belnap::reduce_belnap_states, belnap::softmax_weights

CONSTANTS
    MaxParticipants,    \* Maximum number of participants
    MaxDim,             \* Maximum embedding dimensionality
    BelnapValues        \* {"True", "False", "Both", "Neither"}

ASSUME MaxParticipants \in Nat /\ MaxParticipants >= 1
ASSUME MaxDim \in Nat /\ MaxDim >= 1
ASSUME BelnapValues = {"True", "False", "Both", "Neither"}

VARIABLES
    numParticipants,    \* Current number of participants (1..MaxParticipants)
    dim,                \* Current embedding dimensionality (1..MaxDim)
    inputs,             \* Sequence of participant inputs: [embedding_sign, confidence, weight]
                        \*   embedding_sign: per-dim "pos"|"neg" (abstract direction)
                        \*   confidence: per-dim "high"|"low"
                        \*   weight: "positive"|"zero"
    aggregated,         \* Result: [stateVector, confidenceLevel]
                        \*   stateVector: sequence of BelnapValues (length = dim)
                        \*   confidenceLevel: "high"|"low"|"zero"
    phase               \* "init"|"collecting"|"aggregated"

vars == <<numParticipants, dim, inputs, aggregated, phase>>

\* ---- Belnap join lattice ----
\* The lattice order: Neither < True, Neither < False, True < Both, False < Both
\* Join (least upper bound) operator:
BelnapJoin(a, b) ==
    IF a = b THEN a
    ELSE IF a = "Neither" THEN b
    ELSE IF b = "Neither" THEN a
    ELSE "Both"  \* True join False = Both, anything else = Both

\* Classify a single participant's single dimension.
\* Based on belnap::classify_belnap: high confidence + positive = True,
\* high confidence + negative = False, low confidence = Neither.
ClassifyDim(sign, conf) ==
    IF conf = "low" THEN "Neither"
    ELSE IF sign = "pos" THEN "True"
    ELSE "False"

\* Reduce a set of per-participant classifications to a single Belnap value.
ReduceDim(classifications) ==
    IF classifications = <<>> THEN "Neither"
    ELSE LET RECURSIVE Fold(_, _)
             Fold(seq, acc) ==
                IF seq = <<>> THEN acc
                ELSE Fold(Tail(seq), BelnapJoin(acc, Head(seq)))
         IN Fold(Tail(classifications), Head(classifications))

\* ---- State machine ----

Init ==
    /\ numParticipants = 0
    /\ dim = 1
    /\ inputs = <<>>
    /\ aggregated = [stateVector |-> <<>>, confidenceLevel |-> "zero"]
    /\ phase = "init"

\* Set the dimensionality for this aggregation round.
SetDimension(d) ==
    /\ phase = "init"
    /\ d \in 1..MaxDim
    /\ dim' = d
    /\ phase' = "collecting"
    /\ UNCHANGED <<numParticipants, inputs, aggregated>>

\* Add a participant input.
AddParticipant(signs, confs, w) ==
    /\ phase = "collecting"
    /\ numParticipants < MaxParticipants
    /\ Len(signs) = dim
    /\ Len(confs) = dim
    /\ \A i \in 1..dim : signs[i] \in {"pos", "neg"}
    /\ \A i \in 1..dim : confs[i] \in {"high", "low"}
    /\ w \in {"positive", "zero"}
    /\ LET entry == [signs |-> signs, confs |-> confs, weight |-> w]
       IN inputs' = Append(inputs, entry)
    /\ numParticipants' = numParticipants + 1
    /\ UNCHANGED <<dim, aggregated, phase>>

\* Perform aggregation: compute state vector and confidence.
Aggregate ==
    /\ phase = "collecting"
    /\ numParticipants >= 1
    \* Compute per-dimension state vector via Belnap join reduction.
    /\ LET
           \* For each dimension j, classify all participants and reduce.
           stateVec == [j \in 1..dim |->
               LET classifications == [i \in 1..numParticipants |->
                       IF inputs[i].weight = "zero"
                       THEN "Neither"  \* Zero weight contributes nothing
                       ELSE ClassifyDim(inputs[i].signs[j], inputs[i].confs[j])]
                   classSeq == [k \in 1..numParticipants |-> classifications[k]]
               IN ReduceDim(classSeq)]

           \* Confidence level: high if any participant has positive weight + high confidence
           hasHighConf == \E i \in 1..numParticipants :
                            inputs[i].weight = "positive" /\
                            \E j \in 1..dim : inputs[i].confs[j] = "high"
           confLevel == IF hasHighConf THEN "high" ELSE "low"

       IN aggregated' = [stateVector |-> stateVec,
                         confidenceLevel |-> confLevel]
    /\ phase' = "aggregated"
    /\ UNCHANGED <<numParticipants, dim, inputs>>

Next ==
    \/ \E d \in 1..MaxDim : SetDimension(d)
    \/ \E signs \in [1..dim -> {"pos", "neg"}],
         confs \in [1..dim -> {"high", "low"}],
         w \in {"positive", "zero"} :
            AddParticipant(signs, confs, w)
    \/ Aggregate

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ numParticipants \in 0..MaxParticipants
    /\ dim \in 1..MaxDim
    /\ phase \in {"init", "collecting", "aggregated"}
    /\ Len(inputs) = numParticipants

\* INV-2: DimensionConsistency — all inputs have the declared dimensionality.
DimensionConsistency ==
    \A i \in 1..Len(inputs) :
        /\ Len(inputs[i].signs) = dim
        /\ Len(inputs[i].confs) = dim

\* INV-3: StateVectorCanonical — state vector length matches dim when aggregated.
StateVectorCanonical ==
    phase = "aggregated" =>
        /\ aggregated.stateVector \in [1..dim -> BelnapValues]

\* INV-4: ConfidenceBounded — confidence level is always in the valid set.
ConfidenceBounded ==
    aggregated.confidenceLevel \in {"high", "low", "zero"}

\* INV-5: BelnapJoinIdempotent — joining a value with itself yields itself.
BelnapJoinIdempotent ==
    \A v \in BelnapValues : BelnapJoin(v, v) = v

\* INV-6: BelnapJoinCommutative — join is commutative.
BelnapJoinCommutative ==
    \A a, b \in BelnapValues : BelnapJoin(a, b) = BelnapJoin(b, a)

\* INV-7: NeitherIsBottom — Neither join X = X (Neither is the lattice bottom).
NeitherIsBottom ==
    \A v \in BelnapValues : BelnapJoin("Neither", v) = v

\* INV-8: AgreementProducesTrue — if all high-confidence participants agree on
\* positive direction at some dimension, the state vector has True there.
AgreementProducesTrue ==
    phase = "aggregated" =>
        \A j \in 1..dim :
            (\A i \in 1..numParticipants :
                inputs[i].weight = "positive" =>
                    (inputs[i].confs[j] = "high" /\ inputs[i].signs[j] = "pos"))
            /\ (\E i \in 1..numParticipants : inputs[i].weight = "positive")
            => aggregated.stateVector[j] = "True"

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM DimConsistent == Spec => []DimensionConsistency
THEOREM StateVecCanonical == Spec => []StateVectorCanonical
THEOREM ConfBounded == Spec => []ConfidenceBounded
THEOREM JoinIdempotent == Spec => []BelnapJoinIdempotent
THEOREM JoinCommutative == Spec => []BelnapJoinCommutative
THEOREM NeitherBottom == Spec => []NeitherIsBottom

=============================================================================
