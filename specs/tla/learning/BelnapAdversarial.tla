--------------------- MODULE BelnapAdversarial ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* RM-FL-1 / WP-1.1 — Adversary model for Belnap-FOUR aggregation
\*
\* I64-S1 (2026-06-28): the Q16 backing type widened i32 -> i64 and the
\* 0x0110 wire format went 4-byte -> 8-byte per Q16 value. This spec is
\* UNAFFECTED: it models the lattice classification + state reduction and
\* the adversary's control of validators — properties independent of the
\* integer width or byte encoding. Same TLC run re-certifies i64.
\*
\* Models the per-dimension classification + state-vector reduction step
\* (Paper II §3.1 Definition 5 + §3.2 Algorithm 1 step 3) under an
\* adversary that controls a subset of the validators.
\*
\* This spec complements:
\*   - BelnapLattice.tla            (lattice axioms, complete)
\*   - ParaconsistentAggregation.tla (honest-path aggregation, complete)
\*   - ByzantineDetection.tla       (detector lifecycle, non-overlapping)
\*
\* What this spec adds: the adversary action space + safety invariants
\* that must hold under the Honest Dominance Assumption.
\*
\* Source/target:
\*   - core/learning/src/belnap.rs::classify_belnap (off-chain reference)
\*   - core/execution/src/precompiles/q16/belnap.rs::aggregate (target, WP-1.5)

CONSTANTS
    Validators,         \* Set of validator IDs
    MaxByzantine,       \* Max # of validators allowed in ByzantineSet
    Signs,              \* {"pos", "neg"} — abstract direction symbol
    Confs,              \* {"high", "low"}
    Weights,            \* {"full", "half", "zero"} — abstract weight regime
    GroundTruthSign     \* The honest direction: "pos" or "neg"

ASSUME Validators # {}
ASSUME MaxByzantine \in Nat /\ MaxByzantine >= 0
ASSUME Signs = {"pos", "neg"}
ASSUME Confs = {"high", "low"}
ASSUME Weights = {"full", "half", "zero"}
ASSUME GroundTruthSign \in Signs

\* Belnap state values (single-dim spec — multi-dim follows by induction).
BelnapValues == {"Neither", "True", "False", "Both"}

\* Numeric weight scaling for Honest Dominance Assumption checks.
\* "full" = 2 units, "half" = 1 unit, "zero" = 0 units.
WeightUnits(w) ==
    IF w = "full" THEN 2
    ELSE IF w = "half" THEN 1
    ELSE 0

\* Sentinel default submission used before a validator submits.
\* (TLC requires homogeneous record types; we use a triple of "none"
\*  sentinels rather than a string-or-record union.)
DefaultSign == "none-sign"
DefaultConf == "none-conf"
DefaultWeight == "none-w"

DefaultSubmission ==
    [sign |-> DefaultSign, conf |-> DefaultConf, weight |-> DefaultWeight]

\* Extended domains used in the TypeOK; submission fields can hold the
\* default sentinels until the validator submits.
SignsExt == Signs \cup {DefaultSign}
ConfsExt == Confs \cup {DefaultConf}
WeightsExt == Weights \cup {DefaultWeight}

VARIABLES
    mode,           \* Function: validator -> {"HONEST", "BYZANTINE"}
    submission,     \* Function: validator -> [sign, conf, weight]
    submitted,      \* Function: validator -> BOOLEAN
    state,          \* Aggregated Belnap state (dim=1 abstraction); init "Neither"
    phase           \* "init" | "assigned" | "submitting" | "aggregated"

vars == <<mode, submission, submitted, state, phase>>

\* ---- Sets and helpers ----

HonestSet == { v \in Validators : mode[v] = "HONEST" }
ByzantineSet == { v \in Validators : mode[v] = "BYZANTINE" }

PositiveWeightSubmitted ==
    { v \in Validators :
        submitted[v] /\ submission[v].weight # "zero" /\ submission[v].weight # DefaultWeight }

HighConfSubmitted ==
    { v \in PositiveWeightSubmitted : submission[v].conf = "high" }

\* Sum of weight units across a set of validators that have submitted.
RECURSIVE SumWeights(_)
SumWeights(S) ==
    IF S = {} THEN 0
    ELSE LET v == CHOOSE x \in S : TRUE
             contrib == IF submitted[v] THEN WeightUnits(submission[v].weight) ELSE 0
         IN contrib + SumWeights(S \ {v})

\* Honest Dominance Assumption (HDA): honest weight > Byzantine weight,
\* counting only validators that have submitted with positive weight.
HonestDominance ==
    SumWeights(HonestSet \cap PositiveWeightSubmitted)
        > SumWeights(ByzantineSet \cap PositiveWeightSubmitted)

\* Per-validator side under the ground truth.
\* "agree" = sign matches ground truth, "oppose" = opposite, "absent" = none.
SideOf(v) ==
    IF \neg submitted[v] \/ submission[v].weight = "zero" \/ submission[v].weight = DefaultWeight
        THEN "absent"
    ELSE IF submission[v].sign = GroundTruthSign
        THEN "agree"
    ELSE "oppose"

\* High-confidence positive-weight validators on each side (set form).
HighConfAgreeSet ==
    { v \in HighConfSubmitted : SideOf(v) = "agree" }

HighConfOpposeSet ==
    { v \in HighConfSubmitted : SideOf(v) = "oppose" }

\* ---- Aggregation oracle ----
\*
\* Computes the Belnap state for the single dimension under symbolic
\* semantics. Mirrors the *intent* of belnap.rs::classify_belnap +
\* reduce_belnap_states, abstracting away Q16 numerics. The Q16
\* substrate is verified separately (RM-M2 + Rust property tests).
\*
\* Rules (semantic, at the reduced state-vector level):
\*   - No positive-weight high-conf participant         -> Neither
\*   - All positive-weight high-conf participants agree -> True
\*   - High-conf participants on both sides             -> Both
\*   - The reduced level NEVER outputs False — a single dissenter
\*     becomes Both via the lattice join (Paper II §3.2 step 3).
ComputeAggregateState ==
    IF HighConfAgreeSet = {} /\ HighConfOpposeSet = {}
        THEN "Neither"
    ELSE IF HighConfAgreeSet # {} /\ HighConfOpposeSet = {}
        THEN "True"
    ELSE IF HighConfAgreeSet = {} /\ HighConfOpposeSet # {}
        \* All high-conf participants oppose ground truth. Aggregator
        \* doesn't know ground truth — it sees unanimous high-conf
        \* "oppose" and reports True relative to that observed majority.
        THEN "True"
    ELSE
        \* Both sides have high-conf positive-weight participants.
        "Both"

\* ---- State machine ----

Init ==
    /\ mode \in [Validators -> {"HONEST", "BYZANTINE"}]
    /\ Cardinality(ByzantineSet) <= MaxByzantine
    /\ submission = [v \in Validators |-> DefaultSubmission]
    /\ submitted = [v \in Validators |-> FALSE]
    /\ state = "Neither"
    /\ phase = "assigned"

\* Honest validators submit truthfully aligned with ground truth.
HonestSubmit(v) ==
    /\ phase \in {"assigned", "submitting"}
    /\ v \in HonestSet
    /\ \neg submitted[v]
    /\ \E c \in Confs, w \in Weights :
        /\ submission' = [submission EXCEPT
            ![v] = [sign |-> GroundTruthSign, conf |-> c, weight |-> w]]
        /\ submitted' = [submitted EXCEPT ![v] = TRUE]
    /\ phase' = "submitting"
    /\ UNCHANGED <<mode, state>>

\* Byzantine validators may submit anything.
ByzantineSubmit(v) ==
    /\ phase \in {"assigned", "submitting"}
    /\ v \in ByzantineSet
    /\ \neg submitted[v]
    /\ \E s \in Signs, c \in Confs, w \in Weights :
        /\ submission' = [submission EXCEPT
            ![v] = [sign |-> s, conf |-> c, weight |-> w]]
        /\ submitted' = [submitted EXCEPT ![v] = TRUE]
    /\ phase' = "submitting"
    /\ UNCHANGED <<mode, state>>

\* Aggregate once (or any subset of) validators have submitted. In the
\* real protocol this happens at cycle close; here it can fire at any
\* point, modeling partial-participation aggregation.
Aggregate ==
    /\ phase = "submitting"
    /\ state' = ComputeAggregateState
    /\ phase' = "aggregated"
    /\ UNCHANGED <<mode, submission, submitted>>

Next ==
    \/ \E v \in Validators : HonestSubmit(v)
    \/ \E v \in Validators : ByzantineSubmit(v)
    \/ Aggregate

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ mode \in [Validators -> {"HONEST", "BYZANTINE"}]
    /\ Cardinality(ByzantineSet) <= MaxByzantine
    /\ submitted \in [Validators -> BOOLEAN]
    /\ \A v \in Validators :
        /\ submission[v].sign \in SignsExt
        /\ submission[v].conf \in ConfsExt
        /\ submission[v].weight \in WeightsExt
    /\ state \in BelnapValues
    /\ phase \in {"init", "assigned", "submitting", "aggregated"}

\* INV-2: HonestSafety
\* Under Honest Dominance, if any honest validator has submitted with
\* positive weight + high confidence, the aggregator MUST output True
\* or Both at the reduced state-vector level — never False, never
\* Neither.
HonestSafety ==
    (phase = "aggregated"
     /\ HonestDominance
     /\ \E h \in HonestSet : h \in HighConfSubmitted)
    => state \in {"True", "Both"}

\* INV-3: NoSpontaneousFalseAtReducedLevel
\* Reduction lifts per-participant False into Both at the aggregated
\* level. The reduced output is never False.
NoSpontaneousFalseAtReducedLevel ==
    phase = "aggregated" => state # "False"

\* INV-4: BothRequiresTwoSides
\* Aggregator must NOT report Both unless at least one high-conf
\* positive-weight participant exists on each side.
BothRequiresTwoSides ==
    (phase = "aggregated" /\ state = "Both")
        => /\ HighConfAgreeSet # {}
           /\ HighConfOpposeSet # {}

\* INV-5: NeitherImpliesUnderconfidence
\* Aggregator outputs Neither only when no positive-weight high-conf
\* participant has submitted at all. The adversary cannot "ghost" the
\* cycle if any honest high-conf signal is present.
NeitherImpliesUnderconfidence ==
    (phase = "aggregated" /\ state = "Neither")
        => HighConfSubmitted = {}

\* INV-6: AdversaryCannotFlipUnderHDA
\* Under HDA, an adversary submitting high-conf opposite-side cannot
\* make the reduced output align with the adversary. The aggregator
\* reports Both (genuine paraconsistent disagreement).
AdversaryCannotFlipUnderHDA ==
    (phase = "aggregated"
     /\ HonestDominance
     /\ \E h \in HonestSet : h \in HighConfSubmitted
     /\ \E b \in ByzantineSet : b \in HighConfSubmitted /\ SideOf(b) = "oppose")
    => state = "Both"

\* INV-7: WeightZeroIgnored
\* A validator with weight=zero must not be in the high-conf or
\* positive-weight sets. Operationally, the aggregator filters
\* zero-weight inputs before the per-participant classification step.
WeightZeroIgnored ==
    \A v \in Validators :
        (submitted[v] /\ submission[v].weight = "zero")
            => v \notin HighConfSubmitted /\ v \notin PositiveWeightSubmitted

\* ---- WP-1.8 — Stronger adversarial invariants ----
\*
\* The base 7 invariants pin safety under the existing
\* HonestSubmit/ByzantineSubmit action set. WP-1.8 adds explicit
\* coverage for two strawmen the planset (RM-FL §1.8) names:
\*
\*   1. Coordinated collusion under HDA — already implicit in the
\*      free Byzantine choice over (sign, conf, weight). INV-6
\*      AdversaryCannotFlipUnderHDA already pins the resilience.
\*      INV-8 below adds the contrapositive: honest high-conf cannot
\*      be silently dropped before classification.
\*
\*   2. Worst-case all-Byzantine — when HonestSet is empty, the
\*      aggregator sees only Byzantine inputs. INV-9 pins that the
\*      reduced state is always in {Neither, True, Both} — never
\*      False — even with maximum adversary control.
\*
\* Threshold-edge attacks are NOT modeled here — they are a Q16
\* numeric-precision concern, covered by:
\*   - precompiles/q16/belnap.rs::tests::classify_one_ulp_below_threshold_is_neither
\*   - precompiles/q16/belnap.rs::tests::classify_at_threshold_inclusive_passes
\*   - the WP-1.7 cargo-fuzz target (fuzz_belnap_aggregate)
\* This spec abstracts numeric thresholds; mixing the two layers
\* would just duplicate the Rust property tests.

\* INV-8: HonestHighConfImpliesAgreeSetNonEmpty
\* If any honest validator submitted with positive weight + high
\* confidence, the aggregator's "agree" set must be non-empty —
\* contrapositive of "the adversary can ghost honest input".
HonestHighConfImpliesAgreeSetNonEmpty ==
    (phase = "aggregated"
     /\ \E h \in HonestSet : h \in HighConfSubmitted)
    => HighConfAgreeSet # {}

\* INV-9: AllByzantineProducesAcceptableState
\* Worst case: zero honest validators, all submissions Byzantine.
\* The aggregator does NOT distinguish all-Byzantine-unanimous from
\* all-honest-unanimous (both produce True). This is a known
\* aggregator property (Paper II §3 acknowledges the aggregator is
\* honest-trust-bounded), formalized here so the spec's behavior
\* under maximum adversary control is explicit.
AllByzantineProducesAcceptableState ==
    (phase = "aggregated" /\ HonestSet = {})
        => state \in {"Neither", "True", "Both"}  \* never False

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM Safety == Spec => []HonestSafety
THEOREM NoFalse == Spec => []NoSpontaneousFalseAtReducedLevel
THEOREM BothTwoSides == Spec => []BothRequiresTwoSides
THEOREM NeitherUnder == Spec => []NeitherImpliesUnderconfidence
THEOREM AdvCannotFlip == Spec => []AdversaryCannotFlipUnderHDA
THEOREM ZeroIgnored == Spec => []WeightZeroIgnored
THEOREM AgreeNonEmpty == Spec => []HonestHighConfImpliesAgreeSetNonEmpty
THEOREM AllByzAcceptable == Spec => []AllByzantineProducesAcceptableState

=============================================================================
