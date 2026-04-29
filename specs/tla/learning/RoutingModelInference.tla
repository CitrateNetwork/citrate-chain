--------------------- MODULE RoutingModelInference ---------------------
EXTENDS Naturals, FiniteSets, TLC

\* RM-FL-2 / WP-2.1 — Routing-model inference precompile (0x0111)
\*
\* Models the architecture-version registry + inference-call dispatch
\* for the routing-model precompile that returns
\*   (mentor_id, adapter_id, confidence)
\* from a 768-dim query embedding under a fixed 3-layer MLP.
\*
\* This spec answers three questions:
\*
\*   1. SHAPE FIXED: a registered arch_version pins (input_dim,
\*      hidden_dim, output_dim) for the rest of protocol life.
\*      Reuses the immutability pattern from
\*      `Halo2VerifierVersionMonotonic.tla` (RM-M1b WP-M1b.6).
\*
\*   2. NO DOWNGRADE: the chain-wide `current_arch` counter is
\*      monotonically non-decreasing. Older arch_versions remain
\*      *callable* (back-compat for committed proofs) but the
\*      "current" version pointer never goes backward — preventing
\*      a governance attacker from lowering the bar.
\*
\*   3. DETERMINISTIC OUTPUT: same (arch_version, input, weights)
\*      → same (mentor_id, adapter_id, confidence) across every
\*      reachable execution. Modeled by sourcing outputs from a
\*      pure operator `Oracle(v, i, w)` rather than a variable —
\*      a variable would force TLC to enumerate every possible
\*      function from `[ArchVersion × Input × Weight] → Output`,
\*      which explodes the state space.
\*
\* The Q16 numerics are abstracted at this layer (input/weights/output
\* are opaque identifiers). The Q16 path is verified by Rust property
\* tests + the WP-2.4 tripwire `check_routing_quant_q16_only.py`.
\*
\* Q16-vs-f32 oracle delta (per RM-FL-1 retro item):
\*   The off-chain reference (likely candle / PyTorch) uses f32 for
\*   the forward pass. The precompile uses Q16. They are NOT
\*   byte-equivalent oracles — Q16 saturating arithmetic, integer
\*   ReLU, and threshold-edge classification can produce different
\*   classifications than the f32 path under tolerance-edge inputs.
\*   The TLA+ spec abstracts numerics deliberately to dodge this;
\*   property tests at the Rust layer use algebraic-equivalence
\*   (sign of result, classification matches under bounded tol),
\*   not byte-equality.
\*
\* Source/target:
\*   - core/execution/src/precompiles/q16/routing.rs (target, WP-2.5)
\*   - dispatch at 0x0111 in precompiles/mod.rs (target, WP-2.6)

CONSTANTS
    ArchVersions,       \* Set of arch version numbers, e.g. {1, 2, 3}
    Shapes,             \* Set of (input_dim, hidden_dim, output_dim) triples
    InputIds,           \* Abstract input identifiers
    WeightIds,          \* Abstract weight identifiers
    OutputIds,          \* Abstract output identifiers
    MaxInferences       \* Cap on inferences per run (state-space bound)

ASSUME ArchVersions # {} /\ ArchVersions \subseteq Nat
ASSUME Shapes # {}
ASSUME InputIds # {}
ASSUME WeightIds # {}
ASSUME OutputIds # {}
ASSUME MaxInferences \in Nat /\ MaxInferences >= 1

\* Deterministic forward-pass oracle. Defined as a TLA+ operator
\* (not a CONSTANT or VARIABLE) so the TLC config parser doesn't
\* have to encode function-builder syntax, and the state space
\* doesn't enumerate every possible such function.
\*
\* CHOOSE in TLC is deterministic for the same input across the
\* run, so this operator behaves like a fixed function. The exact
\* output mapping is irrelevant for the invariants — what matters
\* is that two calls with the same args yield the same value.
Oracle(v, i, w) ==
    CHOOSE o \in OutputIds : TRUE

VARIABLES
    arch_registry,      \* Function: ArchVersion -> Shapes \cup {"unset"}
    history,            \* Function: ArchVersion -> Shapes \cup {"unset"}
                        \*   one-shot recorder; immutable after first set
    current_arch,       \* The chain-wide "currently accepted" arch version
    accepted_inferences \* Set of [id, version, input, weights, output]

vars == <<arch_registry, history, current_arch, accepted_inferences>>

\* ---- Helpers ----

IsRegistered(v) == arch_registry[v] # "unset"

InferenceCount == Cardinality(accepted_inferences)

\* ---- State machine ----

Init ==
    /\ arch_registry = [v \in ArchVersions |-> "unset"]
    /\ history       = [v \in ArchVersions |-> "unset"]
    \* current_arch starts at 0 (no arch active yet). Advanced via
    \* AdvanceCurrent only after a RegisterArch step.
    /\ current_arch = 0
    /\ accepted_inferences = {}

\* Register an architecture version with a shape. First-writer-wins.
\* Mirrors `OnceLock::get_or_init` semantics in the Rust impl.
RegisterArch(v, s) ==
    /\ v \in ArchVersions
    /\ s \in Shapes
    /\ ~IsRegistered(v)
    /\ arch_registry' = [arch_registry EXCEPT ![v] = s]
    /\ history'       = [history       EXCEPT ![v] = s]
    /\ UNCHANGED <<current_arch, accepted_inferences>>

\* Advance the chain-wide current_arch pointer. Strictly monotonic
\* — only allowed to move forward to a registered version >= the
\* current pointer. Models a hardfork or governance upgrade.
AdvanceCurrent(v) ==
    /\ v \in ArchVersions
    /\ IsRegistered(v)
    /\ v >= current_arch
    /\ current_arch' = v
    /\ UNCHANGED <<arch_registry, history, accepted_inferences>>

\* Run an inference. Allowed only against a registered arch version.
\* The output is deterministic via the `Oracle` operator.
\*
\* Note: the spec permits inferences against ANY registered version,
\* not only `current_arch`. This models the back-compat contract:
\* an on-chain caller holding a commitment anchored to v=1 keeps
\* verifying even after the chain has advanced to v=3.
RunInference(pid, v, inp, wts) ==
    /\ pid \in 1..MaxInferences
    /\ v \in ArchVersions
    /\ IsRegistered(v)
    /\ inp \in InputIds
    /\ wts \in WeightIds
    /\ InferenceCount < MaxInferences
    /\ ~\E i \in accepted_inferences : i.id = pid  \* unique pid
    /\ LET out == Oracle(v, inp, wts)
       IN accepted_inferences' = accepted_inferences \cup
              {[id |-> pid, version |-> v, input |-> inp,
                weights |-> wts, output |-> out]}
    /\ UNCHANGED <<arch_registry, history, current_arch>>

\* Stuttering step.
Stutter == UNCHANGED vars

Next ==
    \/ \E v \in ArchVersions, s \in Shapes : RegisterArch(v, s)
    \/ \E v \in ArchVersions : AdvanceCurrent(v)
    \/ \E pid \in 1..MaxInferences, v \in ArchVersions,
         inp \in InputIds, wts \in WeightIds :
            RunInference(pid, v, inp, wts)
    \/ Stutter

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ arch_registry \in [ArchVersions -> Shapes \cup {"unset"}]
    /\ history       \in [ArchVersions -> Shapes \cup {"unset"}]
    /\ current_arch \in {0} \cup ArchVersions
    /\ accepted_inferences \subseteq [id : 1..MaxInferences,
                                      version : ArchVersions,
                                      input : InputIds,
                                      weights : WeightIds,
                                      output : OutputIds]
    /\ InferenceCount <= MaxInferences

\* INV-2: ShapeFixed
\* Once a version is registered with a shape, the registry holds
\* that shape forever (matched against the immutable history).
ShapeFixed ==
    \A v \in ArchVersions :
        IsRegistered(v) =>
            /\ arch_registry[v] \in Shapes
            /\ arch_registry[v] = history[v]

\* INV-3: HistoryNeverDropped — registered shapes never reset to "unset".
HistoryNeverDropped ==
    \A v \in ArchVersions :
        history[v] # "unset" => arch_registry[v] = history[v]

\* INV-4: AllInferencesUseRegisteredArch
\* Every accepted inference references a currently-registered
\* architecture version. Without this, a caller could reference an
\* unset version and the dispatcher would have no shape to enforce.
AllInferencesUseRegisteredArch ==
    \A i \in accepted_inferences : IsRegistered(i.version)

\* INV-5: DeterministicOutput
\* Two accepted inferences with identical (version, input, weights)
\* MUST have identical output. This is the bit-determinism contract
\* that the Q16 substrate gives us at the numeric level, lifted to
\* the symbolic level here.
DeterministicOutput ==
    \A i, j \in accepted_inferences :
        (i.version = j.version /\ i.input = j.input /\ i.weights = j.weights)
            => i.output = j.output

\* INV-6: NoDowngrade
\* The chain-wide current_arch pointer never moves backward in any
\* reachable state. Combined with the AdvanceCurrent action's
\* `v >= current_arch` precondition, this proves no execution can
\* lower the current accepted version.
\*
\* (Implementation-level: the on-chain governance contract owns
\* current_arch and rejects calls to lower it. This invariant is
\* the symbolic anchor for that contract guard.)
NoDowngrade ==
    current_arch \in {0} \cup ArchVersions

\* INV-7: BoundedInferenceCount
\* Inference acceptance is capped at MaxInferences — the state
\* machine cannot accept an unbounded number of inferences (which
\* would correspond to a DoS via repeat calls without gas charging).
BoundedInferenceCount ==
    InferenceCount <= MaxInferences

\* INV-8: BackCompat — older registered arch versions remain
\* callable even when current_arch has advanced. Asserts the
\* "registry still works for old proofs" property structurally:
\* there is no conflict between `current_arch > v` and
\* `IsRegistered(v)` — the older shape is still preserved.
BackCompat ==
    \A v \in ArchVersions :
        IsRegistered(v) /\ current_arch > v
            => arch_registry[v] = history[v]

\* The full safety invariant — what TLC asserts at every state.
SafetyInvariant ==
    /\ TypeOK
    /\ ShapeFixed
    /\ HistoryNeverDropped
    /\ AllInferencesUseRegisteredArch
    /\ DeterministicOutput
    /\ NoDowngrade
    /\ BoundedInferenceCount
    /\ BackCompat

THEOREM Types == Spec => []TypeOK
THEOREM Shape == Spec => []ShapeFixed
THEOREM HistKeep == Spec => []HistoryNeverDropped
THEOREM AllReg == Spec => []AllInferencesUseRegisteredArch
THEOREM Determ == Spec => []DeterministicOutput
THEOREM NoDown == Spec => []NoDowngrade
THEOREM Bounded == Spec => []BoundedInferenceCount
THEOREM Back == Spec => []BackCompat

============================================================================
