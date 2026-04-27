--------------------- MODULE AttestationGate ---------------------
EXTENDS Naturals, FiniteSets, TLC

\* RM-M3 WP-M3.4 — TEE attestation gate.
\*
\* Source: core/execution/src/precompiles/attestation/{mod,types,
\* always_reject,mock}.rs, plumbed into precompiles/inference.rs.
\*
\* Statement:
\*   The AttestationGate is the SINGLE chokepoint for inference
\*   precompiles 0x0101 / 0x0102. In Strict mode, every inference
\*   call MUST consult the gate and proceed only on Allow. The
\*   AlwaysReject default never returns Allow under any input.
\*
\* Invariants:
\*   1. NeverAllowOnAlwaysReject: when gate = AlwaysReject, the
\*      decision is always Reject.
\*   2. StrictRequiresAllow: in Strict mode, an inference call
\*      that received Reject must NOT execute.
\*   3. Phase2OnlyAllowsOnValidInput: a future MaaPlusNras gate
\*      may allow only inputs starting with a valid attestation
\*      blob (modeled here as the "VALID:" prefix).

CONSTANTS
    GateImpls,          \* {"AlwaysReject", "MaaPlusNras", "AlwaysAllow"}
    Inputs              \* {"valid_attestation", "invalid", "empty"}

ASSUME GateImpls # {} /\ Inputs # {}

VARIABLES
    current_gate,       \* element of GateImpls
    current_input,      \* element of Inputs
    last_decision,      \* "Allow" | "Reject"
    inference_executed  \* BOOLEAN — tracks whether the precompile
                        \* actually ran past the gate

vars == <<current_gate, current_input, last_decision, inference_executed>>

\* ---- Decision function ----

\* AlwaysReject: every input → Reject.
\* AlwaysAllow (test only): every input → Allow.
\* MaaPlusNras (Phase 2): "valid_attestation" → Allow, else Reject.
DecisionFor(gate, input) ==
    IF gate = "AlwaysReject" THEN "Reject"
    ELSE IF gate = "AlwaysAllow" THEN "Allow"
    ELSE IF gate = "MaaPlusNras" THEN
        IF input = "valid_attestation" THEN "Allow" ELSE "Reject"
    ELSE "Reject"  \* Conservative default for unknown gates.

\* ---- State machine ----

Init ==
    /\ current_gate \in GateImpls
    /\ current_input \in Inputs
    /\ last_decision = DecisionFor(current_gate, current_input)
    /\ inference_executed = (last_decision = "Allow")

\* Step: pick a new (gate, input) pair, recompute the decision,
\* and execute inference iff the decision is Allow.
PickAndExecute ==
    /\ \E g \in GateImpls, i \in Inputs :
        /\ current_gate' = g
        /\ current_input' = i
        /\ last_decision' = DecisionFor(g, i)
        /\ inference_executed' = (DecisionFor(g, i) = "Allow")

Next == PickAndExecute

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

TypeOK ==
    /\ current_gate \in GateImpls
    /\ current_input \in Inputs
    /\ last_decision \in {"Allow", "Reject"}
    /\ inference_executed \in BOOLEAN

\* CORE INVARIANT: AlwaysReject never produces Allow.
NeverAllowOnAlwaysReject ==
    current_gate = "AlwaysReject" => last_decision = "Reject"

\* CORE INVARIANT: inference runs IFF the gate said Allow.
\* The Strict-mode gate is the only enforcement.
StrictRequiresAllow ==
    inference_executed = (last_decision = "Allow")

\* CORE INVARIANT: MaaPlusNras only allows on valid attestation.
Phase2OnlyAllowsOnValidInput ==
    (current_gate = "MaaPlusNras" /\ last_decision = "Allow")
        => current_input = "valid_attestation"

SafetyInvariant ==
    /\ TypeOK
    /\ NeverAllowOnAlwaysReject
    /\ StrictRequiresAllow
    /\ Phase2OnlyAllowsOnValidInput

============================================================================
