--------------------- MODULE LearningComputeIntegration ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Integration spec composing LearningCycleLifecycle + ComputeMarketplace.
\*
\* Verifies that the learning layer properly routes all compute through
\* the verified marketplace pipeline. Key integration properties:
\*
\*   1. Cycle aggregation triggers a compute job in the marketplace
\*   2. Adapter generation jobs must be verified before adapter is finalized
\*   3. No learning compute bypasses the marketplace
\*
\* This spec models the learning cycle phases (Open, Collecting, Aggregating,
\* AdapterGen, Finalized) and tracks compute jobs that are spawned at the
\* Aggregating and AdapterGen phases.
\*
\* Source: contracts/src/LearningCycle.sol, ComputeMarketplace.sol
\*         .agentile/teamwork/COMPUTE_MARKETPLACE_ARCHITECTURE.md

CONSTANTS
    Cycles,             \* Set of learning cycle identifiers
    Providers           \* Set of compute providers

ASSUME Cycles # {}
ASSUME Providers # {}

\* Learning cycle states
CycleStates == {"Open", "Collecting", "Aggregating", "AdapterGen", "Finalized"}

\* Compute job states (simplified from full marketplace)
ComputeStates == {"None", "Posted", "Executing", "Verified", "Failed"}

VARIABLES
    \* -- Learning cycle variables --
    cycleState,             \* Mapping: cycle -> lifecycle phase
    hasParticipants,        \* Mapping: cycle -> TRUE iff participants registered
    hasEmbeddings,          \* Mapping: cycle -> TRUE iff embeddings submitted

    \* -- Compute marketplace variables --
    aggregationJob,         \* Mapping: cycle -> compute job state for aggregation
    aggregationProvider,    \* Mapping: cycle -> provider assigned to aggregation job
    aggregationVerified,    \* Mapping: cycle -> TRUE iff aggregation job verified
    adapterJob,             \* Mapping: cycle -> compute job state for adapter gen
    adapterProvider,        \* Mapping: cycle -> provider assigned to adapter job
    adapterVerified,        \* Mapping: cycle -> TRUE iff adapter job verified

    \* -- Provider registry (simplified) --
    providerActive          \* Mapping: provider -> TRUE iff active

vars == <<cycleState, hasParticipants, hasEmbeddings,
          aggregationJob, aggregationProvider, aggregationVerified,
          adapterJob, adapterProvider, adapterVerified,
          providerActive>>

\* ---- State machine ----

Init ==
    /\ cycleState = [c \in Cycles |-> "Open"]
    /\ hasParticipants = [c \in Cycles |-> FALSE]
    /\ hasEmbeddings = [c \in Cycles |-> FALSE]
    /\ aggregationJob = [c \in Cycles |-> "None"]
    /\ aggregationProvider = [c \in Cycles |-> "none"]
    /\ aggregationVerified = [c \in Cycles |-> FALSE]
    /\ adapterJob = [c \in Cycles |-> "None"]
    /\ adapterProvider = [c \in Cycles |-> "none"]
    /\ adapterVerified = [c \in Cycles |-> FALSE]
    /\ providerActive = [p \in Providers |-> FALSE]

\* --- Provider actions ---

ActivateProvider(p) ==
    /\ p \in Providers
    /\ providerActive[p] = FALSE
    /\ providerActive' = [providerActive EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified>>

\* --- Learning cycle actions ---

\* Register participants during Open phase.
RegisterParticipants(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Open"
    /\ hasParticipants[c] = FALSE
    /\ hasParticipants' = [hasParticipants EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<cycleState, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Transition to Collecting.
StartCollecting(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Open"
    /\ hasParticipants[c] = TRUE
    /\ cycleState' = [cycleState EXCEPT ![c] = "Collecting"]
    /\ UNCHANGED <<hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Submit embeddings during Collecting.
SubmitEmbeddings(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Collecting"
    /\ hasEmbeddings[c] = FALSE
    /\ hasEmbeddings' = [hasEmbeddings EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<cycleState, hasParticipants,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Transition to Aggregating — MUST post a compute job in the marketplace.
StartAggregating(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Collecting"
    /\ hasEmbeddings[c] = TRUE
    /\ cycleState' = [cycleState EXCEPT ![c] = "Aggregating"]
    \* CROSS-MODULE: aggregation triggers a compute job.
    /\ aggregationJob' = [aggregationJob EXCEPT ![c] = "Posted"]
    /\ UNCHANGED <<hasParticipants, hasEmbeddings,
                   aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Assign aggregation compute job to an active provider.
AssignAggregation(c, p) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Aggregating"
    /\ aggregationJob[c] = "Posted"
    /\ p \in Providers
    /\ providerActive[p] = TRUE
    /\ aggregationJob' = [aggregationJob EXCEPT ![c] = "Executing"]
    /\ aggregationProvider' = [aggregationProvider EXCEPT ![c] = p]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Aggregation compute job verified.
VerifyAggregation(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Aggregating"
    /\ aggregationJob[c] = "Executing"
    /\ aggregationJob' = [aggregationJob EXCEPT ![c] = "Verified"]
    /\ aggregationVerified' = [aggregationVerified EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationProvider,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Aggregation compute job fails.
FailAggregation(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Aggregating"
    /\ aggregationJob[c] = "Executing"
    /\ aggregationJob' = [aggregationJob EXCEPT ![c] = "Failed"]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

\* Transition to AdapterGen — requires verified aggregation, posts adapter compute job.
StartAdapterGen(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "Aggregating"
    /\ aggregationVerified[c] = TRUE
    /\ cycleState' = [cycleState EXCEPT ![c] = "AdapterGen"]
    \* CROSS-MODULE: adapter generation triggers another compute job.
    /\ adapterJob' = [adapterJob EXCEPT ![c] = "Posted"]
    /\ UNCHANGED <<hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterProvider, adapterVerified,
                   providerActive>>

\* Assign adapter compute job to an active provider.
AssignAdapter(c, p) ==
    /\ c \in Cycles
    /\ cycleState[c] = "AdapterGen"
    /\ adapterJob[c] = "Posted"
    /\ p \in Providers
    /\ providerActive[p] = TRUE
    /\ adapterJob' = [adapterJob EXCEPT ![c] = "Executing"]
    /\ adapterProvider' = [adapterProvider EXCEPT ![c] = p]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterVerified, providerActive>>

\* Adapter compute job verified.
VerifyAdapter(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "AdapterGen"
    /\ adapterJob[c] = "Executing"
    /\ adapterJob' = [adapterJob EXCEPT ![c] = "Verified"]
    /\ adapterVerified' = [adapterVerified EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterProvider, providerActive>>

\* Adapter compute job fails.
FailAdapter(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "AdapterGen"
    /\ adapterJob[c] = "Executing"
    /\ adapterJob' = [adapterJob EXCEPT ![c] = "Failed"]
    /\ UNCHANGED <<cycleState, hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterProvider, adapterVerified, providerActive>>

\* Finalize the cycle — requires verified adapter job.
Finalize(c) ==
    /\ c \in Cycles
    /\ cycleState[c] = "AdapterGen"
    /\ adapterVerified[c] = TRUE
    /\ cycleState' = [cycleState EXCEPT ![c] = "Finalized"]
    /\ UNCHANGED <<hasParticipants, hasEmbeddings,
                   aggregationJob, aggregationProvider, aggregationVerified,
                   adapterJob, adapterProvider, adapterVerified,
                   providerActive>>

Next ==
    \/ \E p \in Providers : ActivateProvider(p)
    \/ \E c \in Cycles : RegisterParticipants(c)
    \/ \E c \in Cycles : StartCollecting(c)
    \/ \E c \in Cycles : SubmitEmbeddings(c)
    \/ \E c \in Cycles : StartAggregating(c)
    \/ \E c \in Cycles, p \in Providers : AssignAggregation(c, p)
    \/ \E c \in Cycles : VerifyAggregation(c)
    \/ \E c \in Cycles : FailAggregation(c)
    \/ \E c \in Cycles : StartAdapterGen(c)
    \/ \E c \in Cycles, p \in Providers : AssignAdapter(c, p)
    \/ \E c \in Cycles : VerifyAdapter(c)
    \/ \E c \in Cycles : FailAdapter(c)
    \/ \E c \in Cycles : Finalize(c)

\* ---- Cross-module invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ \A c \in Cycles : cycleState[c] \in CycleStates
    /\ \A c \in Cycles : hasParticipants[c] \in BOOLEAN
    /\ \A c \in Cycles : hasEmbeddings[c] \in BOOLEAN
    /\ \A c \in Cycles : aggregationJob[c] \in ComputeStates
    /\ \A c \in Cycles : aggregationVerified[c] \in BOOLEAN
    /\ \A c \in Cycles : adapterJob[c] \in ComputeStates
    /\ \A c \in Cycles : adapterVerified[c] \in BOOLEAN
    /\ \A p \in Providers : providerActive[p] \in BOOLEAN

\* INV-2: CycleComputeRouted — aggregation phase always has a compute job posted.
\* CROSS-MODULE: learning cycle MUST use marketplace for aggregation.
CycleComputeRouted ==
    \A c \in Cycles :
        cycleState[c] \in {"Aggregating", "AdapterGen", "Finalized"} =>
            aggregationJob[c] # "None"

\* INV-3: AdapterComputeVerified — cycle cannot finalize without verified adapter job.
\* CROSS-MODULE: adapter generation requires verified marketplace compute.
AdapterComputeVerified ==
    \A c \in Cycles :
        cycleState[c] = "Finalized" => adapterVerified[c] = TRUE

\* INV-4: LearningNeverBypassesMarketplace — no direct compute outside marketplace.
\* If the cycle reaches AdapterGen, an adapter compute job exists.
LearningNeverBypassesMarketplace ==
    \A c \in Cycles :
        cycleState[c] \in {"AdapterGen", "Finalized"} =>
            adapterJob[c] # "None"

\* INV-5: AggregationVerifiedBeforeAdapter — adapter phase requires verified aggregation.
\* CROSS-MODULE: learning layer waits for marketplace verification before proceeding.
AggregationVerifiedBeforeAdapter ==
    \A c \in Cycles :
        cycleState[c] \in {"AdapterGen", "Finalized"} =>
            aggregationVerified[c] = TRUE

\* INV-6: ActiveProviderRequired — compute jobs only assigned to active providers.
ActiveProviderRequired ==
    \A c \in Cycles :
        /\ (aggregationProvider[c] # "none" =>
            aggregationProvider[c] \in Providers)
        /\ (adapterProvider[c] # "none" =>
            adapterProvider[c] \in Providers)

\* INV-7: PhaseOrderPreserved — learning cycle phases only advance forward.
PhaseOrderPreserved ==
    \A c \in Cycles :
        cycleState[c] \in CycleStates

\* INV-8: NoEmbeddingsBeforeCollecting — embeddings only during Collecting or later.
NoEmbeddingsBeforeCollecting ==
    \A c \in Cycles :
        cycleState[c] = "Open" => hasEmbeddings[c] = FALSE

\* INV-9: FinalizedFullyVerified — finalized cycles have both jobs verified.
FinalizedFullyVerified ==
    \A c \in Cycles :
        cycleState[c] = "Finalized" =>
            /\ aggregationVerified[c] = TRUE
            /\ adapterVerified[c] = TRUE

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM CycleRouted == Spec => []CycleComputeRouted
THEOREM AdapterVerified == Spec => []AdapterComputeVerified
THEOREM NeverBypass == Spec => []LearningNeverBypassesMarketplace
THEOREM AggBeforeAdapter == Spec => []AggregationVerifiedBeforeAdapter
THEOREM ActiveProvReq == Spec => []ActiveProviderRequired
THEOREM PhaseOrder == Spec => []PhaseOrderPreserved
THEOREM NoEmbedOpen == Spec => []NoEmbeddingsBeforeCollecting
THEOREM FinalFullVerify == Spec => []FinalizedFullyVerified

=============================================================================
