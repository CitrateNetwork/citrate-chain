------------------------------ MODULE ZKKeyManagement ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the ZK key setup and handoff protocol: idle → generating → sharing → complete.
\* Ensures all proof types are set up atomically — partial setup rolls back.
\* Source: core/execution/src/zkp/prover.rs (setup), backend.rs (initialize)

CONSTANTS
    ProofTypes      \* Set of proof types requiring key setup

ASSUME ProofTypes # {}

VARIABLES
    setup_phase,          \* "idle" | "generating" | "sharing" | "complete"
    prover_key_store,     \* Function: ProofType -> "none" | "present"
    verifier_key_store,   \* Function: ProofType -> "none" | "present"
    setup_types_done,     \* Set of ProofTypes that completed key generation
    setup_types_shared    \* Set of ProofTypes whose VKs were shared to verifier

vars == <<setup_phase, prover_key_store, verifier_key_store, setup_types_done, setup_types_shared>>

\* ---- State machine ----

Init ==
    /\ setup_phase = "idle"
    /\ prover_key_store = [pt \in ProofTypes |-> "none"]
    /\ verifier_key_store = [pt \in ProofTypes |-> "none"]
    /\ setup_types_done = {}
    /\ setup_types_shared = {}

\* Begin the key generation phase (transition from idle to generating).
BeginSetup ==
    /\ setup_phase = "idle"
    /\ setup_phase' = "generating"
    /\ UNCHANGED <<prover_key_store, verifier_key_store, setup_types_done, setup_types_shared>>

\* Generate keys for a single proof type.
\* Models prover.setup(pt) which generates proving + verifying keys.
GenerateKeyForType(pt) ==
    /\ setup_phase = "generating"
    /\ pt \in ProofTypes
    /\ pt \notin setup_types_done
    /\ prover_key_store' = [prover_key_store EXCEPT ![pt] = "present"]
    /\ setup_types_done' = setup_types_done \cup {pt}
    /\ UNCHANGED <<setup_phase, verifier_key_store, setup_types_shared>>

\* All types generated — transition to sharing phase.
\* If not all types are done, this cannot fire (atomicity guarantee).
BeginSharing ==
    /\ setup_phase = "generating"
    /\ setup_types_done = ProofTypes      \* ALL types must be done
    /\ setup_phase' = "sharing"
    /\ UNCHANGED <<prover_key_store, verifier_key_store, setup_types_done, setup_types_shared>>

\* Key generation failed — roll back entire setup to idle.
\* Models the error path where setup() returns Err for any type.
RollbackSetup ==
    /\ setup_phase = "generating"
    /\ setup_types_done # ProofTypes        \* Not all types succeeded yet (failure scenario)
    /\ setup_phase' = "idle"
    /\ prover_key_store' = [pt \in ProofTypes |-> "none"]
    /\ verifier_key_store' = [pt \in ProofTypes |-> "none"]
    /\ setup_types_done' = {}
    /\ setup_types_shared' = {}

\* Share a verifying key from prover to verifier for a single type.
\* Models the VK handoff loop in ZKPBackend::initialize().
ShareVKForType(pt) ==
    /\ setup_phase = "sharing"
    /\ pt \in ProofTypes
    /\ pt \notin setup_types_shared
    /\ prover_key_store[pt] = "present"       \* Can only share if PK exists
    /\ verifier_key_store' = [verifier_key_store EXCEPT ![pt] = "present"]
    /\ setup_types_shared' = setup_types_shared \cup {pt}
    /\ UNCHANGED <<setup_phase, prover_key_store, setup_types_done>>

\* All VKs shared — transition to complete.
CompleteSetup ==
    /\ setup_phase = "sharing"
    /\ setup_types_shared = ProofTypes        \* ALL types shared
    /\ setup_phase' = "complete"
    /\ UNCHANGED <<prover_key_store, verifier_key_store, setup_types_done, setup_types_shared>>

Next ==
    \/ BeginSetup
    \/ \E pt \in ProofTypes : GenerateKeyForType(pt)
    \/ BeginSharing
    \/ RollbackSetup
    \/ \E pt \in ProofTypes : ShareVKForType(pt)
    \/ CompleteSetup

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ setup_phase \in {"idle", "generating", "sharing", "complete"}
    /\ prover_key_store \in [ProofTypes -> {"none", "present"}]
    /\ verifier_key_store \in [ProofTypes -> {"none", "present"}]
    /\ setup_types_done \subseteq ProofTypes
    /\ setup_types_shared \subseteq ProofTypes

\* INV-2: When setup is complete, ALL proof types have been set up
AllTypesSetup ==
    setup_phase = "complete" => setup_types_done = ProofTypes

\* INV-3: A verifier key exists only if the corresponding prover key exists
\* (VK is extracted from PK — never generated independently)
VKFromSameSetup ==
    \A pt \in ProofTypes :
        verifier_key_store[pt] = "present" => prover_key_store[pt] = "present"

\* INV-4: Keys are immutable once setup is complete — no key changes after "complete"
\* (Enforced structurally: no action modifies keys when phase = "complete")
KeysImmutable ==
    setup_phase = "complete" =>
        /\ \A pt \in ProofTypes : prover_key_store[pt] = "present"
        /\ \A pt \in ProofTypes : verifier_key_store[pt] = "present"

\* INV-5: No partial setup — if in idle or complete, either all keys present or all absent
NoPartialSetup ==
    \/ setup_phase \in {"generating", "sharing"}
    \/ (setup_phase = "idle" /\
        \A pt \in ProofTypes : prover_key_store[pt] = "none" /\ verifier_key_store[pt] = "none")
    \/ (setup_phase = "complete" /\
        \A pt \in ProofTypes : prover_key_store[pt] = "present" /\ verifier_key_store[pt] = "present")

\* INV-6: Sharing only happens after generation is complete for all types
ShareRequiresGeneration ==
    setup_phase = "sharing" => setup_types_done = ProofTypes

\* INV-7: VK sharing tracks prover key presence
ShareTracksProver ==
    \A pt \in setup_types_shared : prover_key_store[pt] = "present"

\* ---- Specification ----

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

THEOREM TypeSafety == Spec => []TypeOK
THEOREM AllSetup == Spec => []AllTypesSetup
THEOREM VKDependsOnPK == Spec => []VKFromSameSetup
THEOREM Immutability == Spec => []KeysImmutable
THEOREM AtomicSetup == Spec => []NoPartialSetup
THEOREM ShareAfterGen == Spec => []ShareRequiresGeneration
THEOREM ShareFromProver == Spec => []ShareTracksProver

=============================================================================
