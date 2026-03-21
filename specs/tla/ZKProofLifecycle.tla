------------------------------ MODULE ZKProofLifecycle ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the ZK proof lifecycle: backend initialization, proof generation,
\* serialization, and verification.
\* Source: core/execution/src/zkp/backend.rs, prover.rs, verifier.rs, types.rs

CONSTANTS
    ProofTypes,     \* Set of proof type identifiers (e.g., {ModelExecution, GradientSubmission, ...})
    MaxProofs,      \* Maximum number of proofs that can be generated
    ProofIds        \* Set of possible proof identifiers

ASSUME ProofTypes # {}
ASSUME MaxProofs \in Nat /\ MaxProofs >= 1
ASSUME ProofIds # {}

VARIABLES
    backend_state,    \* "uninitialized" | "ready"
    prover_keys,      \* Function: ProofType -> "none" | "present" (has pk + vk)
    verifier_keys,    \* Function: ProofType -> "none" | "present" (has vk only)
    proofs,           \* Set of generated proof records: [id, proof_type, public_inputs, status]
    verified          \* Set of verified proof IDs

vars == <<backend_state, prover_keys, verifier_keys, proofs, verified>>

\* ---- Helper operators ----

\* Count of generated proofs
ProofCount == Cardinality(proofs)

\* A proof record by ID
ProofById(pid) ==
    CHOOSE p \in proofs : p.id = pid

\* Whether a proof with the given ID exists
HasProof(pid) ==
    \E p \in proofs : p.id = pid

\* ---- State machine ----

Init ==
    /\ backend_state = "uninitialized"
    /\ prover_keys = [pt \in ProofTypes |-> "none"]
    /\ verifier_keys = [pt \in ProofTypes |-> "none"]
    /\ proofs = {}
    /\ verified = {}

\* Initialize the backend: run setup for all proof types, then share VKs.
\* This mirrors ZKPBackend::initialize() which iterates all proof types,
\* calls prover.setup() for each, then wires VKs to the verifier.
Initialize ==
    /\ backend_state = "uninitialized"
    /\ prover_keys' = [pt \in ProofTypes |-> "present"]
    /\ verifier_keys' = [pt \in ProofTypes |-> "present"]
    /\ backend_state' = "ready"
    /\ proofs' = proofs
    /\ verified' = verified

\* Generate a proof for a given type.
\* Requires: backend ready, proving key present, not exceeded max proofs.
\* The proof is assigned a unique ID and stored with its public_inputs hash.
GenerateProof(pid, pt, pub_inputs) ==
    /\ backend_state = "ready"
    /\ pt \in ProofTypes
    /\ prover_keys[pt] = "present"
    /\ ProofCount < MaxProofs
    /\ pid \in ProofIds
    /\ ~HasProof(pid)                           \* Unique proof ID
    /\ proofs' = proofs \cup {[
            id |-> pid,
            proof_type |-> pt,
            public_inputs |-> pub_inputs,
            status |-> "generated"
        ]}
    /\ UNCHANGED <<backend_state, prover_keys, verifier_keys, verified>>

\* Verify a previously generated proof.
\* Requires: verifier key present for the proof's type, proof exists and not yet verified.
VerifyProof(pid) ==
    /\ HasProof(pid)
    /\ pid \notin verified
    /\ LET p == ProofById(pid) IN
        /\ verifier_keys[p.proof_type] = "present"
        /\ verified' = verified \cup {pid}
    /\ UNCHANGED <<backend_state, prover_keys, verifier_keys, proofs>>

Next ==
    \/ Initialize
    \/ \E pid \in ProofIds, pt \in ProofTypes, pub \in 1..3 :
        GenerateProof(pid, pt, pub)
    \/ \E pid \in ProofIds : VerifyProof(pid)

\* ---- Invariants ----

\* INV-1: Type correctness for all variables
TypeOK ==
    /\ backend_state \in {"uninitialized", "ready"}
    /\ prover_keys \in [ProofTypes -> {"none", "present"}]
    /\ verifier_keys \in [ProofTypes -> {"none", "present"}]
    /\ \A p \in proofs :
        /\ p.id \in ProofIds
        /\ p.proof_type \in ProofTypes
        /\ p.public_inputs \in Nat
        /\ p.status \in {"generated"}
    /\ verified \subseteq ProofIds

\* INV-2: No verification can happen before the backend is initialized
NoVerifyWithoutInit ==
    verified # {} => backend_state = "ready"

\* INV-3: Verifying key consistency — every VK comes from the same setup as the PK.
\* If verifier has a key, prover must also have a key (VK is extracted from PK).
VKConsistency ==
    \A pt \in ProofTypes :
        verifier_keys[pt] = "present" => prover_keys[pt] = "present"

\* INV-4: Public inputs preserved — every verified proof has a corresponding
\* proof record whose public_inputs match the generation-time value.
\* (Since we never mutate proofs, this checks the proof still exists.)
PublicInputsPreserved ==
    \A pid \in verified : HasProof(pid)

\* INV-5: Proof immutability — once a proof enters the verified set,
\* its corresponding proof record is never removed or changed.
\* We check that no verified proof ID lacks a matching proof record.
ProofImmutable ==
    \A pid \in verified :
        \E p \in proofs : p.id = pid

\* INV-6: No proof generation without keys
NoProofWithoutKeys ==
    \A p \in proofs : prover_keys[p.proof_type] = "present"

\* INV-7: No verification without verifier keys
NoVerifyWithoutVK ==
    \A pid \in verified :
        LET p == ProofById(pid) IN
            verifier_keys[p.proof_type] = "present"

\* INV-8: Proof count bounded
ProofsBounded ==
    ProofCount <= MaxProofs

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM InitBeforeVerify == Spec => []NoVerifyWithoutInit
THEOREM KeyConsistency == Spec => []VKConsistency
THEOREM InputsPreserved == Spec => []PublicInputsPreserved
THEOREM Immutability == Spec => []ProofImmutable
THEOREM KeysBeforeProof == Spec => []NoProofWithoutKeys
THEOREM VKBeforeVerify == Spec => []NoVerifyWithoutVK
THEOREM BoundedProofs == Spec => []ProofsBounded

=============================================================================
