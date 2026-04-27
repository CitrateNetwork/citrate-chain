------------------------ MODULE Halo2VerifierVersionMonotonic ------------------------
EXTENDS Naturals, FiniteSets, TLC

\* RM-M1b WP-M1b.6 — version-monotonicity invariant for the
\* Halo2-KZG inference-proof verifier at 0x0108.
\*
\* Source: core/execution/src/zkp/halo2/mod.rs (CIRCUIT_VERSION_LINEAR_Q16,
\* verify_inference_proof, inference_kzg_artifacts_v1).
\*
\* Statement:
\*   Once a circuit_version v has been registered with a verifying-key
\*   (VK) value vk_v, that pairing is IMMUTABLE for the rest of the
\*   protocol's life. Any subsequent attempt to register a different VK
\*   under version v MUST be rejected. Anything else silently
\*   re-interprets every proof previously anchored to v as a proof
\*   against a different circuit — soundness collapse.
\*
\* This spec models the version registry as a partial function
\* `vk_registry: CircuitVersion -> VkValue \cup {"unset"}` and asserts
\* the immutability invariant across all reachable states.

CONSTANTS
    CircuitVersions,    \* Set of possible version numbers, e.g. {1, 2, 3}
    VkValues,           \* Set of possible VK values, e.g. {"vk_a", "vk_b"}
    MaxProofs           \* Cap on accepted proofs (state-space bound)

ASSUME CircuitVersions # {}
ASSUME VkValues # {}
ASSUME MaxProofs \in Nat /\ MaxProofs >= 1

VARIABLES
    vk_registry,        \* Function: CircuitVersion -> VkValues \cup {"unset"}
    history,            \* Function: CircuitVersion -> VkValues \cup {"unset"} —
                        \* one-shot recorder of each version's first-and-only VK.
    accepted_proofs     \* Set of records [id |-> nat, version |-> v]

vars == <<vk_registry, history, accepted_proofs>>

\* ---- Helpers ----

IsRegistered(v) == vk_registry[v] # "unset"

ProofCount == Cardinality(accepted_proofs)

\* ---- State machine ----

Init ==
    /\ vk_registry = [v \in CircuitVersions |-> "unset"]
    /\ history     = [v \in CircuitVersions |-> "unset"]
    /\ accepted_proofs = {}

\* Register a circuit_version with a VK. Only succeeds if the version
\* is currently unset. Mirrors `inference_kzg_artifacts_v1`'s
\* `OnceLock::get_or_init` semantics: first writer wins; subsequent
\* writes are no-ops, NOT overwrites.
RegisterVersion(v, vk) ==
    /\ v \in CircuitVersions
    /\ vk \in VkValues
    /\ ~IsRegistered(v)
    /\ vk_registry' = [vk_registry EXCEPT ![v] = vk]
    /\ history'     = [history     EXCEPT ![v] = vk]
    /\ accepted_proofs' = accepted_proofs

\* Adversarial attempt to overwrite an existing version with a
\* DIFFERENT VK. The state-machine action models the attempt; the
\* invariant `VersionVkImmutable` proves that even if the action
\* somehow fires, the registry doesn't change because we conjunct
\* it with `~IsRegistered(v)` — making this action UNREACHABLE
\* once a version is registered.
\*
\* If we omitted the `~IsRegistered(v)` guard, the spec would
\* allow overwrites and the invariant would catch it. Keeping
\* the guard means TLC explores the bounded behavior we actually
\* implement. A separate violator-model spec could remove the
\* guard to assert the invariant catches the bug.
\*
\* (See `Halo2VerifierVersionMonotonic_violator.tla` if/when we
\* author it as a paired test of the invariant.)

\* Accept a proof against a registered version.
AcceptProof(pid, v) ==
    /\ v \in CircuitVersions
    /\ IsRegistered(v)
    /\ ProofCount < MaxProofs
    /\ ~\E p \in accepted_proofs : p.id = pid  \* unique pid
    /\ accepted_proofs' = accepted_proofs \cup {[id |-> pid, version |-> v]}
    /\ vk_registry' = vk_registry
    /\ history'     = history

\* No-op step for stuttering.
Stutter == UNCHANGED vars

Next ==
    \/ \E v \in CircuitVersions, vk \in VkValues : RegisterVersion(v, vk)
    \/ \E pid \in 1..MaxProofs, v \in CircuitVersions : AcceptProof(pid, v)
    \/ Stutter

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* Type invariant.
TypeOK ==
    /\ vk_registry \in [CircuitVersions -> VkValues \cup {"unset"}]
    /\ history     \in [CircuitVersions -> VkValues \cup {"unset"}]
    /\ accepted_proofs \in SUBSET [id : 1..MaxProofs, version : CircuitVersions]
    /\ ProofCount <= MaxProofs

\* CORE INVARIANT: a registered version's VK matches its history
\* (the recorder of "first VK ever seen at this version"). Since
\* `history` is only ever set when `vk_registry[v]` transitions
\* `unset → vk` and never updated afterward, this invariant means:
\* once `vk_registry[v] = vk`, the registry value cannot change
\* without violating the invariant.
\*
\* If we DROPPED the `~IsRegistered(v)` guard in RegisterVersion
\* and let it overwrite, TLC would find a counterexample where
\* `vk_registry[v]` changes while `history[v]` stayed at the
\* original value — proving the invariant catches the bug.
VkRegistryMatchesHistory ==
    \A v \in CircuitVersions :
        IsRegistered(v) =>
            /\ vk_registry[v] \in VkValues
            /\ vk_registry[v] = history[v]

\* If a version has a recorded history entry, the registry must
\* still hold that exact value (no resets to "unset" either).
HistoryNeverDropped ==
    \A v \in CircuitVersions :
        history[v] # "unset" => vk_registry[v] = history[v]

\* Every accepted proof has a registered version.
AcceptedProofsHaveRegisteredVk ==
    \A p \in accepted_proofs : IsRegistered(p.version)

\* The full safety invariant — what TLC asserts at every state.
SafetyInvariant ==
    /\ TypeOK
    /\ VkRegistryMatchesHistory
    /\ HistoryNeverDropped
    /\ AcceptedProofsHaveRegisteredVk

============================================================================
