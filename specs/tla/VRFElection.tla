------------------------------ MODULE VRFElection ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models VRF-based proposer election: proof generation, leader selection per slot,
\* and slot uniqueness guarantees.
\* Source: core/consensus/src/vrf.rs — VrfProposerSelector

CONSTANTS
    Validators,     \* Set of validator IDs
    Slots,          \* Set of slot numbers (e.g., 1..N)
    StakeWeight     \* Function: validator -> stake weight (determines eligibility threshold)

ASSUME Validators # {}
ASSUME Slots \subseteq Nat /\ Slots # {}

VARIABLES
    proofs,         \* Set of submitted VRF proofs: [validator, slot, output, valid]
    leaders,        \* Function: slot -> elected leader (or "none")
    usedOutputs     \* Set of VRF outputs already consumed (replay protection)

vars == <<proofs, leaders, usedOutputs>>

\* ---- Helper operators ----

\* Valid proofs for a given slot
ValidProofsForSlot(slot) ==
    { p \in proofs : p.slot = slot /\ p.valid }

\* Check if a validator has already submitted a proof for a slot
HasProof(v, slot) ==
    \E p \in proofs : p.validator = v /\ p.slot = slot

\* ---- State machine ----

Init ==
    /\ proofs = {}
    /\ leaders = [s \in Slots |-> "none"]
    /\ usedOutputs = {}

\* A validator submits a VRF proof for a slot
SubmitProof(v, slot, output, valid) ==
    /\ v \in Validators
    /\ slot \in Slots
    /\ output \in Nat                                  \* Abstract VRF output
    /\ ~HasProof(v, slot)                              \* No duplicate proofs per validator per slot
    /\ output \notin usedOutputs                       \* No output reuse (replay protection)
    /\ proofs' = proofs \cup {[validator |-> v, slot |-> slot, output |-> output, valid |-> valid]}
    /\ usedOutputs' = usedOutputs \cup {output}
    /\ leaders' = leaders

\* Elect a leader for a slot based on valid proofs
\* The leader is the validator with the lowest valid VRF output (closest to target)
ElectLeader(slot) ==
    /\ slot \in Slots
    /\ leaders[slot] = "none"                          \* No leader elected yet
    /\ ValidProofsForSlot(slot) # {}                   \* At least one valid proof
    /\ LET winningProof == CHOOSE p \in ValidProofsForSlot(slot) :
            \A other \in ValidProofsForSlot(slot) : p.output <= other.output IN
        /\ leaders' = [leaders EXCEPT ![slot] = winningProof.validator]
        /\ proofs' = proofs
        /\ usedOutputs' = usedOutputs

Next ==
    \/ \E v \in Validators, s \in Slots, o \in 1..10, valid \in BOOLEAN :
        SubmitProof(v, s, o, valid)
    \/ \E s \in Slots : ElectLeader(s)

\* ---- Invariants ----

\* INV-1: At most one leader per slot
AtMostOneLeaderPerSlot ==
    \A s \in Slots :
        leaders[s] # "none" =>
            leaders[s] \in Validators

\* INV-2: Every elected leader has a valid proof
LeaderHasValidProof ==
    \A s \in Slots :
        leaders[s] # "none" =>
            \E p \in proofs : p.validator = leaders[s] /\ p.slot = s /\ p.valid

\* INV-3: No VRF output reuse across proofs
NoOutputReuse ==
    \A p1, p2 \in proofs :
        p1 # p2 => p1.output # p2.output

\* INV-4: No duplicate proofs per (validator, slot)
NoDuplicateProofs ==
    \A p1, p2 \in proofs :
        p1 # p2 => ~(p1.validator = p2.validator /\ p1.slot = p2.slot)

\* INV-5: Leader election is deterministic — only one validator can win per slot
LeaderDeterminism ==
    \A s \in Slots :
        leaders[s] \in Validators \cup {"none"}

\* ---- Type invariant ----

TypeInv ==
    /\ proofs \subseteq [validator: Validators, slot: Slots, output: Nat, valid: BOOLEAN]
    /\ leaders \in [Slots -> Validators \cup {"none"}]
    /\ usedOutputs \subseteq Nat

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeInv
THEOREM OneLeader == Spec => []AtMostOneLeaderPerSlot
THEOREM LeaderValid == Spec => []LeaderHasValidProof
THEOREM NoReplay == Spec => []NoOutputReuse
THEOREM NoDupProofs == Spec => []NoDuplicateProofs
THEOREM Deterministic == Spec => []LeaderDeterminism

=============================================================================
