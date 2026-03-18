------------------------------ MODULE VRFChainContinuity ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Models VRF output chaining across blocks: each block's VRF alpha input
\* includes the parent block's VRF output, ensuring an unbroken verifiable
\* random chain along the selected-parent spine.
\* Source: core/consensus/src/vrf.rs — alpha binding: SHA3(pubkey || prev_vrf || slot)

CONSTANTS
    Validators,     \* Set of validator IDs
    MaxBlocks,      \* Maximum number of blocks (bounds state space)
    MaxSlots        \* Maximum number of slots

ASSUME Validators # {}
ASSUME MaxBlocks \in Nat /\ MaxBlocks >= 1
ASSUME MaxSlots \in Nat /\ MaxSlots >= 1

\* Block IDs: 0 = genesis, 1..MaxBlocks = producible blocks
BlockIds == 0..MaxBlocks
SlotNums == 1..MaxSlots

\* VRF outputs are modeled as abstract naturals.
\* We encode them as (validator index * MaxSlots * MaxBlocks + slot * MaxBlocks + parentVRF)
\* to make them deterministic given (validator, slot, parentVRF) and unique otherwise.
\* Range: 1..(|Validators| * MaxSlots * (MaxBlocks + 1) * 2) to allow enough room.
VRFOutputRange == 1..(Cardinality(Validators) * MaxSlots * (MaxBlocks + 1) * 2 + 10)

VARIABLES
    blocks,               \* Function: block ID -> record [producer, slot, parentId, vrfAlpha, vrfOutput, blueScore]
    vrfOutputs,           \* Set of all VRF outputs produced so far (for replay detection)
    selectedParentChain,  \* Sequence of block IDs forming the current selected-parent chain from genesis
    tips,                 \* Set of current tip block IDs (no children)
    currentSlot           \* Current slot number

vars == <<blocks, vrfOutputs, selectedParentChain, tips, currentSlot>>

\* ---- Helper operators ----

\* The set of block IDs that have been added to the DAG
AddedBlocks == DOMAIN blocks

\* Deterministic VRF output function: hash(validator, slot, parentVRF)
\* We model this as a unique natural per (v, slot, parentVRF) triple.
\* Use a bijective-ish encoding to ensure uniqueness.
RECURSIVE ValidatorIndex(_, _)
ValidatorIndex(v, vs) ==
    IF vs = {} THEN 0
    ELSE LET w == CHOOSE x \in vs : TRUE IN
         IF v = w THEN 1
         ELSE 1 + ValidatorIndex(v, vs \ {w})

ComputeVRFOutput(v, slot, parentVRF) ==
    LET vi == ValidatorIndex(v, Validators) IN
    (vi - 1) * MaxSlots * (MaxBlocks + 1) + (slot - 1) * (MaxBlocks + 1) + parentVRF + 1

\* Genesis VRF output (seed value)
GenesisVRFOutput == 0

\* Compute the VRF alpha input for a block: includes parent's VRF output
ComputeVRFAlpha(v, slot, parentVRF) ==
    \* Alpha = hash(pubkey || parentVRF || slot) — modeled as the triple
    [validator |-> v, slot |-> slot, parentVRF |-> parentVRF]

\* Build the selected-parent chain: walk from a tip back to genesis
RECURSIVE ChainToGenesis(_)
ChainToGenesis(bid) ==
    IF bid = 0 THEN <<0>>
    ELSE Append(ChainToGenesis(blocks[bid].parentId), bid)

\* Blue score: for simplicity, depth from genesis along selected parent
RECURSIVE Depth(_)
Depth(bid) ==
    IF bid = 0 THEN 0
    ELSE 1 + Depth(blocks[bid].parentId)

\* Find the tip with the highest blue score (for selected chain)
BestTip ==
    CHOOSE t \in tips :
        \A other \in tips :
            blocks[t].blueScore >= blocks[other].blueScore

\* ---- State machine ----

Init ==
    /\ blocks = [bid \in {0} |-> [
            producer   |-> CHOOSE v \in Validators : TRUE,
            slot       |-> 0,
            parentId   |-> 0,
            vrfAlpha   |-> [validator |-> CHOOSE v \in Validators : TRUE, slot |-> 0, parentVRF |-> 0],
            vrfOutput  |-> GenesisVRFOutput,
            blueScore  |-> 0
       ]]
    /\ vrfOutputs = {GenesisVRFOutput}
    /\ selectedParentChain = <<0>>
    /\ tips = {0}
    /\ currentSlot = 1

\* A validator v produces a block extending a parent tip
ProduceBlock(v) ==
    /\ v \in Validators
    /\ currentSlot <= MaxSlots
    /\ Cardinality(AddedBlocks) <= MaxBlocks   \* Don't exceed block budget
    /\ \E parentTip \in tips :
        LET
            parentVRF   == blocks[parentTip].vrfOutput
            alpha       == ComputeVRFAlpha(v, currentSlot, parentVRF)
            vrfOut      == ComputeVRFOutput(v, currentSlot, parentVRF)
            newId       == Cardinality(AddedBlocks)   \* Next available block ID
            newScore    == Depth(parentTip) + 1
        IN
            /\ newId <= MaxBlocks
            /\ vrfOut \notin vrfOutputs               \* No VRF output replay
            /\ blocks' = [bid \in AddedBlocks \cup {newId} |->
                IF bid = newId
                THEN [
                    producer   |-> v,
                    slot       |-> currentSlot,
                    parentId   |-> parentTip,
                    vrfAlpha   |-> alpha,
                    vrfOutput  |-> vrfOut,
                    blueScore  |-> newScore
                ]
                ELSE blocks[bid]]
            /\ vrfOutputs' = vrfOutputs \cup {vrfOut}
            /\ tips' = (tips \ {parentTip}) \cup {newId}
            /\ currentSlot' = currentSlot + 1
            \* Recompute selected chain from best tip
            /\ LET bestId == IF newScore > blocks[BestTip].blueScore
                             THEN newId
                             ELSE BestTip
               IN selectedParentChain' = ChainToGenesis(bestId)

\* Reorg: switch selected parent chain to a different fork with higher score
Reorg ==
    /\ Cardinality(tips) > 1
    /\ LET best == BestTip
           chain == ChainToGenesis(best)
       IN
        /\ chain # selectedParentChain      \* Actually a different chain
        /\ selectedParentChain' = chain
        /\ UNCHANGED <<blocks, vrfOutputs, tips, currentSlot>>

\* ValidateChain: a no-op validation step that asserts VRF continuity
\* (used to force TLC to explore states where we check the chain)
ValidateChain ==
    /\ Len(selectedParentChain) > 0
    /\ UNCHANGED vars

Next ==
    \/ \E v \in Validators : ProduceBlock(v)
    \/ Reorg
    \/ ValidateChain

\* ---- Invariants ----

\* INV-1: TypeInv — well-formed state
TypeInv ==
    /\ DOMAIN blocks \subseteq BlockIds
    /\ 0 \in DOMAIN blocks
    /\ \A bid \in DOMAIN blocks :
        /\ blocks[bid].producer \in Validators
        /\ blocks[bid].slot \in Nat
        /\ blocks[bid].parentId \in DOMAIN blocks
        /\ blocks[bid].vrfOutput \in Nat
        /\ blocks[bid].blueScore \in Nat
    /\ vrfOutputs \subseteq Nat
    /\ tips \subseteq DOMAIN blocks
    /\ tips # {}
    /\ currentSlot \in Nat

\* INV-2: VRFChainValid — each non-genesis block's VRF alpha includes parent's VRF output
VRFChainValid ==
    \A bid \in DOMAIN blocks :
        bid # 0 =>
            LET parent == blocks[bid].parentId IN
            /\ parent \in DOMAIN blocks
            /\ blocks[bid].vrfAlpha.parentVRF = blocks[parent].vrfOutput

\* INV-3: NoVRFReplay — no two blocks share the same VRF output
NoVRFReplay ==
    \A b1, b2 \in DOMAIN blocks :
        (b1 # b2 /\ b1 # 0 /\ b2 # 0) =>
            blocks[b1].vrfOutput # blocks[b2].vrfOutput

\* INV-4: ReorgPreservesChain — the selected parent chain has valid VRF continuity
ReorgPreservesChain ==
    \A i \in 2..Len(selectedParentChain) :
        LET bid    == selectedParentChain[i]
            parent == selectedParentChain[i - 1]
        IN
            /\ bid \in DOMAIN blocks
            /\ parent \in DOMAIN blocks
            /\ blocks[bid].parentId = parent
            /\ blocks[bid].vrfAlpha.parentVRF = blocks[parent].vrfOutput

\* INV-5: DeterministicLeader — same (validator, slot, parentVRF) triple produces same VRF output
DeterministicLeader ==
    \A b1, b2 \in DOMAIN blocks :
        (/\ b1 # 0 /\ b2 # 0
         /\ blocks[b1].producer = blocks[b2].producer
         /\ blocks[b1].slot = blocks[b2].slot
         /\ blocks[b1].vrfAlpha.parentVRF = blocks[b2].vrfAlpha.parentVRF)
        => blocks[b1].vrfOutput = blocks[b2].vrfOutput

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety       == Spec => []TypeInv
THEOREM ChainValidity    == Spec => []VRFChainValid
THEOREM NoReplay         == Spec => []NoVRFReplay
THEOREM ReorgSafety      == Spec => []ReorgPreservesChain
THEOREM Determinism      == Spec => []DeterministicLeader

=============================================================================
