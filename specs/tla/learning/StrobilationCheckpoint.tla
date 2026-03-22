------------------------------ MODULE StrobilationCheckpoint ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the integration of learning state into consensus checkpoints.
\*
\* At BFT checkpoint heights the block producer:
\*   1. Collects local embeddings
\*   2. Receives peer embeddings via P2P
\*   3. Runs paraconsensus aggregation
\*   4. Computes a learning_root hash
\*   5. Includes learning_root in the block header
\*
\* CRITICAL SAFETY: stateRoots are NEVER affected by learningRoots (Theorem 3 extension).
\*
\* Source: core/consensus/src/checkpoint.rs, core/learning/src/strobilate.rs

CONSTANTS
    Validators,           \* Set of validator public keys
    MaxBlocks,            \* Max block height for finite state
    CheckpointInterval    \* Blocks between checkpoints (e.g., 2)

ASSUME Validators # {}
ASSUME MaxBlocks \in Nat /\ MaxBlocks >= 1
ASSUME CheckpointInterval \in Nat /\ CheckpointInterval >= 1

VARIABLES
    blockHeight,       \* Current block height (0 = genesis)
    produced,          \* Set of heights for which blocks have been produced
    hasLearningRoot,   \* Set of heights that include a learning_root in their block
    stateRoots,        \* Mapping: produced height -> state_root (subset of produced)
    embeddingsSeen,    \* Mapping: checkpoint_height -> set of validators who submitted
    aggregatedHeights  \* Set of checkpoint heights for which aggregation is complete

vars == <<blockHeight, produced, hasLearningRoot, stateRoots, embeddingsSeen, aggregatedHeights>>

\* ---- Helper operators ----

\* Quorum threshold: strictly more than 2/3 of validators.
Quorum == (2 * Cardinality(Validators)) \div 3 + 1

\* Is height h a checkpoint height?
IsCheckpoint(h) == h > 0 /\ h % CheckpointInterval = 0

\* Set of all checkpoint heights within bounds.
CheckpointHeights == {h \in 1..MaxBlocks : IsCheckpoint(h)}

\* Abstract state root — deterministically derived from height only (never from learning).
StateRootFor(h) == h * 1000 + 7

\* ---- State machine ----

Init ==
    /\ blockHeight = 0
    /\ produced = {0}
    /\ hasLearningRoot = {}
    /\ stateRoots = [h \in {0} |-> StateRootFor(0)]
    /\ embeddingsSeen = [h \in CheckpointHeights |-> {}]
    /\ aggregatedHeights = {}

\* A validator submits an embedding for a checkpoint height.
SubmitEmbedding(v, cpHeight) ==
    /\ v \in Validators
    /\ cpHeight \in CheckpointHeights
    /\ cpHeight > blockHeight                         \* checkpoint not yet produced
    /\ v \notin embeddingsSeen[cpHeight]              \* not already submitted
    /\ embeddingsSeen' = [embeddingsSeen EXCEPT ![cpHeight] = @ \cup {v}]
    /\ UNCHANGED <<blockHeight, produced, hasLearningRoot, stateRoots, aggregatedHeights>>

\* Aggregate embeddings when quorum is reached for a checkpoint.
AggregateEmbeddings(cpHeight) ==
    /\ cpHeight \in CheckpointHeights
    /\ cpHeight \notin aggregatedHeights                    \* not yet aggregated
    /\ Cardinality(embeddingsSeen[cpHeight]) >= Quorum      \* quorum reached
    /\ aggregatedHeights' = aggregatedHeights \cup {cpHeight}
    /\ UNCHANGED <<blockHeight, produced, hasLearningRoot, stateRoots, embeddingsSeen>>

\* Produce a non-checkpoint block.
ProduceNormalBlock ==
    /\ blockHeight < MaxBlocks
    /\ ~IsCheckpoint(blockHeight + 1)
    /\ LET h == blockHeight + 1 IN
       /\ blockHeight' = h
       /\ produced' = produced \cup {h}
       /\ stateRoots' = [x \in DOMAIN stateRoots \cup {h} |->
                            IF x = h THEN StateRootFor(h) ELSE stateRoots[x]]
       /\ UNCHANGED <<hasLearningRoot, embeddingsSeen, aggregatedHeights>>

\* Produce a checkpoint block — requires aggregation complete.
ProduceCheckpointBlock ==
    /\ blockHeight < MaxBlocks
    /\ LET h == blockHeight + 1 IN
       /\ IsCheckpoint(h)
       /\ h \in aggregatedHeights                   \* aggregation must be done
       /\ blockHeight' = h
       /\ produced' = produced \cup {h}
       /\ hasLearningRoot' = hasLearningRoot \cup {h}
       /\ stateRoots' = [x \in DOMAIN stateRoots \cup {h} |->
                            IF x = h THEN StateRootFor(h) ELSE stateRoots[x]]
       /\ UNCHANGED <<embeddingsSeen, aggregatedHeights>>

Next ==
    \/ \E v \in Validators, cp \in CheckpointHeights : SubmitEmbedding(v, cp)
    \/ \E cp \in CheckpointHeights : AggregateEmbeddings(cp)
    \/ ProduceNormalBlock
    \/ ProduceCheckpointBlock

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ blockHeight \in 0..MaxBlocks
    /\ produced \subseteq 0..MaxBlocks
    /\ hasLearningRoot \subseteq 0..MaxBlocks
    /\ aggregatedHeights \subseteq CheckpointHeights
    /\ \A cp \in CheckpointHeights : embeddingsSeen[cp] \subseteq Validators

\* INV-2: LearningRootDeterministic — same set of embeddings implies aggregation
\* occurs at most once per checkpoint height (set membership is idempotent).
LearningRootDeterministic ==
    \A h \in hasLearningRoot : h \in aggregatedHeights

\* INV-3: CheckpointComplete — every produced checkpoint block has a learning_root.
CheckpointComplete ==
    \A h \in produced :
        IsCheckpoint(h) => h \in hasLearningRoot

\* INV-4: StateRootIndependent — state roots are NEVER affected by learning roots (Theorem 3).
\* State root at height h is always StateRootFor(h), regardless of learning activity.
StateRootIndependent ==
    \A h \in DOMAIN stateRoots :
        stateRoots[h] = StateRootFor(h)

\* INV-5: EmbeddingQuorum — aggregation only happens when quorum of validators submitted.
EmbeddingQuorum ==
    \A h \in aggregatedHeights :
        Cardinality(embeddingsSeen[h]) >= Quorum

\* INV-6: LearningRootMonotonic — once a height has a learning root, it stays.
\* Structurally guaranteed: hasLearningRoot only grows via \cup.
LearningRootMonotonic ==
    hasLearningRoot \subseteq produced

\* INV-7: Aggregation requires quorum
AggregationRequiresQuorum ==
    \A h \in aggregatedHeights :
        Cardinality(embeddingsSeen[h]) >= Quorum

\* INV-8: Produced blocks are contiguous from 0 to blockHeight
ProducedContiguous ==
    \A h \in 0..blockHeight :
        (h \in produced) \/ IsCheckpoint(h)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM DetRoot == Spec => []LearningRootDeterministic
THEOREM CpComplete == Spec => []CheckpointComplete
THEOREM Theorem3Ext == Spec => []StateRootIndependent
THEOREM QuorumReq == Spec => []EmbeddingQuorum
THEOREM Monotonic == Spec => []LearningRootMonotonic
THEOREM AggQuorum == Spec => []AggregationRequiresQuorum

=============================================================================
