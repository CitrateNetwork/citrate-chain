--------------------- MODULE TestnetFarming ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the TestnetFarmingAccounting snapshot and distribution lifecycle.
\*
\* Lifecycle:
\*   1. Governance takes a one-time snapshot of contribution scores
\*   2. Governance activates distribution with a stablecoin pool
\*   3. Participants claim proportional shares
\*   4. Governance sweeps unclaimed funds after grace period
\*
\* The model verifies conservation of funds, no double-claims, proportionality,
\* and lifecycle ordering invariants.
\*
\* Source: contracts/src/TestnetFarmingAccounting.sol

CONSTANTS
    NUM_PARTICIPANTS,    \* Number of participant addresses
    DISTRIBUTION_POOL   \* Total stablecoin pool for distribution

ASSUME NUM_PARTICIPANTS \in Nat /\ NUM_PARTICIPANTS >= 1
ASSUME DISTRIBUTION_POOL \in Nat /\ DISTRIBUTION_POOL >= 1

Participants == 1..NUM_PARTICIPANTS

\* Lifecycle states
LifecycleStates == {"PreSnapshot", "SnapshotTaken", "DistributionActive", "DistributionComplete"}

\* Maximum score per participant (bound for tractable checking)
MaxScore == 10

\* Grace period in blocks before sweep is allowed
GracePeriodBlocks == 3

\* Max block to bound state space
MaxBlock == GracePeriodBlocks + 5

VARIABLES
    lifecycleState,     \* Current lifecycle state
    snapshotTaken,      \* TRUE once snapshot is taken
    snapshotScores,     \* Mapping: participant -> snapshotted score
    totalScore,         \* Sum of all snapshotted scores
    distributionActive, \* TRUE once distribution is activated
    distributionPool,   \* Total pool amount
    hasClaimed,         \* Set of participants who have claimed
    claimedAmounts,     \* Mapping: participant -> amount claimed
    totalClaimed,       \* Sum of all claims
    swept,              \* TRUE if unclaimed funds were swept
    currentBlock,       \* Current block number
    distributionBlock   \* Block when distribution was activated

vars == <<lifecycleState, snapshotTaken, snapshotScores, totalScore,
          distributionActive, distributionPool, hasClaimed, claimedAmounts,
          totalClaimed, swept, currentBlock, distributionBlock>>

\* ---- Helpers ----

\* Recursive sum over participants
RECURSIVE SumScores(_, _)
SumScores(S, acc) ==
    IF S = {} THEN acc
    ELSE LET p == CHOOSE x \in S : TRUE
         IN SumScores(S \ {p}, acc + snapshotScores[p])

\* Calculate a participant's proportional share
\* share = (pool * score) \div totalScore
ShareFor(p) ==
    IF totalScore = 0 THEN 0
    ELSE (distributionPool * snapshotScores[p]) \div totalScore

\* ---- State machine ----

Init ==
    /\ lifecycleState = "PreSnapshot"
    /\ snapshotTaken = FALSE
    /\ snapshotScores = [p \in Participants |-> 0]
    /\ totalScore = 0
    /\ distributionActive = FALSE
    /\ distributionPool = 0
    /\ hasClaimed = {}
    /\ claimedAmounts = [p \in Participants |-> 0]
    /\ totalClaimed = 0
    /\ swept = FALSE
    /\ currentBlock = 0
    /\ distributionBlock = 0

\* --- Take a one-time snapshot of contribution scores ---
\* Models takeSnapshot(): reads scores and records them.
\* Uses deterministic scores (participant ID as score) to keep state space tractable.
\* For NUM_PARTICIPANTS=3: scores = {1:1, 2:2, 3:3}, totalScore = 6.
TakeSnapshotSimple ==
    /\ snapshotTaken = FALSE
    /\ distributionActive = FALSE
    \* Each participant gets score = their ID (1, 2, 3, ...)
    /\ snapshotScores' = [p \in Participants |-> p]
    /\ totalScore' = (NUM_PARTICIPANTS * (NUM_PARTICIPANTS + 1)) \div 2
    /\ snapshotTaken' = TRUE
    /\ lifecycleState' = "SnapshotTaken"
    /\ UNCHANGED <<distributionActive, distributionPool, hasClaimed, claimedAmounts,
                   totalClaimed, swept, currentBlock, distributionBlock>>

\* --- Activate distribution ---
ActivateDistribution ==
    /\ snapshotTaken = TRUE
    /\ distributionActive = FALSE
    /\ totalScore > 0
    /\ distributionActive' = TRUE
    /\ distributionPool' = DISTRIBUTION_POOL
    /\ distributionBlock' = currentBlock
    /\ lifecycleState' = "DistributionActive"
    /\ UNCHANGED <<snapshotTaken, snapshotScores, totalScore,
                   hasClaimed, claimedAmounts, totalClaimed, swept,
                   currentBlock>>

\* --- Participant claims their share ---
Claim(p) ==
    /\ p \in Participants
    /\ distributionActive = TRUE
    /\ p \notin hasClaimed             \* No double claim
    /\ snapshotScores[p] > 0           \* Must have score
    /\ ~swept                          \* Cannot claim after sweep
    /\ LET share == ShareFor(p)
       IN /\ share > 0
          /\ totalClaimed + share <= distributionPool
          /\ hasClaimed' = hasClaimed \union {p}
          /\ claimedAmounts' = [claimedAmounts EXCEPT ![p] = share]
          /\ totalClaimed' = totalClaimed + share
    /\ IF Cardinality(hasClaimed \union {p}) = NUM_PARTICIPANTS
       THEN lifecycleState' = "DistributionComplete"
       ELSE lifecycleState' = lifecycleState
    /\ UNCHANGED <<snapshotTaken, snapshotScores, totalScore,
                   distributionActive, distributionPool, swept,
                   currentBlock, distributionBlock>>

\* --- Sweep unclaimed funds (governance, after grace period) ---
SweepUnclaimed ==
    /\ distributionActive = TRUE
    /\ ~swept
    /\ currentBlock >= distributionBlock + GracePeriodBlocks
    /\ swept' = TRUE
    /\ lifecycleState' = "DistributionComplete"
    /\ UNCHANGED <<snapshotTaken, snapshotScores, totalScore,
                   distributionActive, distributionPool,
                   hasClaimed, claimedAmounts, totalClaimed,
                   currentBlock, distributionBlock>>

\* --- Advance block ---
AdvanceBlock ==
    /\ currentBlock < MaxBlock
    /\ currentBlock' = currentBlock + 1
    /\ UNCHANGED <<lifecycleState, snapshotTaken, snapshotScores, totalScore,
                   distributionActive, distributionPool,
                   hasClaimed, claimedAmounts, totalClaimed, swept,
                   distributionBlock>>

Next ==
    \/ TakeSnapshotSimple
    \/ ActivateDistribution
    \/ \E p \in Participants : Claim(p)
    \/ SweepUnclaimed
    \/ AdvanceBlock

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ lifecycleState \in LifecycleStates
    /\ snapshotTaken \in BOOLEAN
    /\ \A p \in Participants : snapshotScores[p] \in Nat
    /\ totalScore \in Nat
    /\ distributionActive \in BOOLEAN
    /\ distributionPool \in Nat
    /\ hasClaimed \subseteq Participants
    /\ \A p \in Participants : claimedAmounts[p] \in Nat
    /\ totalClaimed \in Nat
    /\ swept \in BOOLEAN
    /\ currentBlock \in Nat
    /\ distributionBlock \in Nat

\* INV-2: SnapshotOnce — snapshot cannot be taken twice.
SnapshotOnce ==
    snapshotTaken => lifecycleState # "PreSnapshot"

\* INV-3: NoClaimBeforeDistribution — claims only when distributionActive.
NoClaimBeforeDistribution ==
    hasClaimed # {} => distributionActive = TRUE

\* INV-4: NoDoubleClaim — each participant claims exactly once.
\* Structurally enforced by set membership. We verify total claims <= participants.
NoDoubleClaim ==
    Cardinality(hasClaimed) <= NUM_PARTICIPANTS

\* INV-5: ClaimsConserved — sum of all claims never exceeds the pool.
ClaimsConserved ==
    totalClaimed <= distributionPool

\* INV-6: ProportionalShares — each claimed amount matches the formula.
\* share = (pool * score) / totalScore
ProportionalShares ==
    \A p \in Participants :
        (p \in hasClaimed /\ totalScore > 0) =>
            claimedAmounts[p] = (distributionPool * snapshotScores[p]) \div totalScore

\* INV-7: SweepOnlyAfterGrace — sweep only after grace period blocks.
SweepOnlyAfterGrace ==
    swept => (distributionActive /\ currentBlock >= distributionBlock + GracePeriodBlocks)

\* INV-8: LifecycleOrdered — states progress forward.
LifecycleOrdered ==
    /\ (~snapshotTaken => lifecycleState = "PreSnapshot")
    /\ (snapshotTaken /\ ~distributionActive => lifecycleState = "SnapshotTaken")

\* INV-9: BlockBounded
BlockBounded ==
    currentBlock <= MaxBlock

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety       == Spec => []TypeOK
THEOREM SnapOnce         == Spec => []SnapshotOnce
THEOREM NoEarlyClaim     == Spec => []NoClaimBeforeDistribution
THEOREM NoDupClaim       == Spec => []NoDoubleClaim
THEOREM ClaimsOK         == Spec => []ClaimsConserved
THEOREM Proportional     == Spec => []ProportionalShares
THEOREM SweepGated       == Spec => []SweepOnlyAfterGrace
THEOREM LifecycleFwd     == Spec => []LifecycleOrdered
THEOREM BlocksOK         == Spec => []BlockBounded

=============================================================================
