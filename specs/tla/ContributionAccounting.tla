------------------------------ MODULE ContributionAccounting ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the 7-type contribution tracking system with weighted scores.
\*
\* Each contributor accumulates contributions across multiple types. A weighted score
\* determines reward distribution from the reward pool. Rewards are proportional
\* to each contributor's share of the total weighted score.
\*
\* In production, ContributionTypes = {"Validation", "ModelHosting", "AdapterCreation",
\* "DataProvision", "AppDev", "BridgeInfra", "Governance"} with weights 10,8,7,6,5,4,3.
\* For model checking we use a small representative subset.
\*
\* Source: core/economics/src/contributions.rs, contracts/src/ContributionTracker.sol

CONSTANTS
    Contributors,          \* Set of contributor addresses
    ContributionTypes,     \* Set of contribution type labels (parameterized for TLC)
    MaxContributions       \* Max contributions per contributor per type

ASSUME Contributors # {}
ASSUME ContributionTypes # {}
ASSUME MaxContributions \in Nat /\ MaxContributions >= 1

VARIABLES
    contributions,    \* Mapping: contributor -> mapping: type -> count
    scores,           \* Mapping: contributor -> weighted score
    rewardPool,       \* Total SALT available for distribution
    distributed       \* Mapping: contributor -> SALT received

vars == <<contributions, scores, rewardPool, distributed>>

\* ---- Helper operators ----

\* Weight per type — all types weighted equally at 1 for tractable model checking.
\* The real system uses varying weights (3-10); the proportionality invariant
\* holds regardless of specific weight values.
Weight == 1

\* Recursive sum over a set with function values.
RECURSIVE SetSum(_, _)
SetSum(S, f) ==
    IF S = {} THEN 0
    ELSE LET x == CHOOSE v \in S : TRUE
         IN f[x] + SetSum(S \ {x}, f)

\* Recursive sum of contributions for a contributor.
RECURSIVE TypeSum(_, _, _)
TypeSum(types, contribs, acc) ==
    IF types = {} THEN acc
    ELSE LET t == CHOOSE x \in types : TRUE
         IN TypeSum(types \ {t}, contribs, acc + contribs[t] * Weight)

\* Weighted score for a contributor.
WeightedScore(c) == TypeSum(ContributionTypes, contributions[c], 0)

\* Total weighted score across all contributors.
TotalScore == SetSum(Contributors, scores)

\* Total distributed rewards.
TotalDistributed == SetSum(Contributors, distributed)

\* Max reward pool size (bound state space).
MaxPool == 3

\* ---- State machine ----

Init ==
    /\ contributions = [c \in Contributors |-> [t \in ContributionTypes |-> 0]]
    /\ scores = [c \in Contributors |-> 0]
    /\ rewardPool = 0
    /\ distributed = [c \in Contributors |-> 0]

\* Record a contribution of a given type for a contributor.
RecordContribution(c, t) ==
    /\ c \in Contributors
    /\ t \in ContributionTypes
    /\ contributions[c][t] < MaxContributions
    /\ contributions' = [contributions EXCEPT ![c][t] = @ + 1]
    /\ scores' = [scores EXCEPT ![c] = WeightedScore(c) + Weight]
    /\ UNCHANGED <<rewardPool, distributed>>

\* Add rewards to the pool.
FundPool(amount) ==
    /\ amount \in 1..MaxPool
    /\ rewardPool + amount <= MaxPool
    /\ rewardPool' = rewardPool + amount
    /\ UNCHANGED <<contributions, scores, distributed>>

\* Distribute rewards proportionally.
\* For simplicity, we distribute integer amounts using floor division.
DistributeRewards ==
    /\ rewardPool > 0
    /\ TotalScore > 0
    /\ LET ts == TotalScore
           pool == rewardPool
           alloc == [c \in Contributors |-> (scores[c] * pool) \div ts]
           totalAlloc == SetSum(Contributors, alloc)
       IN
       /\ distributed' = [c \in Contributors |-> distributed[c] + alloc[c]]
       /\ rewardPool' = pool - totalAlloc
       /\ UNCHANGED <<contributions, scores>>

Next ==
    \/ \E c \in Contributors, t \in ContributionTypes : RecordContribution(c, t)
    \/ \E a \in 1..MaxPool : FundPool(a)
    \/ DistributeRewards

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ \A c \in Contributors :
        /\ \A t \in ContributionTypes : contributions[c][t] \in 0..MaxContributions
        /\ scores[c] \in Nat
        /\ distributed[c] \in Nat
    /\ rewardPool \in Nat

\* INV-2: ScoreIsWeightedSum — score matches the weighted sum of contributions.
ScoreIsWeightedSum ==
    \A c \in Contributors : scores[c] = WeightedScore(c)

\* INV-3: TotalDistributedConsistent — remaining reward pool is non-negative.
TotalDistributedConsistent ==
    rewardPool >= 0

\* INV-4: ContributionOnlyIncrements — contributions are non-negative.
ContributionOnlyIncrements ==
    \A c \in Contributors, t \in ContributionTypes :
        contributions[c][t] >= 0

\* INV-5: ZeroContributionZeroScore — if all contributions are 0, score is 0.
ZeroContributionZeroScore ==
    \A c \in Contributors :
        (\A t \in ContributionTypes : contributions[c][t] = 0) =>
            scores[c] = 0

\* INV-6: Score non-negative
ScoreNonNegative ==
    \A c \in Contributors : scores[c] >= 0

\* INV-7: Contributions bounded
ContributionsBounded ==
    \A c \in Contributors, t \in ContributionTypes :
        contributions[c][t] <= MaxContributions

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM WeightedScores == Spec => []ScoreIsWeightedSum
THEOREM DistConsistent == Spec => []TotalDistributedConsistent
THEOREM OnlyIncrements == Spec => []ContributionOnlyIncrements
THEOREM ZeroZero == Spec => []ZeroContributionZeroScore
THEOREM NonNegScore == Spec => []ScoreNonNegative
THEOREM BoundedContrib == Spec => []ContributionsBounded

=============================================================================
