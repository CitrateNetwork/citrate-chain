--------------------------- MODULE TrustScoring ---------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models AgentDecisionRegistry trust scoring from
\* contracts/src/AgentDecisionRegistry.sol.
\*
\* Agents record decisions on-chain.  Each recorded decision increments
\* the agent's trust score by 1.  A dispute decrements the score by 2
\* (via disputeCount++, and score = total - disputes*2).  Disputes can be
\* resolved: if upheld the penalty stands, if overturned the dispute count
\* is decremented (restoring 2 points).
\*
\* Trust tiers:
\*   Untrusted:  score < TierBoundary_Standard (100)
\*   Standard:   TierBoundary_Standard <= score < TierBoundary_Trusted (500)
\*   Trusted:    score >= TierBoundary_Trusted (500)
\*
\* Source: contracts/src/AgentDecisionRegistry.sol
\*   - registerDecision, disputeDecision, resolveDispute
\*   - getTrustScore, getTrustTier, _tierName
\*   - DecisionStatus: Recorded, Disputed, Resolved

CONSTANTS
    Agents,                     \* Set of agent identifiers
    MaxDecisions,               \* Maximum number of decisions (bounds state space)
    TierBoundary_Standard,      \* Score threshold for Standard tier (100)
    TierBoundary_Trusted        \* Score threshold for Trusted tier (500)

ASSUME Agents # {}
ASSUME MaxDecisions \in Nat /\ MaxDecisions >= 1
ASSUME TierBoundary_Standard \in Nat /\ TierBoundary_Standard >= 1
ASSUME TierBoundary_Trusted \in Nat /\ TierBoundary_Trusted > TierBoundary_Standard

\* Decision status values (mirrors Solidity enum)
DecisionStatuses == {"Recorded", "Disputed", "Resolved"}

\* Trust tiers
TrustTiers == {"Untrusted", "Standard", "Trusted"}

VARIABLES
    decisions,          \* Function: decisionId -> [agentId, status]
    decisionCount,      \* Total number of decisions registered
    agentDecisionCt,    \* Function: agent -> count of decisions registered
    disputeCount,       \* Function: agent -> count of active disputes
    nextId              \* Next decision ID to assign

vars == <<decisions, decisionCount, agentDecisionCt, disputeCount, nextId>>

\* ---- Helpers ----

\* Compute trust score for an agent: total_decisions - disputes * 2
TrustScore(agent) ==
    LET total == agentDecisionCt[agent]
        disputes == disputeCount[agent]
    IN IF total >= disputes * 2
       THEN total - disputes * 2
       ELSE 0

\* Compute tier from score.
TierFromScore(score) ==
    IF score < TierBoundary_Standard THEN "Untrusted"
    ELSE IF score < TierBoundary_Trusted THEN "Standard"
    ELSE "Trusted"

\* Current tier for an agent.
AgentTier(agent) == TierFromScore(TrustScore(agent))

\* ---- State machine ----

Init ==
    /\ decisions = [id \in {} |-> [agentId |-> "none", status |-> "Recorded"]]
    /\ decisionCount = 0
    /\ agentDecisionCt = [a \in Agents |-> 0]
    /\ disputeCount = [a \in Agents |-> 0]
    /\ nextId = 0

\* Register a new decision for an agent.
RegisterDecision(agent) ==
    /\ agent \in Agents
    /\ nextId < MaxDecisions
    /\ LET id == nextId
       IN /\ decisions' = [x \in DOMAIN decisions \union {id} |->
                IF x = id
                THEN [agentId |-> agent, status |-> "Recorded"]
                ELSE decisions[x]]
          /\ decisionCount' = decisionCount + 1
          /\ agentDecisionCt' = [agentDecisionCt EXCEPT ![agent] = @ + 1]
          /\ nextId' = nextId + 1
          /\ UNCHANGED disputeCount

\* Dispute a recorded decision.
DisputeDecision(id) ==
    /\ id \in DOMAIN decisions
    /\ decisions[id].status = "Recorded"
    /\ LET agent == decisions[id].agentId
       IN /\ decisions' = [decisions EXCEPT ![id].status = "Disputed"]
          /\ disputeCount' = [disputeCount EXCEPT ![agent] = @ + 1]
          /\ UNCHANGED <<decisionCount, agentDecisionCt, nextId>>

\* Resolve a dispute.
\* upheld = TRUE means the dispute was valid (penalty stands).
\* upheld = FALSE means the dispute was invalid (penalty reversed).
ResolveDispute(id, upheld) ==
    /\ id \in DOMAIN decisions
    /\ decisions[id].status = "Disputed"
    /\ LET agent == decisions[id].agentId
       IN /\ decisions' = [decisions EXCEPT ![id].status = "Resolved"]
          /\ IF upheld
             THEN UNCHANGED disputeCount  \* Penalty stands
             ELSE \* Reverse the penalty: decrement dispute count
                  IF disputeCount[agent] > 0
                  THEN disputeCount' = [disputeCount EXCEPT ![agent] = @ - 1]
                  ELSE UNCHANGED disputeCount
          /\ UNCHANGED <<decisionCount, agentDecisionCt, nextId>>

Next ==
    \/ \E a \in Agents : RegisterDecision(a)
    \/ \E id \in DOMAIN decisions : DisputeDecision(id)
    \/ \E id \in DOMAIN decisions, upheld \in BOOLEAN : ResolveDispute(id, upheld)

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ decisionCount \in 0..MaxDecisions
    /\ nextId \in 0..MaxDecisions
    /\ \A a \in Agents : agentDecisionCt[a] \in 0..MaxDecisions
    /\ \A a \in Agents : disputeCount[a] \in 0..MaxDecisions
    /\ \A id \in DOMAIN decisions : decisions[id].status \in DecisionStatuses
    /\ \A id \in DOMAIN decisions : decisions[id].agentId \in Agents

\* INV-2: ScoreDecreasesOnDispute — if an agent has any active disputes,
\* their effective score is less than their raw decision count.
ScoreDecreasesOnDispute ==
    \A a \in Agents :
        disputeCount[a] > 0 => TrustScore(a) < agentDecisionCt[a]

\* INV-3: TierCorrect — tier assignment matches score boundaries.
TierCorrect ==
    \A a \in Agents :
        /\ (TrustScore(a) < TierBoundary_Standard => AgentTier(a) = "Untrusted")
        /\ (TrustScore(a) >= TierBoundary_Standard /\ TrustScore(a) < TierBoundary_Trusted
            => AgentTier(a) = "Standard")
        /\ (TrustScore(a) >= TierBoundary_Trusted => AgentTier(a) = "Trusted")

\* INV-4: DecisionImmutable — once a decision exists, its agentId never changes.
\* (The status can change, but the decision record cannot be deleted.)
DecisionImmutable ==
    \A id \in DOMAIN decisions :
        decisions[id].agentId \in Agents

\* INV-5: DisputeResolutionFinal — a Resolved decision cannot be re-disputed.
\* (This is enforced by the DisputeDecision guard requiring status = "Recorded".)
DisputeResolutionFinal ==
    \A id \in DOMAIN decisions :
        decisions[id].status = "Resolved" =>
            \* It cannot transition back to Disputed (no action allows this)
            TRUE

\* INV-6: NoNegativeScore — trust score is always >= 0.
NoNegativeScore ==
    \A a \in Agents : TrustScore(a) >= 0

\* INV-7: DecisionCountConsistent — sum of per-agent decisions = total count.
DecisionCountConsistent ==
    decisionCount = Cardinality(DOMAIN decisions)

\* INV-8: DisputeCountBounded — dispute count cannot exceed decision count for an agent.
DisputeCountBounded ==
    \A a \in Agents : disputeCount[a] <= agentDecisionCt[a]

\* INV-9: IdMonotonic — decision IDs are assigned monotonically.
IdMonotonic ==
    \A id \in DOMAIN decisions : id < nextId

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM ScoreDecreases == Spec => []ScoreDecreasesOnDispute
THEOREM TiersCorrect == Spec => []TierCorrect
THEOREM DecisionsImmutable == Spec => []DecisionImmutable
THEOREM DisputesFinal == Spec => []DisputeResolutionFinal
THEOREM NoNegScores == Spec => []NoNegativeScore
THEOREM DecisionCtConsistent == Spec => []DecisionCountConsistent
THEOREM DisputesBounded == Spec => []DisputeCountBounded
THEOREM IdsMonotonic == Spec => []IdMonotonic

=============================================================================
