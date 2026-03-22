--------------------- MODULE TreasuryGovernor ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the TreasuryGovernor on-chain DAO governance for treasury spending.
\*
\* Proposal lifecycle: Pending -> Active -> Succeeded -> Queued -> Executed
\* Alternative terminal states: Defeated (Failed), Expired, Canceled
\*
\* Voting power = SALT balance + stSALT shares. Proposals require threshold
\* SALT to create, quorum to pass, 60% approval, and a timelock before execution.
\*
\* Source: contracts/src/TreasuryGovernor.sol

CONSTANTS
    PROPOSAL_THRESHOLD,  \* Min SALT to create a proposal
    QUORUM,              \* Min total votes to reach quorum
    APPROVAL_BPS,        \* Approval threshold in BPS (6000 = 60%)
    VOTING_PERIOD,       \* Blocks for voting
    EXECUTION_DELAY,     \* Blocks of timelock after queue
    GRACE_PERIOD,        \* Blocks after timelock before expiry
    NUM_VOTERS           \* Number of voter addresses

ASSUME PROPOSAL_THRESHOLD \in Nat /\ PROPOSAL_THRESHOLD >= 1
ASSUME QUORUM \in Nat /\ QUORUM >= 1
ASSUME APPROVAL_BPS \in Nat /\ APPROVAL_BPS >= 1 /\ APPROVAL_BPS <= 10000
ASSUME VOTING_PERIOD \in Nat /\ VOTING_PERIOD >= 1
ASSUME EXECUTION_DELAY \in Nat /\ EXECUTION_DELAY >= 1
ASSUME GRACE_PERIOD \in Nat /\ GRACE_PERIOD >= 1
ASSUME NUM_VOTERS \in Nat /\ NUM_VOTERS >= 1

Voters == 1..NUM_VOTERS

\* Proposal states (matching contract enum)
ProposalStates == {"Pending", "Active", "Succeeded", "Queued",
                   "Executed", "Defeated", "Expired", "Canceled"}

\* Vote types
VoteTypes == {"For", "Against", "Abstain"}

\* Maximum block height to bound state space
MaxBlock == VOTING_PERIOD + EXECUTION_DELAY + GRACE_PERIOD + 5

\* Maximum voting power per voter (bound for tractable checking)
MaxVotingPower == 3

VARIABLES
    currentBlock,       \* Current block number
    proposalState,      \* Current state of THE proposal (single proposal model)
    proposer,           \* Voter ID who created the proposal ("none" if no proposal)
    votingStarts,       \* Block when voting starts
    votingEnds,         \* Block when voting ends
    executionEta,       \* Block when execution becomes possible (0 = not queued)
    forVotes,           \* Total for-votes weight
    againstVotes,       \* Total against-votes weight
    abstainVotes,       \* Total abstain-votes weight
    hasVoted,           \* Set of voter IDs that have voted
    executed,           \* TRUE if executed
    canceled,           \* TRUE if canceled
    votingPower         \* Mapping: voter -> voting power (fixed at init)

vars == <<currentBlock, proposalState, proposer, votingStarts, votingEnds,
          executionEta, forVotes, againstVotes, abstainVotes, hasVoted,
          executed, canceled, votingPower>>

\* ---- Helpers ----

\* Total votes cast
TotalVotes == forVotes + againstVotes + abstainVotes

\* Has quorum been met?
QuorumMet == TotalVotes >= QUORUM

\* Has approval been met? (forVotes / totalVotes >= APPROVAL_BPS / 10000)
\* Integer math: forVotes * 10000 >= totalVotes * APPROVAL_BPS
ApprovalMet ==
    IF TotalVotes = 0 THEN FALSE
    ELSE forVotes * 10000 >= TotalVotes * APPROVAL_BPS

\* Compute the derived state from raw variables
DerivedState ==
    IF canceled THEN "Canceled"
    ELSE IF executed THEN "Executed"
    ELSE IF proposer = "none" THEN "Pending"
    ELSE IF currentBlock < votingStarts THEN "Pending"
    ELSE IF currentBlock <= votingEnds THEN "Active"
    ELSE IF ~QuorumMet \/ ~ApprovalMet THEN "Defeated"
    ELSE IF executionEta = 0 THEN "Succeeded"
    ELSE IF currentBlock < executionEta THEN "Queued"
    ELSE IF currentBlock <= executionEta + GRACE_PERIOD THEN "Queued"
    ELSE "Expired"

\* ---- State machine ----

Init ==
    /\ currentBlock = 0
    /\ proposalState = "Pending"
    /\ proposer = "none"
    /\ votingStarts = 0
    /\ votingEnds = 0
    /\ executionEta = 0
    /\ forVotes = 0
    /\ againstVotes = 0
    /\ abstainVotes = 0
    /\ hasVoted = {}
    /\ executed = FALSE
    /\ canceled = FALSE
    \* Each voter gets a fixed voting power (1 to MaxVotingPower)
    /\ votingPower = [v \in Voters |-> 1 + ((v - 1) % MaxVotingPower)]

\* --- Create a proposal (any voter with enough power) ---
Propose(voter) ==
    /\ voter \in Voters
    /\ proposer = "none"              \* No active proposal (single-proposal model)
    /\ votingPower[voter] >= PROPOSAL_THRESHOLD
    /\ currentBlock < MaxBlock - VOTING_PERIOD - EXECUTION_DELAY - GRACE_PERIOD
    /\ proposer' = voter
    /\ votingStarts' = currentBlock + 1
    /\ votingEnds' = currentBlock + 1 + VOTING_PERIOD
    /\ proposalState' = "Pending"
    /\ UNCHANGED <<currentBlock, executionEta, forVotes, againstVotes, abstainVotes,
                   hasVoted, executed, canceled, votingPower>>

\* --- Cast a vote ---
CastVote(voter, support) ==
    /\ voter \in Voters
    /\ support \in VoteTypes
    /\ proposer # "none"
    /\ ~canceled
    /\ ~executed
    /\ currentBlock >= votingStarts
    /\ currentBlock <= votingEnds
    /\ voter \notin hasVoted           \* OneVotePerVoter
    /\ votingPower[voter] > 0
    /\ hasVoted' = hasVoted \union {voter}
    /\ LET weight == votingPower[voter]
       IN IF support = "For"
          THEN /\ forVotes' = forVotes + weight
               /\ UNCHANGED <<againstVotes, abstainVotes>>
          ELSE IF support = "Against"
          THEN /\ againstVotes' = againstVotes + weight
               /\ UNCHANGED <<forVotes, abstainVotes>>
          ELSE /\ abstainVotes' = abstainVotes + weight
               /\ UNCHANGED <<forVotes, againstVotes>>
    /\ UNCHANGED <<currentBlock, proposalState, proposer, votingStarts, votingEnds,
                   executionEta, executed, canceled, votingPower>>

\* --- Queue a succeeded proposal ---
Queue ==
    /\ proposer # "none"
    /\ ~canceled
    /\ ~executed
    /\ currentBlock > votingEnds       \* Voting has ended
    /\ QuorumMet
    /\ ApprovalMet
    /\ executionEta = 0                \* Not yet queued
    /\ executionEta' = currentBlock + EXECUTION_DELAY
    /\ proposalState' = "Queued"
    /\ UNCHANGED <<currentBlock, proposer, votingStarts, votingEnds,
                   forVotes, againstVotes, abstainVotes, hasVoted,
                   executed, canceled, votingPower>>

\* --- Execute a queued proposal ---
Execute ==
    /\ proposer # "none"
    /\ ~canceled
    /\ ~executed
    /\ executionEta > 0
    /\ currentBlock >= executionEta                     \* Timelock elapsed
    /\ currentBlock <= executionEta + GRACE_PERIOD      \* Within grace period
    /\ executed' = TRUE
    /\ proposalState' = "Executed"
    /\ UNCHANGED <<currentBlock, proposer, votingStarts, votingEnds, executionEta,
                   forVotes, againstVotes, abstainVotes, hasVoted,
                   canceled, votingPower>>

\* --- Cancel a proposal (proposer or guardian) ---
Cancel ==
    /\ proposer # "none"
    /\ ~executed
    /\ ~canceled
    /\ canceled' = TRUE
    /\ proposalState' = "Canceled"
    /\ UNCHANGED <<currentBlock, proposer, votingStarts, votingEnds, executionEta,
                   forVotes, againstVotes, abstainVotes, hasVoted,
                   executed, votingPower>>

\* --- Advance block ---
AdvanceBlock ==
    /\ currentBlock < MaxBlock
    /\ currentBlock' = currentBlock + 1
    \* Update derived state
    /\ LET newBlock == currentBlock + 1
       IN IF canceled THEN proposalState' = "Canceled"
          ELSE IF executed THEN proposalState' = "Executed"
          ELSE IF proposer = "none" THEN proposalState' = "Pending"
          ELSE IF newBlock < votingStarts THEN proposalState' = "Pending"
          ELSE IF newBlock <= votingEnds THEN proposalState' = "Active"
          ELSE IF ~QuorumMet \/ ~ApprovalMet THEN proposalState' = "Defeated"
          ELSE IF executionEta = 0 THEN proposalState' = "Succeeded"
          ELSE IF newBlock < executionEta THEN proposalState' = "Queued"
          ELSE IF newBlock <= executionEta + GRACE_PERIOD THEN proposalState' = "Queued"
          ELSE proposalState' = "Expired"
    /\ UNCHANGED <<proposer, votingStarts, votingEnds, executionEta,
                   forVotes, againstVotes, abstainVotes, hasVoted,
                   executed, canceled, votingPower>>

Next ==
    \/ \E v \in Voters : Propose(v)
    \/ \E v \in Voters, s \in VoteTypes : CastVote(v, s)
    \/ Queue
    \/ Execute
    \/ Cancel
    \/ AdvanceBlock

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ proposalState \in ProposalStates
    /\ currentBlock \in Nat
    /\ forVotes \in Nat
    /\ againstVotes \in Nat
    /\ abstainVotes \in Nat
    /\ executionEta \in Nat
    /\ hasVoted \subseteq Voters
    /\ executed \in BOOLEAN
    /\ canceled \in BOOLEAN
    /\ \A v \in Voters : votingPower[v] \in Nat

\* INV-2: TimelockEnforced — cannot execute before queue_block + EXECUTION_DELAY.
\* If executed, the current block must be >= executionEta.
TimelockEnforced ==
    executed => (executionEta > 0 /\ currentBlock >= executionEta)

\* INV-3: QuorumRequired — Succeeded only if total votes >= quorum AND approval met.
QuorumRequired ==
    (proposalState = "Succeeded" \/ proposalState = "Queued" \/
     proposalState = "Executed") => (QuorumMet /\ ApprovalMet)

\* INV-4: OneVotePerVoter — each address votes once per proposal.
\* Structurally enforced by set membership check. We verify vote count <= voters.
OneVotePerVoter ==
    Cardinality(hasVoted) <= NUM_VOTERS

\* INV-5: ForwardOnly — state transitions are monotonic.
\* Canceled or Executed proposals cannot transition to any other state.
ForwardOnly ==
    /\ (canceled => proposalState = "Canceled")
    /\ (executed => proposalState = "Executed")

\* INV-6: GracePeriodEnforced — queued proposals expire after GRACE_PERIOD.
\* If past executionEta + GRACE_PERIOD, proposal is Expired (not Queued/Executed).
GracePeriodEnforced ==
    (executionEta > 0 /\ currentBlock > executionEta + GRACE_PERIOD
     /\ ~executed /\ ~canceled) =>
        proposalState = "Expired"

\* INV-7: ThresholdEnforced — proposer must have >= PROPOSAL_THRESHOLD.
\* If a proposal exists, the proposer had enough voting power.
ThresholdEnforced ==
    proposer # "none" => votingPower[proposer] >= PROPOSAL_THRESHOLD

\* INV-8: CanceledIsFinal — canceled proposal cannot be executed.
CanceledIsFinal ==
    canceled => ~executed

\* INV-9: BlockBounded
BlockBounded ==
    currentBlock <= MaxBlock

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety       == Spec => []TypeOK
THEOREM TimelockOK       == Spec => []TimelockEnforced
THEOREM QuorumOK         == Spec => []QuorumRequired
THEOREM VoteUnique       == Spec => []OneVotePerVoter
THEOREM Monotonic        == Spec => []ForwardOnly
THEOREM GraceOK          == Spec => []GracePeriodEnforced
THEOREM ThresholdOK      == Spec => []ThresholdEnforced
THEOREM CancelFinal      == Spec => []CanceledIsFinal
THEOREM BlocksOK         == Spec => []BlockBounded

=============================================================================
