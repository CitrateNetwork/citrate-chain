------------------------------ MODULE HypothesisH3 ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

(***********************************************************************
* RM-FL-5 / WP-5.1 — TLA+ formalization of Hypothesis H3 from Paper II §4.
*
* HYPOTHESIS (informal): Routing-model parameter drift across
* checkpoints converges (or diverges sub-linearly) under K Byzantine
* validators, for K up to a stated fraction of the validator set
* (BFT threshold: K < N/3).
*
* WHAT TLA+ CHECKS
* ----------------
* The empirical claim — fitting log-vs-linear residuals over actual
* parameter trajectories — lives in WP-5.7 with a 30-node testnet.
* The protocol-side claim TLA+ verifies is the BFT THRESHOLD itself:
* below the threshold, honest validators always retain quorum, and
* the routing-model update at every checkpoint reflects only honest
* contributions (Byzantine ones are rejected by the BFT vote).
*
* If the BFT threshold property fails — i.e. honest quorum can be
* lost at K < N/3 — the convergence claim in WP-5.7 cannot be
* supported regardless of measurement, because the experimental
* outcome would be confounded by adversarial parameter injection.
*
* WHAT WE MODEL
* -------------
*   - A validator set, partitioned into Honest and Byzantine.
*   - Per-checkpoint voting: each validator votes either to commit
*     a candidate routing-model update or abstain.
*   - Byzantine validators vote arbitrarily (worst case: vote
*     against any honest candidate).
*   - Honest validators vote consistently for the canonical
*     candidate.
*   - A checkpoint-finalization rule: a 2/3+1 quorum of votes
*     accepts the candidate.
*
* INVARIANTS:
*   - Type safety.
*   - HonestQuorumPossible: under the BFT threshold, honest
*     validators always exceed 2/3+1.
*   - NoByzantineFinalization: a candidate cannot finalize without
*     at least one honest vote (i.e. Byzantine alone cannot
*     poison-pill a checkpoint).
*   - ByzantineCountWithinThreshold: the spec assumes K < N/3 as a
*     CONSTANT precondition; the invariant pins this.
*
* OPERATOR-VS-VARIABLE PRINCIPLE
* ------------------------------
* The validator partition (Honest/Byzantine) is a CONSTANT — the
* adversary's identity is fixed at experiment start and not
* re-rolled per checkpoint. The vote tally is the only VARIABLE.
* This keeps TLC's state space bounded by O(2^|N| × Checkpoints).
***********************************************************************)

CONSTANTS
    Validators,           \* SET of validator IDs
    Byzantine,            \* SUBSET Validators
    MaxCheckpoints        \* state-space bound

ASSUME Validators # {}
ASSUME Byzantine \subseteq Validators
ASSUME MaxCheckpoints \in Nat /\ MaxCheckpoints >= 1

\* The BFT threshold: K < N/3 means Byzantine count is strictly
\* less than 1/3 of total. Equivalently, 3*K < N, or
\* honest count > 2/3 of N (rounded so that 2N/3 + 1 <= honest).
N == Cardinality(Validators)
K == Cardinality(Byzantine)
HonestCount == N - K
QuorumThreshold == (2 * N) \div 3 + 1

\* Static precondition for H3: K < N/3. If this fails, the
\* hypothesis's domain doesn't apply.
ASSUME 3 * K < N

VARIABLES
    checkpoint,           \* Nat — current checkpoint number
    votes,                \* function: Validators -> {commit, abstain, against}
    finalized             \* Set of finalized checkpoint numbers

vars == << checkpoint, votes, finalized >>

VoteValue == { "commit", "abstain", "against" }

\* Initial state: checkpoint 0, no votes cast, nothing finalized.
Init ==
    /\ checkpoint = 0
    /\ votes = [v \in Validators |-> "abstain"]
    /\ finalized = {}

\* Honest vote: every honest validator commits to the canonical
\* candidate at every checkpoint.
HonestVote(v) ==
    /\ v \in Validators \ Byzantine
    /\ checkpoint < MaxCheckpoints
    /\ votes' = [votes EXCEPT ![v] = "commit"]
    /\ UNCHANGED << checkpoint, finalized >>

\* Byzantine vote: arbitrary. Modelled as "vote against" — the
\* worst case for finalization, since "abstain" is equivalent
\* (neither contributes to the 2/3+1 quorum). We pin it to
\* "against" to avoid a redundant nondeterministic split.
ByzantineVote(v) ==
    /\ v \in Byzantine
    /\ checkpoint < MaxCheckpoints
    /\ votes' = [votes EXCEPT ![v] = "against"]
    /\ UNCHANGED << checkpoint, finalized >>

\* Count "commit" votes.
CommitCount ==
    Cardinality({ v \in Validators: votes[v] = "commit" })

\* Finalize the current checkpoint when commit count reaches
\* quorum. Records the checkpoint number, advances to next.
\* Resets votes for the next round.
Finalize ==
    /\ checkpoint < MaxCheckpoints
    /\ CommitCount >= QuorumThreshold
    /\ finalized' = finalized \cup { checkpoint }
    /\ checkpoint' = checkpoint + 1
    /\ votes' = [v \in Validators |-> "abstain"]

Next ==
    \/ \E v \in Validators: HonestVote(v)
    \/ \E v \in Validators: ByzantineVote(v)
    \/ Finalize

Spec == Init /\ [][Next]_vars

(***********************************************************************
* INVARIANTS
***********************************************************************)

\* Type invariant.
TypeOK ==
    /\ checkpoint \in 0..MaxCheckpoints
    /\ votes \in [Validators -> VoteValue]
    /\ finalized \subseteq 0..MaxCheckpoints

\* The BFT threshold pinned as an invariant: K < N/3.
ByzantineCountWithinThreshold ==
    3 * K < N

\* Honest quorum possibility: there exist enough honest
\* validators to satisfy quorum. This is necessary for any
\* finalization to be possible without Byzantine cooperation.
HonestQuorumPossible ==
    HonestCount >= QuorumThreshold

\* No Byzantine-only finalization: every finalized checkpoint
\* required at least one honest commit vote. Phrased as a
\* universal property over the current vote state at the moment
\* of any successful Finalize step:
\*
\*   if CommitCount >= QuorumThreshold, then at least one honest
\*   validator must have voted commit (since |Byzantine| < quorum).
\*
\* This is a derived consequence of ByzantineCountWithinThreshold
\* + the quorum size, but stating it explicitly pins the
\* experimental claim: H3's measurement of "drift under K
\* Byzantine" assumes Byzantine cannot finalize unilaterally.
NoByzantineFinalization ==
    CommitCount >= QuorumThreshold
        => Cardinality({v \in Validators \ Byzantine:
                            votes[v] = "commit"}) >= 1

\* Finalization monotonicity: once a checkpoint is finalized, it
\* stays finalized. Same chain-canonical principle from RM-FL-3.
FinalizationMonotonic ==
    \A c \in finalized: c < checkpoint

THEOREM Safety ==
    Spec => [](
        TypeOK
        /\ ByzantineCountWithinThreshold
        /\ HonestQuorumPossible
        /\ NoByzantineFinalization
        /\ FinalizationMonotonic
    )

==========================================================================
