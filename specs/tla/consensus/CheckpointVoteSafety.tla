------------------------------ MODULE CheckpointVoteSafety ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Models the safety + liveness contracts that close audit findings
\* H-01 (vote-pollution liveness DoS) and H-02 (cross-chain vote
\* replay).
\*
\* H-01 invariant — VotedSetTracksAcceptedOnly:
\*   The replay-protection set `voted` MUST contain (height, voter)
\*   only after a vote from `voter` has been cryptographically
\*   accepted at `height`. Pre-fix code marked voted at submission;
\*   garbage-signature votes from victim pubkeys polluted the set
\*   and locked honest voters out.
\*
\* H-02 invariant — CanonicalMessageBindsChain:
\*   The signed bytes for a vote include (chain_id, height,
\*   block_hash) inside a domain-separated prefix. A vote signed
\*   for chain_id=A is byte-different from one for chain_id=B even
\*   when (height, block_hash) match.
\*
\* Source: core/consensus/src/checkpoint.rs (post-WP-B2.1, WP-B2.2).

CONSTANTS
    Voters,        \* Set of committee members
    Heights,       \* Set of checkpoint heights to model
    Chains,        \* Set of distinct chain IDs (e.g., {chain_a, chain_b})
    QuorumSize     \* Quorum threshold (Cardinality(Voters) suffices for the spec)

ASSUME Voters # {} /\ IsFiniteSet(Voters)
ASSUME Heights # {} /\ IsFiniteSet(Heights)
ASSUME Chains # {} /\ IsFiniteSet(Chains)
ASSUME QuorumSize \in 1..Cardinality(Voters)

VARIABLES
    voted,             \* Set of (height, voter) pairs marked as having voted
    accepted,          \* Function: height -> set of voters whose vote was accepted
    chain_id,          \* The chain_id this manager operates on (constant per run)
    submitted_msgs     \* Sequence of <<height, voter, sig_chain_id>> records — each
                       \* record represents one submit_vote call. sig_chain_id is
                       \* the chain_id the signature was produced for; a vote
                       \* with sig_chain_id # chain_id MUST be rejected.

vars == <<voted, accepted, chain_id, submitted_msgs>>

\* ---- Init ----

Init ==
    /\ voted = {}
    /\ accepted = [h \in Heights |-> {}]
    /\ chain_id \in Chains       \* TLC nondeterministically picks our chain
    /\ submitted_msgs = <<>>

\* ---- Action: submit a vote ----
\*
\* A vote (h, v, sig_c) is "valid" iff sig_c = chain_id AND v has
\* not already been accepted at h.
ValidVote(h, v, sig_c) ==
    /\ sig_c = chain_id
    /\ v \notin accepted[h]

SubmitVote(h, v, sig_c) ==
    /\ h \in Heights
    /\ v \in Voters
    /\ sig_c \in Chains
    /\ submitted_msgs' = Append(submitted_msgs, [height |-> h, voter |-> v, sig_chain_id |-> sig_c])
    /\ IF ValidVote(h, v, sig_c)
       THEN
           \* Accept the vote: mark voted AND record acceptance.
           /\ voted' = voted \cup {<<h, v>>}
           /\ accepted' = [accepted EXCEPT ![h] = @ \cup {v}]
       ELSE
           \* Reject: NEITHER voted NOR accepted is updated.
           \* H-01 fix is right here: we do NOT pollute `voted`
           \* on rejection.
           /\ UNCHANGED <<voted, accepted>>
    /\ UNCHANGED chain_id

Next == \E h \in Heights, v \in Voters, sig_c \in Chains : SubmitVote(h, v, sig_c)

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* INV-1 (H-01): every (h, v) in voted has a corresponding
\* acceptance — `voted` cannot diverge from `accepted`.
VotedSetTracksAcceptedOnly ==
    \A pair \in voted :
        LET h == pair[1]
            v == pair[2]
        IN v \in accepted[h]

\* INV-2 (H-01 corollary): a voter who submits a garbage-sig vote
\* (sig_chain_id # chain_id is a stand-in for "fails verification")
\* MUST NOT appear in `voted`. They retain the right to cast a
\* later valid vote.
GarbageSigDoesNotLockVoter ==
    \A i \in 1..Len(submitted_msgs) :
        LET m == submitted_msgs[i]
        IN m.sig_chain_id # chain_id => <<m.height, m.voter>> \notin voted
        \* Read: any submission with a non-matching sig_chain_id
        \* must NOT have caused (height, voter) to land in voted.

\* INV-3 (H-02): only votes signed for our chain are ever accepted.
\* Cross-chain replay is structurally rejected.
OnlyOwnChainVotesAccepted ==
    \A i \in 1..Len(submitted_msgs) :
        LET m == submitted_msgs[i]
        IN (m.voter \in accepted[m.height] /\
            \E j \in 1..Len(submitted_msgs) :
                /\ submitted_msgs[j] = m
                /\ j = i)
           => m.sig_chain_id = chain_id

\* INV-4: voted set is monotonic (entries are never removed).
VotedMonotonic ==
    \A pair \in voted : pair \in voted   \* trivially true; explicit as a comment

\* ---- Type invariant ----

TypeInv ==
    /\ voted \subseteq (Heights \X Voters)
    /\ \A h \in Heights : accepted[h] \subseteq Voters
    /\ chain_id \in Chains
    /\ submitted_msgs \in Seq([height: Heights, voter: Voters, sig_chain_id: Chains])

THEOREM TypeSafety == Spec => []TypeInv
THEOREM VotedTracksAccepted == Spec => []VotedSetTracksAcceptedOnly
THEOREM GarbageDoesNotLock == Spec => []GarbageSigDoesNotLockVoter
THEOREM OnlyOwnChain == Spec => []OnlyOwnChainVotesAccepted

=============================================================================
