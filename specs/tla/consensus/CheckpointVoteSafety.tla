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

\* State constraint for TLC: `submitted_msgs` grows without bound, so a run
\* must cap it (Stage 2: without the cap TLC never terminates). Every
\* interleaving of up to 5 submissions over the configured voters, heights
\* and chains is explored.
SubmissionBound == Len(submitted_msgs) <= 5

\* ---- Invariants ----

\* INV-1 (H-01): every (h, v) in voted has a corresponding
\* acceptance — `voted` cannot diverge from `accepted`.
VotedSetTracksAcceptedOnly ==
    \A pair \in voted :
        LET h == pair[1]
            v == pair[2]
        IN v \in accepted[h]

\* INV-2 (H-01 corollary): a garbage-sig vote (sig_chain_id # chain_id is a
\* stand-in for "fails verification") never puts its (height, voter) into
\* `voted`: every (h, v) in `voted` is backed by a VALID submission from v at h.
\* A voter hit by garbage submissions therefore keeps the right to cast a
\* later valid vote.
\*
\* Stage 2 erratum (2026-10-19): the first version required every garbage
\* submission's (height, voter) to be absent from `voted`, which TLC refutes
\* with a valid vote followed by a garbage resubmission for the same pair
\* (the pair is in `voted` because of the VALID vote, which is correct). The
\* property intended — garbage alone never locks a voter — is stated below.
GarbageSigDoesNotLockVoter ==
    \A pair \in voted :
        \E i \in 1..Len(submitted_msgs) :
            /\ submitted_msgs[i].height = pair[1]
            /\ submitted_msgs[i].voter = pair[2]
            /\ submitted_msgs[i].sig_chain_id = chain_id

\* INV-3 (H-02): only votes signed for our chain are ever accepted. Every
\* accepted (height, voter) is backed by a submission whose signature was made
\* for this chain; cross-chain replay is structurally rejected.
\*
\* Stage 2 erratum (2026-10-19): the first version attributed acceptance to
\* EVERY submission from an accepted voter, which TLC refutes with a valid vote
\* followed by a cross-chain resubmission (rejected, but the voter is already
\* accepted from the valid one). Restated as intended.
OnlyOwnChainVotesAccepted ==
    \A h \in Heights : \A v \in accepted[h] :
        \E i \in 1..Len(submitted_msgs) :
            /\ submitted_msgs[i].height = h
            /\ submitted_msgs[i].voter = v
            /\ submitted_msgs[i].sig_chain_id = chain_id

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
