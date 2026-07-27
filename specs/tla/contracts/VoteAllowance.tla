--------------------------- MODULE VoteAllowance ---------------------------
EXTENDS Integers, FiniteSets, TLC

\* Models the delegated voting franchise from
\* contracts/src/quorum/VoteAllowance.sol (citrate-quorum QRM-S6.6).
\*
\* Agents never hold voting power.  A human principal delegates a bounded,
\* expiring, revocable allowance to an agent, and the agent's caster spends it.
\*
\* The four invariants this exists to check:
\*   VA-1  spent <= weightCap, in every reachable state — including after an
\*         increase, a decrease, and any interleaving of casts with either.
\*   VA-2  an expired or revoked allowance can never be spent.  Checked as a
\*         state property (`spent` cannot move once dead) rather than only as an
\*         action guard, because the guard is the thing under test.
\*   VA-3  every cast traces to exactly one human principal.
\*   VA-4  allowances never compound — no agent is ever the principal of one.
\*
\* Source: contracts/src/quorum/VoteAllowance.sol
\*   - grant, increase, decrease, revoke, castVote
\*   - isLive, remaining, covers, hasCast

CONSTANTS
    Principals,       \* Humans who may delegate.  Disjoint from Agents.
    Agents,           \* Delegates.  Model as SBT ids; they cannot grant.
    Ids,              \* Bounded set of allowance ids
    Classes,          \* Proposal classes
    Proposals,        \* Proposal ids
    MaxWeight,        \* Bound on caps and cast weights (bounds the state space)
    MaxTime           \* Bound on the clock

ASSUME Principals # {}
ASSUME Agents # {}
ASSUME Principals \cap Agents = {}
ASSUME Ids # {}
ASSUME MaxWeight \in Nat /\ MaxWeight >= 1
ASSUME MaxTime \in Nat /\ MaxTime >= 1

VARIABLES
    allowance,        \* Ids -> allowance record (or the empty record)
    now,              \* the clock, in abstract ticks (the contract's ms)
    votes,            \* set of cast records: what actually happened
    castKeys,         \* set of <<id, proposal>> already used (the contract's hasCast)
    spentAtDeath      \* Ids -> spent at the moment the allowance died, or -1

vars == <<allowance, now, votes, castKeys, spentAtDeath>>

NoOne == "none"

EmptyAllowance ==
    [exists    |-> FALSE,
     principal |-> NoOne,
     agent     |-> NoOne,
     classes   |-> {},
     cap       |-> 0,
     spent     |-> 0,
     expiresAt |-> 0,
     revoked   |-> FALSE]

\* Mirrors isLive(): not revoked, and strictly before expiry.
IsLive(id) ==
    /\ allowance[id].exists
    /\ ~allowance[id].revoked
    /\ allowance[id].expiresAt > now

Remaining(id) ==
    IF allowance[id].spent >= allowance[id].cap
    THEN 0
    ELSE allowance[id].cap - allowance[id].spent

Init ==
    /\ allowance = [i \in Ids |-> EmptyAllowance]
    /\ now = 0
    /\ votes = {}
    /\ castKeys = {}
    /\ spentAtDeath = [i \in Ids |-> -1]

\* ── Actions ─────────────────────────────────────────────────────────

\* grant(): the principal is always the caller.  Note the domain: `p` ranges
\* over Principals only, which is how VA-4 is enforced structurally in Solidity
\* (the delegate is an SBT id, so it has nothing to grant from).
Grant(id, p, g, cs, cap, exp) ==
    /\ ~allowance[id].exists
    /\ p \in Principals
    /\ g \in Agents
    /\ cs \subseteq Classes /\ cs # {}
    /\ cap \in 1..MaxWeight
    /\ exp \in (now + 1)..MaxTime      \* an already-expired grant is refused
    /\ allowance' = [allowance EXCEPT ![id] =
           [exists    |-> TRUE,
            principal |-> p,
            agent     |-> g,
            classes   |-> cs,
            cap       |-> cap,
            spent     |-> 0,
            expiresAt |-> exp,
            revoked   |-> FALSE]]
    /\ UNCHANGED <<now, votes, castKeys, spentAtDeath>>

Increase(id, by) ==
    /\ allowance[id].exists
    /\ by \in 1..MaxWeight
    /\ allowance[id].cap + by <= MaxWeight
    /\ allowance' = [allowance EXCEPT ![id].cap = @ + by]
    /\ UNCHANGED <<now, votes, castKeys, spentAtDeath>>

\* decrease() refuses to go below what is already spent — otherwise VA-1 would
\* become retroactively false and the record would imply votes that were cast
\* never were.
Decrease(id, to) ==
    /\ allowance[id].exists
    /\ to \in 0..MaxWeight
    /\ to >= allowance[id].spent
    /\ allowance' = [allowance EXCEPT ![id].cap = to]
    /\ UNCHANGED <<now, votes, castKeys, spentAtDeath>>

\* revoke() is immediate and idempotent.  Records the spend at the moment of
\* death so VA-2 can be checked as a state property afterwards.
Revoke(id) ==
    /\ allowance[id].exists
    /\ ~allowance[id].revoked
    /\ allowance' = [allowance EXCEPT ![id].revoked = TRUE]
    /\ spentAtDeath' = [spentAtDeath EXCEPT ![id] = allowance[id].spent]
    /\ UNCHANGED <<now, votes, castKeys>>

\* castVote(): refuses rather than clamping.
Cast(id, prop, c, w) ==
    /\ IsLive(id)
    /\ c \in allowance[id].classes
    /\ <<id, prop>> \notin castKeys
    /\ w \in 1..MaxWeight
    /\ w <= Remaining(id)
    /\ allowance' = [allowance EXCEPT ![id].spent = @ + w]
    /\ votes' = votes \cup
           {[allowance |-> id,
             principal |-> allowance[id].principal,
             agent     |-> allowance[id].agent,
             proposal  |-> prop,
             weight    |-> w]}
    /\ castKeys' = castKeys \cup {<<id, prop>>}
    /\ UNCHANGED <<now, spentAtDeath>>

\* Time passes.  Expiry records the spend at death exactly once, for the same
\* reason revocation does.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ spentAtDeath' = [i \in Ids |->
           IF /\ allowance[i].exists
              /\ spentAtDeath[i] = -1
              /\ allowance[i].expiresAt <= now + 1
           THEN allowance[i].spent
           ELSE spentAtDeath[i]]
    /\ UNCHANGED <<allowance, votes, castKeys>>

Next ==
    \/ \E id \in Ids, p \in Principals, g \in Agents, cs \in SUBSET Classes,
          cap \in 1..MaxWeight, exp \in 0..MaxTime : Grant(id, p, g, cs, cap, exp)
    \/ \E id \in Ids, by \in 1..MaxWeight : Increase(id, by)
    \/ \E id \in Ids, to \in 0..MaxWeight : Decrease(id, to)
    \/ \E id \in Ids : Revoke(id)
    \/ \E id \in Ids, prop \in Proposals, c \in Classes, w \in 1..MaxWeight : Cast(id, prop, c, w)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* ── Invariants ──────────────────────────────────────────────────────

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A id \in Ids :
         /\ spentAtDeath[id] \in (-1)..MaxWeight
         /\ allowance[id].spent \in 0..MaxWeight
         /\ allowance[id].cap \in 0..MaxWeight
         /\ allowance[id].revoked \in BOOLEAN
         /\ allowance[id].exists \in BOOLEAN

\* VA-1: spent never exceeds the cap.  The interesting case is not a single
\* cast — it is a cast interleaved with a decrease, which is why `decrease`
\* has a floor at `spent`.
VA1_SpentWithinCap ==
    \A id \in Ids : allowance[id].spent <= allowance[id].cap

\* VA-2: once dead, spend cannot move.  Checked as a property of the state
\* rather than only as a guard on the action, because the guard is the thing
\* being tested.
VA2_DeadAllowancesNeverSpend ==
    \A id \in Ids :
        (allowance[id].exists /\ spentAtDeath[id] # -1)
            => allowance[id].spent = spentAtDeath[id]

\* VA-3: every cast names exactly one human principal, and it is that
\* allowance's principal — not merely someone, and not reconstructible.
VA3_EveryVoteTracesToOnePrincipal ==
    \A v \in votes :
        /\ v.principal \in Principals
        /\ v.principal = allowance[v.allowance].principal
        /\ v.agent \in Agents

\* VA-4: no allowance is ever held BY an agent, so a delegation chain cannot
\* form.  In Solidity this is structural — the delegate is an SBT id, not an
\* address, and `grant` always writes principal = msg.sender.
VA4_NoSubDelegation ==
    \A id \in Ids :
        allowance[id].exists => /\ allowance[id].principal \in Principals
                                /\ allowance[id].agent \in Agents

\* One cast per (allowance, proposal): a second is either a duplicate or a
\* contradiction, and neither should be resolved silently by whatever tallies.
OneCastPerProposal ==
    \A v1 \in votes, v2 \in votes :
        (v1.allowance = v2.allowance /\ v1.proposal = v2.proposal) => v1 = v2

\* The recorded spend equals the sum of the votes actually cast against it.
\* Catches a cast that moved the meter without producing a vote, or a vote that
\* did not move the meter — the two halves of "what happened" disagreeing.
RECURSIVE SumWeights(_)
SumWeights(S) ==
    IF S = {} THEN 0
    ELSE LET v == CHOOSE x \in S : TRUE
         IN  v.weight + SumWeights(S \ {v})

SpendMatchesVotes ==
    \A id \in Ids :
        allowance[id].spent = SumWeights({v \in votes : v.allowance = id})

\* An allowance that was never granted has no votes against it.
NoVotesWithoutAnAllowance ==
    \A v \in votes : allowance[v.allowance].exists

=============================================================================
