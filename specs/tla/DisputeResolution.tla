--------------------- MODULE DisputeResolution ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the bisection game for challenged compute results.
\*
\* When a challenger disputes a provider's result:
\*   1. Challenger posts a dispute bond
\*   2. Bisection narrows the disputed computation range each round
\*   3. After MaxBisectionRounds (or earlier), referee determines winner
\*   4. Winner receives loser's bond
\*   5. If defender (provider) loses, their stake is also slashed
\*
\* Inspired by Gensyn Verde bisection protocol.
\*
\* Source: contracts/src/DisputeResolution.sol
\*         .agentile/teamwork/COMPUTE_MARKETPLACE_ARCHITECTURE.md

CONSTANTS
    Disputes,            \* Set of dispute identifiers
    MaxBisectionRounds,  \* Maximum rounds before forced resolution
    DisputeBond          \* Bond required to initiate dispute

ASSUME Disputes # {}
ASSUME MaxBisectionRounds \in Nat /\ MaxBisectionRounds >= 1
ASSUME DisputeBond \in Nat /\ DisputeBond >= 1

DisputeStates == {"Inactive", "Initiated", "Bisecting", "Resolved"}
Outcomes == {"none", "ChallengerWins", "DefenderWins"}

VARIABLES
    disputeState,     \* Mapping: dispute -> state
    round,            \* Mapping: dispute -> current bisection round
    rangeSize,        \* Mapping: dispute -> current range size (abstract: starts at 2^MaxRounds)
    challengerBond,   \* Mapping: dispute -> SALT bonded by challenger
    defenderBond,     \* Mapping: dispute -> SALT bonded by defender
    outcome,          \* Mapping: dispute -> resolution outcome
    winnerPaid,       \* Mapping: dispute -> TRUE iff winner has been paid
    defenderSlashed   \* Mapping: dispute -> TRUE iff defender stake was slashed

vars == <<disputeState, round, rangeSize, challengerBond, defenderBond,
          outcome, winnerPaid, defenderSlashed>>

\* ---- Helpers ----

\* Initial range size: 2^MaxBisectionRounds (bounded for model checking).
\* We model this abstractly as MaxBisectionRounds + 1 (decrements to 1).
InitialRange == MaxBisectionRounds + 1

\* ---- State machine ----

Init ==
    /\ disputeState = [d \in Disputes |-> "Inactive"]
    /\ round = [d \in Disputes |-> 0]
    /\ rangeSize = [d \in Disputes |-> 0]
    /\ challengerBond = [d \in Disputes |-> 0]
    /\ defenderBond = [d \in Disputes |-> 0]
    /\ outcome = [d \in Disputes |-> "none"]
    /\ winnerPaid = [d \in Disputes |-> FALSE]
    /\ defenderSlashed = [d \in Disputes |-> FALSE]

\* Initiate a dispute — challenger and defender both post bonds.
InitiateDispute(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Inactive"
    /\ disputeState' = [disputeState EXCEPT ![d] = "Initiated"]
    /\ challengerBond' = [challengerBond EXCEPT ![d] = DisputeBond]
    /\ defenderBond' = [defenderBond EXCEPT ![d] = DisputeBond]
    /\ round' = [round EXCEPT ![d] = 0]
    /\ rangeSize' = [rangeSize EXCEPT ![d] = InitialRange]
    /\ UNCHANGED <<outcome, winnerPaid, defenderSlashed>>

\* Begin bisection.
StartBisection(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Initiated"
    /\ disputeState' = [disputeState EXCEPT ![d] = "Bisecting"]
    /\ UNCHANGED <<round, rangeSize, challengerBond, defenderBond,
                   outcome, winnerPaid, defenderSlashed>>

\* One round of bisection — range halves, round increments.
BisectionRound(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Bisecting"
    /\ round[d] < MaxBisectionRounds
    /\ rangeSize[d] > 1
    /\ round' = [round EXCEPT ![d] = @ + 1]
    /\ rangeSize' = [rangeSize EXCEPT ![d] = (@ + 1) \div 2]
    /\ UNCHANGED <<disputeState, challengerBond, defenderBond,
                   outcome, winnerPaid, defenderSlashed>>

\* Resolve dispute — challenger wins.
ResolveChallengerWins(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Bisecting"
    /\ round[d] >= 1               \* at least one round must have occurred
    /\ disputeState' = [disputeState EXCEPT ![d] = "Resolved"]
    /\ outcome' = [outcome EXCEPT ![d] = "ChallengerWins"]
    /\ UNCHANGED <<round, rangeSize, challengerBond, defenderBond,
                   winnerPaid, defenderSlashed>>

\* Resolve dispute — defender wins.
ResolveDefenderWins(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Bisecting"
    /\ round[d] >= 1
    /\ disputeState' = [disputeState EXCEPT ![d] = "Resolved"]
    /\ outcome' = [outcome EXCEPT ![d] = "DefenderWins"]
    /\ UNCHANGED <<round, rangeSize, challengerBond, defenderBond,
                   winnerPaid, defenderSlashed>>

\* Pay the winner — winner gets loser's bond.
PayWinner(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Resolved"
    /\ outcome[d] # "none"
    /\ winnerPaid[d] = FALSE
    /\ winnerPaid' = [winnerPaid EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<disputeState, round, rangeSize, challengerBond,
                   defenderBond, outcome, defenderSlashed>>

\* Slash defender if they lost.
SlashDefender(d) ==
    /\ d \in Disputes
    /\ disputeState[d] = "Resolved"
    /\ outcome[d] = "ChallengerWins"
    /\ defenderSlashed[d] = FALSE
    /\ defenderSlashed' = [defenderSlashed EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<disputeState, round, rangeSize, challengerBond,
                   defenderBond, outcome, winnerPaid>>

Next ==
    \/ \E d \in Disputes : InitiateDispute(d)
    \/ \E d \in Disputes : StartBisection(d)
    \/ \E d \in Disputes : BisectionRound(d)
    \/ \E d \in Disputes : ResolveChallengerWins(d)
    \/ \E d \in Disputes : ResolveDefenderWins(d)
    \/ \E d \in Disputes : PayWinner(d)
    \/ \E d \in Disputes : SlashDefender(d)

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ \A d \in Disputes : disputeState[d] \in DisputeStates
    /\ \A d \in Disputes : round[d] \in 0..MaxBisectionRounds
    /\ \A d \in Disputes : rangeSize[d] \in Nat
    /\ \A d \in Disputes : challengerBond[d] \in Nat
    /\ \A d \in Disputes : defenderBond[d] \in Nat
    /\ \A d \in Disputes : outcome[d] \in Outcomes
    /\ \A d \in Disputes : winnerPaid[d] \in BOOLEAN
    /\ \A d \in Disputes : defenderSlashed[d] \in BOOLEAN

\* INV-2: BondRequired — active disputes must have bonds posted.
BondRequired ==
    \A d \in Disputes :
        disputeState[d] \in {"Initiated", "Bisecting", "Resolved"} =>
            (challengerBond[d] >= DisputeBond /\ defenderBond[d] >= DisputeBond)

\* INV-3: RangeNarrows — range size decreases (or stays same) as rounds increase.
\* After at least one round, range < InitialRange.
RangeNarrows ==
    \A d \in Disputes :
        round[d] >= 1 => rangeSize[d] < InitialRange

\* INV-4: TerminatesInMaxRounds — round never exceeds MaxBisectionRounds.
TerminatesInMaxRounds ==
    \A d \in Disputes :
        round[d] <= MaxBisectionRounds

\* INV-5: WinnerGetsBond — resolved disputes with a winner can pay the winner.
\* (If resolved and outcome is determined, winnerPaid can become TRUE.)
WinnerGetsBond ==
    \A d \in Disputes :
        winnerPaid[d] = TRUE => outcome[d] # "none"

\* INV-6: LoserSlashed — defender slashing only occurs when challenger wins.
LoserSlashed ==
    \A d \in Disputes :
        defenderSlashed[d] = TRUE => outcome[d] = "ChallengerWins"

\* INV-7: NoPaymentBeforeResolution — winner not paid before dispute resolved.
NoPaymentBeforeResolution ==
    \A d \in Disputes :
        winnerPaid[d] = TRUE => disputeState[d] = "Resolved"

\* INV-8: NoSlashBeforeResolution — no slashing before resolution.
NoSlashBeforeResolution ==
    \A d \in Disputes :
        defenderSlashed[d] = TRUE => disputeState[d] = "Resolved"

\* INV-9: InactiveClean — inactive disputes have no bonds, no outcome, no payment.
InactiveClean ==
    \A d \in Disputes :
        disputeState[d] = "Inactive" =>
            /\ challengerBond[d] = 0
            /\ defenderBond[d] = 0
            /\ outcome[d] = "none"
            /\ winnerPaid[d] = FALSE
            /\ defenderSlashed[d] = FALSE

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM BondReq == Spec => []BondRequired
THEOREM RangeNarr == Spec => []RangeNarrows
THEOREM MaxRounds == Spec => []TerminatesInMaxRounds
THEOREM WinnerPaid == Spec => []WinnerGetsBond
THEOREM DefSlashed == Spec => []LoserSlashed
THEOREM NoPayNoResolve == Spec => []NoPaymentBeforeResolution
THEOREM NoSlashNoResolve == Spec => []NoSlashBeforeResolution
THEOREM InactiveIsClean == Spec => []InactiveClean

=============================================================================
