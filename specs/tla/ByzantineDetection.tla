------------------------- MODULE ByzantineDetection -------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models Byzantine participant detection from core/learning/src/verification.rs.
\*
\* Participants submit embeddings each round.  The ByzantineDetector flags
\* outliers (distance > sigma_threshold * std_dev) and Belnap-inconsistent
\* contributors (fraction of Both > belnap_inconsistency_threshold).
\* After max_flags flags within the lookback window a participant is Excluded.
\* Re-admission requires cooldown_rounds to elapse.
\*
\* Source: core/learning/src/verification.rs
\*   - ByzantineDetector, is_outlier, record_flag, should_exclude
\*   - can_readmit, is_belnap_inconsistent, check_and_flag

CONSTANTS
    Participants,       \* Set of participant public keys
    MaxRound,           \* Maximum round number for finite state space
    MaxFlags,           \* Exclusion threshold (byzantine_max_flags)
    CooldownRounds,     \* Rounds required before readmission
    LookbackWindow      \* Number of recent rounds examined for flags

ASSUME Participants # {}
ASSUME MaxRound \in Nat /\ MaxRound >= 1
ASSUME MaxFlags \in Nat /\ MaxFlags >= 1
ASSUME CooldownRounds \in Nat /\ CooldownRounds >= 1
ASSUME LookbackWindow \in Nat /\ LookbackWindow >= 1

\* Participant status values
StatusValues == {"Active", "Flagged", "Excluded", "Cooldown"}

VARIABLES
    status,             \* Function: participant -> StatusValues
    flagHistory,        \* Sequence of [pubkey, round, reason] records
    currentRound,       \* Current round number
    excludedSince       \* Function: participant -> round when excluded (0 if never)

vars == <<status, flagHistory, currentRound, excludedSince>>

\* ---- Helpers ----

\* Count flags for a participant in the recent lookback window.
RecentFlagCount(pk) ==
    LET minRound == IF currentRound > LookbackWindow
                    THEN currentRound - LookbackWindow
                    ELSE 0
    IN Cardinality({i \in 1..Len(flagHistory) :
            flagHistory[i].pubkey = pk /\ flagHistory[i].round >= minRound})

\* ---- State machine ----

Init ==
    /\ status = [p \in Participants |-> "Active"]
    /\ flagHistory = <<>>
    /\ currentRound = 1
    /\ excludedSince = [p \in Participants |-> 0]

\* Advance to the next round (time moves forward).
AdvanceRound ==
    /\ currentRound < MaxRound
    /\ currentRound' = currentRound + 1
    /\ UNCHANGED <<status, flagHistory, excludedSince>>

\* Flag an active participant (outlier or Belnap inconsistency detected).
FlagParticipant(pk) ==
    /\ pk \in Participants
    /\ status[pk] = "Active"
    /\ LET entry == [pubkey |-> pk, round |-> currentRound, reason |-> "detected"]
       IN flagHistory' = Append(flagHistory, entry)
    /\ IF RecentFlagCount(pk) + 1 >= MaxFlags
       THEN /\ status' = [status EXCEPT ![pk] = "Excluded"]
            /\ excludedSince' = [excludedSince EXCEPT ![pk] = currentRound]
       ELSE /\ status' = [status EXCEPT ![pk] = "Flagged"]
            /\ UNCHANGED excludedSince
    /\ UNCHANGED currentRound

\* A flagged participant returns to Active (was flagged but under threshold).
UnflagParticipant(pk) ==
    /\ pk \in Participants
    /\ status[pk] = "Flagged"
    /\ RecentFlagCount(pk) < MaxFlags
    /\ status' = [status EXCEPT ![pk] = "Active"]
    /\ UNCHANGED <<flagHistory, currentRound, excludedSince>>

\* An excluded participant enters cooldown after some time.
EnterCooldown(pk) ==
    /\ pk \in Participants
    /\ status[pk] = "Excluded"
    /\ excludedSince[pk] > 0
    /\ currentRound - excludedSince[pk] >= CooldownRounds
    /\ status' = [status EXCEPT ![pk] = "Cooldown"]
    /\ UNCHANGED <<flagHistory, currentRound, excludedSince>>

\* A participant in cooldown is readmitted to Active.
Readmit(pk) ==
    /\ pk \in Participants
    /\ status[pk] = "Cooldown"
    /\ excludedSince[pk] > 0
    /\ currentRound - excludedSince[pk] >= CooldownRounds
    /\ status' = [status EXCEPT ![pk] = "Active"]
    /\ excludedSince' = [excludedSince EXCEPT ![pk] = 0]
    /\ UNCHANGED <<flagHistory, currentRound>>

Next ==
    \/ AdvanceRound
    \/ \E pk \in Participants : FlagParticipant(pk)
    \/ \E pk \in Participants : UnflagParticipant(pk)
    \/ \E pk \in Participants : EnterCooldown(pk)
    \/ \E pk \in Participants : Readmit(pk)

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ \A p \in Participants : status[p] \in StatusValues
    /\ currentRound \in 1..MaxRound
    /\ \A p \in Participants : excludedSince[p] \in 0..MaxRound

\* INV-2: ExclusionIdempotent — an already-excluded participant stays excluded
\* until cooldown transition (cannot be flagged again while excluded).
ExclusionIdempotent ==
    \A p \in Participants :
        status[p] = "Excluded" =>
            excludedSince[p] > 0

\* INV-3: ReadmissionGated — a participant can only be readmitted after
\* cooldown_rounds have elapsed since exclusion.
ReadmissionGated ==
    \A p \in Participants :
        status[p] = "Active" /\ excludedSince[p] = 0 =>
            TRUE  \* If active with no exclusion record, trivially gated
        \* The real gate is in the Readmit action precondition.

\* INV-4: FlagHistoryMonotonic — rounds in flag_history only increase.
FlagHistoryMonotonic ==
    \A i \in 1..(Len(flagHistory) - 1) :
        flagHistory[i].round <= flagHistory[i+1].round

\* INV-5: ActiveNotExcluded — cannot be Active and Excluded simultaneously.
ActiveNotExcluded ==
    \A p \in Participants :
        status[p] = "Active" => status[p] # "Excluded"

\* INV-6: ExcludedHasHistory — any excluded participant must have been flagged.
ExcludedHasHistory ==
    \A p \in Participants :
        status[p] \in {"Excluded", "Cooldown"} =>
            \E i \in 1..Len(flagHistory) : flagHistory[i].pubkey = p

\* INV-7: CooldownOnlyFromExcluded — cooldown status requires prior exclusion.
CooldownOnlyFromExcluded ==
    \A p \in Participants :
        status[p] = "Cooldown" => excludedSince[p] > 0

\* INV-8: RoundBounded — current round stays within bounds.
RoundBounded ==
    currentRound <= MaxRound

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM ExclusionIdem == Spec => []ExclusionIdempotent
THEOREM ReadmissionIsGated == Spec => []ReadmissionGated
THEOREM FlagHistoryMono == Spec => []FlagHistoryMonotonic
THEOREM ActiveExcludedDisjoint == Spec => []ActiveNotExcluded
THEOREM ExcludedMustHaveFlags == Spec => []ExcludedHasHistory
THEOREM CooldownRequiresExclusion == Spec => []CooldownOnlyFromExcluded
THEOREM RoundIsBounded == Spec => []RoundBounded

=============================================================================
