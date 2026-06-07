-------------------------- MODULE ComputePoolSettlement --------------------------
EXTENDS Naturals, FiniteSets, TLC

\* INFER-S2 (chain) — settlement-authority + requester timeout-refund for
\* ComputePool pooled jobs.
\*
\* Source: contracts/src/ComputePool.sol
\*   completeJob:410  failJob:431  recordDispatch:664  reassignCoordinator:693
\*   reclaimExpiredJob (WP-G2)
\* WP:  citrate-labs/handoffs/INFER_COMPUTEPOOL_SETTLEMENT_WP.md (PR #11)
\* BDD: specs/gherkin/computepool_settlement.feature
\* Solidity twin: contracts/test/invariant/ComputePoolSettlementInvariant.t.sol
\*   (the same four invariants, fuzzed at 128k randomised calls).
\*
\* Models one pool's job-escrow state machine. A job's payment is held in
\* escrow on request and leaves escrow exactly once — paid out to providers
\* (Complete) XOR refunded to the requester (Fail / Reclaim). The four
\* safety invariants below are the ones the WP requires.

CONSTANTS
    Jobs    \* finite set of job identifiers, e.g. {j1, j2}

\* Fixed actor roles. The coordinator is the VRF-elected executor recorded
\* by recordDispatch; only it (plus governance / creator) may settle.
Governance == "gov"
Creator    == "creator"
Coordinator == "coord"
Requester  == "requester"
Outsider   == "outsider"
NoActor    == "none"

Actors == {Governance, Creator, Coordinator, Requester, Outsider}

\* Authorized to call completeJob / failJob for a job dispatched to `db`.
SettlementAuthorized(actor, db) ==
    actor = Governance \/ actor = Creator \/ actor = db

JobStates == {"Pending", "Executing", "Completed", "Failed"}
TerminalStates == {"Completed", "Failed"}
EscrowStates == {"escrowed", "paid", "refunded"}

VARIABLES
    status,       \* Jobs -> JobStates
    escrow,       \* Jobs -> EscrowStates
    dispatchedBy, \* Jobs -> Actors \cup {NoActor}
    expired,      \* Jobs -> BOOLEAN  (JOB_DEADLINE elapsed)
    settleCount,  \* Jobs -> Nat      (# of times escrow left escrow)
    settledBy,    \* Jobs -> Actors \cup {NoActor} (who completed, if Completed)
    everTerminal  \* Jobs -> BOOLEAN  (has this job ever been terminal)

vars == <<status, escrow, dispatchedBy, expired, settleCount, settledBy, everTerminal>>

Init ==
    /\ status = [j \in Jobs |-> "Pending"]
    /\ escrow = [j \in Jobs |-> "escrowed"]
    /\ dispatchedBy = [j \in Jobs |-> NoActor]
    /\ expired = [j \in Jobs |-> FALSE]
    /\ settleCount = [j \in Jobs |-> 0]
    /\ settledBy = [j \in Jobs |-> NoActor]
    /\ everTerminal = [j \in Jobs |-> FALSE]

IsOpen(j) == status[j] = "Pending" \/ status[j] = "Executing"

\* recordDispatch — only the elected coordinator, only while Pending.
Dispatch(j) ==
    /\ status[j] = "Pending"
    /\ status' = [status EXCEPT ![j] = "Executing"]
    /\ dispatchedBy' = [dispatchedBy EXCEPT ![j] = Coordinator]
    /\ UNCHANGED <<escrow, expired, settleCount, settledBy, everTerminal>>

\* completeJob — authorized actor settles to providers (escrow -> paid).
Complete(j, actor) ==
    /\ IsOpen(j)
    /\ SettlementAuthorized(actor, dispatchedBy[j])
    /\ status' = [status EXCEPT ![j] = "Completed"]
    /\ escrow' = [escrow EXCEPT ![j] = "paid"]
    /\ settleCount' = [settleCount EXCEPT ![j] = @ + 1]
    /\ settledBy' = [settledBy EXCEPT ![j] = actor]
    /\ everTerminal' = [everTerminal EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<dispatchedBy, expired>>

\* failJob — authorized actor settles refund (escrow -> refunded).
Fail(j, actor) ==
    /\ IsOpen(j)
    /\ SettlementAuthorized(actor, dispatchedBy[j])
    /\ status' = [status EXCEPT ![j] = "Failed"]
    /\ escrow' = [escrow EXCEPT ![j] = "refunded"]
    /\ settleCount' = [settleCount EXCEPT ![j] = @ + 1]
    /\ settledBy' = [settledBy EXCEPT ![j] = actor]
    /\ everTerminal' = [everTerminal EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<dispatchedBy, expired>>

\* reclaimExpiredJob — requester-only, only after the deadline, refund-only.
Reclaim(j) ==
    /\ IsOpen(j)
    /\ expired[j]
    /\ status' = [status EXCEPT ![j] = "Failed"]
    /\ escrow' = [escrow EXCEPT ![j] = "refunded"]
    /\ settleCount' = [settleCount EXCEPT ![j] = @ + 1]
    /\ settledBy' = [settledBy EXCEPT ![j] = Requester]
    /\ everTerminal' = [everTerminal EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<dispatchedBy, expired>>

\* reassignCoordinator — stalled coordinator reset; escrow untouched.
Reassign(j) ==
    /\ status[j] = "Executing"
    /\ status' = [status EXCEPT ![j] = "Pending"]
    /\ dispatchedBy' = [dispatchedBy EXCEPT ![j] = NoActor]
    /\ UNCHANGED <<escrow, expired, settleCount, settledBy, everTerminal>>

\* JOB_DEADLINE elapses (abstract clock).
Expire(j) ==
    /\ ~expired[j]
    /\ expired' = [expired EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<status, escrow, dispatchedBy, settleCount, settledBy, everTerminal>>

Next ==
    \E j \in Jobs :
        \/ Dispatch(j)
        \/ \E a \in Actors : Complete(j, a)
        \/ \E a \in Actors : Fail(j, a)
        \/ Reclaim(j)
        \/ Reassign(j)
        \/ Expire(j)

Spec == Init /\ [][Next]_vars

\* ── Invariants ──────────────────────────────────────────────────────

TypeOK ==
    /\ status \in [Jobs -> JobStates]
    /\ escrow \in [Jobs -> EscrowStates]
    /\ dispatchedBy \in [Jobs -> Actors \cup {NoActor}]
    /\ expired \in [Jobs -> BOOLEAN]
    /\ settleCount \in [Jobs -> Nat]
    /\ settledBy \in [Jobs -> Actors \cup {NoActor}]
    /\ everTerminal \in [Jobs -> BOOLEAN]

\* (1) A job's escrow is settled at most once — paid XOR refunded XOR still
\*     escrowed, never two of those.
NoDoubleSpendEscrow ==
    \A j \in Jobs :
        /\ settleCount[j] <= 1
        /\ (status[j] = "Completed") <=> (escrow[j] = "paid")
        /\ (status[j] = "Failed")    <=> (escrow[j] = "refunded")
        /\ (IsOpen(j))               <=> (escrow[j] = "escrowed")

\* (2) The refund path only ever moves a job to refunded from an open,
\*     escrowed state — never re-credits an already-paid job.
RefundConservation ==
    \A j \in Jobs :
        (escrow[j] = "refunded") => (status[j] = "Failed")

\* (3) Once Completed/Failed, a job stays terminal forever.
TerminalMonotonicity ==
    \A j \in Jobs :
        everTerminal[j] => (status[j] \in TerminalStates)

\* (4) A Completed job was closed only by governance, creator, or the
\*     dispatched coordinator — never the requester or an outsider.
ExecutorOnlyCompletion ==
    \A j \in Jobs :
        (status[j] = "Completed") =>
            (settledBy[j] = Governance
                \/ settledBy[j] = Creator
                \/ settledBy[j] = Coordinator)

=============================================================================
