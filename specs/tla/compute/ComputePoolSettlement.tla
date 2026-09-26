-------------------------- MODULE ComputePoolSettlement --------------------------
EXTENDS Naturals, FiniteSets, TLC

\* INFER-S2 (chain) — settlement-authority + requester timeout-refund for
\* ComputePool pooled jobs.
\*
\* Source: contracts/src/ComputePool.sol
\*   completeJob:410  failJob:431  recordDispatch:664  reassignCoordinator:693
\*   reclaimExpiredJob (WP-G2)
\*   requestLeave / leavePool (PBA-L2-022: two-step exit, live activeJobs)
\*   reassignCoordinator: caller must be a current pool member; liveness
\*     slash keeps pool.totalStaked == sum(member.stake) and is retained in
\*     slashedStakeRetained; leavePool returns the remaining stake.
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
Peer       == "peer"      \* another current pool member (never leaves here)
NoActor    == "none"

Actors == {Governance, Creator, Coordinator, Requester, Outsider, Peer}

\* Stake of the coordinator's membership, in abstract slash units.
\* LIVENESS_SLASH_BPS of stake is modelled as one unit per reassignment.
InitStake == 2
SlashUnit == 1

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
    everTerminal, \* Jobs -> BOOLEAN  (has this job ever been terminal)
    \* PBA-L2-022: the coordinator's pool membership.
    activeJobs,     \* Nat: member.activeJobs of the coordinator
    memberActive,   \* BOOLEAN: coordinator still a pool member
    leaveRequested, \* BOOLEAN: requestLeave called (cooldown started)
    cooldownDone,   \* BOOLEAN: LEAVE_COOLDOWN blocks elapsed since request
    \* Stake accounting for the coordinator's membership.
    coordStake,     \* Nat: members[pool][coord].stake
    totalStaked,    \* Nat: coordinator's share of pools[pool].totalStaked
    slashRetained,  \* Nat: slashedStakeRetained credited from this member
    stakeReturned   \* Nat: stake paid back by leavePool

jobVars == <<status, escrow, dispatchedBy, expired, settleCount, settledBy, everTerminal>>
memberVars == <<activeJobs, memberActive, leaveRequested, cooldownDone>>
stakeVars == <<coordStake, totalStaked, slashRetained, stakeReturned>>
vars == <<jobVars, memberVars, stakeVars>>

\* reassignCoordinator requires `members[poolId][msg.sender].active`.
IsMember(a) == a = Peer \/ (a = Coordinator /\ memberActive)

\* Open jobs currently dispatched to the coordinator.
DispatchedOpen == {j \in Jobs : status[j] = "Executing" /\ dispatchedBy[j] = Coordinator}

\* activeJobs is decremented when a dispatched job leaves Executing.
Release(j) ==
    IF status[j] = "Executing" /\ dispatchedBy[j] = Coordinator
    THEN activeJobs' = activeJobs - 1
    ELSE activeJobs' = activeJobs

Init ==
    /\ status = [j \in Jobs |-> "Pending"]
    /\ escrow = [j \in Jobs |-> "escrowed"]
    /\ dispatchedBy = [j \in Jobs |-> NoActor]
    /\ expired = [j \in Jobs |-> FALSE]
    /\ settleCount = [j \in Jobs |-> 0]
    /\ settledBy = [j \in Jobs |-> NoActor]
    /\ everTerminal = [j \in Jobs |-> FALSE]
    /\ activeJobs = 0
    /\ memberActive = TRUE
    /\ leaveRequested = FALSE
    /\ cooldownDone = FALSE
    /\ coordStake = InitStake
    /\ totalStaked = InitStake
    /\ slashRetained = 0
    /\ stakeReturned = 0

IsOpen(j) == status[j] = "Pending" \/ status[j] = "Executing"

\* recordDispatch — only the elected coordinator, only while Pending.
Dispatch(j) ==
    /\ status[j] = "Pending"
    /\ memberActive
    /\ status' = [status EXCEPT ![j] = "Executing"]
    /\ dispatchedBy' = [dispatchedBy EXCEPT ![j] = Coordinator]
    /\ activeJobs' = activeJobs + 1
    /\ UNCHANGED <<escrow, expired, settleCount, settledBy, everTerminal>>
    /\ UNCHANGED <<memberActive, leaveRequested, cooldownDone>>
    /\ UNCHANGED stakeVars

\* completeJob — authorized actor settles to providers (escrow -> paid).
Complete(j, actor) ==
    /\ IsOpen(j)
    /\ SettlementAuthorized(actor, dispatchedBy[j])
    /\ status' = [status EXCEPT ![j] = "Completed"]
    /\ escrow' = [escrow EXCEPT ![j] = "paid"]
    /\ settleCount' = [settleCount EXCEPT ![j] = @ + 1]
    /\ settledBy' = [settledBy EXCEPT ![j] = actor]
    /\ everTerminal' = [everTerminal EXCEPT ![j] = TRUE]
    /\ Release(j)
    /\ UNCHANGED <<dispatchedBy, expired>>
    /\ UNCHANGED <<memberActive, leaveRequested, cooldownDone>>
    /\ UNCHANGED stakeVars

\* failJob — authorized actor settles refund (escrow -> refunded).
Fail(j, actor) ==
    /\ IsOpen(j)
    /\ SettlementAuthorized(actor, dispatchedBy[j])
    /\ status' = [status EXCEPT ![j] = "Failed"]
    /\ escrow' = [escrow EXCEPT ![j] = "refunded"]
    /\ settleCount' = [settleCount EXCEPT ![j] = @ + 1]
    /\ settledBy' = [settledBy EXCEPT ![j] = actor]
    /\ everTerminal' = [everTerminal EXCEPT ![j] = TRUE]
    /\ Release(j)
    /\ UNCHANGED <<dispatchedBy, expired>>
    /\ UNCHANGED <<memberActive, leaveRequested, cooldownDone>>
    /\ UNCHANGED stakeVars

\* reclaimExpiredJob — requester-only, only after the deadline, refund-only.
Reclaim(j) ==
    /\ IsOpen(j)
    /\ expired[j]
    /\ status' = [status EXCEPT ![j] = "Failed"]
    /\ escrow' = [escrow EXCEPT ![j] = "refunded"]
    /\ settleCount' = [settleCount EXCEPT ![j] = @ + 1]
    /\ settledBy' = [settledBy EXCEPT ![j] = Requester]
    /\ everTerminal' = [everTerminal EXCEPT ![j] = TRUE]
    /\ Release(j)
    /\ UNCHANGED <<dispatchedBy, expired>>
    /\ UNCHANGED <<memberActive, leaveRequested, cooldownDone>>
    /\ UNCHANGED stakeVars

\* reassignCoordinator — stalled coordinator reset; escrow untouched.
\* Only a current pool member may call it. The stalled coordinator is
\* liveness-slashed; the slash leaves member.stake AND pool.totalStaked
\* together and is retained for governance (PBA-L2-022).
Reassign(j, caller) ==
    /\ status[j] = "Executing"
    /\ IsMember(caller)
    /\ status' = [status EXCEPT ![j] = "Pending"]
    /\ dispatchedBy' = [dispatchedBy EXCEPT ![j] = NoActor]
    /\ Release(j)
    /\ IF dispatchedBy[j] = Coordinator /\ coordStake >= SlashUnit
          THEN /\ coordStake' = coordStake - SlashUnit
               /\ totalStaked' = totalStaked - SlashUnit
               /\ slashRetained' = slashRetained + SlashUnit
          ELSE UNCHANGED <<coordStake, totalStaked, slashRetained>>
    /\ UNCHANGED stakeReturned
    /\ UNCHANGED <<escrow, expired, settleCount, settledBy, everTerminal>>
    /\ UNCHANGED <<memberActive, leaveRequested, cooldownDone>>

\* JOB_DEADLINE elapses (abstract clock).
Expire(j) ==
    /\ ~expired[j]
    /\ expired' = [expired EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<status, escrow, dispatchedBy, settleCount, settledBy, everTerminal>>
    /\ UNCHANGED memberVars
    /\ UNCHANGED stakeVars

\* PBA-L2-022: two-step exit. requestLeave starts LEAVE_COOLDOWN; the
\* member stays active (dispatchable, slashable) until leavePool.
RequestLeave ==
    /\ memberActive /\ ~leaveRequested
    /\ leaveRequested' = TRUE
    /\ UNCHANGED <<jobVars, activeJobs, memberActive, cooldownDone>>
    /\ UNCHANGED stakeVars

CooldownElapse ==
    /\ leaveRequested /\ ~cooldownDone
    /\ cooldownDone' = TRUE
    /\ UNCHANGED <<jobVars, activeJobs, memberActive, leaveRequested>>
    /\ UNCHANGED stakeVars

\* leavePool: requested, cooldown elapsed, and no dispatched open job.
Leave ==
    /\ memberActive /\ leaveRequested /\ cooldownDone
    /\ activeJobs = 0
    /\ memberActive' = FALSE
    /\ leaveRequested' = FALSE
    /\ cooldownDone' = FALSE
    \* the remaining (post-slash) stake is returned and leaves totalStaked
    /\ stakeReturned' = stakeReturned + coordStake
    /\ coordStake' = 0
    /\ totalStaked' = totalStaked - coordStake
    /\ UNCHANGED slashRetained
    /\ UNCHANGED <<jobVars, activeJobs>>

Next ==
    \E j \in Jobs :
        \/ Dispatch(j)
        \/ \E a \in Actors : Complete(j, a)
        \/ \E a \in Actors : Fail(j, a)
        \/ Reclaim(j)
        \/ \E a \in Actors : Reassign(j, a)
        \/ Expire(j)
    \/ RequestLeave
    \/ CooldownElapse
    \/ Leave

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
    /\ activeJobs \in Nat
    /\ memberActive \in BOOLEAN
    /\ leaveRequested \in BOOLEAN
    /\ cooldownDone \in BOOLEAN
    /\ coordStake \in 0..InitStake
    /\ totalStaked \in 0..InitStake
    /\ slashRetained \in 0..InitStake
    /\ stakeReturned \in 0..InitStake

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

\* (5) PBA-L2-022: member.activeJobs is live — it always equals the number
\*     of open jobs dispatched to the member (pre-fix it was never written).
ActiveJobsAccurate == activeJobs = Cardinality(DispatchedOpen)

\* (6) PBA-L2-022: a member that has left holds no dispatched open job, so a
\*     dispatched coordinator cannot escape its liveness/SLA slash by leaving.
NoLeaveWithOpenDispatch == ~memberActive => DispatchedOpen = {}

\* (7) PBA-L2-022: pool.totalStaked tracks the sum of live member stakes
\*     through liveness slashes and exits.
TotalStakedMatchesMembers ==
    totalStaked = IF memberActive THEN coordStake ELSE 0

\* (8) Stake is conserved: every unit is still staked, retained as a slash,
\*     or returned on exit — never lost or double-paid.
StakeConservation ==
    coordStake + slashRetained + stakeReturned = InitStake

=============================================================================
