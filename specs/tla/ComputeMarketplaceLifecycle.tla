--------------------- MODULE ComputeMarketplaceLifecycle ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the Compute Marketplace job lifecycle from
\* contracts/src/ComputeMarketplace.sol.
\*
\* Job states:
\*   Posted -> Bidding -> Assigned -> Executing -> Verifying -> Completed
\*   Posted -> Expired
\*   Assigned -> Timeout
\*   Executing -> Failed
\*   Verifying -> Disputed
\*   Timeout -> Assigned (reassignment to next provider)
\*
\* Pricing: reverse auction — providers bid below the requester's maxPrice.
\* Escrow: locked on job creation, released on completion or refunded on expiry.
\* Payment split: 95% provider, 2.5% burned (BME), 2.5% treasury.
\*
\* Source: .agentile/teamwork/COMPUTE_MARKETPLACE_ARCHITECTURE.md

CONSTANTS
    Jobs,           \* Set of job identifiers
    Providers,      \* Set of provider addresses (must be registered)
    MaxBids,        \* Maximum number of bids per job
    MaxPrice        \* Maximum price ceiling

ASSUME Jobs # {}
ASSUME Providers # {}
ASSUME MaxBids \in Nat /\ MaxBids >= 1
ASSUME MaxPrice \in Nat /\ MaxPrice >= 2

\* Job states (mirrors Solidity enum)
JobStates == {"Posted", "Bidding", "Assigned", "Executing",
              "Verifying", "Completed", "Expired", "Timeout", "Failed", "Disputed"}

\* Terminal states — no further transitions.
TerminalStates == {"Completed", "Expired", "Failed", "Disputed"}

VARIABLES
    jobState,       \* Mapping: job -> state
    jobPrice,       \* Mapping: job -> maxPrice set by requester
    bids,           \* Mapping: job -> set of [provider, amount] records
    escrow,         \* Mapping: job -> SALT locked in escrow (0 if none)
    assignments,    \* Mapping: job -> assigned provider ("none" if unassigned)
    payments,       \* Mapping: job -> SALT paid out (0 if none)
    verified,       \* Mapping: job -> TRUE iff verification passed
    registered      \* Set of registered providers

vars == <<jobState, jobPrice, bids, escrow, assignments, payments, verified, registered>>

\* ---- Helpers ----

\* Number of bids on a job.
BidCount(j) == Cardinality(bids[j])

\* Total escrow across all jobs.
RECURSIVE SumEscrow(_, _)
SumEscrow(js, acc) ==
    IF js = {} THEN acc
    ELSE LET j == CHOOSE x \in js : TRUE
         IN SumEscrow(js \ {j}, acc + escrow[j])

TotalEscrow == SumEscrow(Jobs, 0)

\* Total locked by active (non-terminal, non-zero-escrow) jobs.
RECURSIVE SumLockedByJobs(_, _)
SumLockedByJobs(js, acc) ==
    IF js = {} THEN acc
    ELSE LET j == CHOOSE x \in js : TRUE
             locked == IF jobState[j] \notin TerminalStates THEN escrow[j] ELSE 0
         IN SumLockedByJobs(js \ {j}, acc + locked)

TotalLockedByJobs == SumLockedByJobs(Jobs, 0)

\* ---- State machine ----

Init ==
    /\ jobState = [j \in Jobs |-> "Posted"]
    /\ jobPrice = [j \in Jobs |-> 0]
    /\ bids = [j \in Jobs |-> {}]
    /\ escrow = [j \in Jobs |-> 0]
    /\ assignments = [j \in Jobs |-> "none"]
    /\ payments = [j \in Jobs |-> 0]
    /\ verified = [j \in Jobs |-> FALSE]
    /\ registered = {}

\* Register a provider.
RegisterProvider(p) ==
    /\ p \in Providers
    /\ p \notin registered
    /\ registered' = registered \union {p}
    /\ UNCHANGED <<jobState, jobPrice, bids, escrow, assignments, payments, verified>>

\* Post a job with a price ceiling and lock escrow.
PostJob(j, price) ==
    /\ j \in Jobs
    /\ jobState[j] = "Posted"
    /\ jobPrice[j] = 0        \* not yet configured
    /\ price \in 1..MaxPrice
    /\ jobState' = [jobState EXCEPT ![j] = "Bidding"]
    /\ jobPrice' = [jobPrice EXCEPT ![j] = price]
    /\ escrow' = [escrow EXCEPT ![j] = price]
    /\ UNCHANGED <<bids, assignments, payments, verified, registered>>

\* Provider places a bid on a job (must be <= maxPrice).
PlaceBid(j, p, amount) ==
    /\ j \in Jobs
    /\ jobState[j] = "Bidding"
    /\ p \in registered
    /\ amount \in 1..MaxPrice
    /\ amount <= jobPrice[j]
    /\ BidCount(j) < MaxBids
    \* Provider hasn't already bid on this job.
    /\ ~ \E b \in bids[j] : b.provider = p
    /\ bids' = [bids EXCEPT ![j] = @ \union {[provider |-> p, amount |-> amount]}]
    /\ UNCHANGED <<jobState, jobPrice, escrow, assignments, payments, verified, registered>>

\* Assign the job to the lowest bidder (or any bidder for simplicity).
AssignJob(j, p) ==
    /\ j \in Jobs
    /\ jobState[j] = "Bidding"
    /\ BidCount(j) >= 1
    /\ \E b \in bids[j] : b.provider = p
    /\ p \in registered
    /\ jobState' = [jobState EXCEPT ![j] = "Assigned"]
    /\ assignments' = [assignments EXCEPT ![j] = p]
    /\ UNCHANGED <<jobPrice, bids, escrow, payments, verified, registered>>

\* Provider begins execution.
StartExecution(j) ==
    /\ j \in Jobs
    /\ jobState[j] = "Assigned"
    /\ assignments[j] # "none"
    /\ assignments[j] \in registered
    /\ jobState' = [jobState EXCEPT ![j] = "Executing"]
    /\ UNCHANGED <<jobPrice, bids, escrow, assignments, payments, verified, registered>>

\* Provider submits result — moves to verification.
SubmitResult(j) ==
    /\ j \in Jobs
    /\ jobState[j] = "Executing"
    /\ jobState' = [jobState EXCEPT ![j] = "Verifying"]
    /\ UNCHANGED <<jobPrice, bids, escrow, assignments, payments, verified, registered>>

\* Verification passes — job completed, payment released.
VerifyAndComplete(j) ==
    /\ j \in Jobs
    /\ jobState[j] = "Verifying"
    /\ verified' = [verified EXCEPT ![j] = TRUE]
    /\ LET price == escrow[j]
       IN /\ payments' = [payments EXCEPT ![j] = price]
          /\ escrow' = [escrow EXCEPT ![j] = 0]
    /\ jobState' = [jobState EXCEPT ![j] = "Completed"]
    /\ UNCHANGED <<jobPrice, bids, assignments, registered>>

\* Verification fails — result disputed.
DisputeResult(j) ==
    /\ j \in Jobs
    /\ jobState[j] = "Verifying"
    /\ jobState' = [jobState EXCEPT ![j] = "Disputed"]
    /\ UNCHANGED <<jobPrice, bids, escrow, assignments, payments, verified, registered>>

\* Job expires (no bids received in time).
ExpireJob(j) ==
    /\ j \in Jobs
    /\ jobState[j] = "Bidding"
    /\ jobState' = [jobState EXCEPT ![j] = "Expired"]
    \* Refund escrow to requester.
    /\ escrow' = [escrow EXCEPT ![j] = 0]
    /\ UNCHANGED <<jobPrice, bids, assignments, payments, verified, registered>>

\* Provider times out during execution.
TimeoutJob(j) ==
    /\ j \in Jobs
    /\ jobState[j] \in {"Assigned", "Executing"}
    /\ jobState' = [jobState EXCEPT ![j] = "Timeout"]
    /\ UNCHANGED <<jobPrice, bids, escrow, assignments, payments, verified, registered>>

\* Reassign a timed-out job to another provider (if bids exist).
ReassignJob(j, p) ==
    /\ j \in Jobs
    /\ jobState[j] = "Timeout"
    /\ \E b \in bids[j] : b.provider = p /\ p # assignments[j]
    /\ p \in registered
    /\ jobState' = [jobState EXCEPT ![j] = "Assigned"]
    /\ assignments' = [assignments EXCEPT ![j] = p]
    /\ UNCHANGED <<jobPrice, bids, escrow, payments, verified, registered>>

\* Execution fails.
FailJob(j) ==
    /\ j \in Jobs
    /\ jobState[j] = "Executing"
    /\ jobState' = [jobState EXCEPT ![j] = "Failed"]
    \* Escrow refunded on failure.
    /\ escrow' = [escrow EXCEPT ![j] = 0]
    /\ UNCHANGED <<jobPrice, bids, assignments, payments, verified, registered>>

Next ==
    \/ \E p \in Providers : RegisterProvider(p)
    \/ \E j \in Jobs, pr \in 1..MaxPrice : PostJob(j, pr)
    \/ \E j \in Jobs, p \in Providers, a \in 1..MaxPrice : PlaceBid(j, p, a)
    \/ \E j \in Jobs, p \in Providers : AssignJob(j, p)
    \/ \E j \in Jobs : StartExecution(j)
    \/ \E j \in Jobs : SubmitResult(j)
    \/ \E j \in Jobs : VerifyAndComplete(j)
    \/ \E j \in Jobs : DisputeResult(j)
    \/ \E j \in Jobs : ExpireJob(j)
    \/ \E j \in Jobs : TimeoutJob(j)
    \/ \E j \in Jobs, p \in Providers : ReassignJob(j, p)
    \/ \E j \in Jobs : FailJob(j)

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ \A j \in Jobs : jobState[j] \in JobStates
    /\ \A j \in Jobs : jobPrice[j] \in 0..MaxPrice
    /\ \A j \in Jobs : escrow[j] \in Nat
    /\ \A j \in Jobs : payments[j] \in Nat
    /\ \A j \in Jobs : verified[j] \in BOOLEAN
    /\ \A j \in Jobs :
        \A b \in bids[j] :
            /\ b.provider \in Providers
            /\ b.amount \in 1..MaxPrice
    /\ registered \subseteq Providers

\* INV-2: NoPaymentWithoutVerification — payment only after verification passes.
NoPaymentWithoutVerification ==
    \A j \in Jobs :
        payments[j] > 0 => verified[j] = TRUE

\* INV-3: EscrowConservation — escrow + payments account for all locked funds.
\* For every completed job: escrow = 0, payments = original price.
\* For every active job: escrow = price, payments = 0.
EscrowConservation ==
    \A j \in Jobs :
        /\ (jobState[j] = "Completed" => escrow[j] = 0)
        /\ (jobState[j] \in {"Bidding", "Assigned", "Executing", "Verifying"} =>
            escrow[j] = jobPrice[j])

\* INV-4: StateOnlyForward — no backward state transitions for terminal states.
StateOnlyForward ==
    \A j \in Jobs :
        /\ (jobState[j] = "Completed" => verified[j] = TRUE)
        /\ (jobState[j] = "Expired" => escrow[j] = 0)
        /\ (jobState[j] = "Failed" => escrow[j] = 0)

\* INV-5: BidBelowCeiling — all bids must be at or below the job's maxPrice.
BidBelowCeiling ==
    \A j \in Jobs :
        \A b \in bids[j] : b.amount <= jobPrice[j]

\* INV-6: AssignedProviderRegistered — assigned provider must be in registered set.
AssignedProviderRegistered ==
    \A j \in Jobs :
        assignments[j] # "none" => assignments[j] \in registered

\* INV-7: ExpiredJobsRefunded — expired jobs have zero escrow.
ExpiredJobsRefunded ==
    \A j \in Jobs :
        jobState[j] = "Expired" => escrow[j] = 0

\* INV-8: TimeoutTriggersReassignment — a timed-out job still has escrow held
\* (not yet refunded) so it can be reassigned.
TimeoutEscrowHeld ==
    \A j \in Jobs :
        jobState[j] = "Timeout" => escrow[j] > 0

\* INV-9: CompletedPaid — completed jobs have payments > 0.
CompletedPaid ==
    \A j \in Jobs :
        jobState[j] = "Completed" => payments[j] > 0

\* INV-10: PostedNoBids — jobs still in Posted state have no bids.
PostedNoBids ==
    \A j \in Jobs :
        jobState[j] = "Posted" => BidCount(j) = 0

\* INV-11: PostedNoEscrow — jobs still in initial Posted state have no escrow.
PostedNoEscrow ==
    \A j \in Jobs :
        jobState[j] = "Posted" => escrow[j] = 0

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM NoPayWithoutVerify == Spec => []NoPaymentWithoutVerification
THEOREM EscrowConserv == Spec => []EscrowConservation
THEOREM ForwardOnly == Spec => []StateOnlyForward
THEOREM BidCeiling == Spec => []BidBelowCeiling
THEOREM AssignedRegistered == Spec => []AssignedProviderRegistered
THEOREM ExpiredRefund == Spec => []ExpiredJobsRefunded
THEOREM TimeoutEscrow == Spec => []TimeoutEscrowHeld
THEOREM CompletedIsPaid == Spec => []CompletedPaid
THEOREM PostedClean == Spec => []PostedNoBids
THEOREM PostedNoEsc == Spec => []PostedNoEscrow

=============================================================================
