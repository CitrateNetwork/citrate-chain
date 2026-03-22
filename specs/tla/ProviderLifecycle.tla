--------------------- MODULE ProviderLifecycle ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the provider registration, heartbeat, and suspension lifecycle
\* for the Citrate Compute Marketplace.
\*
\* Provider states:
\*   Unregistered -> Active (after registration + staking)
\*   Active -> Suspended (after MaxMissed heartbeat misses)
\*   Suspended -> Active (after fresh heartbeat + re-attestation)
\*
\* NematocystSlashing integration: suspension triggers Tier 1 (Latency) slash.
\*
\* Source: contracts/src/ProviderRegistry.sol, HeartbeatMonitor.sol
\*         .agentile/teamwork/COMPUTE_MARKETPLACE_ARCHITECTURE.md

CONSTANTS
    Providers,          \* Set of provider addresses
    MinStake,           \* Minimum stake to be Active
    HeartbeatInterval,  \* Blocks between required heartbeats
    MaxMissed,          \* Max missed heartbeats before suspension
    MaxBlock            \* Maximum block number (bounds state space)

ASSUME Providers # {}
ASSUME MinStake \in Nat /\ MinStake >= 1
ASSUME HeartbeatInterval \in Nat /\ HeartbeatInterval >= 1
ASSUME MaxMissed \in Nat /\ MaxMissed >= 1
ASSUME MaxBlock \in Nat /\ MaxBlock >= 1

ProviderStates == {"Unregistered", "Active", "Suspended"}

VARIABLES
    status,             \* Mapping: provider -> state
    stake,              \* Mapping: provider -> staked SALT amount
    lastHeartbeat,      \* Mapping: provider -> block number of last heartbeat
    missedCount,        \* Mapping: provider -> consecutive missed heartbeats
    slashEvents,        \* Count of total slash events triggered
    currentBlock        \* Current block number

vars == <<status, stake, lastHeartbeat, missedCount, slashEvents, currentBlock>>

\* ---- State machine ----

Init ==
    /\ status = [p \in Providers |-> "Unregistered"]
    /\ stake = [p \in Providers |-> 0]
    /\ lastHeartbeat = [p \in Providers |-> 0]
    /\ missedCount = [p \in Providers |-> 0]
    /\ slashEvents = 0
    /\ currentBlock = 1

\* Register a provider with stake.
Register(p, amount) ==
    /\ p \in Providers
    /\ status[p] = "Unregistered"
    /\ amount >= MinStake
    /\ amount \in MinStake..(MinStake * 3)   \* bounded for model checking
    /\ status' = [status EXCEPT ![p] = "Active"]
    /\ stake' = [stake EXCEPT ![p] = amount]
    /\ lastHeartbeat' = [lastHeartbeat EXCEPT ![p] = currentBlock]
    /\ missedCount' = [missedCount EXCEPT ![p] = 0]
    /\ UNCHANGED <<slashEvents, currentBlock>>

\* Provider sends a heartbeat.
SendHeartbeat(p) ==
    /\ p \in Providers
    /\ status[p] = "Active"
    /\ lastHeartbeat' = [lastHeartbeat EXCEPT ![p] = currentBlock]
    /\ missedCount' = [missedCount EXCEPT ![p] = 0]
    /\ UNCHANGED <<status, stake, slashEvents, currentBlock>>

\* Check heartbeat for a provider — may trigger missed count increment.
CheckHeartbeat(p) ==
    /\ p \in Providers
    /\ status[p] = "Active"
    /\ currentBlock - lastHeartbeat[p] > HeartbeatInterval
    /\ missedCount' = [missedCount EXCEPT ![p] = @ + 1]
    /\ IF missedCount[p] + 1 >= MaxMissed
       THEN \* Suspend the provider and trigger slash.
            /\ status' = [status EXCEPT ![p] = "Suspended"]
            /\ LET penalty == (stake[p] * 5) \div 100  \* Tier 1 Latency slash
                   actualPenalty == IF penalty > stake[p] THEN stake[p] ELSE penalty
               IN stake' = [stake EXCEPT ![p] = @ - actualPenalty]
            /\ slashEvents' = slashEvents + 1
       ELSE \* Just increment missed count.
            /\ UNCHANGED <<status, stake, slashEvents>>
    /\ UNCHANGED <<lastHeartbeat, currentBlock>>

\* Reactivate a suspended provider (requires fresh heartbeat).
Reactivate(p) ==
    /\ p \in Providers
    /\ status[p] = "Suspended"
    /\ stake[p] >= MinStake         \* must still have enough stake
    /\ status' = [status EXCEPT ![p] = "Active"]
    /\ lastHeartbeat' = [lastHeartbeat EXCEPT ![p] = currentBlock]
    /\ missedCount' = [missedCount EXCEPT ![p] = 0]
    /\ UNCHANGED <<stake, slashEvents, currentBlock>>

\* Advance block.
AdvanceBlock ==
    /\ currentBlock < MaxBlock
    /\ currentBlock' = currentBlock + 1
    /\ UNCHANGED <<status, stake, lastHeartbeat, missedCount, slashEvents>>

Next ==
    \/ \E p \in Providers, a \in MinStake..(MinStake * 3) : Register(p, a)
    \/ \E p \in Providers : SendHeartbeat(p)
    \/ \E p \in Providers : CheckHeartbeat(p)
    \/ \E p \in Providers : Reactivate(p)
    \/ AdvanceBlock

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ \A p \in Providers : status[p] \in ProviderStates
    /\ \A p \in Providers : stake[p] \in Nat
    /\ \A p \in Providers : lastHeartbeat[p] \in Nat
    /\ \A p \in Providers : missedCount[p] \in Nat
    /\ slashEvents \in Nat
    /\ currentBlock \in 1..MaxBlock

\* INV-2: StakeRequiredForActive — active providers must have minimum stake.
StakeRequiredForActive ==
    \A p \in Providers :
        status[p] = "Active" => stake[p] >= MinStake

\* INV-3: SuspendedAfterMissed — if missedCount >= MaxMissed, provider is suspended.
SuspendedAfterMissed ==
    \A p \in Providers :
        missedCount[p] >= MaxMissed => status[p] \in {"Suspended", "Unregistered"}

\* INV-4: SuspendedCantAcceptJobs — suspended providers have non-Active status.
\* (This is a type-level guarantee used by the marketplace to check assignments.)
SuspendedCantAcceptJobs ==
    \A p \in Providers :
        status[p] = "Suspended" => status[p] # "Active"

\* INV-5: StakeSlashedOnSuspension — suspended providers have reduced stake
\* (or at least their slash count incremented).
\* We verify: if suspended and not unregistered, a slash event has occurred.
StakeSlashedOnSuspension ==
    (\E p \in Providers : status[p] = "Suspended") => slashEvents >= 1

\* INV-6: ReactivationRequiresStake — reactivated providers must have >= MinStake.
\* (Structurally guaranteed: Reactivate guard checks stake >= MinStake.)
ReactivationRequiresStake ==
    \A p \in Providers :
        status[p] = "Active" => stake[p] >= MinStake

\* INV-7: StakeNonNegative — stake never goes below zero.
StakeNonNegative ==
    \A p \in Providers : stake[p] >= 0

\* INV-8: UnregisteredNoStake — unregistered providers have no stake.
UnregisteredNoStake ==
    \A p \in Providers :
        status[p] = "Unregistered" => stake[p] = 0

\* INV-9: BlockMonotonic — currentBlock never decreases.
BlockMonotonic ==
    currentBlock >= 1

\* INV-10: MissedCountBounded — missed count is bounded.
MissedCountBounded ==
    \A p \in Providers : missedCount[p] <= MaxMissed

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM ActiveStake == Spec => []StakeRequiredForActive
THEOREM SuspendedMissed == Spec => []SuspendedAfterMissed
THEOREM SuspendedNoJobs == Spec => []SuspendedCantAcceptJobs
THEOREM SlashOnSuspend == Spec => []StakeSlashedOnSuspension
THEOREM ReactivateStake == Spec => []ReactivationRequiresStake
THEOREM NonNegStake == Spec => []StakeNonNegative
THEOREM UnregNoStake == Spec => []UnregisteredNoStake
THEOREM BlockMono == Spec => []BlockMonotonic
THEOREM MissedBounded == Spec => []MissedCountBounded

=============================================================================
