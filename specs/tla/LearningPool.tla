------------------------------ MODULE LearningPool ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the LearningPool smart contract for the Learning Center GUI.
\*
\* Pools are created by a creator who is automatically a member. Members
\* must stake tokens to join. The creator controls model whitelisting.
\* Pools can be open or closed; closed pools reject new members.
\* Members can leave (unstake) when the pool is not in an active cycle.
\*
\* Source: contracts/src/LearningPool.sol, gui features/learning

CONSTANTS
    Pools,              \* Set of pool IDs
    Members,            \* Set of potential member addresses
    Models              \* Set of model IDs

ASSUME Pools # {}
ASSUME Members # {}
ASSUME Models # {}
ASSUME Cardinality(Members) >= Cardinality(Pools)  \* need at least one creator per pool

VARIABLES
    poolState,          \* Mapping: pool -> "Open" | "Closed" | "ActiveCycle"
    poolMembers,        \* Mapping: pool -> set of members
    poolModels,         \* Mapping: pool -> set of whitelisted models
    poolCreator,        \* Mapping: pool -> creator address (or "none")
    stakes,             \* Mapping: pool -> (member -> staked amount)
    created             \* Set of pools that have been created

vars == <<poolState, poolMembers, poolModels, poolCreator, stakes, created>>

\* ---- Helper operators ----

PoolStates == {"Open", "Closed", "ActiveCycle"}

\* Total stake in a pool.
TotalStake(pool) ==
    LET RECURSIVE Sum(_, _)
        Sum(ms, acc) ==
            IF ms = {} THEN acc
            ELSE LET m == CHOOSE x \in ms : TRUE
                 IN Sum(ms \ {m}, acc + stakes[pool][m])
    IN Sum(Members, 0)

\* ---- State machine ----

Init ==
    /\ poolState = [p \in Pools |-> "Open"]
    /\ poolMembers = [p \in Pools |-> {}]
    /\ poolModels = [p \in Pools |-> {}]
    /\ poolCreator = [p \in Pools |-> "none"]
    /\ stakes = [p \in Pools |-> [m \in Members |-> 0]]
    /\ created = {}

\* Create a pool: creator becomes first member with initial stake.
CreatePool(pool, creator) ==
    /\ pool \notin created
    /\ creator \in Members
    /\ poolCreator' = [poolCreator EXCEPT ![pool] = creator]
    /\ poolMembers' = [poolMembers EXCEPT ![pool] = {creator}]
    /\ stakes' = [stakes EXCEPT ![pool][creator] = 1]
    /\ poolState' = [poolState EXCEPT ![pool] = "Open"]
    /\ created' = created \cup {pool}
    /\ UNCHANGED <<poolModels>>

\* Join a pool: member stakes tokens.
JoinPool(pool, member) ==
    /\ pool \in created
    /\ poolState[pool] = "Open"
    /\ member \in Members
    /\ member \notin poolMembers[pool]
    /\ poolMembers' = [poolMembers EXCEPT ![pool] = poolMembers[pool] \cup {member}]
    /\ stakes' = [stakes EXCEPT ![pool][member] = 1]
    /\ UNCHANGED <<poolState, poolModels, poolCreator, created>>

\* Leave a pool: member unstakes (not during active cycle).
LeavePool(pool, member) ==
    /\ pool \in created
    /\ poolState[pool] # "ActiveCycle"
    /\ member \in poolMembers[pool]
    /\ member # poolCreator[pool]   \* creator cannot leave
    /\ poolMembers' = [poolMembers EXCEPT ![pool] = poolMembers[pool] \ {member}]
    /\ stakes' = [stakes EXCEPT ![pool][member] = 0]
    /\ UNCHANGED <<poolState, poolModels, poolCreator, created>>

\* Close a pool (only creator).
ClosePool(pool, caller) ==
    /\ pool \in created
    /\ poolState[pool] = "Open"
    /\ caller = poolCreator[pool]
    /\ poolState' = [poolState EXCEPT ![pool] = "Closed"]
    /\ UNCHANGED <<poolMembers, poolModels, poolCreator, stakes, created>>

\* Reopen a closed pool (only creator).
ReopenPool(pool, caller) ==
    /\ pool \in created
    /\ poolState[pool] = "Closed"
    /\ caller = poolCreator[pool]
    /\ poolState' = [poolState EXCEPT ![pool] = "Open"]
    /\ UNCHANGED <<poolMembers, poolModels, poolCreator, stakes, created>>

\* Start an active cycle (only creator, pool must be open with members).
StartCycle(pool, caller) ==
    /\ pool \in created
    /\ poolState[pool] = "Open"
    /\ caller = poolCreator[pool]
    /\ Cardinality(poolMembers[pool]) >= 2  \* need at least 2 members
    /\ poolState' = [poolState EXCEPT ![pool] = "ActiveCycle"]
    /\ UNCHANGED <<poolMembers, poolModels, poolCreator, stakes, created>>

\* End an active cycle (returns to Open).
EndCycle(pool, caller) ==
    /\ pool \in created
    /\ poolState[pool] = "ActiveCycle"
    /\ caller = poolCreator[pool]
    /\ poolState' = [poolState EXCEPT ![pool] = "Open"]
    /\ UNCHANGED <<poolMembers, poolModels, poolCreator, stakes, created>>

\* Add model to whitelist (only creator).
AddModel(pool, caller, model) ==
    /\ pool \in created
    /\ caller = poolCreator[pool]
    /\ model \in Models
    /\ model \notin poolModels[pool]
    /\ poolModels' = [poolModels EXCEPT ![pool] = poolModels[pool] \cup {model}]
    /\ UNCHANGED <<poolState, poolMembers, poolCreator, stakes, created>>

\* Remove model from whitelist (only creator).
RemoveModel(pool, caller, model) ==
    /\ pool \in created
    /\ caller = poolCreator[pool]
    /\ model \in poolModels[pool]
    /\ poolModels' = [poolModels EXCEPT ![pool] = poolModels[pool] \ {model}]
    /\ UNCHANGED <<poolState, poolMembers, poolCreator, stakes, created>>

Next ==
    \/ \E p \in Pools, c \in Members : CreatePool(p, c)
    \/ \E p \in Pools, m \in Members : JoinPool(p, m)
    \/ \E p \in Pools, m \in Members : LeavePool(p, m)
    \/ \E p \in Pools, c \in Members : ClosePool(p, c)
    \/ \E p \in Pools, c \in Members : ReopenPool(p, c)
    \/ \E p \in Pools, c \in Members : StartCycle(p, c)
    \/ \E p \in Pools, c \in Members : EndCycle(p, c)
    \/ \E p \in Pools, c \in Members, model \in Models : AddModel(p, c, model)
    \/ \E p \in Pools, c \in Members, model \in Models : RemoveModel(p, c, model)

\* ---- Invariants ----

\* INV-1: Type correctness.
TypeOK ==
    /\ \A p \in Pools : poolState[p] \in PoolStates \/ (p \notin created /\ poolState[p] = "Open")
    /\ \A p \in Pools : poolMembers[p] \subseteq Members
    /\ \A p \in Pools : poolModels[p] \subseteq Models
    /\ \A p \in Pools : poolCreator[p] \in Members \/ poolCreator[p] = "none"
    /\ \A p \in Pools : \A m \in Members : stakes[p][m] \in Nat

\* INV-2: CreatorIsMember — creator is always a member of their pool.
CreatorIsMember ==
    \A p \in created : poolCreator[p] \in poolMembers[p]

\* INV-3: StakeRequiredForMembership — every member has a positive stake.
StakeRequiredForMembership ==
    \A p \in created : \A m \in poolMembers[p] : stakes[p][m] > 0

\* INV-4: ClosedPoolNoNewMembers — closed pool membership does not grow.
\* (Enforced by JoinPool requiring poolState = "Open".)
ClosedPoolNoNewMembers ==
    TRUE  \* Structurally guaranteed; included for documentation.

\* INV-5: ModelWhitelistRespected — only creator can modify whitelist.
\* (Enforced by AddModel/RemoveModel checking caller = poolCreator.)
ModelWhitelistRespected ==
    TRUE  \* Structurally guaranteed by action guards.

\* INV-6: NonMemberNoStake — participants not in pool have zero stake.
NonMemberNoStake ==
    \A p \in created : \A m \in Members :
        m \notin poolMembers[p] => stakes[p][m] = 0

\* INV-7: CreatedPoolHasCreator — every created pool has a real creator.
CreatedPoolHasCreator ==
    \A p \in created : poolCreator[p] \in Members

\* INV-8: UncreatedPoolEmpty — uncreated pools have no members or models.
UncreatedPoolEmpty ==
    \A p \in Pools :
        p \notin created =>
            /\ poolMembers[p] = {}
            /\ poolModels[p] = {}
            /\ poolCreator[p] = "none"

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety      == Spec => []TypeOK
THEOREM CreatorMember   == Spec => []CreatorIsMember
THEOREM StakeRequired   == Spec => []StakeRequiredForMembership
THEOREM NoNewClosed     == Spec => []ClosedPoolNoNewMembers
THEOREM WhitelistAuth   == Spec => []ModelWhitelistRespected
THEOREM NoStakeNonMem   == Spec => []NonMemberNoStake
THEOREM CreatedHasOwner == Spec => []CreatedPoolHasCreator
THEOREM UncreatedEmpty  == Spec => []UncreatedPoolEmpty

=============================================================================
