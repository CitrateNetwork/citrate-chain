------------------------------ MODULE GenesisSafetyAcrossNodes ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models multi-node genesis initialization to verify that all nodes
\* produce identical genesis blocks regardless of initialization order,
\* timing, or profile selection.
\*
\* CRITICAL: This spec models the exact bug we found — GUI and standalone
\* node produced different genesis hashes because they used different
\* initialization code paths.
\*
\* Source:
\*   node/src/genesis.rs (standalone node genesis)
\*   gui/src-tauri/src/node/mod.rs (GUI embedded node genesis)
\*   core/economics/src/genesis.rs (genesis config profiles)

CONSTANTS
    Nodes,            \* Set of node IDs (e.g., {standalone, gui1, gui2})
    Profiles,         \* Set of genesis profiles (e.g., {"team_testnet", "testnet_beta", "default"})
    Accounts,         \* Set of possible genesis accounts
    CorrectProfile    \* The profile that should be used by all nodes

ASSUME CorrectProfile \in Profiles
ASSUME Cardinality(Nodes) >= 2

VARIABLES
    nodeProfile,        \* Function: Nodes -> Profiles (which profile each node chose)
    nodeAccounts,       \* Function: Nodes -> SUBSET Accounts (accounts initialized)
    nodeModelRegistered,\* Function: Nodes -> BOOLEAN (genesis model registered)
    nodeStateRoot,      \* Function: Nodes -> Nat (state root, 0 = not computed)
    nodeGenesisHash,    \* Function: Nodes -> Nat (block hash, 0 = not computed)
    nodeInitialized,    \* Function: Nodes -> BOOLEAN
    nodeCanPeer         \* Function: Nodes x Nodes -> BOOLEAN (can two nodes peer?)

vars == <<nodeProfile, nodeAccounts, nodeModelRegistered, nodeStateRoot, nodeGenesisHash, nodeInitialized, nodeCanPeer>>

\* ---- Derived state ----

\* Compute a deterministic state root from accounts and model registration
\* In the real code, state_root = executor.state_db().commit()
\* Here we model it as a function of the inputs
StateRootFor(accounts, modelRegistered) ==
    \* Hash-like function: different inputs → different outputs
    Cardinality(accounts) * 100 + (IF modelRegistered THEN 1 ELSE 0)

\* Compute genesis hash from state root
\* In the real code: calculate_block_hash(block) includes state_root
GenesisHashFor(stateRoot) ==
    stateRoot + 1000000  \* Injective: different state roots → different hashes

\* Accounts for a given profile
AccountsForProfile(profile) ==
    IF profile = CorrectProfile
    THEN Accounts  \* All accounts included
    ELSE IF Cardinality(Accounts) > 1
         THEN {CHOOSE a \in Accounts : TRUE}  \* Only one account (wrong profile)
         ELSE Accounts

\* ---- Type invariant ----

TypeOK ==
    /\ nodeProfile \in [Nodes -> Profiles]
    /\ nodeAccounts \in [Nodes -> SUBSET Accounts]
    /\ nodeModelRegistered \in [Nodes -> BOOLEAN]
    /\ nodeStateRoot \in [Nodes -> Nat]
    /\ nodeGenesisHash \in [Nodes -> Nat]
    /\ nodeInitialized \in [Nodes -> BOOLEAN]

\* ---- Initial state ----

Init ==
    /\ nodeProfile = [n \in Nodes |-> CorrectProfile]  \* Start with correct profile
    /\ nodeAccounts = [n \in Nodes |-> {}]
    /\ nodeModelRegistered = [n \in Nodes |-> FALSE]
    /\ nodeStateRoot = [n \in Nodes |-> 0]
    /\ nodeGenesisHash = [n \in Nodes |-> 0]
    /\ nodeInitialized = [n \in Nodes |-> FALSE]
    /\ nodeCanPeer = [n1 \in Nodes, n2 \in Nodes |-> FALSE]

\* ---- Actions ----

\* Node selects a genesis profile (could be correct or wrong)
SelectProfile(n, profile) ==
    /\ ~nodeInitialized[n]
    /\ nodeAccounts[n] = {}  \* Haven't started init yet
    /\ nodeProfile' = [nodeProfile EXCEPT ![n] = profile]
    /\ UNCHANGED <<nodeAccounts, nodeModelRegistered, nodeStateRoot, nodeGenesisHash, nodeInitialized, nodeCanPeer>>

\* Node initializes genesis accounts from its selected profile
InitializeAccounts(n) ==
    /\ ~nodeInitialized[n]
    /\ nodeAccounts[n] = {}  \* Not yet initialized
    /\ nodeAccounts' = [nodeAccounts EXCEPT ![n] = AccountsForProfile(nodeProfile[n])]
    /\ UNCHANGED <<nodeProfile, nodeModelRegistered, nodeStateRoot, nodeGenesisHash, nodeInitialized, nodeCanPeer>>

\* Node registers the genesis model in state DB
RegisterGenesisModel(n) ==
    /\ ~nodeInitialized[n]
    /\ nodeAccounts[n] # {}  \* Accounts must be initialized first
    /\ ~nodeModelRegistered[n]
    /\ nodeModelRegistered' = [nodeModelRegistered EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<nodeProfile, nodeAccounts, nodeStateRoot, nodeGenesisHash, nodeInitialized, nodeCanPeer>>

\* Node skips model registration (the bug: GUI didn't register the model)
SkipModelRegistration(n) ==
    /\ ~nodeInitialized[n]
    /\ nodeAccounts[n] # {}
    /\ ~nodeModelRegistered[n]
    \* Model stays unregistered — this produces a different state root
    /\ UNCHANGED <<nodeProfile, nodeAccounts, nodeModelRegistered, nodeStateRoot, nodeGenesisHash, nodeInitialized, nodeCanPeer>>

\* Node computes state root and genesis hash
ComputeGenesisHash(n) ==
    /\ ~nodeInitialized[n]
    /\ nodeAccounts[n] # {}  \* Must have accounts
    /\ nodeStateRoot[n] = 0  \* Not yet computed
    /\ LET sr == StateRootFor(nodeAccounts[n], nodeModelRegistered[n])
           gh == GenesisHashFor(sr)
       IN /\ nodeStateRoot' = [nodeStateRoot EXCEPT ![n] = sr]
          /\ nodeGenesisHash' = [nodeGenesisHash EXCEPT ![n] = gh]
          /\ nodeInitialized' = [nodeInitialized EXCEPT ![n] = TRUE]
    \* Update peering matrix
    /\ nodeCanPeer' = [n1 \in Nodes, n2 \in Nodes |->
        IF (n1 = n \/ n2 = n) /\ nodeInitialized'[n1] /\ nodeInitialized'[n2]
        THEN nodeGenesisHash'[n1] = nodeGenesisHash'[n2]
        ELSE nodeCanPeer[n1, n2]]
    /\ UNCHANGED <<nodeProfile, nodeAccounts, nodeModelRegistered>>

\* ---- Next state relation ----

Next ==
    \/ \E n \in Nodes, p \in Profiles : SelectProfile(n, p)
    \/ \E n \in Nodes : InitializeAccounts(n)
    \/ \E n \in Nodes : RegisterGenesisModel(n)
    \/ \E n \in Nodes : SkipModelRegistration(n)
    \/ \E n \in Nodes : ComputeGenesisHash(n)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

\* ---- Safety Invariants ----

\* 1. DETERMINISTIC GENESIS: All nodes using the same profile MUST produce the same genesis hash
\* This is THE invariant that caught the dual-chain bug
DeterministicGenesis ==
    \A n1, n2 \in Nodes :
        (nodeInitialized[n1] /\ nodeInitialized[n2] /\ nodeProfile[n1] = nodeProfile[n2])
        => nodeGenesisHash[n1] = nodeGenesisHash[n2]

\* 2. STATE ROOT CONSISTENCY: Same accounts + same model = same state root
StateRootConsistency ==
    \A n1, n2 \in Nodes :
        (nodeInitialized[n1] /\ nodeInitialized[n2]
         /\ nodeAccounts[n1] = nodeAccounts[n2]
         /\ nodeModelRegistered[n1] = nodeModelRegistered[n2])
        => nodeStateRoot[n1] = nodeStateRoot[n2]

\* 3. PROFILE BINDING: Genesis profile uniquely determines the account set
ProfileBinding ==
    \A n1, n2 \in Nodes :
        (nodeProfile[n1] = nodeProfile[n2] /\ nodeAccounts[n1] # {} /\ nodeAccounts[n2] # {})
        => nodeAccounts[n1] = nodeAccounts[n2]

\* 4. PEERING REQUIRES MATCHING GENESIS: Two nodes can peer only if genesis matches
PeeringRequiresMatchingGenesis ==
    \A n1, n2 \in Nodes :
        nodeCanPeer[n1, n2] => nodeGenesisHash[n1] = nodeGenesisHash[n2]

\* 5. MODEL REGISTRATION AFFECTS HASH: Registering vs skipping model produces different hashes
\* (This catches the GUI bug — skipping model registration = different state root)
ModelRegistrationMatters ==
    \A n1, n2 \in Nodes :
        (nodeInitialized[n1] /\ nodeInitialized[n2]
         /\ nodeAccounts[n1] = nodeAccounts[n2]
         /\ nodeModelRegistered[n1] # nodeModelRegistered[n2])
        => nodeGenesisHash[n1] # nodeGenesisHash[n2]

\* Combined safety
Safety ==
    /\ TypeOK
    /\ DeterministicGenesis
    /\ StateRootConsistency
    /\ ProfileBinding
    /\ PeeringRequiresMatchingGenesis
    /\ ModelRegistrationMatters

\* ---- Theorems ----

THEOREM Spec => []Safety

==============================================================================
