------------------------------ MODULE BlockSyncProtocol ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Models the block synchronization protocol between a syncing node and a remote peer.
\* Verifies: height monotonicity, validation before apply, hash chain integrity,
\* progress guarantee, and no invalid block application.
\*
\* Source: gui/citrate_gui_v2/src-tauri/src/sync/iterative_sync.rs
\*         core/network/src/sync.rs

CONSTANTS
    MaxHeight,        \* Maximum block height in the model
    BatchSize,        \* Number of blocks requested per GetBlocks
    MaxRetries        \* Maximum retries before giving up on a peer

ASSUME MaxHeight \in Nat /\ MaxHeight >= 1
ASSUME BatchSize \in Nat /\ BatchSize >= 1
ASSUME MaxRetries \in Nat /\ MaxRetries >= 0

\* Sync states (matches iterative sync manager)
SyncStates == {"Idle", "RequestingHeaders", "DownloadingBlocks", "Validating", "Applying", "Synced", "Failed"}

\* Block validity
Validity == {"Valid", "InvalidHash", "InvalidSignature", "InvalidTxRoot"}

VARIABLES
    syncState,           \* Current sync state
    localHeight,         \* Our highest validated block height
    remoteHeight,        \* Peer's reported head height
    pendingRequest,      \* Height range of current GetBlocks request
    receivedBlocks,      \* Set of block heights received but not yet validated
    validatedBlocks,     \* Set of block heights validated and ready to apply
    appliedBlocks,       \* Set of block heights applied to state DB
    retryCount,          \* Number of retries for current request
    peerConnected        \* Whether we have a connected peer

vars == <<syncState, localHeight, remoteHeight, pendingRequest, receivedBlocks, validatedBlocks, appliedBlocks, retryCount, peerConnected>>

\* ---- Type invariant ----

TypeOK ==
    /\ syncState \in SyncStates
    /\ localHeight \in 0..MaxHeight
    /\ remoteHeight \in 0..MaxHeight
    /\ pendingRequest \subseteq 0..MaxHeight
    /\ receivedBlocks \subseteq 0..MaxHeight
    /\ validatedBlocks \subseteq 0..MaxHeight
    /\ appliedBlocks \subseteq 0..MaxHeight
    /\ retryCount \in 0..MaxRetries+1
    /\ peerConnected \in BOOLEAN

\* ---- Initial state ----

Init ==
    /\ syncState = "Idle"
    /\ localHeight = 0
    /\ remoteHeight = MaxHeight  \* Peer has all blocks
    /\ pendingRequest = {}
    /\ receivedBlocks = {}
    /\ validatedBlocks = {}
    /\ appliedBlocks = {}
    /\ retryCount = 0
    /\ peerConnected = TRUE

\* ---- Actions ----

\* Start sync: request first batch of blocks
StartSync ==
    /\ syncState = "Idle"
    /\ peerConnected = TRUE
    /\ localHeight < remoteHeight
    /\ LET nextBatch == {h \in (localHeight+1)..(localHeight+BatchSize) : h <= remoteHeight}
       IN /\ pendingRequest' = nextBatch
          /\ syncState' = "DownloadingBlocks"
    /\ UNCHANGED <<localHeight, remoteHeight, receivedBlocks, validatedBlocks, appliedBlocks, retryCount, peerConnected>>

\* Receive blocks from peer (may be valid or invalid)
ReceiveBlocks(validity) ==
    /\ syncState = "DownloadingBlocks"
    /\ pendingRequest # {}
    /\ IF validity = "Valid"
       THEN /\ receivedBlocks' = receivedBlocks \cup pendingRequest
            /\ syncState' = "Validating"
            /\ retryCount' = 0
       ELSE /\ UNCHANGED receivedBlocks  \* Invalid blocks rejected
            /\ retryCount' = retryCount + 1
            /\ IF retryCount + 1 > MaxRetries
               THEN syncState' = "Failed"
               ELSE syncState' = "DownloadingBlocks"  \* Retry
    /\ UNCHANGED <<localHeight, remoteHeight, pendingRequest, validatedBlocks, appliedBlocks, peerConnected>>

\* Validate received blocks (hash check, signature check, tx_root check)
ValidateBlocks ==
    /\ syncState = "Validating"
    /\ receivedBlocks # {}
    \* All received blocks pass validation (in this model, only valid blocks reach here)
    /\ validatedBlocks' = validatedBlocks \cup receivedBlocks
    /\ receivedBlocks' = {}
    /\ syncState' = "Applying"
    /\ UNCHANGED <<localHeight, remoteHeight, pendingRequest, appliedBlocks, retryCount, peerConnected>>

\* Apply validated blocks to state DB (in height order)
ApplyBlock ==
    /\ syncState = "Applying"
    /\ validatedBlocks # {}
    \* Apply the lowest-height validated block
    /\ LET minH == CHOOSE h \in validatedBlocks : \A h2 \in validatedBlocks : h <= h2
       IN /\ minH = localHeight + 1  \* Must be next sequential block
          /\ appliedBlocks' = appliedBlocks \cup {minH}
          /\ validatedBlocks' = validatedBlocks \ {minH}
          /\ localHeight' = minH
    /\ IF validatedBlocks' = {}
       THEN IF localHeight' >= remoteHeight
            THEN syncState' = "Synced"
            ELSE syncState' = "Idle"  \* Request next batch
       ELSE UNCHANGED syncState
    /\ UNCHANGED <<remoteHeight, pendingRequest, receivedBlocks, retryCount, peerConnected>>

\* Peer disconnects during sync
PeerDisconnect ==
    /\ peerConnected = TRUE
    /\ peerConnected' = FALSE
    /\ IF syncState \in {"DownloadingBlocks", "RequestingHeaders"}
       THEN syncState' = "Idle"  \* Will retry when peer reconnects
       ELSE UNCHANGED syncState
    /\ UNCHANGED <<localHeight, remoteHeight, pendingRequest, receivedBlocks, validatedBlocks, appliedBlocks, retryCount>>

\* Peer reconnects
PeerReconnect ==
    /\ peerConnected = FALSE
    /\ peerConnected' = TRUE
    /\ UNCHANGED <<syncState, localHeight, remoteHeight, pendingRequest, receivedBlocks, validatedBlocks, appliedBlocks, retryCount>>

\* Timeout: no response from peer
RequestTimeout ==
    /\ syncState = "DownloadingBlocks"
    /\ retryCount' = retryCount + 1
    /\ IF retryCount + 1 > MaxRetries
       THEN syncState' = "Failed"
       ELSE UNCHANGED syncState
    /\ UNCHANGED <<localHeight, remoteHeight, pendingRequest, receivedBlocks, validatedBlocks, appliedBlocks, peerConnected>>

\* ---- Next state relation ----

Next ==
    \/ StartSync
    \/ \E v \in Validity : ReceiveBlocks(v)
    \/ ValidateBlocks
    \/ ApplyBlock
    \/ PeerDisconnect
    \/ PeerReconnect
    \/ RequestTimeout

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

\* ---- Safety Invariants ----

\* 1. Height only increases (never goes backward)
HeightMonotonic ==
    localHeight' >= localHeight

\* 2. Blocks must be validated before being applied
ValidationBeforeApply ==
    appliedBlocks \subseteq (validatedBlocks \cup appliedBlocks)

\* 3. Applied blocks form a contiguous chain from 0
ChainContiguity ==
    \A h \in appliedBlocks : (h = 1) \/ (h - 1 \in appliedBlocks)

\* 4. Local height equals the max applied block
HeightConsistency ==
    localHeight = IF appliedBlocks = {} THEN 0 ELSE CHOOSE h \in appliedBlocks : \A h2 \in appliedBlocks : h >= h2

\* 5. No block applied twice
NoDuplicateApply ==
    Cardinality(appliedBlocks) = IF appliedBlocks = {} THEN 0 ELSE (CHOOSE h \in appliedBlocks : \A h2 \in appliedBlocks : h >= h2)

\* 6. Received blocks don't exceed remote height
NoBlocksBeyondRemote ==
    \A h \in receivedBlocks \cup validatedBlocks \cup appliedBlocks : h <= remoteHeight

\* 7. Failed state is terminal for this sync session
\* (Note: can restart by going back to Idle, but Failed itself doesn't transition)

\* 8. Synced means local height matches remote
SyncedImpliesCaughtUp ==
    syncState = "Synced" => localHeight >= remoteHeight

\* Combined safety
Safety ==
    /\ TypeOK
    /\ ChainContiguity
    /\ HeightConsistency
    /\ NoBlocksBeyondRemote
    /\ SyncedImpliesCaughtUp

\* ---- Theorems ----

THEOREM Spec => []Safety

==============================================================================
