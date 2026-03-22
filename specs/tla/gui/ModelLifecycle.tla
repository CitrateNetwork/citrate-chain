------------------------ MODULE ModelLifecycle ------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the lifecycle of an AI model from initial download through
\* IPFS upload to on-chain registration.
\* Source: gui/citrate_gui_v2/src/features/models/, core/mcp/
\*
\* States:
\*   not_downloaded    — model is known but not present locally
\*   downloading       — download in progress
\*   local_ready       — model file is available on local disk
\*   ipfs_uploading    — upload to IPFS in progress
\*   ipfs_available    — model is pinned on IPFS with a valid CID
\*   registering       — on-chain registration transaction in progress
\*   on_chain          — model is registered in the ModelRegistry contract

CONSTANTS
    MaxRetries      \* Maximum retry attempts for any failable transition

ASSUME MaxRetries \in Nat /\ MaxRetries >= 0

VARIABLES
    state,          \* Current lifecycle state
    retries,        \* Retry counter for the current operation
    hasLocalFile,   \* Whether the local file exists on disk
    hasCID,         \* Whether a valid IPFS CID has been obtained
    isRegistered    \* Whether on-chain registration is complete

vars == <<state, retries, hasLocalFile, hasCID, isRegistered>>

\* ---- State definitions ----

States == {
    "not_downloaded",
    "downloading",
    "local_ready",
    "ipfs_uploading",
    "ipfs_available",
    "registering",
    "on_chain"
}

\* ---- State machine ----

Init ==
    /\ state = "not_downloaded"
    /\ retries = 0
    /\ hasLocalFile = FALSE
    /\ hasCID = FALSE
    /\ isRegistered = FALSE

\* not_downloaded -> downloading
StartDownload ==
    /\ state = "not_downloaded"
    /\ state' = "downloading"
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID, isRegistered>>

\* downloading -> local_ready (success)
DownloadSuccess ==
    /\ state = "downloading"
    /\ state' = "local_ready"
    /\ hasLocalFile' = TRUE
    /\ retries' = 0
    /\ UNCHANGED <<hasCID, isRegistered>>

\* downloading -> downloading (retry on failure)
DownloadFail ==
    /\ state = "downloading"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<state, hasLocalFile, hasCID, isRegistered>>

\* downloading -> not_downloaded (give up after max retries)
DownloadGiveUp ==
    /\ state = "downloading"
    /\ retries = MaxRetries
    /\ state' = "not_downloaded"
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID, isRegistered>>

\* local_ready -> ipfs_uploading
StartUpload ==
    /\ state = "local_ready"
    /\ hasLocalFile = TRUE
    /\ state' = "ipfs_uploading"
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID, isRegistered>>

\* ipfs_uploading -> ipfs_available (success)
UploadSuccess ==
    /\ state = "ipfs_uploading"
    /\ state' = "ipfs_available"
    /\ hasCID' = TRUE
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, isRegistered>>

\* ipfs_uploading -> ipfs_uploading (retry on failure)
UploadFail ==
    /\ state = "ipfs_uploading"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<state, hasLocalFile, hasCID, isRegistered>>

\* ipfs_uploading -> local_ready (give up, revert to local)
UploadGiveUp ==
    /\ state = "ipfs_uploading"
    /\ retries = MaxRetries
    /\ state' = "local_ready"
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID, isRegistered>>

\* ipfs_available -> registering
StartRegistration ==
    /\ state = "ipfs_available"
    /\ hasCID = TRUE
    /\ state' = "registering"
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID, isRegistered>>

\* registering -> on_chain (success)
RegistrationSuccess ==
    /\ state = "registering"
    /\ state' = "on_chain"
    /\ isRegistered' = TRUE
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID>>

\* registering -> registering (retry on failure)
RegistrationFail ==
    /\ state = "registering"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<state, hasLocalFile, hasCID, isRegistered>>

\* registering -> ipfs_available (give up, revert to ipfs_available)
RegistrationGiveUp ==
    /\ state = "registering"
    /\ retries = MaxRetries
    /\ state' = "ipfs_available"
    /\ retries' = 0
    /\ UNCHANGED <<hasLocalFile, hasCID, isRegistered>>

\* local_ready -> not_downloaded (user deletes local file)
DeleteLocalFile ==
    /\ state = "local_ready"
    /\ state' = "not_downloaded"
    /\ hasLocalFile' = FALSE
    /\ retries' = 0
    /\ UNCHANGED <<hasCID, isRegistered>>

\* Terminal state: on_chain is absorbing
OnChain ==
    /\ state = "on_chain"
    /\ UNCHANGED vars

Next ==
    \/ StartDownload
    \/ DownloadSuccess
    \/ DownloadFail
    \/ DownloadGiveUp
    \/ StartUpload
    \/ UploadSuccess
    \/ UploadFail
    \/ UploadGiveUp
    \/ StartRegistration
    \/ RegistrationSuccess
    \/ RegistrationFail
    \/ RegistrationGiveUp
    \/ DeleteLocalFile
    \/ OnChain

\* ---- Invariants ----

\* INV-1: TypeOK — all variables in valid domains
TypeOK ==
    /\ state \in States
    /\ retries \in 0..MaxRetries
    /\ hasLocalFile \in BOOLEAN
    /\ hasCID \in BOOLEAN
    /\ isRegistered \in BOOLEAN

\* INV-2: NoOrphanedState — cannot be on_chain without having
\*         obtained an IPFS CID (hasCID must be TRUE)
NoOrphanedState ==
    state = "on_chain" => hasCID = TRUE

\* INV-3: DownloadBeforeUse — must have local file before any
\*         upload can begin or complete
DownloadBeforeUse ==
    state \in {"ipfs_uploading", "ipfs_available", "registering", "on_chain"}
        => hasLocalFile = TRUE

\* INV-4: CIDBeforeRegistration — must have CID before registering
CIDBeforeRegistration ==
    state \in {"registering", "on_chain"} => hasCID = TRUE

\* INV-5: RegistrationImpliesOnChain — isRegistered flag only TRUE
\*         when state is on_chain
RegistrationImpliesOnChain ==
    isRegistered = TRUE => state = "on_chain"

\* INV-6: RetryBounded — retry count never exceeds maximum
RetryBounded ==
    retries <= MaxRetries

\* INV-7: LocalFileConsistency — if state requires local file, flag is set
LocalFileConsistency ==
    state = "local_ready" => hasLocalFile = TRUE

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM NoOrphaned == Spec => []NoOrphanedState
THEOREM DownloadFirst == Spec => []DownloadBeforeUse
THEOREM CIDFirst == Spec => []CIDBeforeRegistration
THEOREM RegImpliesOnChain == Spec => []RegistrationImpliesOnChain
THEOREM RetryBound == Spec => []RetryBounded
THEOREM LocalConsistency == Spec => []LocalFileConsistency

=============================================================================
