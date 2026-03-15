------------------------ MODULE SDKConnectionLifecycle ------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models SDK connection lifecycle: connect, disconnect, reconnect, failover,
\* and request management with retry bounds.
\* Source: sdk/javascript/src/ — CitrateProvider, RPC transport

CONSTANTS
    Endpoints,      \* Set of RPC endpoint identifiers (e.g., {primary, fallback})
    MaxRetries,     \* Maximum retry attempts before failover or failure
    MaxPending      \* Maximum number of concurrent pending requests

ASSUME Endpoints # {}
ASSUME MaxRetries \in Nat /\ MaxRetries >= 1
ASSUME MaxPending \in Nat /\ MaxPending >= 1

VARIABLES
    connState,          \* Current connection state: "disconnected" | "connecting" | "connected" | "reconnecting" | "failed"
    retryCount,         \* Number of retry attempts on the current endpoint
    pendingRequests,    \* Number of pending (in-flight) RPC requests
    activeEndpoint,     \* Currently targeted endpoint (or "none")
    failedEndpoints     \* Set of endpoints that have been exhausted

vars == <<connState, retryCount, pendingRequests, activeEndpoint, failedEndpoints>>

\* ---- Helper operators ----

States == {"disconnected", "connecting", "connected", "reconnecting", "failed"}

\* Endpoints that have not been exhausted
AvailableEndpoints ==
    Endpoints \ failedEndpoints

\* Fallback endpoints (available endpoints other than the active one)
FallbackEndpoints ==
    AvailableEndpoints \ {activeEndpoint}

\* ---- State machine ----

Init ==
    /\ connState = "disconnected"
    /\ retryCount = 0
    /\ pendingRequests = 0
    /\ activeEndpoint = "none"
    /\ failedEndpoints = {}

\* Connect(ep) — attempt connection to an endpoint from disconnected state
Connect(ep) ==
    /\ connState = "disconnected"
    /\ ep \in AvailableEndpoints
    /\ connState' = "connecting"
    /\ activeEndpoint' = ep
    /\ retryCount' = 0
    /\ UNCHANGED <<pendingRequests, failedEndpoints>>

\* ConnectSuccess — transition to connected
ConnectSuccess ==
    /\ connState \in {"connecting", "reconnecting"}
    /\ connState' = "connected"
    /\ retryCount' = 0
    /\ UNCHANGED <<pendingRequests, activeEndpoint, failedEndpoints>>

\* ConnectFail — increment retry, potentially mark endpoint for failover
ConnectFail ==
    /\ connState \in {"connecting", "reconnecting"}
    /\ retryCount < MaxRetries
    /\ retryCount' = retryCount + 1
    /\ UNCHANGED <<connState, pendingRequests, activeEndpoint, failedEndpoints>>

\* Disconnect — clean disconnect, drain pending requests
Disconnect ==
    /\ connState = "connected"
    /\ connState' = "disconnected"
    /\ pendingRequests' = 0
    /\ activeEndpoint' = "none"
    /\ retryCount' = 0
    /\ UNCHANGED <<failedEndpoints>>

\* SendRequest — add a pending request (only when connected)
SendRequest ==
    /\ connState = "connected"
    /\ pendingRequests < MaxPending
    /\ pendingRequests' = pendingRequests + 1
    /\ UNCHANGED <<connState, retryCount, activeEndpoint, failedEndpoints>>

\* ReceiveResponse — remove a pending request
ReceiveResponse ==
    /\ connState = "connected"
    /\ pendingRequests > 0
    /\ pendingRequests' = pendingRequests - 1
    /\ UNCHANGED <<connState, retryCount, activeEndpoint, failedEndpoints>>

\* Timeout — trigger reconnection from connected state
Timeout ==
    /\ connState = "connected"
    /\ connState' = "reconnecting"
    /\ pendingRequests' = 0
    /\ retryCount' = 0
    /\ UNCHANGED <<activeEndpoint, failedEndpoints>>

\* Retry — retry connection after a failure (retryCount already incremented by ConnectFail)
Retry ==
    /\ connState \in {"connecting", "reconnecting"}
    /\ retryCount > 0
    /\ retryCount <= MaxRetries
    \* Stay in the same connecting/reconnecting state, awaiting ConnectSuccess or ConnectFail
    /\ UNCHANGED vars

\* Failover — switch to a fallback endpoint when retries are exhausted
Failover ==
    /\ connState \in {"connecting", "reconnecting"}
    /\ retryCount = MaxRetries
    /\ FallbackEndpoints # {}
    /\ \E ep \in FallbackEndpoints :
        /\ activeEndpoint' = ep
        /\ failedEndpoints' = failedEndpoints \cup {activeEndpoint}
        /\ retryCount' = 0
        /\ connState' = "connecting"
        /\ UNCHANGED <<pendingRequests>>

\* ExhaustAllEndpoints — all endpoints exhausted, transition to failed
ExhaustAllEndpoints ==
    /\ connState \in {"connecting", "reconnecting"}
    /\ retryCount = MaxRetries
    /\ FallbackEndpoints = {}
    /\ connState' = "failed"
    /\ failedEndpoints' = failedEndpoints \cup {activeEndpoint}
    /\ pendingRequests' = 0
    /\ UNCHANGED <<retryCount, activeEndpoint>>

Next ==
    \/ \E ep \in Endpoints : Connect(ep)
    \/ ConnectSuccess
    \/ ConnectFail
    \/ Disconnect
    \/ SendRequest
    \/ ReceiveResponse
    \/ Timeout
    \/ Retry
    \/ Failover
    \/ ExhaustAllEndpoints

\* ---- Invariants ----

\* INV-1: TypeInv — well-formed state
TypeInv ==
    /\ connState \in States
    /\ retryCount \in 0..MaxRetries
    /\ pendingRequests \in 0..MaxPending
    /\ (activeEndpoint \in Endpoints \/ activeEndpoint = "none")
    /\ failedEndpoints \subseteq Endpoints

\* INV-2: NoRPCWhenDisconnected — no pending requests when not connected
NoRPCWhenDisconnected ==
    connState \in {"disconnected", "failed"} => pendingRequests = 0

\* INV-3: RetryBounded — retry count never exceeds maximum
RetryBounded ==
    retryCount <= MaxRetries

\* INV-4: PendingBounded — pending requests never exceed maximum
PendingBounded ==
    pendingRequests <= MaxPending

\* INV-5: FailoverOnExhaustion — when retries exhausted on an endpoint with
\*        fallbacks available, the system must not stay stuck (enabled actions
\*        guarantee progress via Failover or ExhaustAllEndpoints)
FailoverOnExhaustion ==
    (connState \in {"connecting", "reconnecting"} /\ retryCount = MaxRetries)
        => (activeEndpoint \in Endpoints /\ activeEndpoint \notin failedEndpoints)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeInv
THEOREM NoRPCDisconnected == Spec => []NoRPCWhenDisconnected
THEOREM RetryBound == Spec => []RetryBounded
THEOREM PendingBound == Spec => []PendingBounded
THEOREM FailoverGuarantee == Spec => []FailoverOnExhaustion

=============================================================================
