------------------------------ MODULE PeerManagementStateMachine ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the peer lifecycle: connection, scoring, banning, eviction,
\* and reconnection policies.
\*
\* Source: core/network/src/peer.rs (PeerManager, PeerState, PeerInfo)

CONSTANTS
    Peers,            \* Set of possible peer IDs
    MaxPeers,         \* Maximum active peers allowed
    BanThreshold,     \* Score below which peer is banned (e.g., -100)
    BanDuration       \* Blocks before a banned peer can reconnect

ASSUME MaxPeers \in Nat /\ MaxPeers >= 1
ASSUME BanThreshold \in Int
ASSUME BanDuration \in Nat

\* Peer states (from peer.rs PeerState enum)
States == {"Disconnected", "Connecting", "Handshaking", "Connected", "Disconnecting", "Banned"}

VARIABLES
    state,          \* Function: Peers -> States
    score,          \* Function: Peers -> Int (reputation score)
    banExpiry,      \* Function: Peers -> Nat (block at which ban expires, 0 = not banned)
    currentBlock,   \* Current block height (for ban duration tracking)
    activePeers     \* Set of currently connected peers

vars == <<state, score, banExpiry, currentBlock, activePeers>>

TypeOK ==
    /\ state \in [Peers -> States]
    /\ score \in [Peers -> Int]
    /\ banExpiry \in [Peers -> Nat]
    /\ currentBlock \in Nat
    /\ activePeers \subseteq Peers

Init ==
    /\ state = [p \in Peers |-> "Disconnected"]
    /\ score = [p \in Peers |-> 0]
    /\ banExpiry = [p \in Peers |-> 0]
    /\ currentBlock = 0
    /\ activePeers = {}

\* Peer initiates connection
Connect(p) ==
    /\ state[p] = "Disconnected"
    /\ banExpiry[p] <= currentBlock  \* Ban expired
    /\ Cardinality(activePeers) < MaxPeers  \* Room for more peers
    /\ state' = [state EXCEPT ![p] = "Connecting"]
    /\ UNCHANGED <<score, banExpiry, currentBlock, activePeers>>

\* Connection established, start handshake
StartHandshake(p) ==
    /\ state[p] = "Connecting"
    /\ state' = [state EXCEPT ![p] = "Handshaking"]
    /\ UNCHANGED <<score, banExpiry, currentBlock, activePeers>>

\* Handshake succeeds
CompleteHandshake(p) ==
    /\ state[p] = "Handshaking"
    /\ Cardinality(activePeers) < MaxPeers
    /\ state' = [state EXCEPT ![p] = "Connected"]
    /\ activePeers' = activePeers \cup {p}
    /\ UNCHANGED <<score, banExpiry, currentBlock>>

\* Peer sends good data (score increases)
GoodBehavior(p) ==
    /\ state[p] = "Connected"
    /\ score' = [score EXCEPT ![p] = @ + 1]
    /\ UNCHANGED <<state, banExpiry, currentBlock, activePeers>>

\* Peer sends bad data (score decreases)
BadBehavior(p) ==
    /\ state[p] = "Connected"
    /\ score' = [score EXCEPT ![p] = @ - 10]
    \* If score drops below threshold, ban the peer
    /\ IF score[p] - 10 < BanThreshold
       THEN /\ state' = [state EXCEPT ![p] = "Banned"]
            /\ banExpiry' = [banExpiry EXCEPT ![p] = currentBlock + BanDuration]
            /\ activePeers' = activePeers \ {p}
       ELSE /\ UNCHANGED <<state, banExpiry, activePeers>>
    /\ UNCHANGED currentBlock

\* Graceful disconnect
Disconnect(p) ==
    /\ state[p] = "Connected"
    /\ state' = [state EXCEPT ![p] = "Disconnecting"]
    /\ activePeers' = activePeers \ {p}
    /\ UNCHANGED <<score, banExpiry, currentBlock>>

\* Complete disconnect
CompleteDisconnect(p) ==
    /\ state[p] = "Disconnecting"
    /\ state' = [state EXCEPT ![p] = "Disconnected"]
    /\ UNCHANGED <<score, banExpiry, currentBlock, activePeers>>

\* Ban expires, peer becomes disconnected (can reconnect)
BanExpires(p) ==
    /\ state[p] = "Banned"
    /\ currentBlock >= banExpiry[p]
    /\ state' = [state EXCEPT ![p] = "Disconnected"]
    /\ score' = [score EXCEPT ![p] = 0]  \* Reset score
    /\ UNCHANGED <<banExpiry, currentBlock, activePeers>>

\* Evict lowest-scoring peer when at capacity
EvictPeer ==
    /\ Cardinality(activePeers) >= MaxPeers
    /\ \E p \in activePeers :
        \* Evict the peer with the lowest score
        /\ \A p2 \in activePeers : score[p] <= score[p2]
        /\ state' = [state EXCEPT ![p] = "Disconnecting"]
        /\ activePeers' = activePeers \ {p}
    /\ UNCHANGED <<score, banExpiry, currentBlock>>

\* Block advances
AdvanceBlock ==
    /\ currentBlock' = currentBlock + 1
    /\ UNCHANGED <<state, score, banExpiry, activePeers>>

\* Timeout during handshake
HandshakeTimeout(p) ==
    /\ state[p] \in {"Connecting", "Handshaking"}
    /\ state' = [state EXCEPT ![p] = "Disconnected"]
    /\ UNCHANGED <<score, banExpiry, currentBlock, activePeers>>

Next ==
    \/ \E p \in Peers : Connect(p)
    \/ \E p \in Peers : StartHandshake(p)
    \/ \E p \in Peers : CompleteHandshake(p)
    \/ \E p \in Peers : GoodBehavior(p)
    \/ \E p \in Peers : BadBehavior(p)
    \/ \E p \in Peers : Disconnect(p)
    \/ \E p \in Peers : CompleteDisconnect(p)
    \/ \E p \in Peers : BanExpires(p)
    \/ \E p \in Peers : HandshakeTimeout(p)
    \/ EvictPeer
    \/ AdvanceBlock

Spec == Init /\ [][Next]_vars

\* ---- Safety Invariants ----

\* 1. Valid state transitions only
ValidTransitions ==
    \A p \in Peers :
        state[p] = "Connected" => p \in activePeers

\* 2. Active peers never exceed max
MaxPeersEnforced ==
    Cardinality(activePeers) <= MaxPeers

\* 3. Banned peers cannot be in Connected state
BanEnforcement ==
    \A p \in Peers : state[p] = "Banned" => p \notin activePeers

\* 4. Active peer set consistent with state
ActivePeerConsistency ==
    activePeers = {p \in Peers : state[p] = "Connected"}

Safety ==
    /\ TypeOK
    /\ ValidTransitions
    /\ MaxPeersEnforced
    /\ BanEnforcement
    /\ ActivePeerConsistency

THEOREM Spec => []Safety

==============================================================================
