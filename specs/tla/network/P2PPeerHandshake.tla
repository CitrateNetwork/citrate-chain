------------------------------ MODULE P2PPeerHandshake ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the P2P peer handshake protocol between Citrate nodes.
\* Verifies: version compatibility, genesis hash binding, network ID matching,
\* no data before handshake, and peer uniqueness.
\*
\* Source: core/network/src/peer.rs (perform_handshake_inbound, perform_handshake_outbound)
\*
\* CRITICAL FINDING: The current code receives genesis_hash in Hello but IGNORES it
\* (parameter named _genesis_hash with underscore). This spec requires verification
\* and will show violations if genesis_hash checking is omitted.

CONSTANTS
    Peers,          \* Set of all possible peer IDs
    Versions,       \* Set of protocol versions (integers representing major version)
    NetworkIds,     \* Set of network IDs (e.g., {40204, 1337})
    GenesisHashes,  \* Set of possible genesis hashes
    LocalPeer,      \* This node's peer ID
    LocalVersion,   \* This node's protocol version
    LocalNetworkId, \* This node's network ID
    LocalGenesis    \* This node's genesis hash

ASSUME LocalPeer \in Peers
ASSUME LocalVersion \in Versions
ASSUME LocalNetworkId \in NetworkIds
ASSUME LocalGenesis \in GenesisHashes

\* Peer connection states (matches PeerState enum in peer.rs)
PeerStates == {"Disconnected", "Connecting", "HelloSent", "HelloReceived", "Connected", "Disconnecting"}

\* Direction
Directions == {"Inbound", "Outbound"}

VARIABLES
    peerState,        \* Function: Peers -> PeerStates
    peerVersion,      \* Function: Peers -> Versions (learned during handshake)
    peerNetworkId,    \* Function: Peers -> NetworkIds (learned during handshake)
    peerGenesis,      \* Function: Peers -> GenesisHashes (learned during handshake)
    peerDirection,    \* Function: Peers -> Directions \cup {"None"}
    activePeers,      \* Set of peers in Connected state
    dataExchanged,    \* Function: Peers -> BOOLEAN (has data been sent/received?)
    messageLog        \* Sequence of events for debugging

vars == <<peerState, peerVersion, peerNetworkId, peerGenesis, peerDirection, activePeers, dataExchanged, messageLog>>

\* ---- Type invariant ----

TypeOK ==
    /\ peerState \in [Peers -> PeerStates]
    /\ peerVersion \in [Peers -> Versions \cup {0}]
    /\ peerNetworkId \in [Peers -> NetworkIds \cup {0}]
    /\ peerGenesis \in [Peers -> GenesisHashes \cup {"none"}]
    /\ peerDirection \in [Peers -> Directions \cup {"None"}]
    /\ activePeers \subseteq Peers
    /\ dataExchanged \in [Peers -> BOOLEAN]

\* ---- Initial state ----

Init ==
    /\ peerState = [p \in Peers |-> "Disconnected"]
    /\ peerVersion = [p \in Peers |-> 0]
    /\ peerNetworkId = [p \in Peers |-> 0]
    /\ peerGenesis = [p \in Peers |-> "none"]
    /\ peerDirection = [p \in Peers |-> "None"]
    /\ activePeers = {}
    /\ dataExchanged = [p \in Peers |-> FALSE]
    /\ messageLog = <<>>

\* ---- Actions ----

\* Outbound: We initiate connection and send Hello
InitiateOutbound(p) ==
    /\ p # LocalPeer
    /\ peerState[p] = "Disconnected"
    /\ peerState' = [peerState EXCEPT ![p] = "HelloSent"]
    /\ peerDirection' = [peerDirection EXCEPT ![p] = "Outbound"]
    /\ UNCHANGED <<peerVersion, peerNetworkId, peerGenesis, activePeers, dataExchanged, messageLog>>

\* Inbound: Remote peer connects and sends Hello to us
ReceiveInboundHello(p, remoteVersion, remoteNetId, remoteGenesis) ==
    /\ p # LocalPeer
    /\ peerState[p] = "Disconnected"
    /\ peerState' = [peerState EXCEPT ![p] = "HelloReceived"]
    /\ peerVersion' = [peerVersion EXCEPT ![p] = remoteVersion]
    /\ peerNetworkId' = [peerNetworkId EXCEPT ![p] = remoteNetId]
    /\ peerGenesis' = [peerGenesis EXCEPT ![p] = remoteGenesis]
    /\ peerDirection' = [peerDirection EXCEPT ![p] = "Inbound"]
    /\ UNCHANGED <<activePeers, dataExchanged, messageLog>>

\* Receive HelloAck for our outbound connection
ReceiveHelloAck(p, remoteVersion, remoteNetId, remoteGenesis) ==
    /\ peerState[p] = "HelloSent"
    /\ peerDirection[p] = "Outbound"
    /\ peerVersion' = [peerVersion EXCEPT ![p] = remoteVersion]
    /\ peerNetworkId' = [peerNetworkId EXCEPT ![p] = remoteNetId]
    /\ peerGenesis' = [peerGenesis EXCEPT ![p] = remoteGenesis]
    \* Check compatibility — only connect if version, network, and genesis match
    /\ IF remoteVersion = LocalVersion /\ remoteNetId = LocalNetworkId /\ remoteGenesis = LocalGenesis
       THEN /\ peerState' = [peerState EXCEPT ![p] = "Connected"]
            /\ activePeers' = activePeers \cup {p}
       ELSE /\ peerState' = [peerState EXCEPT ![p] = "Disconnecting"]
            /\ UNCHANGED activePeers
    /\ UNCHANGED <<peerDirection, dataExchanged, messageLog>>

\* Complete inbound handshake: we verify and send HelloAck
CompleteInboundHandshake(p) ==
    /\ peerState[p] = "HelloReceived"
    /\ peerDirection[p] = "Inbound"
    \* Check compatibility — version, network ID, AND genesis hash
    /\ IF peerVersion[p] = LocalVersion /\ peerNetworkId[p] = LocalNetworkId /\ peerGenesis[p] = LocalGenesis
       THEN /\ peerState' = [peerState EXCEPT ![p] = "Connected"]
            /\ activePeers' = activePeers \cup {p}
       ELSE /\ peerState' = [peerState EXCEPT ![p] = "Disconnecting"]
            /\ UNCHANGED activePeers
    /\ UNCHANGED <<peerVersion, peerNetworkId, peerGenesis, peerDirection, dataExchanged, messageLog>>

\* Send or receive data (blocks, transactions, etc.)
ExchangeData(p) ==
    /\ peerState[p] = "Connected"
    /\ dataExchanged' = [dataExchanged EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<peerState, peerVersion, peerNetworkId, peerGenesis, peerDirection, activePeers, messageLog>>

\* Disconnect (can happen from any non-Disconnected state)
DisconnectPeer(p) ==
    /\ peerState[p] # "Disconnected"
    /\ peerState' = [peerState EXCEPT ![p] = "Disconnected"]
    /\ activePeers' = activePeers \ {p}
    /\ peerVersion' = [peerVersion EXCEPT ![p] = 0]
    /\ peerNetworkId' = [peerNetworkId EXCEPT ![p] = 0]
    /\ peerGenesis' = [peerGenesis EXCEPT ![p] = "none"]
    /\ peerDirection' = [peerDirection EXCEPT ![p] = "None"]
    /\ dataExchanged' = [dataExchanged EXCEPT ![p] = FALSE]
    /\ UNCHANGED messageLog

\* Timeout during handshake
HandshakeTimeout(p) ==
    /\ peerState[p] \in {"Connecting", "HelloSent", "HelloReceived"}
    /\ peerState' = [peerState EXCEPT ![p] = "Disconnected"]
    /\ peerVersion' = [peerVersion EXCEPT ![p] = 0]
    /\ peerNetworkId' = [peerNetworkId EXCEPT ![p] = 0]
    /\ peerGenesis' = [peerGenesis EXCEPT ![p] = "none"]
    /\ peerDirection' = [peerDirection EXCEPT ![p] = "None"]
    /\ UNCHANGED <<activePeers, dataExchanged, messageLog>>

\* ---- Next state relation ----

Next ==
    \/ \E p \in Peers : InitiateOutbound(p)
    \/ \E p \in Peers, v \in Versions, n \in NetworkIds, g \in GenesisHashes :
        ReceiveInboundHello(p, v, n, g)
    \/ \E p \in Peers, v \in Versions, n \in NetworkIds, g \in GenesisHashes :
        ReceiveHelloAck(p, v, n, g)
    \/ \E p \in Peers : CompleteInboundHandshake(p)
    \/ \E p \in Peers : ExchangeData(p)
    \/ \E p \in Peers : DisconnectPeer(p)
    \/ \E p \in Peers : HandshakeTimeout(p)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

\* ---- Safety Invariants ----

\* 1. Connected peers MUST have compatible protocol version
VersionCompatibility ==
    \A p \in activePeers : peerVersion[p] = LocalVersion

\* 2. Connected peers MUST have matching genesis hash
\* THIS IS THE INVARIANT THE CURRENT CODE VIOLATES (genesis_hash is ignored)
GenesisBinding ==
    \A p \in activePeers : peerGenesis[p] = LocalGenesis

\* 3. Connected peers MUST have matching network ID
NetworkIdMatch ==
    \A p \in activePeers : peerNetworkId[p] = LocalNetworkId

\* 4. No data exchange before handshake is complete
\* A peer can only have dataExchanged = TRUE if it's in Connected state
HandshakeBeforeData ==
    \A p \in Peers : dataExchanged[p] = TRUE => peerState[p] = "Connected"

\* 5. No duplicate peers in active set
\* (activePeers is a set, so this is structural — but verify consistency with peerState)
ActivePeerConsistency ==
    \A p \in Peers : (p \in activePeers) <=> (peerState[p] = "Connected")

\* 6. LocalPeer never appears as a remote peer
NoSelfConnection ==
    LocalPeer \notin activePeers

\* 7. Disconnecting state only transitions to Disconnected (no reconnect without going through Disconnected)
DisconnectingIsTerminal ==
    \A p \in Peers : peerState[p] = "Disconnecting" =>
        (peerState'[p] = "Disconnected" \/ peerState'[p] = "Disconnecting")

\* Combined safety invariant
Safety ==
    /\ TypeOK
    /\ VersionCompatibility
    /\ GenesisBinding
    /\ NetworkIdMatch
    /\ HandshakeBeforeData
    /\ ActivePeerConsistency
    /\ NoSelfConnection

\* ---- Theorems ----

THEOREM Spec => []Safety

==============================================================================
