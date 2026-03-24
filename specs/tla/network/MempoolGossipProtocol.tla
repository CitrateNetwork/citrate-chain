------------------------------ MODULE MempoolGossipProtocol ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models transaction gossip between peers to verify deduplication,
\* nonce ordering, and double-spend detection.
\*
\* Source: core/network/src/transaction_gossip.rs, core/sequencer/src/mempool.rs

CONSTANTS
    Nodes,         \* Set of node IDs
    Txs,           \* Set of possible transaction IDs
    Senders        \* Set of possible sender addresses

\* Sender and nonce mappings defined as CHOOSE operators
\* TLC will assign arbitrary but consistent mappings
TxSender == CHOOSE f \in [Txs -> Senders] : TRUE
TxNonce == CHOOSE f \in [Txs -> 0..2] : TRUE

VARIABLES
    mempool,          \* Function: Nodes -> SUBSET Txs
    seenTxs,          \* Function: Nodes -> SUBSET Txs
    gossipQueue,      \* Set of (from_node, to_node, tx) pending
    appliedNonce      \* Function: Nodes x Senders -> Nat

vars == <<mempool, seenTxs, gossipQueue, appliedNonce>>

TypeOK ==
    /\ mempool \in [Nodes -> SUBSET Txs]
    /\ seenTxs \in [Nodes -> SUBSET Txs]
    /\ \A ns \in Nodes \X Senders : appliedNonce[ns] \in Nat

Init ==
    /\ mempool = [n \in Nodes |-> {}]
    /\ seenTxs = [n \in Nodes |-> {}]
    /\ gossipQueue = {}
    /\ appliedNonce = [ns \in Nodes \X Senders |-> 0]

SubmitTx(node, tx) ==
    /\ tx \notin seenTxs[node]
    /\ TxNonce[tx] >= appliedNonce[<<node, TxSender[tx]>>]
    /\ mempool' = [mempool EXCEPT ![node] = @ \cup {tx}]
    /\ seenTxs' = [seenTxs EXCEPT ![node] = @ \cup {tx}]
    /\ gossipQueue' = gossipQueue \cup {<<node, n, tx>> : n \in Nodes \ {node}}
    /\ UNCHANGED appliedNonce

DeliverGossip(from, to, tx) ==
    /\ <<from, to, tx>> \in gossipQueue
    /\ gossipQueue' = gossipQueue \ {<<from, to, tx>>}
    /\ IF tx \notin seenTxs[to]
       THEN /\ seenTxs' = [seenTxs EXCEPT ![to] = @ \cup {tx}]
            /\ IF TxNonce[tx] >= appliedNonce[<<to, TxSender[tx]>>]
               THEN mempool' = [mempool EXCEPT ![to] = @ \cup {tx}]
               ELSE UNCHANGED mempool
       ELSE UNCHANGED <<mempool, seenTxs>>
    /\ UNCHANGED appliedNonce

IncludeInBlock(node, tx) ==
    /\ tx \in mempool[node]
    /\ TxNonce[tx] = appliedNonce[<<node, TxSender[tx]>>]
    /\ mempool' = [mempool EXCEPT ![node] = @ \ {tx}]
    /\ appliedNonce' = [appliedNonce EXCEPT ![<<node, TxSender[tx]>>] = @ + 1]
    /\ UNCHANGED <<seenTxs, gossipQueue>>

Next ==
    \/ \E n \in Nodes, t \in Txs : SubmitTx(n, t)
    \/ \E f \in Nodes, t2 \in Nodes, tx \in Txs : DeliverGossip(f, t2, tx)
    \/ \E n \in Nodes, t \in Txs : IncludeInBlock(n, t)

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

NoDuplicateTx ==
    \A nd \in Nodes : \A t \in mempool[nd] : t \in seenTxs[nd]

NonceOrdering ==
    \A n \in Nodes : \A t \in mempool[n] :
        TxNonce[t] >= appliedNonce[<<n, TxSender[t]>>]

NoDoubleSend ==
    \A n \in Nodes : \A t1 \in mempool[n] : \A t2 \in mempool[n] :
        (TxSender[t1] = TxSender[t2] /\ TxNonce[t1] = TxNonce[t2]) => t1 = t2

Safety ==
    /\ TypeOK
    /\ NoDuplicateTx
    /\ NonceOrdering
    /\ NoDoubleSend

THEOREM Spec => []Safety

==============================================================================
