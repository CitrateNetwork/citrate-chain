------------------------------ MODULE MempoolGossipProtocol ------------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models transaction gossip between peers to verify deduplication,
\* nonce ordering, and double-spend detection.
\*
\* Source: core/network/src/transaction_gossip.rs
\*         core/sequencer/src/mempool.rs

CONSTANTS
    Nodes,         \* Set of node IDs
    Txs,           \* Set of possible transaction IDs
    Senders,       \* Set of possible sender addresses
    TxSender,      \* Function: Txs -> Senders (who sent each tx)
    TxNonce        \* Function: Txs -> Nat (nonce of each tx)

ASSUME \A t \in Txs : TxSender[t] \in Senders
ASSUME \A t \in Txs : TxNonce[t] \in Nat

VARIABLES
    mempool,          \* Function: Nodes -> SUBSET Txs (each node's mempool)
    seenTxs,          \* Function: Nodes -> SUBSET Txs (txs seen, including rejected)
    gossipQueue,      \* Set of (from_node, to_node, tx) pending gossip
    appliedNonce      \* Function: Nodes x Senders -> Nat (highest nonce applied per sender)

vars == <<mempool, seenTxs, gossipQueue, appliedNonce>>

TypeOK ==
    /\ mempool \in [Nodes -> SUBSET Txs]
    /\ seenTxs \in [Nodes -> SUBSET Txs]
    /\ appliedNonce \in [Nodes \X Senders -> Nat]

Init ==
    /\ mempool = [n \in Nodes |-> {}]
    /\ seenTxs = [n \in Nodes |-> {}]
    /\ gossipQueue = {}
    /\ appliedNonce = [ns \in Nodes \X Senders |-> 0]

\* Node receives a new transaction from a user
SubmitTx(node, tx) ==
    /\ tx \notin seenTxs[node]
    /\ TxNonce[tx] >= appliedNonce[<<node, TxSender[tx]>>]
    /\ mempool' = [mempool EXCEPT ![node] = @ \cup {tx}]
    /\ seenTxs' = [seenTxs EXCEPT ![node] = @ \cup {tx}]
    \* Queue gossip to all other nodes
    /\ gossipQueue' = gossipQueue \cup {<<node, n, tx>> : n \in Nodes \ {node}}
    /\ UNCHANGED appliedNonce

\* Gossip delivers a transaction to a peer
DeliverGossip(from, to, tx) ==
    /\ <<from, to, tx>> \in gossipQueue
    /\ gossipQueue' = gossipQueue \ {<<from, to, tx>>}
    /\ IF tx \notin seenTxs[to]
       THEN /\ seenTxs' = [seenTxs EXCEPT ![to] = @ \cup {tx}]
            /\ IF TxNonce[tx] >= appliedNonce[<<to, TxSender[tx]>>]
               THEN mempool' = [mempool EXCEPT ![to] = @ \cup {tx}]
               ELSE UNCHANGED mempool  \* Stale nonce, reject
       ELSE UNCHANGED <<mempool, seenTxs>>  \* Already seen, deduplicate
    /\ UNCHANGED appliedNonce

\* Transaction included in a block (removed from mempool, nonce advances)
IncludeInBlock(node, tx) ==
    /\ tx \in mempool[node]
    /\ TxNonce[tx] = appliedNonce[<<node, TxSender[tx]>>]  \* Must be next nonce
    /\ mempool' = [mempool EXCEPT ![node] = @ \ {tx}]
    /\ appliedNonce' = [appliedNonce EXCEPT ![<<node, TxSender[tx]>>] = @ + 1]
    /\ UNCHANGED <<seenTxs, gossipQueue>>

Next ==
    \/ \E n \in Nodes, t \in Txs : SubmitTx(n, t)
    \/ \E f \in Nodes, t2 \in Nodes, tx \in Txs : DeliverGossip(f, t2, tx)
    \/ \E n \in Nodes, t \in Txs : IncludeInBlock(n, t)

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* No transaction appears twice in any node's mempool (deduplication)
NoDuplicateTx ==
    \A n \in Nodes : \A t \in mempool[n] : t \in seenTxs[n]

\* Nonce ordering: mempool only contains txs with valid nonces
NonceOrdering ==
    \A n \in Nodes, t \in mempool[n] :
        TxNonce[t] >= appliedNonce[<<n, TxSender[t]>>]

\* No two txs in mempool from same sender with same nonce (double-spend)
NoDoubleSend ==
    \A n \in Nodes, t1 \in mempool[n], t2 \in mempool[n] :
        (TxSender[t1] = TxSender[t2] /\ TxNonce[t1] = TxNonce[t2]) => t1 = t2

Safety ==
    /\ TypeOK
    /\ NoDuplicateTx
    /\ NonceOrdering
    /\ NoDoubleSend

THEOREM Spec => []Safety

==============================================================================
