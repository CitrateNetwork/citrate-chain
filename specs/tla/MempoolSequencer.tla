------------------------------ MODULE MempoolSequencer ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Models mempool transaction admission, nonce validation, priority ordering,
\* sender-limit enforcement, and eviction under capacity.
\* Source: core/sequencer/src/mempool.rs

CONSTANTS
    Senders,        \* Set of possible sender addresses
    MaxCapacity,    \* Maximum mempool size
    MaxNonce,       \* Maximum nonce value (bounds model)
    MaxPerSender    \* Maximum transactions per sender

ASSUME MaxCapacity \in Nat /\ MaxCapacity > 0
ASSUME MaxNonce \in Nat /\ MaxNonce > 0
ASSUME MaxPerSender \in Nat /\ MaxPerSender > 0

VARIABLES
    mempool,        \* Set of tx records: [hash, sender, nonce, priority]
    stateNonces,    \* Function: sender -> last confirmed nonce
    nextTxId        \* Monotonic counter for unique tx hashes

vars == <<mempool, stateNonces, nextTxId>>

\* ---- Helper operators ----

\* All transactions from a given sender
SenderTxs(s) == { tx \in mempool : tx.sender = s }

\* Count of transactions from a sender
SenderCount(s) == Cardinality(SenderTxs(s))

\* Maximum nonce in mempool for a sender (0 if none)
MaxMempoolNonce(s) ==
    IF SenderTxs(s) = {} THEN 0
    ELSE CHOOSE n \in { tx.nonce : tx \in SenderTxs(s) } :
        \A tx \in SenderTxs(s) : tx.nonce <= n

\* Pending nonce for a sender = max(mempool nonce + 1, state nonce)
PendingNonce(s) ==
    LET mempoolMax == MaxMempoolNonce(s)
        stateN == stateNonces[s]
    IN IF mempoolMax + 1 > stateN THEN mempoolMax + 1 ELSE stateN

\* Lowest priority transaction in mempool
LowestPriorityTx ==
    CHOOSE tx \in mempool :
        \A other \in mempool : tx.priority <= other.priority

\* ---- State machine ----

Init ==
    /\ mempool = {}
    /\ stateNonces = [s \in Senders |-> 0]
    /\ nextTxId = 1

\* Submit a valid transaction to the mempool
SubmitTx(sender, nonce, priority) ==
    /\ sender \in Senders
    /\ nonce \in 1..MaxNonce
    /\ priority \in 1..10
    /\ nonce >= stateNonces[sender]                    \* Nonce not below confirmed
    /\ SenderCount(sender) < MaxPerSender              \* Sender limit not exceeded
    /\ ~(\E tx \in mempool : tx.sender = sender /\ tx.nonce = nonce) \* No duplicate nonce per sender
    /\ LET newTx == [hash |-> nextTxId, sender |-> sender,
                     nonce |-> nonce, priority |-> priority] IN
        IF Cardinality(mempool) < MaxCapacity THEN
            \* Pool has room — add directly
            /\ mempool' = mempool \cup {newTx}
            /\ stateNonces' = stateNonces
            /\ nextTxId' = nextTxId + 1
        ELSE
            \* Pool full — evict lowest priority if new tx has higher priority
            /\ priority > LowestPriorityTx.priority
            /\ mempool' = (mempool \ {LowestPriorityTx}) \cup {newTx}
            /\ stateNonces' = stateNonces
            /\ nextTxId' = nextTxId + 1

\* Confirm a transaction (e.g., included in a block) — removes from mempool, advances nonce
ConfirmTx(sender) ==
    /\ SenderTxs(sender) # {}
    /\ LET tx == CHOOSE t \in SenderTxs(sender) :
            \A other \in SenderTxs(sender) : t.nonce <= other.nonce IN
        /\ mempool' = mempool \ {tx}
        /\ stateNonces' = [stateNonces EXCEPT ![sender] = tx.nonce + 1]
        /\ nextTxId' = nextTxId

Next ==
    \/ \E s \in Senders, n \in 1..MaxNonce, p \in 1..10 : SubmitTx(s, n, p)
    \/ \E s \in Senders : ConfirmTx(s)

\* ---- Invariants ----

\* INV-1: No duplicate transaction hashes
NoDuplicateHashes ==
    \A tx1, tx2 \in mempool : tx1 # tx2 => tx1.hash # tx2.hash

\* INV-2: No duplicate nonces per sender
NoDuplicateNoncePerSender ==
    \A tx1, tx2 \in mempool :
        tx1 # tx2 /\ tx1.sender = tx2.sender => tx1.nonce # tx2.nonce

\* INV-3: Pool size never exceeds capacity
CapacityRespected ==
    Cardinality(mempool) <= MaxCapacity

\* INV-4: Sender limit respected
SenderLimitRespected ==
    \A s \in Senders : SenderCount(s) <= MaxPerSender

\* INV-5: Nonces never below confirmed state
NoncesAboveState ==
    \A tx \in mempool : tx.nonce >= stateNonces[tx.sender]

\* ---- Type invariant ----

TypeInv ==
    /\ mempool \subseteq [hash: Nat, sender: Senders, nonce: 1..MaxNonce, priority: 1..10]
    /\ stateNonces \in [Senders -> 0..MaxNonce]
    /\ nextTxId \in Nat

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeInv
THEOREM NoDupHashes == Spec => []NoDuplicateHashes
THEOREM NoDupNonces == Spec => []NoDuplicateNoncePerSender
THEOREM CapacitySafe == Spec => []CapacityRespected
THEOREM SenderLimitSafe == Spec => []SenderLimitRespected
THEOREM NonceAboveStateSafe == Spec => []NoncesAboveState

=============================================================================
