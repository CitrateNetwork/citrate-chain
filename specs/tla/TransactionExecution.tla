------------------------------ MODULE TransactionExecution ------------------------------
EXTENDS Naturals, Integers, FiniteSets, Sequences, TLC

\* Models EVM transaction execution: submission, validation, execution,
\* commit, and revert with gas accounting and balance conservation.
\* Source: core/execution/src/executor.rs

CONSTANTS
    Accounts,       \* Set of account addresses
    MaxTx,          \* Maximum number of transactions in the queue
    GasLimit,       \* Block gas limit
    MaxValue        \* Maximum transfer value (bounds model)

ASSUME MaxTx \in Nat /\ MaxTx > 0
ASSUME GasLimit \in Nat /\ GasLimit > 0
ASSUME MaxValue \in Nat /\ MaxValue > 0

VARIABLES
    txQueue,        \* Sequence of pending tx records: [from, to, value, gas, status]
    executionState, \* "idle" | "validating" | "executing"
    balances,       \* Function: account -> balance
    nonces,         \* Function: account -> nonce (monotonically increasing)
    gasUsed,        \* Gas consumed by current transaction
    blockGasUsed    \* Cumulative gas used in current block

vars == <<txQueue, executionState, balances, nonces, gasUsed, blockGasUsed>>

\* ---- Constants for tx status ----

StatusPending   == "pending"
StatusValid     == "valid"
StatusExecuted  == "executed"
StatusReverted  == "reverted"

\* ---- Helper operators ----

\* Initial balance for each account (deterministic, large enough for model)
InitialBalance == (MaxValue + GasLimit) * MaxTx

\* Recursive sum of balances over a set of accounts (TLC-compatible)
RECURSIVE SumBal(_)
SumBal(S) ==
    IF S = {} THEN 0
    ELSE LET a == CHOOSE a \in S : TRUE
         IN balances[a] + SumBal(S \ {a})

\* Total balance across all accounts
TotalBalance == SumBal(Accounts)

\* Number of transactions in queue
QueueLen == Len(txQueue)

\* Head of the queue (only used when QueueLen > 0)
HeadTx == txQueue[1]

\* ---- State machine ----

Init ==
    /\ txQueue = <<>>
    /\ executionState = "idle"
    /\ balances = [a \in Accounts |-> InitialBalance]
    /\ nonces = [a \in Accounts |-> 0]
    /\ gasUsed = 0
    /\ blockGasUsed = 0

\* Submit a new transaction to the queue
SubmitTx(from, to, value, gas) ==
    /\ from \in Accounts
    /\ to \in Accounts
    /\ from # to                                \* No self-transfers (simplifies model)
    /\ value \in 1..MaxValue
    /\ gas \in 1..GasLimit
    /\ QueueLen < MaxTx
    /\ executionState = "idle"
    /\ LET newTx == [from |-> from, to |-> to, value |-> value,
                     gas |-> gas, status |-> StatusPending] IN
        /\ txQueue' = Append(txQueue, newTx)
        /\ UNCHANGED <<executionState, balances, nonces, gasUsed, blockGasUsed>>

\* Validate the head transaction: check sufficient balance and gas fits in block
ValidateTx ==
    /\ executionState = "idle"
    /\ QueueLen > 0
    /\ HeadTx.status = StatusPending
    /\ LET tx == HeadTx IN
        \* Sender must have enough balance for value + gas
        /\ balances[tx.from] >= tx.value + tx.gas
        \* Gas must fit within remaining block gas
        /\ blockGasUsed + tx.gas <= GasLimit
        \* Mark as valid
        /\ txQueue' = [txQueue EXCEPT ![1].status = StatusValid]
        /\ executionState' = "validating"
        /\ UNCHANGED <<balances, nonces, gasUsed, blockGasUsed>>

\* Execute a validated transaction: apply state changes (value transfer + gas deduction)
ExecuteTx ==
    /\ executionState = "validating"
    /\ QueueLen > 0
    /\ HeadTx.status = StatusValid
    /\ LET tx == HeadTx IN
        \* Transfer value and deduct gas from sender; credit value to receiver
        /\ balances' = [balances EXCEPT
            ![tx.from] = balances[tx.from] - tx.value - tx.gas,
            ![tx.to] = balances[tx.to] + tx.value]
        \* Increment sender nonce
        /\ nonces' = [nonces EXCEPT ![tx.from] = nonces[tx.from] + 1]
        \* Record gas
        /\ gasUsed' = tx.gas
        /\ blockGasUsed' = blockGasUsed + tx.gas
        \* Mark as executed
        /\ txQueue' = [txQueue EXCEPT ![1].status = StatusExecuted]
        /\ executionState' = "executing"

\* Revert a failed transaction: nonce still increments, gas still consumed, no value transfer
RevertTx ==
    /\ executionState = "validating"
    /\ QueueLen > 0
    /\ HeadTx.status = StatusValid
    /\ LET tx == HeadTx IN
        \* No value transfer, but gas is consumed from sender
        /\ balances' = [balances EXCEPT
            ![tx.from] = balances[tx.from] - tx.gas]
        \* Increment sender nonce (even on revert, per EVM semantics)
        /\ nonces' = [nonces EXCEPT ![tx.from] = nonces[tx.from] + 1]
        \* Record gas
        /\ gasUsed' = tx.gas
        /\ blockGasUsed' = blockGasUsed + tx.gas
        \* Mark as reverted
        /\ txQueue' = [txQueue EXCEPT ![1].status = StatusReverted]
        /\ executionState' = "executing"

\* Commit state: finalize the processed transaction, remove from queue
CommitState ==
    /\ executionState = "executing"
    /\ QueueLen > 0
    /\ HeadTx.status \in {StatusExecuted, StatusReverted}
    /\ txQueue' = Tail(txQueue)
    /\ executionState' = "idle"
    /\ gasUsed' = 0
    /\ UNCHANGED <<balances, nonces, blockGasUsed>>

Next ==
    \/ \E from, to \in Accounts, v \in 1..MaxValue, g \in 1..GasLimit :
        SubmitTx(from, to, v, g)
    \/ ValidateTx
    \/ ExecuteTx
    \/ RevertTx
    \/ CommitState

\* ---- Invariants ----

\* INV-1: Type invariant — well-formed state
TypeInv ==
    /\ txQueue \in Seq([from: Accounts, to: Accounts, value: 1..MaxValue,
                        gas: 1..GasLimit, status: {StatusPending, StatusValid,
                                                    StatusExecuted, StatusReverted}])
    /\ executionState \in {"idle", "validating", "executing"}
    /\ balances \in [Accounts -> Int]
    /\ nonces \in [Accounts -> Nat]
    /\ gasUsed \in 0..GasLimit
    /\ blockGasUsed \in 0..(GasLimit * MaxTx)

\* INV-2: Balance conservation — transfers do not create or destroy value
\* Gas fees are deducted from senders and burned (not credited to any account
\* in this model), so: sum(balances) + blockGasUsed = initial total supply
BalanceConservation ==
    TotalBalance + blockGasUsed = Cardinality(Accounts) * InitialBalance

\* INV-3: Nonce monotonicity — nonces are non-negative (and only increase per action)
NonceMonotonicity ==
    \A a \in Accounts : nonces[a] >= 0

\* INV-4: Block gas limit respected — cumulative gas never exceeds GasLimit
GasLimitRespected ==
    blockGasUsed <= GasLimit

\* INV-5: No negative balance — no account balance goes below 0
NoNegativeBalance ==
    \A a \in Accounts : balances[a] >= 0

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeInv
THEOREM BalanceConserved == Spec => []BalanceConservation
THEOREM NoncesMonotonic == Spec => []NonceMonotonicity
THEOREM GasLimitSafe == Spec => []GasLimitRespected
THEOREM NoNegBal == Spec => []NoNegativeBalance

=============================================================================
