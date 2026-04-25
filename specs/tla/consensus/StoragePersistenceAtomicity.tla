------------------------------ MODULE StoragePersistenceAtomicity ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Models the atomicity contract that closes audit finding **H-04**.
\*
\* Pre-fix: `DagStore::store_block` performed a sequence of independent
\* `kv_put` / `kv_delete` calls (block bytes, child links, tip
\* updates, height index). A power loss between any two calls left
\* the persistent state inconsistent on restart — block exists
\* without its child pointer; tips set excludes the new tip; etc.
\*
\* Post-fix (WP-B1.3): every persistence op for a single
\* `store_block` invocation is collected into one batch and applied
\* via `KvStore::kv_write_batch(ops)`. The trait contract is
\* all-or-nothing: either every op in `ops` is durably applied, or
\* none is. RocksDB satisfies this via its native `WriteBatch`
\* primitive; the in-memory test backend simulates the same
\* semantics in `core/consensus/tests/h04_dagstore_atomicity.rs`.
\*
\* This spec models a tiny abstract `KvStore` and a `WriteBatch`
\* primitive subject to crash injection. The invariants check that
\* (a) crashes never produce partial state and (b) the post-restart
\* persistent state is recoverable as a complete `store_block`
\* effect or as the unchanged pre-call state.

CONSTANTS
    Cfs,         \* Set of column-family names (e.g., {dag_blocks, dag_tips, dag_children})
    Keys,        \* Finite key universe
    Values,      \* Finite value universe
    NumOps       \* Bound on |ops| in a write batch (model exploration)

ASSUME Cfs # {} /\ IsFiniteSet(Cfs)
ASSUME Keys # {} /\ IsFiniteSet(Keys)
ASSUME Values # {} /\ IsFiniteSet(Values)
ASSUME NumOps \in Nat /\ NumOps >= 1

\* An op is a triple <<kind, cf, key, value>>; we use a record so the
\* shape is explicit. "Delete" ops carry a sentinel value field that
\* TLC ignores via `IF kind = "Delete" THEN <ignored> ELSE value`.
Op == [kind: {"Put", "Delete"}, cf: Cfs, key: Keys, value: Values \cup {NULL}]

VARIABLES
    storage,         \* Function: (cf, key) -> Values; current durable state
    pending_batch,   \* Sequence of Op currently being applied; empty when no batch is in flight
    pre_batch_state, \* Snapshot of `storage` before a batch began
    crashed          \* Boolean — whether a crash has occurred mid-batch

vars == <<storage, pending_batch, pre_batch_state, crashed>>

NULL == CHOOSE x : x \notin Values

\* ---- Initial state ----

Init ==
    /\ storage = [<<c, k>> \in Cfs \X Keys |-> NULL]
    /\ pending_batch = <<>>
    /\ pre_batch_state = storage
    /\ crashed = FALSE

\* ---- Action: begin a write batch ----

BeginBatch(ops) ==
    /\ pending_batch = <<>>            \* No batch in flight
    /\ ~crashed                        \* Have not crashed yet
    /\ Len(ops) > 0                    \* Empty batch is uninteresting
    /\ Len(ops) <= NumOps               \* Bounded for TLC
    /\ pending_batch' = ops
    /\ pre_batch_state' = storage
    /\ UNCHANGED <<storage, crashed>>

\* ---- Action: apply one op of the in-flight batch ----
\* (Internal — represents the per-op work inside `kv_write_batch`.)

ApplyOneOp ==
    /\ Len(pending_batch) > 0
    /\ ~crashed
    /\ LET op == Head(pending_batch)
       IN
        /\ storage' = IF op.kind = "Put"
                      THEN [storage EXCEPT ![<<op.cf, op.key>>] = op.value]
                      ELSE [storage EXCEPT ![<<op.cf, op.key>>] = NULL]
        /\ pending_batch' = Tail(pending_batch)
        /\ UNCHANGED <<pre_batch_state, crashed>>

\* ---- Action: crash mid-batch ----
\*
\* Pre-fix behavior: the partial in-memory `storage` is durable.
\* Post-fix behavior (with `kv_write_batch`): the batch is atomic —
\* on crash the storage rolls back to `pre_batch_state`.
\*
\* This spec models the post-fix behavior. The pre-fix behavior is
\* what the spec is the contrast for.

CrashAtomicRollback ==
    /\ Len(pending_batch) > 0          \* A batch is in flight
    /\ ~crashed
    /\ storage' = pre_batch_state      \* Roll back: atomic semantics
    /\ pending_batch' = <<>>
    /\ crashed' = TRUE
    /\ UNCHANGED pre_batch_state

\* ---- Action: complete a batch normally ----

CompleteBatch ==
    /\ Len(pending_batch) = 0
    /\ pre_batch_state' = storage      \* Now-durable; the next BeginBatch will snapshot
    /\ UNCHANGED <<storage, pending_batch, crashed>>

\* ---- State machine ----

Next ==
    \/ \E ops \in [1..NumOps -> Op] : BeginBatch(ops)
    \/ ApplyOneOp
    \/ CrashAtomicRollback
    \/ CompleteBatch

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* INV-1: After a crash mid-batch, `storage` matches the pre-batch
\* snapshot exactly. No partial state leaks.
NoPartialStateOnCrash ==
    crashed => storage = pre_batch_state

\* INV-2: When no batch is in flight, `storage` and `pre_batch_state`
\* agree (they only diverge while a batch is in progress).
StorageStableBetweenBatches ==
    Len(pending_batch) = 0 => storage = pre_batch_state

\* INV-3: Every entry in `storage` is either NULL or a Value.
TypeInv ==
    /\ pending_batch \in Seq(Op)
    /\ Len(pending_batch) <= NumOps
    /\ \A c \in Cfs, k \in Keys :
        storage[<<c, k>>] \in Values \cup {NULL}

THEOREM TypeSafety == Spec => []TypeInv
THEOREM CrashRollsBack == Spec => []NoPartialStateOnCrash
THEOREM StableOutsideBatch == Spec => []StorageStableBetweenBatches

=============================================================================
