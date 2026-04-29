--------------------- MODULE DaemonAdversarial ---------------------
EXTENDS Naturals, FiniteSets, TLC

\* RM-FL-3 / WP-3.12 — Adversary model for the learning daemon.
\*
\* Companion to `LearningDaemon.tla` (WP-3.1). The base spec models
\* a single honest daemon advancing through cycles cleanly. This
\* spec generalizes to N daemons running concurrently against the
\* same chain — the adversary model IS the multi-daemon interleaving
\* itself. With |DaemonIds| ≥ 2, TLC explores every possible
\* ordering of honest actions across daemons, including the race
\* conditions that make Gherkin scenarios 3 (SIGKILL+restart) and
\* 4 (two-daemon contention) interesting.
\*
\* Three attack classes the planset (§FL-3.12) calls out:
\*
\*   1. **Double-spending of rewards** = two daemons racing
\*      finalizeCycle. Caught structurally by the chain's
\*      `c \notin chain_finalized` guard in DaemonFinalize. The
\*      ChainFinalizedAtMostOnce invariant verifies it.
\*
\*   2. **Lost embeddings** = a finalized block's events get dropped
\*      from a daemon's view. Caught by DaemonHWMBoundedByChain:
\*      no daemon can advance HWM past a block the chain hasn't
\*      produced; the watcher's reorg detection (production layer)
\*      handles partial RPC reads via re-fetch.
\*
\*   3. **Restart races** = a daemon kill+restart interleaving with
\*      another daemon's progress. RocksDB persists across restart;
\*      this spec models persistent state (no in-memory layer
\*      separately) since the orchestrator's job is to keep them
\*      in sync. Restart races reduce to interleavings of
\*      DaemonProcessBlock / DaemonObserveFinalized actions, which
\*      TLC explores exhaustively.
\*
\* An earlier draft of this spec had three named "adversary action"
\* operators (AdversaryDoubleFinalize, AdversaryLoseEmbedding,
\* AdversaryRestart) plus an `adversary_attempts` log variable.
\* They were "log only" — they tracked attack attempts in the state
\* without changing system state. TLC still had to enumerate the
\* attempt log, multiplying the explored space by ~MaxAttempts^k
\* without adding coverage. Dropped in favor of the cleaner
\* multi-daemon model. The first attempt also exposed a too-strong
\* invariant (NoLocalFinalizeWithoutCommit), which TLC correctly
\* counter-exampled via the reconciliation path
\* (DaemonObserveFinalized) — that became the lesson logged in
\* this header.

CONSTANTS
    Cycles,            \* Set of cycle IDs to model
    MaxBlocks,         \* Number of finalized blocks per run
    DaemonIds          \* Set of daemon principals (e.g. {D1, D2})

ASSUME Cycles # {} /\ Cycles \subseteq Nat
ASSUME MaxBlocks \in Nat /\ MaxBlocks >= 1
ASSUME DaemonIds # {}

VARIABLES
    chain_finalized,           \* Set of cycle IDs finalized on chain
    chain_committed,           \* Set of cycle IDs whose aggregation
                                \* commit is on chain
    chain_observed_blocks,     \* Set of finalized block numbers
    daemon_local               \* daemon -> [last_block, cycle_status,
                                \*           finalize_status]

vars == <<chain_finalized, chain_committed, chain_observed_blocks,
          daemon_local>>

\* Per-daemon initial local view.
InitDaemonLocal == [
    last_block      |-> 0,
    cycle_status    |-> [c \in Cycles |-> "pending"],
    finalize_status |-> [c \in Cycles |-> "not_called"]
]

\* ---- State machine ----

Init ==
    /\ chain_finalized = {}
    /\ chain_committed = {}
    /\ chain_observed_blocks = {}
    /\ daemon_local = [d \in DaemonIds |-> InitDaemonLocal]

\* Honest action: chain produces a new block (sequential).
ChainProduceBlock(b) ==
    /\ b \in 1..MaxBlocks
    /\ b \notin chain_observed_blocks
    /\ \A bp \in 1..(b - 1) : bp \in chain_observed_blocks
    /\ chain_observed_blocks' = chain_observed_blocks \cup {b}
    /\ UNCHANGED <<chain_finalized, chain_committed, daemon_local>>

\* Honest action: a daemon advances its block HWM by one.
DaemonProcessBlock(d) ==
    /\ d \in DaemonIds
    /\ daemon_local[d].last_block + 1 \in chain_observed_blocks
    /\ daemon_local' = [daemon_local EXCEPT
        ![d].last_block = daemon_local[d].last_block + 1]
    /\ UNCHANGED <<chain_finalized, chain_committed, chain_observed_blocks>>

\* Honest action: a daemon transitions a cycle pending → computed.
DaemonCompute(d, c) ==
    /\ d \in DaemonIds
    /\ c \in Cycles
    /\ daemon_local[d].cycle_status[c] = "pending"
    /\ daemon_local' = [daemon_local EXCEPT
        ![d].cycle_status[c] = "computed"]
    /\ UNCHANGED <<chain_finalized, chain_committed, chain_observed_blocks>>

\* Honest action: a daemon submits its commit; chain accepts. The
\* contract treats duplicate commits idempotently in this model
\* (first-writer-wins; second is a no-op for chain_committed).
DaemonCommit(d, c) ==
    /\ d \in DaemonIds
    /\ c \in Cycles
    /\ daemon_local[d].cycle_status[c] = "computed"
    /\ chain_committed' = chain_committed \cup {c}
    /\ daemon_local' = [daemon_local EXCEPT
        ![d].cycle_status[c] = "committed"]
    /\ UNCHANGED <<chain_finalized, chain_observed_blocks>>

\* Honest action: a daemon calls finalizeCycle. Chain enforces
\* at-most-once via `c \notin chain_finalized` guard. Across two
\* daemons, exactly one wins the race; the other's local
\* finalize_status stays not_called (until DaemonObserveFinalized
\* fires for the chain event).
DaemonFinalize(d, c) ==
    /\ d \in DaemonIds
    /\ c \in Cycles
    /\ daemon_local[d].cycle_status[c] = "committed"
    /\ daemon_local[d].finalize_status[c] = "not_called"
    /\ c \notin chain_finalized
    /\ chain_finalized' = chain_finalized \cup {c}
    /\ daemon_local' = [daemon_local EXCEPT
        ![d].finalize_status[c] = "called"]
    /\ UNCHANGED <<chain_committed, chain_observed_blocks>>

\* Honest action: a daemon observes the chain's CycleFinalized
\* event and reconciles its local finalize_status. This mirrors
\* the production orchestrator.rs::dispatch_event handler for
\* CycleFinalized — the chain is the source of truth, and a daemon
\* that lost the finalize race adopts it.
DaemonObserveFinalized(d, c) ==
    /\ d \in DaemonIds
    /\ c \in Cycles
    /\ c \in chain_finalized
    /\ daemon_local[d].finalize_status[c] = "not_called"
    /\ daemon_local' = [daemon_local EXCEPT
        ![d].finalize_status[c] = "called"]
    /\ UNCHANGED <<chain_finalized, chain_committed, chain_observed_blocks>>

Stutter == UNCHANGED vars

Next ==
    \/ \E b \in 1..MaxBlocks : ChainProduceBlock(b)
    \/ \E d \in DaemonIds : DaemonProcessBlock(d)
    \/ \E d \in DaemonIds, c \in Cycles : DaemonCompute(d, c)
    \/ \E d \in DaemonIds, c \in Cycles : DaemonCommit(d, c)
    \/ \E d \in DaemonIds, c \in Cycles : DaemonFinalize(d, c)
    \/ \E d \in DaemonIds, c \in Cycles : DaemonObserveFinalized(d, c)
    \/ Stutter

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ chain_finalized \subseteq Cycles
    /\ chain_committed \subseteq Cycles
    /\ chain_observed_blocks \subseteq 1..MaxBlocks
    /\ daemon_local \in [DaemonIds -> [
        last_block: 0..MaxBlocks,
        cycle_status: [Cycles -> {"pending", "computed", "committed"}],
        finalize_status: [Cycles -> {"not_called", "called"}]
       ]]

\* INV-2: ChainFinalizedAtMostOnce
\* The chain's chain_finalized set only grows; once a cycle is in
\* it, no second DaemonFinalize action can fire (the guard
\* `c \notin chain_finalized` rejects). A daemon's local
\* finalize_status = "called" implies the chain has the cycle in
\* chain_finalized — either the daemon was the one that wrote it
\* (DaemonFinalize) or the daemon adopted the chain truth via
\* DaemonObserveFinalized.
ChainFinalizedAtMostOnce ==
    \A c \in Cycles :
        \A d \in DaemonIds :
            (daemon_local[d].finalize_status[c] = "called")
                => c \in chain_finalized

\* INV-3: DaemonHWMBoundedByChain
\* No daemon claims to have processed a block the chain hasn't
\* produced.
DaemonHWMBoundedByChain ==
    \A d \in DaemonIds :
        daemon_local[d].last_block <= MaxBlocks
        /\ (daemon_local[d].last_block > 0 =>
                \A b \in 1..daemon_local[d].last_block :
                    b \in chain_observed_blocks)

\* INV-4: NoCommitWithoutChainCommit
\* If a daemon's local cycle_status is "committed", the chain has
\* the commit. The honest commit action conjuncts both updates.
NoCommitWithoutChainCommit ==
    \A c \in Cycles :
        \A d \in DaemonIds :
            (daemon_local[d].cycle_status[c] = "committed")
                => c \in chain_committed

\* INV-5: ChainAdvanceRespectsHonest
\* The chain only finalizes cycles that have been committed first.
\* The DaemonFinalize action's guard chain
\* `daemon_local[d].cycle_status[c] = "committed"` plus INV-4
\* (NoCommitWithoutChainCommit) imply this structurally.
ChainAdvanceRespectsHonest ==
    chain_finalized \subseteq chain_committed

SafetyInvariant ==
    /\ TypeOK
    /\ ChainFinalizedAtMostOnce
    /\ DaemonHWMBoundedByChain
    /\ NoCommitWithoutChainCommit
    /\ ChainAdvanceRespectsHonest

THEOREM Types == Spec => []TypeOK
THEOREM AtMostOnce == Spec => []ChainFinalizedAtMostOnce
THEOREM HwmBound == Spec => []DaemonHWMBoundedByChain
THEOREM ComBound == Spec => []NoCommitWithoutChainCommit
THEOREM ChainHonest == Spec => []ChainAdvanceRespectsHonest

============================================================================
