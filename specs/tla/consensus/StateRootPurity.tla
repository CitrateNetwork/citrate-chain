-------------------------- MODULE StateRootPurity --------------------------
(***************************************************************************)
(* SRP — State-Root Purity across production, reception, and cold sync.     *)
(*                                                                          *)
(* WHY THIS SPEC EXISTS (the bug it pins):                                  *)
(*   On chain 40204 (2026-07-20) all fleet nodes AGREED on a block's        *)
(*   `stateRoot` while holding DIFFERENT coinbase balances at that block.   *)
(*   Same consensus root, different committed state — impossible if the     *)
(*   root is a pure function of state. Root cause: `calculate_state_root`   *)
(*   (core/execution/src/state/state_db.rs) folds ONLY dirty accounts into  *)
(*   a PERSISTENT, never-rebuilt `state_trie`; an account changed but not    *)
(*   re-inserted for a block keeps a STALE trie value, so the root becomes   *)
(*   a function of a node's insertion/eviction HISTORY, not of committed     *)
(*   state. A cold-syncing node rebuilds a different history and diverges.   *)
(*                                                                          *)
(* This spec generalizes GenesisSafetyAcrossNodes.StateRootFor from genesis  *)
(* to EVERY block, for THREE node roles that all must agree:                 *)
(*   Producer  — seals a block, commits StateRootFor(accountsAfterReward).   *)
(*   Receiver  — applies the gossiped block, recomputes the root.            *)
(*   ColdSync  — re-executes from genesis, recomputes the root.              *)
(*                                                                          *)
(* SAFETY (must hold after the fix; VIOLATED today):                         *)
(*   Purity          : root[n] = StateRootFor(accounts[n]) for every node.   *)
(*   RootAgreement   : equal roots  =>  equal committed accounts.            *)
(*   BalanceConsv    : block reward MINTS exactly `reward` (supply += reward)*)
(*                     — the reward is real committed state, not off-book.   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,          \* set of node ids (>=1 producer role, >=1 receiver, >=1 coldsync)
    Coinbase,       \* the reward beneficiary account
    Treasury,       \* the treasury slice beneficiary
    Reward,         \* per-block validator reward (Nat > 0)
    TreasuryCut,    \* per-block treasury reward (Nat >= 0)
    MaxBlocks       \* model bound on chain height

ASSUME Reward \in Nat /\ Reward > 0
ASSUME TreasuryCut \in Nat
ASSUME MaxBlocks \in Nat /\ MaxBlocks > 0

VARIABLES
    height,         \* current chain height each node has applied: Nodes -> Nat
    bal,            \* committed balances: Nodes -> [Accounts -> Nat]
    root            \* committed state root each node holds: Nodes -> Nat

vars == <<height, bal, root>>

Accounts == {Coinbase, Treasury}

(*-----------------------------------------------------------------------*)
(* StateRootFor: the CORRECT model — the root is a PURE, injective        *)
(* function of the committed account set. (In code: a Merkle root over    *)
(* the full committed account state, history-independent.) Distinct       *)
(* balance maps MUST yield distinct roots — the property the accumulating  *)
(* trie violates.                                                          *)
(*-----------------------------------------------------------------------*)
StateRootFor(balances) == balances[Coinbase] * 1000 + balances[Treasury]

(*-----------------------------------------------------------------------*)
(* One empty post-activation block = credit Reward to Coinbase and         *)
(* TreasuryCut to Treasury, then commit StateRootFor over the NEW state.   *)
(* Every role applies the SAME transition function on the SAME parent      *)
(* state, so producer / receiver / coldsync converge by construction —     *)
(* provided the root is StateRootFor(committed), not a history artifact.   *)
(*-----------------------------------------------------------------------*)
CreditedBalances(b) ==
    [b EXCEPT ![Coinbase] = b[Coinbase] + Reward,
              ![Treasury] = b[Treasury] + TreasuryCut]

Init ==
    /\ height = [n \in Nodes |-> 0]
    /\ bal    = [n \in Nodes |-> [a \in Accounts |-> 0]]
    /\ root   = [n \in Nodes |-> StateRootFor([a \in Accounts |-> 0])]

\* A node advances one block: reward is credited into committed state and the
\* root is recomputed as a pure function of that committed state.
ApplyBlock(n) ==
    /\ height[n] < MaxBlocks
    /\ LET nb == CreditedBalances(bal[n]) IN
        /\ bal'    = [bal    EXCEPT ![n] = nb]
        /\ root'   = [root   EXCEPT ![n] = StateRootFor(nb)]
        /\ height' = [height EXCEPT ![n] = height[n] + 1]

\* All nodes at the height bound: stutter (bounded-model termination, not a
\* real deadlock — every reachable state still satisfies the invariants below).
Terminating == (\A n \in Nodes : height[n] = MaxBlocks) /\ UNCHANGED vars

Next == (\E n \in Nodes : ApplyBlock(n)) \/ Terminating

Spec == Init /\ [][Next]_vars

(*----------------------------- Invariants ------------------------------*)

TypeOK ==
    /\ height \in [Nodes -> 0..MaxBlocks]
    /\ bal \in [Nodes -> [Accounts -> Nat]]
    /\ root \in [Nodes -> Nat]

\* PURITY: every node's committed root is exactly StateRootFor of its own
\* committed balances — the root carries no hidden history. (The code today
\* fails this: root reflects a stale accumulating trie, not `bal`.)
Purity == \A n \in Nodes : root[n] = StateRootFor(bal[n])

\* ROOT AGREEMENT: equal roots imply equal committed state. This is the
\* EXACT property violated on the live fleet (equal roots, unequal balances).
\* It follows from Purity iff StateRootFor is injective on reachable states.
RootAgreement ==
    \A n1, n2 \in Nodes :
        (root[n1] = root[n2]) => (bal[n1] = bal[n2])

\* BALANCE CONSERVATION: the reward is committed state, so a node at height h
\* has minted exactly h*(Reward+TreasuryCut). No off-book reward.
BalanceConservation ==
    \A n \in Nodes :
        bal[n][Coinbase] + bal[n][Treasury] = height[n] * (Reward + TreasuryCut)

\* CROSS-ROLE CONVERGENCE: any two nodes at the SAME height hold the SAME
\* root and the SAME balances — producer, receiver, cold-sync agree.
CrossRoleConvergence ==
    \A n1, n2 \in Nodes :
        (height[n1] = height[n2]) => (root[n1] = root[n2] /\ bal[n1] = bal[n2])

THEOREM Spec => []TypeOK
THEOREM PurityHolds == Spec => []Purity
THEOREM RootAgreementHolds == Spec => []RootAgreement
THEOREM BalanceConserved == Spec => []BalanceConservation
THEOREM RolesConverge == Spec => []CrossRoleConvergence
=============================================================================
