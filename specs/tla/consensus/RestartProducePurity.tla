------------------------ MODULE RestartProducePurity ------------------------
(***************************************************************************)
(* SRP-S3 — State-Root Purity across the RESIDENT-SET / RESTART surface.    *)
(*                                                                          *)
(* WHY THIS SPEC EXISTS (the bug it pins — block 2042, chain 40204):        *)
(*   SRP-S1 proved the FORWARD root is a pure function of committed state.   *)
(*   SRP-S2 proved the REWARD-settlement path is pure. Neither covered the   *)
(*   RESIDENT-SET surface, and block 2042 forked the fleet on exactly that:  *)
(*     StateDB::calculate_state_root (core/execution/src/state/state_db.rs)  *)
(*     folds the in-memory RESIDENT account map (AccountManager::            *)
(*     all_accounts()) into a trie. That resident map is a VOLATILE, node-   *)
(*     local cache: accounts enter it lazily (read-through) and a restart    *)
(*     re-derives it by bulk-loading from the store. An EMPTY account        *)
(*     (nonce 0, balance 0, no code, no storage, no perms — carrying NO      *)
(*     committed state) can therefore be RESIDENT on one node and ABSENT on  *)
(*     another node WITH IDENTICAL COMMITTED STATE, purely because one node  *)
(*     happened to materialize it via read-through / restart reconstruction  *)
(*     and the other did not. Folding that empty account changes the root.   *)
(*     On block 2042 the restarted miner committed a root the never-         *)
(*     restarted followers could not reproduce → split-brain.                *)
(*                                                                          *)
(* THE FIX (EIP-158, implemented + unit-confirmed):                          *)
(*   An empty account is indistinguishable from an absent one and MUST NOT   *)
(*   be folded into the root. The folded set is then ONLY the NON-EMPTY      *)
(*   (committed-state-bearing) accounts, which is a pure function of         *)
(*   committed state — identical across producer / receiver / cold-sync /    *)
(*   restart / reorg regardless of each node's residency history.            *)
(*                                                                          *)
(* MODEL:                                                                    *)
(*   Several node ROLES must agree on the SAME block: producer, receiver,    *)
(*   coldsync, restart (resident set reconstructed after a restart), reorg.  *)
(*   Every account is either NON-EMPTY (carries a committed value > 0) or    *)
(*   EMPTY (default/zero). RESIDENCY is a per-role set that ALWAYS contains   *)
(*   every NON-EMPTY committed account but may nondeterministically include   *)
(*   or exclude EMPTY accounts — that is the node-local read-through/restart  *)
(*   freedom. Each role computes the block's root = StateRootFor(the set of   *)
(*   accounts it FOLDS).                                                      *)
(*   CONSTANT FoldEmpties governs whether empties contribute to the root:     *)
(*     TRUE  = buggy `main` model (folds every resident account, empties     *)
(*             included) → RootAgreement is VIOLATED (a restart role that     *)
(*             folded an extra resident empty diverges — block 2042).         *)
(*     FALSE = EIP-158 fix (folds only non-empty resident accounts, i.e.     *)
(*             the committed non-empty set) → all invariants hold.            *)
(*                                                                          *)
(* SAFETY (must hold after the fix; VIOLATED by folding empties today):       *)
(*   Purity             : root[r] = StateRootFor(committed NON-EMPTY set) for *)
(*                        every role — the root carries no residency history. *)
(*   RootAgreement (KEY): roles that applied the SAME block hold the SAME     *)
(*                        root  <=>  the root ignores empty-account residency.*)
(*   StateRootInjective : equal roots => equal folded committed set (the      *)
(*                        encoding is injective, so agreement is meaningful). *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Roles,          \* node roles that must all agree on the same block:
                    \* producer, receiver, coldsync, restart, reorg
    Accounts,       \* the account address space (distinct naturals >= 1)
    EmptyAccounts,  \* accounts carrying NO committed state (default/zero);
                    \* residency of these is node-local / restart-dependent
    Base,           \* positional-encoding base for the injective root
    MaxBlocks,      \* model bound on chain height
    FoldEmpties     \* TRUE = buggy model (fold resident empties);
                    \* FALSE = EIP-158 fix (exclude empties from the root)

NonEmpty == Accounts \ EmptyAccounts

(*-----------------------------------------------------------------------*)
(* CV: committed value of an account. An EMPTY account carries 0 (no       *)
(* committed state); a NON-EMPTY account carries a distinct positive value  *)
(* (its address, standing in for its committed balance/nonce/code).        *)
(*-----------------------------------------------------------------------*)
CV(a) == IF a \in EmptyAccounts THEN 0 ELSE a

ASSUME Roles # {}
ASSUME Accounts \subseteq (Nat \ {0})           \* distinct positions >= 1
ASSUME EmptyAccounts \subseteq Accounts
ASSUME MaxBlocks \in Nat /\ MaxBlocks > 0
ASSUME FoldEmpties \in BOOLEAN
\* Base must exceed every digit (CV(a)+1) so the positional encoding below
\* is a valid base-Base numeral and therefore INJECTIVE.
ASSUME Base \in Nat /\ \A a \in Accounts : Base > CV(a) + 1

VARIABLES
    applied,        \* blocks each role has applied: Roles -> Nat
    folded,         \* committed-state-bearing set each role folded: Roles -> SUBSET Accounts
    root            \* state root each role computed: Roles -> Nat

vars == <<applied, folded, root>>

(*-----------------------------------------------------------------------*)
(* StateRootFor: the root is a PURE, INJECTIVE function of the folded       *)
(* account set (in code: a Merkle root over the folded account state).     *)
(* Each account a occupies "digit" position a in a base-`Base` numeral,     *)
(* with digit value (CV(a)+1) when folded and 0 when absent. Because every  *)
(* digit is < Base (see ASSUME), the numeral is unique per folded set →     *)
(* distinct folded sets (or distinct committed values) yield distinct roots.*)
(* Note the +1: even an EMPTY folded account (CV = 0) contributes a nonzero  *)
(* digit, so folding a resident empty DOES change the root — the crux of the *)
(* block-2042 divergence.                                                    *)
(*-----------------------------------------------------------------------*)
RECURSIVE StateRootFor(_)
StateRootFor(F) ==
    IF F = {} THEN 0
    ELSE LET a == CHOOSE x \in F : TRUE
         IN (CV(a) + 1) * (Base ^ a) + StateRootFor(F \ {a})

\* The canonical committed root: fold ONLY the committed non-empty accounts.
\* This is the root every role MUST agree on, independent of residency.
CommittedRoot == StateRootFor(NonEmpty)

(*-----------------------------------------------------------------------*)
(* Residency freedom: a role's resident set always contains every NON-     *)
(* EMPTY committed account and may include ANY subset of the EMPTY ones.    *)
(*-----------------------------------------------------------------------*)
ResidentSets == { NonEmpty \cup S : S \in SUBSET EmptyAccounts }

(*-----------------------------------------------------------------------*)
(* Folded(R): which resident accounts actually fold into the root.         *)
(*   FoldEmpties=TRUE  (buggy): fold the whole resident set, empties incl.  *)
(*   FoldEmpties=FALSE (EIP-158): fold only non-empty resident accounts,    *)
(*                     which — since R always ⊇ NonEmpty — is exactly       *)
(*                     NonEmpty, a pure function of committed state.         *)
(*-----------------------------------------------------------------------*)
Folded(R) == IF FoldEmpties THEN R ELSE { a \in R : a \notin EmptyAccounts }

Init ==
    /\ applied = [r \in Roles |-> 0]
    /\ folded  = [r \in Roles |-> NonEmpty]
    /\ root    = [r \in Roles |-> CommittedRoot]

\* A role applies the next block: it materializes some resident set (its own
\* node-local read-through / restart history), folds per the model, and
\* commits the resulting root over that folded set.
ApplyBlock(r) ==
    /\ applied[r] < MaxBlocks
    /\ \E R \in ResidentSets :
        LET f == Folded(R) IN
        /\ folded'  = [folded  EXCEPT ![r] = f]
        /\ root'    = [root    EXCEPT ![r] = StateRootFor(f)]
        /\ applied' = [applied EXCEPT ![r] = applied[r] + 1]

\* All roles at the height bound: stutter (bounded-model termination, not a
\* real deadlock — every reachable state still satisfies the invariants).
Terminating == (\A r \in Roles : applied[r] = MaxBlocks) /\ UNCHANGED vars

Next == (\E r \in Roles : ApplyBlock(r)) \/ Terminating

Spec == Init /\ [][Next]_vars

(*----------------------------- Invariants ------------------------------*)

TypeOK ==
    /\ applied \in [Roles -> 0..MaxBlocks]
    /\ folded \in [Roles -> SUBSET Accounts]
    /\ root \in [Roles -> Nat]

\* PURITY: every role's root is exactly StateRootFor of the committed NON-
\* EMPTY set — the root carries no residency history. Holds under the fix
\* (Folded collapses to NonEmpty); VIOLATED under FoldEmpties (a role that
\* folds a resident empty commits a root that is not the committed root).
Purity == \A r \in Roles : root[r] = CommittedRoot

\* ROOT AGREEMENT (the key one): any two roles that have applied the SAME
\* number of blocks (the same block) hold the SAME root. Guaranteed IFF the
\* root ignores empty-account residency.
\*   - EIP-158 fix: every role folds NonEmpty => same root. HOLDS.
\*   - FoldEmpties: a restart role folds an extra resident empty while a
\*     never-restarted role does not => same block, DIFFERENT roots =>
\*     StateRootMismatch. VIOLATED — exactly the block-2042 split-brain.
RootAgreement ==
    \A r1, r2 \in Roles :
        (applied[r1] = applied[r2] /\ applied[r1] > 0)
            => (root[r1] = root[r2])

\* STATE-ROOT INJECTIVITY: equal roots imply equal folded committed sets.
\* This is what makes agreement meaningful — equal roots => equal committed
\* state. It follows from the base-`Base` positional encoding and holds in
\* BOTH models (it is a property of StateRootFor, not of the fix).
StateRootInjective ==
    \A r1, r2 \in Roles :
        (root[r1] = root[r2]) => (folded[r1] = folded[r2])

THEOREM Spec => []TypeOK
THEOREM PurityHolds == Spec => []Purity
THEOREM RootAgrees == Spec => []RootAgreement
THEOREM RootInjective == Spec => []StateRootInjective
=============================================================================
