------------------------- MODULE RewardApplyPurity -------------------------
(***************************************************************************)
(* SRP-S2 — Reward-settlement State-Root Purity across roles that re-apply  *)
(* the SAME block (produce / receive / cold-sync / restart / reorg).        *)
(*                                                                          *)
(* WHY THIS SPEC EXISTS (the bug it pins — block 2209, chain 40204):        *)
(*   SRP-S1 proved the FORWARD state root is a pure function of committed    *)
(*   accounts. It did NOT cover reward SETTLEMENT across roles. Block 2209   *)
(*   split the fleet on exactly that gap:                                    *)
(*     The block PRODUCER selects its reward path on a TRANSIENT, node-local *)
(*     runtime flag (`emit_v2_headers`) rather than from committed consensus *)
(*     state. When that flag is unset the producer takes an "enhanced"       *)
(*     reward path that credits a value derived from NODE-LOCAL, non-        *)
(*     consensus state (economics-manager staked balance, an f64 reputation  *)
(*     score, dynamic gas pricing) directly to the validator — with NO       *)
(*     treasury credit and NO on-book settlement.                            *)
(*     A RECEIVER (or cold-sync / restart / reorg) re-applying the same      *)
(*     block always uses the canonical committed-state BASIC reward path     *)
(*     (fixed 9 SALT validator + 1 SALT treasury), which cannot reproduce    *)
(*     the producer's credit → the two roles compute DIFFERENT reward-       *)
(*     settled roots for the SAME block → StateRootMismatch → split-brain.   *)
(*                                                                          *)
(* MODEL:                                                                    *)
(*   Every role applies the same block by SETTLING a reward from one of two  *)
(*   input SOURCES:                                                          *)
(*     Committed — reward derived purely from committed state (block height  *)
(*                 + committed policy): fixed BasicReward to the validator,  *)
(*                 BasicTreasury to the treasury. Deterministic, identical   *)
(*                 across every role.                                        *)
(*     NodeLocal — the enhanced path: a transient/node-local value credited  *)
(*                 to the validator only, no treasury slice, off-book.       *)
(*                 Non-reproducible: distinct roles can settle distinct       *)
(*                 values for the same block.                                *)
(*   CONSTANT AllowNodeLocal toggles whether the NodeLocal path is reachable:*)
(*     TRUE  models `main` today (the enhanced path exists) → the counter-   *)
(*           example below is reachable and RewardRootAgreement is VIOLATED.  *)
(*     FALSE models the fix (enhanced path removed; every role settles from  *)
(*           Committed) → all invariants hold, TLC finds no error.           *)
(*                                                                          *)
(* SAFETY (must hold after the fix; VIOLATED by the enhanced path today):    *)
(*   Purity              : root[r] = StateRootFor(post-reward committed acct) *)
(*   RewardRootAgreement : roles that applied the SAME block (same height)    *)
(*                         hold the SAME reward-settled root. Guaranteed iff  *)
(*                         every role settled from committed state.           *)
(*   BalanceConservation : settlement MINTS exactly the committed reward —    *)
(*                         supply is on-book, no off-book node-local credit.  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Roles,            \* node roles that must all agree on the same block:
                      \* producer, receiver, coldsync, restart, reorg
    Validator,        \* the reward beneficiary account
    Treasury,         \* the treasury slice beneficiary
    BasicReward,      \* committed validator reward (Nat > 0)
    BasicTreasury,    \* committed treasury slice   (Nat >= 0)
    NodeLocalRewards, \* set of possible enhanced-path (node-local) credits
    MaxBlocks,        \* model bound on chain height
    AllowNodeLocal    \* TRUE = buggy model (enhanced path reachable);
                      \* FALSE = fixed model (committed-only settlement)

ASSUME BasicReward \in Nat /\ BasicReward > 0
ASSUME BasicTreasury \in Nat
ASSUME NodeLocalRewards \subseteq Nat
ASSUME MaxBlocks \in Nat /\ MaxBlocks > 0
ASSUME AllowNodeLocal \in BOOLEAN

VARIABLES
    applied,          \* blocks each role has settled: Roles -> Nat
    bal,              \* committed balances: Roles -> [Accounts -> Nat]
    root              \* reward-settled state root each role holds: Roles -> Nat

vars == <<applied, bal, root>>

Accounts == {Validator, Treasury}

(*-----------------------------------------------------------------------*)
(* StateRootFor: the root is a PURE, injective function of the committed   *)
(* account set (in code: a Merkle root over full committed account state). *)
(* Distinct committed balance maps MUST yield distinct roots.             *)
(*-----------------------------------------------------------------------*)
StateRootFor(balances) == balances[Validator] * 1000 + balances[Treasury]

(*-----------------------------------------------------------------------*)
(* Committed settlement (§R' basic path): fixed reward from committed      *)
(* policy — identical on every role by construction.                       *)
(*-----------------------------------------------------------------------*)
CommittedCredit(b) ==
    [b EXCEPT ![Validator] = b[Validator] + BasicReward,
              ![Treasury]  = b[Treasury]  + BasicTreasury]

(*-----------------------------------------------------------------------*)
(* NodeLocal settlement (enhanced path): a transient node-local value      *)
(* credited to the validator only — NO treasury slice, off-book. This is   *)
(* the block-2209 producer credit no clean re-applier can reproduce.       *)
(*-----------------------------------------------------------------------*)
NodeLocalCredit(b, nl) ==
    [b EXCEPT ![Validator] = b[Validator] + nl]

Init ==
    /\ applied = [r \in Roles |-> 0]
    /\ bal     = [r \in Roles |-> [a \in Accounts |-> 0]]
    /\ root    = [r \in Roles |-> StateRootFor([a \in Accounts |-> 0])]

\* Settle the next block from COMMITTED state: deterministic, reproducible.
SettleCommitted(r) ==
    /\ applied[r] < MaxBlocks
    /\ LET nb == CommittedCredit(bal[r]) IN
        /\ bal'     = [bal     EXCEPT ![r] = nb]
        /\ root'    = [root    EXCEPT ![r] = StateRootFor(nb)]
        /\ applied' = [applied EXCEPT ![r] = applied[r] + 1]

\* Settle the next block from NODE-LOCAL state: reachable only in the buggy
\* model. Different roles may pick different values for the SAME block.
SettleNodeLocal(r) ==
    /\ AllowNodeLocal
    /\ applied[r] < MaxBlocks
    /\ \E nl \in NodeLocalRewards :
        LET nb == NodeLocalCredit(bal[r], nl) IN
        /\ bal'     = [bal     EXCEPT ![r] = nb]
        /\ root'    = [root    EXCEPT ![r] = StateRootFor(nb)]
        /\ applied' = [applied EXCEPT ![r] = applied[r] + 1]

\* All roles at the height bound: stutter (bounded-model termination, not a
\* real deadlock — every reachable state still satisfies the invariants).
Terminating == (\A r \in Roles : applied[r] = MaxBlocks) /\ UNCHANGED vars

Next == (\E r \in Roles : SettleCommitted(r) \/ SettleNodeLocal(r)) \/ Terminating

Spec == Init /\ [][Next]_vars

(*----------------------------- Invariants ------------------------------*)

TypeOK ==
    /\ applied \in [Roles -> 0..MaxBlocks]
    /\ bal \in [Roles -> [Accounts -> Nat]]
    /\ root \in [Roles -> Nat]

\* PURITY: every role's reward-settled root is exactly StateRootFor of its
\* own committed balances — the root carries no hidden state. Holds in BOTH
\* models by construction (root is always recomputed from committed `bal`);
\* the divergence lives in `bal`, not in a stale trie.
Purity == \A r \in Roles : root[r] = StateRootFor(bal[r])

\* REWARD-ROOT AGREEMENT (the key one): any two roles that have applied the
\* SAME number of blocks (the same block height) hold the SAME reward-settled
\* root. This is guaranteed IFF every role settled from committed state.
\*   - Committed-only model: same height => same committed reward => same
\*     balances => same root. Invariant HOLDS.
\*   - Enhanced-path model: one role settles block h from NodeLocal while
\*     another settles it from Committed (or a different node-local value) =>
\*     same height, DIFFERENT roots => StateRootMismatch. Invariant VIOLATED
\*     — exactly the block-2209 split-brain.
RewardRootAgreement ==
    \A r1, r2 \in Roles :
        (applied[r1] = applied[r2] /\ applied[r1] > 0)
            => (root[r1] = root[r2])

\* BALANCE CONSERVATION: settlement mints exactly the committed reward, so a
\* role that has applied h blocks holds exactly h*(BasicReward+BasicTreasury)
\* of newly minted supply. The NodeLocal path credits an off-book amount with
\* no treasury slice and violates this.
BalanceConservation ==
    \A r \in Roles :
        bal[r][Validator] + bal[r][Treasury]
            = applied[r] * (BasicReward + BasicTreasury)

THEOREM Spec => []TypeOK
THEOREM PurityHolds == Spec => []Purity
THEOREM RewardRootAgrees == Spec => []RewardRootAgreement
THEOREM BalanceConserved == Spec => []BalanceConservation
=============================================================================
