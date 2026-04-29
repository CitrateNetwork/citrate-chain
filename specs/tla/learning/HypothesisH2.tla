------------------------------ MODULE HypothesisH2 ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

(***********************************************************************
* RM-FL-5 / WP-5.1 — TLA+ formalization of Hypothesis H2 from Paper II §4.
*
* HYPOTHESIS (informal): Aggregate inference accuracy on the union
* test set is monotonically non-decreasing in the number of
* registered LoRA adapters. Stated as a power law:
*       acc(N) = α − β × N^{−γ}      (β, γ > 0; α ≤ 1.0)
* where N is the number of distinct adapters composed at inference
* time, and the experiment fits (α, β, γ) and a 95% CI.
*
* WHAT TLA+ CHECKS
* ----------------
* The statistical claim — fitting a power law — is empirical and
* lives in WP-5.5. The protocol-side claim TLA+ verifies is the
* WEAK MONOTONICITY of the composition operator: adding a new
* adapter that has been verified by `0x0108` and registered via
* `LoRAFactory` cannot DECREASE the aggregate accuracy floor —
* worst case the new adapter is ignored at routing time.
*
* If weak monotonicity fails at the protocol level, the power-law
* fit in WP-5.5 cannot be supported regardless of measurement.
* If weak monotonicity holds, the experiment measures HOW MUCH
* accuracy gain is achieved, not WHETHER any gain is possible.
*
* WHAT WE MODEL
* -------------
*   - A registry of adapters with verification flag (mirrors
*     LoRAFactory.adapterProofVerified from RM-FL-4 / WP-4.7).
*   - A registration action that requires a verified proof.
*   - An accuracy-floor operator that accepts a set of registered
*     adapters and returns the floor any well-formed routing
*     algorithm must achieve (max of per-adapter accuracies, since
*     the routing policy can always select the best adapter on a
*     given input).
*   - A monotonicity invariant: the accuracy floor is
*     non-decreasing as adapters are added.
*
* OPERATOR-VS-VARIABLE PRINCIPLE
* ------------------------------
* The accuracy floor is computed via an OPERATOR (AccuracyFloor)
* over the registry; the registry is the only VARIABLE. Adapter
* accuracies are CONSTANTS, fixed at registration time and stored
* immutably in the spec. This pins TLC's state space to
* O(2^|Adapters|) — bounded by the powerset of registered adapters.
***********************************************************************)

CONSTANTS
    Adapters,             \* SET of adapter IDs to consider
    AdapterAccuracy,      \* function: Adapters -> Nat (Q16)
    MaxAccuracy,          \* Q16 max — typically 65536 (1.0)
    MaxRegistrations      \* state-space bound

ASSUME Adapters # {}
ASSUME MaxAccuracy \in Nat /\ MaxAccuracy >= 1
ASSUME MaxRegistrations \in Nat /\ MaxRegistrations >= 1
ASSUME AdapterAccuracy \in [Adapters -> 0..MaxAccuracy]

\* TLC config-file friendly accuracy table override. Used only when
\* the cfg sets `CONSTANT AdapterAccuracy <- AdapterAccuracyImpl`.
\* Keep the values monotonic enough to exercise both "new adapter
\* improves the floor" and "new adapter is dominated" branches of
\* AccuracyFloorMonotonic.
AdapterAccuracyImpl ==
    [ a \in Adapters |->
        IF a = "a1" THEN 2
        ELSE IF a = "a2" THEN 4
        ELSE IF a = "a3" THEN 3
        ELSE 5 ]

VARIABLES
    registered,           \* SUBSET Adapters — currently registered
    verifiedProofCount    \* Nat — total verifications performed

vars == << registered, verifiedProofCount >>

\* Initial state: no adapters registered, no proofs.
Init ==
    /\ registered = {}
    /\ verifiedProofCount = 0

\* Accuracy floor over a set of adapters: the best per-adapter
\* accuracy. Any routing policy that knows which adapter to call
\* on a given input achieves at least this floor. With zero
\* registered adapters, the floor is 0 (no adapter to route to).
RECURSIVE AccuracyFloor(_)
AccuracyFloor(S) ==
    IF S = {} THEN 0
    ELSE LET x == CHOOSE x \in S: TRUE
             rest == AccuracyFloor(S \ {x}) IN
         IF AdapterAccuracy[x] > rest
            THEN AdapterAccuracy[x]
            ELSE rest

\* Verify a candidate adapter (mirrors `0x0108 INFERENCE_PROOF_VERIFY`).
\* In the spec, verification is an action that increments the count
\* and is the ONLY way an adapter can be subsequently registered.
VerifyAdapter(a) ==
    /\ a \in Adapters
    /\ a \notin registered
    /\ verifiedProofCount < MaxRegistrations
    /\ verifiedProofCount' = verifiedProofCount + 1
    /\ UNCHANGED registered

\* Register a verified adapter. Cannot register without a
\* corresponding proof verification (precondition).
\* In the contract, `LoRAFactory.adapterProofVerified[a]` must be
\* TRUE before the adapter is consumable; we model this as
\* "verifications-so-far must exceed registrations-so-far".
RegisterAdapter(a) ==
    /\ a \in Adapters
    /\ a \notin registered
    /\ Cardinality(registered) < verifiedProofCount
    /\ Cardinality(registered) < MaxRegistrations
    /\ registered' = registered \cup {a}
    /\ UNCHANGED verifiedProofCount

\* No deregistration: once registered, an adapter stays in the
\* set. This mirrors the chain-canonical principle from RM-FL-3 /
\* THE_TRAINING_DAEMON_BET — committed adapters are not retracted.
\* Deregistration would require a separate governance ceremony.

Next ==
    \/ \E a \in Adapters: VerifyAdapter(a)
    \/ \E a \in Adapters: RegisterAdapter(a)

Spec == Init /\ [][Next]_vars

(***********************************************************************
* INVARIANTS
***********************************************************************)

\* Type invariant.
TypeOK ==
    /\ registered \subseteq Adapters
    /\ verifiedProofCount \in 0..MaxRegistrations

\* Verification precondition: every registered adapter has a
\* corresponding verification.
EveryRegisteredAdapterIsVerified ==
    Cardinality(registered) <= verifiedProofCount

\* Bounded growth: registered size never exceeds the cap.
RegisteredBounded ==
    Cardinality(registered) <= MaxRegistrations

\* Composition monotonicity (the H2 protocol-side claim):
\* The accuracy floor under any superset of registered adapters
\* is at least the accuracy floor under the subset. Stated as an
\* always-true property over the current registered set vs all
\* its subsets.
\*
\* This is the necessary protocol-level condition for a
\* well-defined accuracy-vs-N curve. If it ever fails, the H2
\* power-law fit in WP-5.5 is unsupported regardless of
\* empirical measurement.
AccuracyFloorMonotonic ==
    \A S \in SUBSET registered:
        AccuracyFloor(S) <= AccuracyFloor(registered)

\* Empty-floor sanity: with no adapters registered, the routing
\* policy has nothing to call, so the floor is exactly zero.
\* This pins the experimental baseline at N=0.
EmptyFloorIsZero ==
    registered = {} => AccuracyFloor(registered) = 0

\* Non-degenerate: the accuracy floor for non-empty registered
\* sets is at most MaxAccuracy (sanity bound on the operator).
FloorBounded ==
    AccuracyFloor(registered) \in 0..MaxAccuracy

THEOREM Safety ==
    Spec => [](
        TypeOK
        /\ EveryRegisteredAdapterIsVerified
        /\ RegisteredBounded
        /\ AccuracyFloorMonotonic
        /\ EmptyFloorIsZero
        /\ FloorBounded
    )

==========================================================================
