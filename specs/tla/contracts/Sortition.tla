--------------------------- MODULE Sortition ---------------------------
EXTENDS Integers, FiniteSets, TLC

\* Models verifiable committee selection from
\* contracts/src/quorum/Sortition.sol (citrate-quorum QRM-S6.8).
\*
\* The three invariants:
\*   SO-1  reproducibility — a finalized draw's seed is a pure function of
\*         public data, and it never changes once fixed.
\*   SO-2  one honest entropy contributor makes the draw unbiasable.  Modelled
\*         as: no seed is ever fixed unless EVERY commitment was revealed, so a
\*         contributor's value is either in the seed or the draw does not exist.
\*   SO-3  a draw that never reaches finality inside its window is VOID, not
\*         best-effort.  There is no path from a stalled draw to a committee.
\*
\* Source: contracts/src/quorum/Sortition.sol
\*   - openDraw, commit, reveal, finalize, void, selection

CONSTANTS
    Draws,            \* Bounded set of draw ids
    Actors,           \* Who may commit entropy
    MaxBlock,         \* Bound on the clock
    MinDelta,         \* openDraw -> targetBlock distance
    FinalityDelay,    \* targetBlock -> earliest finalize
    Horizon           \* blockhash horizon: past this, finalize is impossible

ASSUME Draws # {}
ASSUME Actors # {}
ASSUME MaxBlock \in Nat /\ MaxBlock >= 1
ASSUME MinDelta \in Nat /\ FinalityDelay \in Nat
ASSUME Horizon \in Nat /\ Horizon > FinalityDelay

VARIABLES
    state,            \* Draws -> {"None","Open","Final","Void"}
    target,           \* Draws -> target block
    committed,        \* Draws -> set of actors who committed
    revealed,         \* Draws -> set of actors who revealed
    seed,             \* Draws -> the fixed seed, or "unset"
    seedInputs,       \* Draws -> the reveal set the seed was fixed over
    finalizedAt,      \* Draws -> the block the seed was fixed in, or -1
    now               \* block number

vars == <<state, target, committed, revealed, seed, seedInputs, finalizedAt, now>>

Unset == "unset"

Init ==
    /\ state = [d \in Draws |-> "None"]
    /\ target = [d \in Draws |-> 0]
    /\ committed = [d \in Draws |-> {}]
    /\ revealed = [d \in Draws |-> {}]
    /\ seed = [d \in Draws |-> Unset]
    /\ seedInputs = [d \in Draws |-> {}]
    /\ finalizedAt = [d \in Draws |-> -1]
    /\ now = 0

\* ── Actions ─────────────────────────────────────────────────────────

Open(d, t) ==
    /\ state[d] = "None"
    /\ t >= now + MinDelta
    /\ t <= MaxBlock
    /\ state' = [state EXCEPT ![d] = "Open"]
    /\ target' = [target EXCEPT ![d] = t]
    /\ UNCHANGED <<committed, revealed, seed, seedInputs, finalizedAt, now>>

\* Commitments close at the target block: one made with the block hash in hand
\* would defeat the whole construction.
Commit(d, a) ==
    /\ state[d] = "Open"
    /\ now < target[d]
    /\ a \notin committed[d]
    /\ committed' = [committed EXCEPT ![d] = @ \cup {a}]
    /\ UNCHANGED <<state, target, revealed, seed, seedInputs, finalizedAt, now>>

Reveal(d, a) ==
    /\ state[d] = "Open"
    /\ now > target[d]
    /\ a \in committed[d]
    /\ a \notin revealed[d]
    /\ revealed' = [revealed EXCEPT ![d] = @ \cup {a}]
    /\ UNCHANGED <<state, target, committed, seed, seedInputs, finalizedAt, now>>

\* Finalize is only enabled inside the window AND with every commitment
\* revealed.  A withheld reveal cannot steer the draw; it can only kill it.
Finalize(d) ==
    /\ state[d] = "Open"
    /\ now >= target[d] + FinalityDelay
    /\ now <= target[d] + Horizon
    /\ revealed[d] = committed[d]
    /\ state' = [state EXCEPT ![d] = "Final"]
    /\ seed' = [seed EXCEPT ![d] = <<target[d], revealed[d]>>]
    /\ seedInputs' = [seedInputs EXCEPT ![d] = revealed[d]]
    /\ finalizedAt' = [finalizedAt EXCEPT ![d] = now]
    /\ UNCHANGED <<target, committed, revealed, now>>

\* Only once the draw can no longer be finalized — otherwise voiding would be a
\* way to cancel a draw somebody is about to lose.
Void(d) ==
    /\ state[d] = "Open"
    /\ now > target[d] + Horizon
    /\ state' = [state EXCEPT ![d] = "Void"]
    /\ UNCHANGED <<target, committed, revealed, seed, seedInputs, finalizedAt, now>>

Tick ==
    /\ now < MaxBlock
    /\ now' = now + 1
    /\ UNCHANGED <<state, target, committed, revealed, seed, seedInputs, finalizedAt>>

Next ==
    \/ \E d \in Draws, t \in 0..MaxBlock : Open(d, t)
    \/ \E d \in Draws, a \in Actors : Commit(d, a)
    \/ \E d \in Draws, a \in Actors : Reveal(d, a)
    \/ \E d \in Draws : Finalize(d)
    \/ \E d \in Draws : Void(d)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* ── Invariants ──────────────────────────────────────────────────────

TypeOK ==
    /\ now \in 0..MaxBlock
    /\ \A d \in Draws :
         /\ state[d] \in {"None", "Open", "Final", "Void"}
         /\ committed[d] \subseteq Actors
         /\ revealed[d] \subseteq committed[d]
         /\ finalizedAt[d] \in (-1)..MaxBlock

\* SO-1: a seed exists exactly when the draw is Final, and it is a function of
\* public inputs recorded at that moment.  Nothing else ever carries a seed.
SO1_SeedExistsOnlyWhenFinal ==
    \A d \in Draws :
        /\ (state[d] = "Final") <=> (seed[d] # Unset)
        /\ (state[d] = "Final") => seed[d] = <<target[d], seedInputs[d]>>

\* SO-2: every committed contributor's entropy is in the seed of any finalized
\* draw.  A contributor is never excluded, so one honest contributor is enough.
SO2_EveryCommitmentIsInTheSeed ==
    \A d \in Draws :
        (state[d] = "Final") => seedInputs[d] = committed[d]

\* SO-3: every finalized draw had its seed fixed INSIDE its window — never
\* early (before the target is BFT-final) and never late (past the horizon,
\* where there is no block hash to read).  A draw that missed the window has no
\* path to a committee at all.
\*
\* This is checked against the block the seed was actually fixed in, rather than
\* against the current state, because "it is Void now" would still hold for an
\* implementation that finalized late and voided afterwards.
SO3_FinalizedInsideItsWindow ==
    \A d \in Draws :
        (state[d] = "Final") =>
            /\ finalizedAt[d] >= target[d] + FinalityDelay
            /\ finalizedAt[d] <= target[d] + Horizon

SO3_NoCommitteeFromAStalledDraw ==
    \A d \in Draws :
        (state[d] = "Void") => seed[d] = Unset

\* Terminal states are terminal: Final and Void never become anything else.
\* (Checked as an action property below.)
StatesAreTerminal ==
    [][\A d \in Draws :
         /\ (state[d] = "Final") => state'[d] = "Final"
         /\ (state[d] = "Void") => state'[d] = "Void"]_vars

\* A seed, once fixed, never changes — the other half of SO-1.
SeedIsImmutable ==
    [][\A d \in Draws : (seed[d] # Unset) => seed'[d] = seed[d]]_vars

\* Commitments only close before the target block.
CommitmentsPrecedeTheTarget ==
    [][\A d \in Draws :
         (committed'[d] # committed[d]) => now < target[d]]_vars

=============================================================================
