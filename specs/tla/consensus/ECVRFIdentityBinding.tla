---- MODULE ECVRFIdentityBinding ----
\* RM-I-3 / WP-I1.5 — REM-N-01 (re-audit Stream 1):
\*
\* The ECVRF math at `core/consensus/src/ecvrf.rs::verify` accepts any
\* (alpha, proof) pair where the math is internally consistent under
\* `proof.pk_p256`. The math does NOT check that `proof.pk_p256` is
\* derived from, or attested by, the claimed proposer's ed25519
\* identity. An attacker with their own (sk_p256, pk_p256) pair can
\* sign alpha = (victim_ed25519_pk || prev_vrf || slot) under sk_p256,
\* set proof.pk_p256 = pk_p256, and have `verify_vrf_proof` accept.
\*
\* The structural binding lives at admission time via the block's
\* ed25519 signature. This spec asserts the safety property:
\*
\*   For every accepted block, the holder of the proposer's ed25519
\*   secret key produced both the block signature AND, by association,
\*   the ECVRF proof attached to the block.
\*
\* The Rust call site `verify_vrf_with_block_signature` in
\* `core/consensus/src/vrf.rs` enforces this by combining the ECVRF
\* check with an ed25519 signature check that covers the block's
\* signed payload (which commits to the ECVRF proof bytes).

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Validators,         \* set of legitimate validator identities (ed25519 pubkeys)
    Adversary,          \* the attacker
    InvalidProof,       \* sentinel for forged proofs the math accepts
    NoSig               \* sentinel for missing or wrong ed25519 signature

ASSUME Adversary \notin Validators

VARIABLES
    submitted_proof,    \* the ECVRF proof attached to the candidate block
    submitted_pk_p256,  \* P-256 key claimed by the proof (could be attacker's)
    claimed_proposer,   \* ed25519 pubkey the block claims as proposer
    block_signature,    \* ed25519 signature over the block payload
    accepted            \* TRUE iff admission accepts the block

\* The set of all P-256 pubkeys an actor *can* present.
P256Keys == { "honest_p256", "adversary_p256" }

\* The signature an actor produces over the block payload — only the
\* holder of the corresponding ed25519 secret key can produce a valid
\* signature for that pubkey.
ValidEd25519Signature(actor, payload) ==
    \* Abstract: a signature is "valid" iff the actor matches the
    \* claimed proposer. Models the property of ed25519: only the
    \* holder of the secret key can sign.
    actor = claimed_proposer

\* Math acceptance — the ECVRF math accepts as long as proof.pk_p256
\* is internally consistent. This is INDEPENDENT of who the claimed
\* proposer is, capturing the REM-N-01 bug shape.
ECVRFMathAccepts(proof, pk_p256, alpha) ==
    proof # InvalidProof

\* Pre-fix admission: only checks the math. Adversary wins by
\* substituting their own pk_p256.
PreFixAccepts(proof, pk_p256, claimed, sig) ==
    ECVRFMathAccepts(proof, pk_p256, "alpha")

\* Post-fix admission: requires BOTH math AND ed25519 signature
\* match the claimed proposer.
PostFixAccepts(proof, pk_p256, claimed, sig) ==
    /\ ECVRFMathAccepts(proof, pk_p256, "alpha")
    /\ sig # NoSig
    /\ ValidEd25519Signature(sig, "block_payload")

\* Initial state: no proof submitted, no signature.
Init ==
    /\ submitted_proof = InvalidProof
    /\ submitted_pk_p256 = "honest_p256"
    /\ claimed_proposer \in Validators
    /\ block_signature = NoSig
    /\ accepted = FALSE

\* Adversary action: submits a proof with their own P-256 key and
\* claims a victim's ed25519 identity. Tries to forge the block
\* signature (always fails for adversary).
AdversarySubmits ==
    /\ submitted_proof' = "forged_under_adversary_p256"
    /\ submitted_pk_p256' = "adversary_p256"
    /\ \E victim \in Validators : claimed_proposer' = victim
    /\ block_signature' = NoSig  \* adversary cannot produce victim's ed25519 sig
    /\ accepted' = PostFixAccepts(submitted_proof', submitted_pk_p256',
                                  claimed_proposer', block_signature')

\* Honest validator action: submits a proof and a valid signature
\* under their own ed25519 identity.
HonestSubmits ==
    /\ \E v \in Validators :
        /\ submitted_proof' = "honest_proof"
        /\ submitted_pk_p256' = "honest_p256"
        /\ claimed_proposer' = v
        /\ block_signature' = v   \* signature == claimed proposer (valid)
    /\ accepted' = PostFixAccepts(submitted_proof', submitted_pk_p256',
                                  claimed_proposer', block_signature')

Next == AdversarySubmits \/ HonestSubmits

\* Safety invariant — REM-N-01: for every accepted block, the holder
\* of the claimed proposer's ed25519 secret key produced the
\* signature. Equivalently: if `accepted = TRUE`, then `block_signature
\* = claimed_proposer` (since only that signer can produce a valid
\* signature for that pubkey under our ed25519 abstraction).
IdentityBindingHolds ==
    accepted => block_signature = claimed_proposer

\* Safety invariant: a forged proof under the adversary's pk_p256
\* combined with no valid ed25519 signature MUST be rejected.
\* (The pre-fix verifier WOULD accept this; the post-fix verifier
\* rejects it.)
NoForgedAcceptance ==
    (submitted_pk_p256 = "adversary_p256" /\ block_signature = NoSig)
        => ~accepted

Spec == Init /\ [][Next]_<<submitted_proof, submitted_pk_p256,
                          claimed_proposer, block_signature, accepted>>

THEOREM Spec => []IdentityBindingHolds
THEOREM Spec => []NoForgedAcceptance

====
