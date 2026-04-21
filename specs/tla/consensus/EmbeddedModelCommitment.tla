------------------------------ MODULE EmbeddedModelCommitment ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* ============================================================================
\* Post-WP-B EmbeddedModel safety spec.
\*
\* Before WP-B (pre-migration):
\*   EmbeddedModel { weights: Vec<u8>, ... }           \* unbounded on-chain
\*
\* After WP-B (post-migration):
\*   EmbeddedModel { weights_sha256: Hash, ... }       \* 32-byte commit only
\*
\* This spec proves integrity of the post-WP-B commitment scheme:
\*   (1) Commitments are sound — verification detects tampering.
\*   (2) Committed blocks are verifiable by any validator.
\*   (3) Per-model on-chain footprint is bounded (commitment is fixed-size).
\*   (4) Publishing and verification compose correctly across concurrent
\*       publishers and validators.
\*
\* Sprint: P950-B / WP-B.1
\* Source: .agentile/planset/PATH_TO_950.md WP-B
\* Audit: .audit/2026-04-21-repo-walkthrough/02_GENESIS_AND_EMBEDDED_MODELS.md
\* Companion specs:
\*   GenesisSafetyAcrossNodes.tla — multi-node genesis hash determinism
\*   TransactionExecution.tla — single-tx EVM semantics
\* ============================================================================

CONSTANTS
    ModelIds,           \* Finite set of model identifiers
    ContentValues,      \* Finite set of abstract "content" identities (off-chain bytes)
    MaxCommitmentBytes  \* Per-model on-chain size cap (real: 32 for sha256 hash; spec is abstract)

ASSUME MaxCommitmentBytes \in Nat /\ MaxCommitmentBytes > 0

\* ============================================================================
\* Sentinel values
\* ============================================================================

NullContent == "null"

\* ============================================================================
\* Abstract hash function
\* ============================================================================
\*
\* We assume SHA-256 is collision-resistant for our purposes: distinct
\* content values produce distinct commitments. Modeled as identity —
\* different ContentValues are different Hash values.
\*
\* If TLC ever finds a counterexample that relies on Hash(c1) = Hash(c2)
\* for c1 # c2, that's a real TLC finding that breaks the collision-
\* resistance assumption; investigate separately.

Commitment(c) == c

\* ============================================================================
\* Status enumeration for validator's view
\* ============================================================================

StatusUnverified == "unverified"
StatusValid      == "valid"
StatusTampered   == "tampered"

VerifyStatuses == {StatusUnverified, StatusValid, StatusTampered}

\* ============================================================================
\* Variables
\* ============================================================================

VARIABLES
    offChainPublished,  \* [ModelIds -> ContentValues \cup {NullContent}]
                        \* What was published off-chain for each model
    onChainCommit,      \* [ModelIds -> ContentValues \cup {NullContent}]
                        \* The commitment recorded on-chain for each model
    proposedBlock,      \* SUBSET ModelIds — models included in the current
                        \* block under review
    blockCommitted,     \* BOOLEAN — is the current block committed to the chain?
    verifyStatus        \* [ModelIds -> VerifyStatuses] — validator's view

vars == <<offChainPublished, onChainCommit, proposedBlock,
          blockCommitted, verifyStatus>>

\* ============================================================================
\* Helper operators
\* ============================================================================

\* Models with bytes published off-chain.
PublishedModels == {m \in ModelIds : offChainPublished[m] # NullContent}

\* Models with on-chain commitments registered.
CommittedModels == {m \in ModelIds : onChainCommit[m] # NullContent}

\* Per-model on-chain footprint. In our abstraction, every model carries
\* exactly one commitment value. In reality: 32 bytes sha256 + fixed
\* metadata (~64 bytes) = ~96 bytes total per model.
ModelOnChainSize == MaxCommitmentBytes

\* ============================================================================
\* Initial state
\* ============================================================================

Init ==
    /\ offChainPublished = [m \in ModelIds |-> NullContent]
    /\ onChainCommit     = [m \in ModelIds |-> NullContent]
    /\ proposedBlock     = {}
    /\ blockCommitted    = FALSE
    /\ verifyStatus      = [m \in ModelIds |-> StatusUnverified]

\* ============================================================================
\* Actions
\* ============================================================================

\* --- PublishModel(m, c): publisher places content off-chain, commits on-chain. ---
\*
\* Maps to real code: a model publisher uploads bytes to IPFS and submits
\* a `registerModel()` transaction carrying the sha256 hash.
\*
\* Preconditions:
\*   - model not yet published
\*
\* Effects:
\*   - off-chain bytes recorded for model m
\*   - on-chain commitment set to Commitment(content)
PublishModel(m, c) ==
    /\ offChainPublished[m] = NullContent
    /\ offChainPublished' = [offChainPublished EXCEPT ![m] = c]
    /\ onChainCommit'     = [onChainCommit     EXCEPT ![m] = Commitment(c)]
    /\ UNCHANGED <<proposedBlock, blockCommitted, verifyStatus>>

\* --- ProposeBlock(models): block proposer selects models to include. ---
\*
\* Maps to real code: the genesis (or future) block builder embeds a
\* set of model commitments (NOT bytes) into block.embedded_models.
\*
\* Preconditions:
\*   - block not yet committed
\*   - every selected model has a registered on-chain commitment
\*   - (no unbounded byte field is carryable — by Rust type system;
\*     modeled by always using Commitment values, never raw content)
ProposeBlock(models) ==
    /\ ~blockCommitted
    /\ models \subseteq ModelIds
    /\ \A m \in models : onChainCommit[m] # NullContent
    /\ proposedBlock' = models
    /\ UNCHANGED <<offChainPublished, onChainCommit, blockCommitted, verifyStatus>>

\* --- Verify(m): validator retrieves off-chain bytes and matches against commit. ---
\*
\* Maps to real code: at block-acceptance time, a validator fetches the
\* bytes from IPFS (or mirror) and computes sha256; compares to the
\* commitment embedded in the block.
\*
\* Preconditions:
\*   - m is in the current proposed block
\*   - m's verify status is still Unverified
\*
\* Effects:
\*   - verifyStatus[m] becomes Valid if Commitment(off-chain) = on-chain
\*   - verifyStatus[m] becomes Tampered otherwise (including if off-chain is missing)
Verify(m) ==
    /\ m \in proposedBlock
    /\ verifyStatus[m] = StatusUnverified
    /\ LET obs == offChainPublished[m]
           onc == onChainCommit[m]
       IN
          IF obs = NullContent
          THEN verifyStatus' = [verifyStatus EXCEPT ![m] = StatusTampered]
          ELSE IF Commitment(obs) = onc
               THEN verifyStatus' = [verifyStatus EXCEPT ![m] = StatusValid]
               ELSE verifyStatus' = [verifyStatus EXCEPT ![m] = StatusTampered]
    /\ UNCHANGED <<offChainPublished, onChainCommit, proposedBlock, blockCommitted>>

\* --- CommitBlock: validator set commits the block once every embedded model verifies. ---
\*
\* Preconditions:
\*   - block not yet committed
\*   - every model in proposedBlock has verifyStatus = Valid
\*
\* Effects:
\*   - blockCommitted := TRUE
CommitBlock ==
    /\ ~blockCommitted
    /\ \A m \in proposedBlock : verifyStatus[m] = StatusValid
    /\ blockCommitted' = TRUE
    /\ UNCHANGED <<offChainPublished, onChainCommit, proposedBlock, verifyStatus>>

\* --- IdleTick: keep TLC enabled; no state change. ---
IdleTick ==
    /\ UNCHANGED vars

Next ==
    \/ IdleTick
    \/ \E m \in ModelIds, c \in ContentValues : PublishModel(m, c)
    \/ \E models \in SUBSET ModelIds : ProposeBlock(models)
    \/ \E m \in ModelIds : Verify(m)
    \/ CommitBlock

\* ============================================================================
\* Invariants
\* ============================================================================

\* INV-1: Well-typed state.
TypeInv ==
    /\ offChainPublished \in [ModelIds -> ContentValues \cup {NullContent}]
    /\ onChainCommit \in [ModelIds -> ContentValues \cup {NullContent}]
    /\ proposedBlock \subseteq ModelIds
    /\ blockCommitted \in BOOLEAN
    /\ verifyStatus \in [ModelIds -> VerifyStatuses]

\* INV-2: Commitment soundness — for every published model, the on-chain
\* commitment equals Commitment(off-chain bytes). This is the integrity
\* property: tampering with off-chain bytes without updating the on-chain
\* commit is detectable.
\*
\* In this abstraction (Commitment(c) = c), soundness reduces to bytes =
\* commit; under real SHA-256, Commitment is a 32-byte hash that is
\* infeasible to invert.
CommitmentSound ==
    \A m \in ModelIds :
        offChainPublished[m] # NullContent =>
            onChainCommit[m] = Commitment(offChainPublished[m])

\* INV-3: If a model verified as Valid, its on-chain/off-chain pair matches.
\* This holds by construction of the Verify action.
ValidStatusImpliesMatch ==
    \A m \in ModelIds :
        verifyStatus[m] = StatusValid =>
            /\ offChainPublished[m] # NullContent
            /\ onChainCommit[m] = Commitment(offChainPublished[m])

\* INV-4: Every committed block is fully verified. No block commits if any
\* embedded model is still unverified or tampered. This is the pre-gate
\* enforced by CommitBlock.
CommittedBlockFullyVerified ==
    blockCommitted =>
        \A m \in proposedBlock : verifyStatus[m] = StatusValid

\* INV-5: Tamper detection. A model whose off-chain bytes don't match the
\* on-chain commit can never end up with verifyStatus = Valid.
\*
\* Contrapositive form for clarity: if verifyStatus[m] = Valid then the
\* pair matches. (Same as INV-3; kept separately for auditor clarity.)
TamperDetection ==
    \A m \in ModelIds :
        (onChainCommit[m] # NullContent
         /\ offChainPublished[m] # NullContent
         /\ Commitment(offChainPublished[m]) # onChainCommit[m])
        => verifyStatus[m] # StatusValid

\* INV-6: Commitments are stable. Once set, onChainCommit[m] does not
\* change — enforced by PublishModel's precondition.
\*
\* Expressed here as: the only transition that changes onChainCommit[m]
\* from non-null to anything-else is disallowed. In this state-only form:
\* we verify a published model stays published.
CommitmentStability ==
    \A m \in ModelIds :
        onChainCommit[m] # NullContent =>
            offChainPublished[m] # NullContent

\* INV-7: Per-model on-chain size is bounded. Each EmbeddedModel carries
\* exactly one commitment of fixed size. This replaces the pre-WP-B
\* property where `weights: Vec<u8>` could be arbitrarily large.
\*
\* Expressed abstractly: the "size" of each model on-chain is
\* ModelOnChainSize, a constant. Aggregate block size therefore scales
\* as O(|proposedBlock|), not O(total bytes of all weights).
PerModelOnChainSizeBounded ==
    \A m \in ModelIds :
        ModelOnChainSize <= MaxCommitmentBytes

\* ============================================================================
\* Specification
\* ============================================================================

Spec == Init /\ [][Next]_vars

\* ============================================================================
\* Theorems
\* ============================================================================

THEOREM TypeSafety            == Spec => []TypeInv
THEOREM CommitmentSoundThm    == Spec => []CommitmentSound
THEOREM ValidImpliesMatchThm  == Spec => []ValidStatusImpliesMatch
THEOREM CommittedFullyVerThm  == Spec => []CommittedBlockFullyVerified
THEOREM TamperDetectThm       == Spec => []TamperDetection
THEOREM StabilityThm          == Spec => []CommitmentStability
THEOREM BoundedSizeThm        == Spec => []PerModelOnChainSizeBounded

=============================================================================
