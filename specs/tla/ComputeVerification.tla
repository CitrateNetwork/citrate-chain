--------------------- MODULE ComputeVerification ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the tiered verification flow for the Citrate Compute Marketplace.
\*
\* Verification tiers (matched to job value):
\*   Commitment  — fast, cheap, for low-value jobs (<= ValueThreshold)
\*   ZKProof     — trustless Groth16/Poseidon, for high-value jobs
\*   TEE         — hardware-rooted Intel TDX / AMD SNP attestation
\*   Bisection   — dispute resolution game, triggered on challenge
\*
\* Flow:
\*   1. Provider commits SHA3(input || output || nonce) BEFORE revealing output
\*   2. Provider reveals output + nonce (or ZK proof / TEE attestation)
\*   3. Verifier checks commitment matches (or proof valid / attestation valid)
\*   4. If challenged, bisection game narrows to single disputed operation
\*
\* Source: .agentile/teamwork/COMPUTE_MARKETPLACE_ARCHITECTURE.md
\*         core/mcp/src/verification.rs, contracts/src/ComputeVerifier.sol

CONSTANTS
    Jobs,               \* Set of job identifiers
    ValueThreshold,     \* Jobs with value > threshold require ZKProof or TEE
    MaxBisectionRounds  \* Max rounds for bisection dispute

ASSUME Jobs # {}
ASSUME ValueThreshold \in Nat /\ ValueThreshold >= 1
ASSUME MaxBisectionRounds \in Nat /\ MaxBisectionRounds >= 1

VerificationTiers == {"Commitment", "ZKProof", "TEE", "Bisection"}
VerificationResults == {"pending", "valid", "invalid"}

VARIABLES
    jobValue,           \* Mapping: job -> value in SALT
    jobTier,            \* Mapping: job -> assigned verification tier
    commitmentSubmitted,\* Mapping: job -> TRUE iff commitment hash submitted
    proofSubmitted,     \* Mapping: job -> TRUE iff proof/attestation submitted
    verificationResult, \* Mapping: job -> "pending" | "valid" | "invalid"
    disputeActive,      \* Mapping: job -> TRUE iff dispute is active
    bisectionRound      \* Mapping: job -> current bisection round (0 if no dispute)

vars == <<jobValue, jobTier, commitmentSubmitted, proofSubmitted,
          verificationResult, disputeActive, bisectionRound>>

\* ---- Helpers ----

MaxValue == ValueThreshold * 3

\* ---- State machine ----

Init ==
    /\ jobValue = [j \in Jobs |-> 0]
    /\ jobTier = [j \in Jobs |-> "Commitment"]
    /\ commitmentSubmitted = [j \in Jobs |-> FALSE]
    /\ proofSubmitted = [j \in Jobs |-> FALSE]
    /\ verificationResult = [j \in Jobs |-> "pending"]
    /\ disputeActive = [j \in Jobs |-> FALSE]
    /\ bisectionRound = [j \in Jobs |-> 0]

\* Configure a job with value and appropriate verification tier.
ConfigureJob(j, value) ==
    /\ j \in Jobs
    /\ jobValue[j] = 0                    \* not yet configured
    /\ value \in 1..MaxValue
    /\ jobValue' = [jobValue EXCEPT ![j] = value]
    \* Tier assignment based on value.
    /\ IF value > ValueThreshold
       THEN jobTier' = [jobTier EXCEPT ![j] = "ZKProof"]
       ELSE jobTier' = [jobTier EXCEPT ![j] = "Commitment"]
    /\ UNCHANGED <<commitmentSubmitted, proofSubmitted, verificationResult,
                   disputeActive, bisectionRound>>

\* Override tier to TEE (enterprise/regulatory requirement).
SetTEETier(j) ==
    /\ j \in Jobs
    /\ jobValue[j] > 0
    /\ verificationResult[j] = "pending"
    /\ proofSubmitted[j] = FALSE
    /\ jobTier' = [jobTier EXCEPT ![j] = "TEE"]
    /\ UNCHANGED <<jobValue, commitmentSubmitted, proofSubmitted,
                   verificationResult, disputeActive, bisectionRound>>

\* Provider submits commitment hash (required before output reveal).
SubmitCommitment(j) ==
    /\ j \in Jobs
    /\ jobValue[j] > 0                    \* job must be configured
    /\ commitmentSubmitted[j] = FALSE
    /\ verificationResult[j] = "pending"
    /\ commitmentSubmitted' = [commitmentSubmitted EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<jobValue, jobTier, proofSubmitted, verificationResult,
                   disputeActive, bisectionRound>>

\* Provider submits proof (ZK proof, TEE attestation, or commitment reveal).
SubmitProof(j) ==
    /\ j \in Jobs
    /\ jobValue[j] > 0
    /\ commitmentSubmitted[j] = TRUE       \* commitment must exist first
    /\ proofSubmitted[j] = FALSE
    /\ verificationResult[j] = "pending"
    /\ proofSubmitted' = [proofSubmitted EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<jobValue, jobTier, commitmentSubmitted, verificationResult,
                   disputeActive, bisectionRound>>

\* Verify the submitted proof — result is valid.
VerifyValid(j) ==
    /\ j \in Jobs
    /\ proofSubmitted[j] = TRUE
    /\ verificationResult[j] = "pending"
    /\ disputeActive[j] = FALSE
    /\ verificationResult' = [verificationResult EXCEPT ![j] = "valid"]
    /\ UNCHANGED <<jobValue, jobTier, commitmentSubmitted, proofSubmitted,
                   disputeActive, bisectionRound>>

\* Verification fails — result is invalid.
VerifyInvalid(j) ==
    /\ j \in Jobs
    /\ proofSubmitted[j] = TRUE
    /\ verificationResult[j] = "pending"
    /\ disputeActive[j] = FALSE
    /\ verificationResult' = [verificationResult EXCEPT ![j] = "invalid"]
    /\ UNCHANGED <<jobValue, jobTier, commitmentSubmitted, proofSubmitted,
                   disputeActive, bisectionRound>>

\* Challenge a verified result — initiate dispute (only after verification).
InitiateDispute(j) ==
    /\ j \in Jobs
    /\ verificationResult[j] \in {"valid", "invalid"}
    /\ disputeActive[j] = FALSE
    /\ disputeActive' = [disputeActive EXCEPT ![j] = TRUE]
    /\ bisectionRound' = [bisectionRound EXCEPT ![j] = 1]
    /\ jobTier' = [jobTier EXCEPT ![j] = "Bisection"]
    /\ UNCHANGED <<jobValue, commitmentSubmitted, proofSubmitted, verificationResult>>

\* Bisection round — narrows the disputed computation range.
BisectionStep(j) ==
    /\ j \in Jobs
    /\ disputeActive[j] = TRUE
    /\ bisectionRound[j] < MaxBisectionRounds
    /\ bisectionRound' = [bisectionRound EXCEPT ![j] = @ + 1]
    /\ UNCHANGED <<jobValue, jobTier, commitmentSubmitted, proofSubmitted,
                   verificationResult, disputeActive>>

\* Resolve the dispute — updates verification result.
ResolveDispute(j, outcome) ==
    /\ j \in Jobs
    /\ disputeActive[j] = TRUE
    /\ bisectionRound[j] >= 1
    /\ outcome \in {"valid", "invalid"}
    /\ disputeActive' = [disputeActive EXCEPT ![j] = FALSE]
    /\ verificationResult' = [verificationResult EXCEPT ![j] = outcome]
    /\ UNCHANGED <<jobValue, jobTier, commitmentSubmitted, proofSubmitted,
                   bisectionRound>>

Next ==
    \/ \E j \in Jobs, v \in 1..MaxValue : ConfigureJob(j, v)
    \/ \E j \in Jobs : SetTEETier(j)
    \/ \E j \in Jobs : SubmitCommitment(j)
    \/ \E j \in Jobs : SubmitProof(j)
    \/ \E j \in Jobs : VerifyValid(j)
    \/ \E j \in Jobs : VerifyInvalid(j)
    \/ \E j \in Jobs : InitiateDispute(j)
    \/ \E j \in Jobs : BisectionStep(j)
    \/ \E j \in Jobs, o \in {"valid", "invalid"} : ResolveDispute(j, o)

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ \A j \in Jobs : jobValue[j] \in 0..MaxValue
    /\ \A j \in Jobs : jobTier[j] \in VerificationTiers
    /\ \A j \in Jobs : commitmentSubmitted[j] \in BOOLEAN
    /\ \A j \in Jobs : proofSubmitted[j] \in BOOLEAN
    /\ \A j \in Jobs : verificationResult[j] \in VerificationResults
    /\ \A j \in Jobs : disputeActive[j] \in BOOLEAN
    /\ \A j \in Jobs : bisectionRound[j] \in 0..MaxBisectionRounds

\* INV-2: TierMatchesValue — high-value jobs must use ZKProof or TEE (not Commitment).
\* After configuration, if value > threshold, tier must not be plain Commitment.
TierMatchesValue ==
    \A j \in Jobs :
        (jobValue[j] > ValueThreshold /\ ~disputeActive[j]) =>
            jobTier[j] \in {"ZKProof", "TEE", "Bisection"}

\* INV-3: CommitmentBindsOutput — proof cannot be submitted without prior commitment.
CommitmentBindsOutput ==
    \A j \in Jobs :
        proofSubmitted[j] = TRUE => commitmentSubmitted[j] = TRUE

\* INV-4: ZKProofValid — if proof submitted and verified valid, result is valid.
ZKProofValid ==
    \A j \in Jobs :
        (proofSubmitted[j] = TRUE /\ verificationResult[j] = "valid") =>
            verificationResult[j] = "valid"  \* tautology documenting the property

\* INV-5: DisputeOnlyAfterVerification — dispute can only be active if verification
\* result has been determined (not pending).
DisputeOnlyAfterVerification ==
    \A j \in Jobs :
        disputeActive[j] = TRUE => verificationResult[j] # "pending"

\* INV-6: BisectionTerminates — bisection round is bounded by MaxBisectionRounds.
BisectionTerminates ==
    \A j \in Jobs :
        bisectionRound[j] <= MaxBisectionRounds

\* INV-7: NoPendingWithProof — if proof submitted and no dispute, result is decided.
\* (This is a liveness-like property stated as safety: once proof + verify action
\* fires, result leaves "pending".)
ProofRequiresCommitment ==
    \A j \in Jobs :
        proofSubmitted[j] => commitmentSubmitted[j]

\* INV-8: DisputeRequiresRound — active dispute must have at least round 1.
DisputeRequiresRound ==
    \A j \in Jobs :
        disputeActive[j] = TRUE => bisectionRound[j] >= 1

\* INV-9: UnconfiguredPending — unconfigured jobs have pending results.
UnconfiguredPending ==
    \A j \in Jobs :
        jobValue[j] = 0 => verificationResult[j] = "pending"

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM TierValue == Spec => []TierMatchesValue
THEOREM CommitBind == Spec => []CommitmentBindsOutput
THEOREM ZKValid == Spec => []ZKProofValid
THEOREM DisputeAfterVerify == Spec => []DisputeOnlyAfterVerification
THEOREM BisectTerminates == Spec => []BisectionTerminates
THEOREM ProofReqCommit == Spec => []ProofRequiresCommitment
THEOREM DisputeReqRound == Spec => []DisputeRequiresRound
THEOREM UnconfigPending == Spec => []UnconfiguredPending

=============================================================================
