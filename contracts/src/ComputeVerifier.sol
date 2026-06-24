// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";

/// @title ComputeVerifier — Tiered Verification Dispatch for Compute Marketplace
/// @notice Verifies compute job outputs using three tiers: Commitment, ZKProof, TEE.
///         Implements all 9 invariants from specs/tla/ComputeVerification.tla:
///           INV-1: TypeOK
///           INV-2: TierMatchesValue — high-value jobs must use ZKProof or TEE
///           INV-3: CommitmentBindsOutput — proof cannot be submitted without prior commitment
///           INV-4: ZKProofValid — verified proof => valid result
///           INV-5: DisputeOnlyAfterVerification — no dispute before verification result
///           INV-6: BisectionTerminates — bisection round bounded
///           INV-7: ProofRequiresCommitment — proof submission requires commitment
///           INV-8: DisputeRequiresRound — active dispute has at least round 1
///           INV-9: UnconfiguredPending — unconfigured jobs have pending results
///
/// @dev Adversarial invariants (from AdversarialCompute.tla) enforced:
///      - VerificationIntegrity: no false positive/negative via commitment hash binding
///      - NoFrontRunning: only marketplace contract can call verify functions
contract ComputeVerifier is ReentrancyGuard, Governable {
    // ============================================================
    // Types
    // ============================================================

    enum VerificationTier { Commitment, ZKProof, TEE }
    enum VerificationResult { Pending, Valid, Invalid }

    struct VerificationRecord {
        uint256 jobId;
        uint256 jobValue;              // SALT value of the job (for tier enforcement)
        VerificationTier tier;
        VerificationResult result;
        bytes32 commitmentHash;        // SHA3(input || output || nonce) submitted before execution
        bool commitmentSubmitted;      // INV-3, INV-7: must be true before proof
        bool proofSubmitted;           // Whether proof/attestation has been submitted
        bool disputeActive;            // INV-5: dispute only after verification
        uint256 bisectionRound;        // INV-6: bounded by MAX_BISECTION_ROUNDS
        address provider;              // Provider who submitted the commitment
        uint256 configuredAt;          // Block when job was configured (0 = unconfigured)
    }

    // ============================================================
    // Constants
    // ============================================================

    /// @notice Value threshold: jobs above this must use ZKProof or TEE (INV-2: TierMatchesValue)
    uint256 public constant VALUE_THRESHOLD = 10 ether;

    /// @notice Maximum bisection rounds for dispute resolution (INV-6: BisectionTerminates)
    uint256 public constant MAX_BISECTION_ROUNDS = 10;

    /// @notice Live Citrate INFERENCE_PROOF_VERIFY precompile (Halo2-KZG), 0x0108.
    /// @dev The Citrate compute marketplace IS an inference marketplace: a compute
    ///      job's ZK proof is an inference proof whose 3 public commitments are
    ///      (input, model, output). This precompile is the live Halo2-KZG verifier
    ///      (core/execution/src/precompiles/verify.rs). It supersedes the legacy
    ///      0x0104 SHA3-commitment STUB, which never performed real ZK verification
    ///      (D2 defect): high-value jobs routed to 0x0104 fell back to fake
    ///      verification. The ZK tier now targets 0x0108.
    address public constant INFERENCE_PROOF_VERIFY = address(0x0108);

    /// @notice circuit_version selecting the v1 inference VK + 3-commitment layout
    ///         on 0x0108 (see verify.rs CIRCUIT_VERSION_LINEAR_Q16).
    uint32 internal constant INFERENCE_CIRCUIT_V1 = 1;

    /// @notice Exact byte length of the ZK-tier publicInputs blob:
    ///         input_commitment(32) ‖ model_commitment(32) ‖ output_commitment(32).
    uint256 internal constant ZK_PUBLIC_INPUTS_LEN = 96;

    // ============================================================
    // State
    // ============================================================

    /// @notice Verification records indexed by job ID
    mapping(uint256 => VerificationRecord) public records;

    /// @notice The ComputeMarketplace contract (only caller for verification actions)
    address public marketplace;

    // Governance state lives in Governable mixin (audit SOL-21).

    /// @notice Trusted TEE attestation oracles
    mapping(address => bool) public teeOracles;
    uint256 public teeOracleCount;

    /// @notice Total jobs verified
    uint256 public totalVerified;

    // ============================================================
    // Events
    // ============================================================

    event JobConfigured(uint256 indexed jobId, uint256 value, VerificationTier tier);
    event CommitmentSubmitted(uint256 indexed jobId, address indexed provider, bytes32 commitmentHash);
    event ProofSubmitted(uint256 indexed jobId, VerificationTier tier);
    event VerificationCompleted(uint256 indexed jobId, VerificationResult result);
    event DisputeInitiated(uint256 indexed jobId, uint256 round);
    event BisectionStep(uint256 indexed jobId, uint256 round);
    event DisputeResolved(uint256 indexed jobId, VerificationResult outcome);
    event TierOverridden(uint256 indexed jobId, VerificationTier oldTier, VerificationTier newTier);
    event TEEOracleAdded(address indexed oracle);
    event TEEOracleRemoved(address indexed oracle);
    event MarketplaceUpdated(address indexed oldMarketplace, address indexed newMarketplace);
    // GovernanceTransferred event is provided by Governable mixin.

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyMarketplace() {
        require(msg.sender == marketplace, "ComputeVerifier: caller is not marketplace");
        _;
    }

    // `onlyGovernance` is inherited from Governable.

    modifier jobConfigured(uint256 jobId) {
        require(records[jobId].configuredAt > 0, "ComputeVerifier: job not configured");
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    constructor(address _marketplace) Governable(msg.sender) {
        require(_marketplace != address(0), "ComputeVerifier: zero marketplace address");
        marketplace = _marketplace;
    }

    // ============================================================
    // Configuration (called by marketplace when job is posted)
    // ============================================================

    /// @notice Configure verification for a job. Assigns tier based on value.
    /// @param jobId The job identifier
    /// @param value The SALT value of the job (determines minimum tier)
    /// @param requestedTier The tier requested by the job poster
    /// @dev INV-2: TierMatchesValue — high-value jobs auto-upgrade to ZKProof
    /// @dev INV-9: UnconfiguredPending — unconfigured jobs have Pending result
    function configureJob(
        uint256 jobId,
        uint256 value,
        VerificationTier requestedTier
    ) external onlyMarketplace {
        require(records[jobId].configuredAt == 0, "ComputeVerifier: already configured");
        require(value > 0, "ComputeVerifier: zero value");

        // INV-2: TierMatchesValue — enforce minimum tier based on value
        VerificationTier effectiveTier = requestedTier;
        if (value > VALUE_THRESHOLD && requestedTier == VerificationTier.Commitment) {
            effectiveTier = VerificationTier.ZKProof;
        }

        // Initialize record field-by-field to reduce stack pressure
        VerificationRecord storage rec = records[jobId];
        rec.jobId = jobId;
        rec.jobValue = value;
        rec.tier = effectiveTier;
        rec.result = VerificationResult.Pending;
        rec.configuredAt = block.number;

        emit JobConfigured(jobId, value, effectiveTier);
    }

    /// @notice Override tier to TEE (enterprise/regulatory requirement)
    /// @param jobId The job identifier
    /// @dev Can only be called before proof submission
    function overrideTierToTEE(uint256 jobId) external onlyMarketplace jobConfigured(jobId) {
        VerificationRecord storage rec = records[jobId];
        require(rec.result == VerificationResult.Pending, "ComputeVerifier: already verified");
        require(!rec.proofSubmitted, "ComputeVerifier: proof already submitted");

        VerificationTier oldTier = rec.tier;
        rec.tier = VerificationTier.TEE;

        emit TierOverridden(jobId, oldTier, VerificationTier.TEE);
    }

    // ============================================================
    // Commitment Phase (required before proof submission)
    // ============================================================

    /// @notice Submit a commitment hash before execution begins
    /// @param jobId The job identifier
    /// @param provider The provider submitting the commitment
    /// @param commitment SHA3(input || output || nonce) — binds the provider to their result
    /// @dev INV-3: CommitmentBindsOutput — must be submitted BEFORE output reveal
    /// @dev INV-7: ProofRequiresCommitment — proof cannot be submitted without this
    function submitCommitment(
        uint256 jobId,
        address provider,
        bytes32 commitment
    ) external onlyMarketplace jobConfigured(jobId) {
        VerificationRecord storage rec = records[jobId];
        require(!rec.commitmentSubmitted, "ComputeVerifier: commitment already submitted");
        require(rec.result == VerificationResult.Pending, "ComputeVerifier: already verified");
        require(commitment != bytes32(0), "ComputeVerifier: empty commitment");

        rec.commitmentHash = commitment;
        rec.commitmentSubmitted = true;
        rec.provider = provider;

        emit CommitmentSubmitted(jobId, provider, commitment);
    }

    // ============================================================
    // Verification — Tiered Dispatch
    // ============================================================

    /// @notice Verify a job result based on its configured tier
    /// @param jobId The job identifier
    /// @param tier The verification tier to use
    /// @param proofData Tier-specific proof data
    /// @return result The verification result
    /// @dev INV-3: CommitmentBindsOutput — commitment must exist before verification
    function verify(
        uint256 jobId,
        VerificationTier tier,
        bytes calldata proofData
    ) external onlyMarketplace jobConfigured(jobId) returns (VerificationResult) {
        VerificationRecord storage rec = records[jobId];
        require(rec.result == VerificationResult.Pending, "ComputeVerifier: already verified");
        require(!rec.proofSubmitted, "ComputeVerifier: proof already submitted");
        // INV-7: ProofRequiresCommitment
        require(rec.commitmentSubmitted, "ComputeVerifier: commitment required first");
        require(tier == rec.tier, "ComputeVerifier: tier mismatch");

        rec.proofSubmitted = true;
        emit ProofSubmitted(jobId, tier);

        VerificationResult result;
        if (tier == VerificationTier.Commitment) {
            result = _verifyCommitment(jobId, proofData);
        } else if (tier == VerificationTier.ZKProof) {
            result = _verifyZKProof(jobId, proofData);
        } else {
            result = _verifyTEEAttestation(jobId, proofData);
        }

        rec.result = result;
        if (result == VerificationResult.Valid) {
            totalVerified++;
        }

        emit VerificationCompleted(jobId, result);
        return result;
    }

    // ============================================================
    // Commitment Verification (Tier 1)
    // ============================================================

    /// @notice Verify a commitment reveal — provider reveals output + nonce
    /// @param jobId The job identifier
    /// @param commitment The original commitment hash (must match stored)
    /// @param output The output data
    /// @param nonce Random nonce used in the commitment
    /// @return valid Whether the commitment matches
    /// @dev INV-3: CommitmentBindsOutput — SHA3(input || output || nonce) must match
    function verifyCommitment(
        uint256 jobId,
        bytes32 commitment,
        bytes calldata output,
        bytes32 nonce
    ) external onlyMarketplace jobConfigured(jobId) returns (bool) {
        VerificationRecord storage rec = records[jobId];
        require(rec.commitmentSubmitted, "ComputeVerifier: no commitment");
        require(rec.result == VerificationResult.Pending, "ComputeVerifier: already verified");
        require(!rec.proofSubmitted, "ComputeVerifier: proof already submitted");
        require(rec.tier == VerificationTier.Commitment, "ComputeVerifier: wrong tier");

        rec.proofSubmitted = true;
        emit ProofSubmitted(jobId, VerificationTier.Commitment);

        // Verify the commitment matches
        bool valid = (commitment == rec.commitmentHash) &&
                     (keccak256(abi.encodePacked(output, nonce)) == commitment);

        rec.result = valid ? VerificationResult.Valid : VerificationResult.Invalid;

        if (valid) {
            totalVerified++;
        }

        emit VerificationCompleted(jobId, rec.result);
        return valid;
    }

    /// @notice Verify a ZK proof for a specific job
    /// @param jobId The job identifier
    /// @param proof The ZK proof bytes
    /// @param publicInputs The public inputs to the ZK circuit
    /// @return valid Whether the ZK proof is valid
    function verifyZKProof(
        uint256 jobId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external onlyMarketplace jobConfigured(jobId) returns (bool) {
        VerificationRecord storage rec = records[jobId];
        require(rec.commitmentSubmitted, "ComputeVerifier: no commitment");
        require(rec.result == VerificationResult.Pending, "ComputeVerifier: already verified");
        require(!rec.proofSubmitted, "ComputeVerifier: proof already submitted");
        require(
            rec.tier == VerificationTier.ZKProof,
            "ComputeVerifier: wrong tier"
        );

        rec.proofSubmitted = true;
        emit ProofSubmitted(jobId, VerificationTier.ZKProof);

        // Call ZK verification precompile
        bool valid = _callZKVerifyPrecompile(proof, publicInputs);

        rec.result = valid ? VerificationResult.Valid : VerificationResult.Invalid;

        if (valid) {
            totalVerified++;
        }

        emit VerificationCompleted(jobId, rec.result);
        return valid;
    }

    /// @notice Verify a TEE attestation for a specific job
    /// @param jobId The job identifier
    /// @param attestation The TEE attestation quote
    /// @param signature Oracle signature over the attestation
    /// @return valid Whether the TEE attestation is valid
    function verifyTEEAttestation(
        uint256 jobId,
        bytes calldata attestation,
        bytes calldata signature
    ) external onlyMarketplace jobConfigured(jobId) returns (bool) {
        VerificationRecord storage rec = records[jobId];
        require(rec.commitmentSubmitted, "ComputeVerifier: no commitment");
        require(rec.result == VerificationResult.Pending, "ComputeVerifier: already verified");
        require(!rec.proofSubmitted, "ComputeVerifier: proof already submitted");
        require(rec.tier == VerificationTier.TEE, "ComputeVerifier: wrong tier");

        rec.proofSubmitted = true;
        emit ProofSubmitted(jobId, VerificationTier.TEE);

        // Verify TEE attestation via oracle signature
        bool valid = _verifyTEESignature(attestation, signature);

        rec.result = valid ? VerificationResult.Valid : VerificationResult.Invalid;

        if (valid) {
            totalVerified++;
        }

        emit VerificationCompleted(jobId, rec.result);
        return valid;
    }

    // ============================================================
    // Dispute Resolution (INV-5, INV-6, INV-8)
    // ============================================================

    /// @notice Initiate a dispute on a verified result
    /// @param jobId The job identifier
    /// @dev INV-5: DisputeOnlyAfterVerification — result must not be pending
    /// @dev INV-8: DisputeRequiresRound — sets bisection round to 1
    function initiateDispute(uint256 jobId) external onlyMarketplace jobConfigured(jobId) {
        VerificationRecord storage rec = records[jobId];
        // INV-5: DisputeOnlyAfterVerification
        require(
            rec.result != VerificationResult.Pending,
            "ComputeVerifier: must verify before dispute"
        );
        require(!rec.disputeActive, "ComputeVerifier: dispute already active");

        rec.disputeActive = true;
        // INV-8: DisputeRequiresRound — starts at 1
        rec.bisectionRound = 1;

        emit DisputeInitiated(jobId, 1);
    }

    /// @notice Perform a bisection step in the dispute resolution
    /// @param jobId The job identifier
    /// @dev INV-6: BisectionTerminates — bounded by MAX_BISECTION_ROUNDS
    function performBisectionStep(uint256 jobId) external onlyMarketplace jobConfigured(jobId) {
        VerificationRecord storage rec = records[jobId];
        require(rec.disputeActive, "ComputeVerifier: no active dispute");
        // INV-6: BisectionTerminates
        require(
            rec.bisectionRound < MAX_BISECTION_ROUNDS,
            "ComputeVerifier: max bisection rounds reached"
        );

        rec.bisectionRound++;

        emit BisectionStep(jobId, rec.bisectionRound);
    }

    /// @notice Resolve a dispute with a final outcome
    /// @param jobId The job identifier
    /// @param outcome The resolution result (Valid or Invalid)
    /// @dev Only governance or marketplace can resolve disputes
    function resolveDispute(
        uint256 jobId,
        VerificationResult outcome
    ) external jobConfigured(jobId) {
        require(
            msg.sender == governance() || msg.sender == marketplace,
            "ComputeVerifier: caller is not governance or marketplace"
        );
        VerificationRecord storage rec = records[jobId];
        require(rec.disputeActive, "ComputeVerifier: no active dispute");
        require(rec.bisectionRound >= 1, "ComputeVerifier: dispute requires at least round 1");
        require(
            outcome == VerificationResult.Valid || outcome == VerificationResult.Invalid,
            "ComputeVerifier: invalid outcome"
        );

        rec.disputeActive = false;
        rec.result = outcome;

        emit DisputeResolved(jobId, outcome);
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get verification result for a job
    /// @param jobId The job identifier
    /// @return The verification result
    function getResult(uint256 jobId) external view returns (VerificationResult) {
        return records[jobId].result;
    }

    /// @notice Get full verification record for a job
    /// @param jobId The job identifier
    function getRecord(uint256 jobId) external view returns (VerificationRecord memory) {
        return records[jobId];
    }

    /// @notice Check if a job has been configured
    /// @param jobId The job identifier
    function isConfigured(uint256 jobId) external view returns (bool) {
        return records[jobId].configuredAt > 0;
    }

    /// @notice Check if a dispute is active for a job
    /// @param jobId The job identifier
    function isDisputeActive(uint256 jobId) external view returns (bool) {
        return records[jobId].disputeActive;
    }

    /// @notice Get the effective tier for a given value
    /// @param value The job value in SALT
    /// @param requestedTier The requested tier
    /// @return effectiveTier The enforced tier after value-based upgrade
    function getEffectiveTier(
        uint256 value,
        VerificationTier requestedTier
    ) external pure returns (VerificationTier effectiveTier) {
        if (value > VALUE_THRESHOLD && requestedTier == VerificationTier.Commitment) {
            return VerificationTier.ZKProof;
        }
        return requestedTier;
    }

    // ============================================================
    // Governance
    // ============================================================

    /// @notice Add a TEE attestation oracle
    /// @param oracle The oracle address
    function addTEEOracle(address oracle) external onlyGovernance {
        require(oracle != address(0), "ComputeVerifier: zero oracle address");
        require(!teeOracles[oracle], "ComputeVerifier: already oracle");

        teeOracles[oracle] = true;
        teeOracleCount++;

        emit TEEOracleAdded(oracle);
    }

    /// @notice Remove a TEE attestation oracle
    /// @param oracle The oracle address
    function removeTEEOracle(address oracle) external onlyGovernance {
        require(teeOracles[oracle], "ComputeVerifier: not oracle");

        teeOracles[oracle] = false;
        teeOracleCount--;

        emit TEEOracleRemoved(oracle);
    }

    /// @notice Update the marketplace contract address
    /// @param newMarketplace The new marketplace address
    function setMarketplace(address newMarketplace) external onlyGovernance {
        require(newMarketplace != address(0), "ComputeVerifier: zero address");
        address old = marketplace;
        marketplace = newMarketplace;
        emit MarketplaceUpdated(old, newMarketplace);
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ============================================================
    // Internal Verification Helpers
    // ============================================================

    /// @dev Verify commitment reveal (Tier 1)
    function _verifyCommitment(
        uint256 jobId,
        bytes calldata proofData
    ) internal view returns (VerificationResult) {
        VerificationRecord storage rec = records[jobId];

        // proofData encodes: commitment (32 bytes) + nonce (32 bytes) + output (remaining)
        require(proofData.length >= 64, "ComputeVerifier: insufficient proof data");

        bytes32 commitment = bytes32(proofData[:32]);
        bytes32 nonce = bytes32(proofData[32:64]);
        bytes calldata output = proofData[64:];

        // Verify commitment matches stored hash
        if (commitment != rec.commitmentHash) {
            return VerificationResult.Invalid;
        }

        // Verify output + nonce hashes to commitment
        if (keccak256(abi.encodePacked(output, nonce)) != commitment) {
            return VerificationResult.Invalid;
        }

        return VerificationResult.Valid;
    }

    /// @dev Verify ZK proof via the live 0x0108 inference verifier (Tier 2).
    /// @dev ZK-tier proofData ABI:
    ///        proofData = proofLen(32) ‖ proof ‖ publicInputs
    ///      where `proof` is `proofLen` bytes of the Halo2-KZG transcript and
    ///      `publicInputs` is EXACTLY 96 bytes:
    ///        input_commitment(32) ‖ model_commitment(32) ‖ output_commitment(32)
    ///      (32-byte big-endian Fr field elements). These three commitments are
    ///      the public inputs the inference circuit binds. See
    ///      _callZKVerifyPrecompile for how they are framed for 0x0108.
    function _verifyZKProof(
        uint256 /* jobId */,
        bytes calldata proofData
    ) internal view returns (VerificationResult) {
        // proofData encodes: proof length (32 bytes) + proof + public inputs
        require(proofData.length >= 32, "ComputeVerifier: insufficient proof data");

        uint256 proofLen = uint256(bytes32(proofData[:32]));
        require(proofData.length >= 32 + proofLen, "ComputeVerifier: proof data too short");

        bytes calldata proof = proofData[32:32 + proofLen];
        bytes calldata publicInputs = proofData[32 + proofLen:];

        bool valid = _callZKVerifyPrecompile(proof, publicInputs);
        return valid ? VerificationResult.Valid : VerificationResult.Invalid;
    }

    /// @dev Verify TEE attestation via oracle signature (Tier 3)
    function _verifyTEEAttestation(
        uint256 /* jobId */,
        bytes calldata proofData
    ) internal view returns (VerificationResult) {
        // proofData encodes: attestation length (32 bytes) + attestation + signature
        require(proofData.length >= 32, "ComputeVerifier: insufficient proof data");

        uint256 attestLen = uint256(bytes32(proofData[:32]));
        require(proofData.length >= 32 + attestLen, "ComputeVerifier: attestation data too short");

        bytes calldata attestation = proofData[32:32 + attestLen];
        bytes calldata signature = proofData[32 + attestLen:];

        bool valid = _verifyTEESignature(attestation, signature);
        return valid ? VerificationResult.Valid : VerificationResult.Invalid;
    }

    /// @dev STATICCALL the live 0x0108 inference verifier with the v1 inference
    ///      wire format and return true iff the proof verifies.
    ///
    ///      `publicInputs` MUST be exactly 96 bytes:
    ///        input_commitment(32) ‖ model_commitment(32) ‖ output_commitment(32)
    ///
    ///      The 0x0108 input is then framed per verify.rs::inference_proof_verify:
    ///        | 32B input_commitment | 32B model_commitment | 32B output_commitment |
    ///        | 4B circuit_version=1 (BE) | 4B chain_id (BE) | proof_bytes |
    ///
    ///      The precompile returns a 32-byte big-endian word: 1 == valid, 0 ==
    ///      reject. A revert / wrong-length return / non-1 verdict => false (the
    ///      "no proof" verdict), mirroring IPFSIncentivesV2._verify. NO state
    ///      changes (view).
    function _callZKVerifyPrecompile(
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal view returns (bool) {
        require(
            publicInputs.length == ZK_PUBLIC_INPUTS_LEN,
            "ComputeVerifier: bad publicInputs length"
        );

        // publicInputs = input_commitment ‖ model_commitment ‖ output_commitment.
        // Frame for 0x0108: commitments ‖ circuit_version(BE) ‖ chain_id(BE) ‖ proof.
        bytes memory input = abi.encodePacked(
            publicInputs,
            INFERENCE_CIRCUIT_V1,
            uint32(block.chainid),
            proof
        );

        (bool success, bytes memory result) = INFERENCE_PROOF_VERIFY.staticcall(input);

        // Safe decode (mirrors IPFSIncentivesV2._verify): a structural failure or
        // a non-1 verdict is treated as "not verified" => Invalid at the caller.
        if (!success || result.length != 32) {
            return false;
        }

        return abi.decode(result, (uint256)) == 1;
    }

    /// @dev Verify TEE attestation signature from a trusted oracle
    function _verifyTEESignature(
        bytes calldata attestation,
        bytes calldata signature
    ) internal view returns (bool) {
        require(signature.length == 65, "ComputeVerifier: invalid signature length");

        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(attestation))
        );

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "ComputeVerifier: invalid v value");
        // FWA-C3-05 sweep: enforce low-s (EIP-2) to reject signature
        // malleability. secp256k1n/2.
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "ComputeVerifier: invalid s value"
        );

        // nosemgrep: fwa-c3-05-raw-ecrecover-no-low-s-guard -- low-s enforced above
        address recovered = ecrecover(messageHash, v, r, s);
        return recovered != address(0) && teeOracles[recovered];
    }
}
