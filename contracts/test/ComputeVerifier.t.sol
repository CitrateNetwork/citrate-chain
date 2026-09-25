// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputeVerifier} from "../src/ComputeVerifier.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @dev Controllable mock of the live 0x0108 INFERENCE_PROOF_VERIFY precompile.
///      Returns a configurable 32-byte big-endian verdict (1 == valid, 0 ==
///      reject), exactly like the real Halo2-KZG verifier. `vm.etch`'d over
///      address(0x0108). It is STATICCALL-safe: the fallback performs no storage
///      writes, so it works under ComputeVerifier's view staticcall. Tests assert
///      the exact wire-format bytes via `vm.expectCall`, not via the mock.
contract MockInferenceVerifier {
    /// @dev The verdict byte (1 or 0) lives in the runtime code's returndata via
    ///      a constant set at etch time. Since storage writes are illegal under
    ///      STATICCALL, we expose two flavors by deploying two distinct mocks.
    bytes32 private immutable VERDICT;

    constructor(bool valid) {
        VERDICT = bytes32(valid ? uint256(1) : uint256(0));
    }

    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(VERDICT);
    }
}

/// @dev A mock 0x0108 that always reverts, to exercise the staticcall-failure
///      path (=> Invalid). STATICCALL-safe (no writes).
contract RevertingInferenceVerifier {
    fallback(bytes calldata) external returns (bytes memory) {
        revert("verifier exploded");
    }
}

/// @title ComputeVerifierTest — 20+ tests covering all 9 ComputeVerification.tla invariants
/// @dev Tests tiered verification dispatch: Commitment, ZKProof, TEE
///      INV-1: TypeOK
///      INV-2: TierMatchesValue
///      INV-3: CommitmentBindsOutput
///      INV-4: ZKProofValid
///      INV-5: DisputeOnlyAfterVerification
///      INV-6: BisectionTerminates
///      INV-7: ProofRequiresCommitment
///      INV-8: DisputeRequiresRound
///      INV-9: UnconfiguredPending
contract ComputeVerifierTest is Test {
    ComputeVerifier internal verifier;

    address internal marketplace;
    address internal governance;
    address internal provider = address(0xBBB1);
    address internal outsider = address(0xBAD1);
    address internal teeOracle;
    uint256 internal teeOracleKey;

    // Commitment verification values
    bytes internal outputData = hex"01020304";
    bytes32 internal nonce = keccak256("secret-nonce");
    bytes32 internal commitmentHash;

    function setUp() public {
        marketplace = address(this); // Test contract acts as marketplace
        governance = address(this);

        verifier = new ComputeVerifier(marketplace);

        // Pre-compute commitment hash: SHA3(output || nonce)
        commitmentHash = keccak256(abi.encodePacked(outputData, nonce));

        // Create TEE oracle keypair
        teeOracleKey = 0xA11CE;
        teeOracle = vm.addr(teeOracleKey);
        verifier.addTEEOracle(teeOracle);
    }

    // ── Helpers ───────────────────────────────────────────────────

    function _configureJob(uint256 jobId, uint256 value, ComputeVerifier.VerificationTier tier) internal {
        verifier.configureJob(jobId, value, tier);
        // PBA-L2-004: bind the job to the commitments the ZK fixtures carry
        // (the marketplace does this in postJob / autoAssignJob).
        if (tier != ComputeVerifier.VerificationTier.Commitment) {
            verifier.bindJob(jobId, inputCommitment, modelCommitment);
        }
    }

    /// PBA-L2-004: ZK-tier commit-reveal — commit to the exact proofData in
    /// an earlier block than the reveal.
    function _zkCommit(uint256 jobId, bytes memory proofData) internal {
        verifier.submitCommitment(jobId, provider, verifier.zkProofCommitment(jobId, proofData));
        vm.roll(block.number + 1);
    }

    function _submitCommitment(uint256 jobId) internal {
        verifier.submitCommitment(jobId, provider, commitmentHash);
    }

    function _buildCommitmentProof(
        bytes32 _commitment,
        bytes32 _nonce,
        bytes memory _output
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(_commitment, _nonce, _output);
    }

    function _signAttestation(
        bytes memory attestation
    ) internal view returns (bytes memory) {
        // PBA-L2-004: the oracle signs a digest bound to (chain, verifier, job).
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                verifier.teeAttestationDigest(1, attestation)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teeOracleKey, msgHash);
        return abi.encodePacked(r, s, v);
    }

    // ============================================================
    // Configuration Tests
    // ============================================================

    /// @dev INV-9: UnconfiguredPending — unconfigured jobs have Pending result
    function test_unconfigured_jobHasPendingResult() public view {
        ComputeVerifier.VerificationResult result = verifier.getResult(999);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Pending), "Unconfigured = Pending");
    }

    function test_configureJob_setsCorrectTier() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertEq(uint(rec.tier), uint(ComputeVerifier.VerificationTier.Commitment), "Tier = Commitment");
        assertEq(rec.jobValue, 5 ether, "Value recorded");
        assertTrue(rec.configuredAt > 0, "Configured block set");
    }

    /// @dev INV-2: TierMatchesValue — high-value jobs auto-upgrade to ZKProof
    function test_tierMatchesValue_lowValueAllowsCommitment() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertEq(uint(rec.tier), uint(ComputeVerifier.VerificationTier.Commitment), "Low value allows Commitment");
    }

    /// @dev INV-2: TierMatchesValue — high value forces ZKProof
    function test_tierMatchesValue_highValueRequiresZK() public {
        // Value > VALUE_THRESHOLD (10 ether) with Commitment tier should auto-upgrade
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.Commitment);
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertEq(uint(rec.tier), uint(ComputeVerifier.VerificationTier.ZKProof), "High value upgrades to ZKProof");
    }

    function test_tierMatchesValue_highValueAllowsTEE() public {
        // TEE is an acceptable tier for high-value jobs
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.TEE);
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertEq(uint(rec.tier), uint(ComputeVerifier.VerificationTier.TEE), "TEE allowed for high value");
    }

    function test_configureJob_doubleConfig_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);

        vm.expectRevert("ComputeVerifier: already configured");
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
    }

    function test_configureJob_zeroValue_reverts() public {
        vm.expectRevert("ComputeVerifier: zero value");
        _configureJob(1, 0, ComputeVerifier.VerificationTier.Commitment);
    }

    function test_overrideTierToTEE() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        verifier.overrideTierToTEE(1);
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertEq(uint(rec.tier), uint(ComputeVerifier.VerificationTier.TEE), "Tier overridden to TEE");
    }

    // ============================================================
    // Commitment Verification Tests (Tier 1)
    // ============================================================

    /// @dev INV-3: CommitmentBindsOutput — valid commitment reveal
    function test_verifyCommitment_validReveal() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        bool valid = verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
        assertTrue(valid, "Valid commitment should pass");

        ComputeVerifier.VerificationResult result = verifier.getResult(1);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Valid), "Result should be Valid");
    }

    /// @dev INV-3: CommitmentBindsOutput — invalid reveal (wrong nonce)
    function test_verifyCommitment_invalidReveal() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        bytes32 wrongNonce = keccak256("wrong-nonce");
        bool valid = verifier.verifyCommitment(1, commitmentHash, outputData, wrongNonce);
        assertFalse(valid, "Invalid nonce should fail");

        ComputeVerifier.VerificationResult result = verifier.getResult(1);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Invalid), "Result should be Invalid");
    }

    function test_verifyCommitment_wrongCommitmentHash() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        bytes32 wrongHash = keccak256("wrong");
        bool valid = verifier.verifyCommitment(1, wrongHash, outputData, nonce);
        assertFalse(valid, "Wrong commitment hash should fail");
    }

    /// @dev INV-7: ProofRequiresCommitment — cannot verify without commitment
    function test_verifyCommitment_beforeSubmission_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);

        // No commitment submitted
        vm.expectRevert("ComputeVerifier: no commitment");
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
    }

    function test_verifyCommitment_alreadyVerified_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);

        // Try again
        vm.expectRevert("ComputeVerifier: already verified");
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
    }

    // ============================================================
    // ZK Proof Verification Tests (Tier 2) — D2 fix: live 0x0108 verifier
    // ============================================================
    //
    // The ZK tier now targets the live Halo2-KZG inference verifier at 0x0108
    // (was the 0x0104 SHA3-commitment STUB). publicInputs MUST be exactly 96
    // bytes: input_commitment(32) ‖ model_commitment(32) ‖ output_commitment(32).
    // These tests etch a controllable mock over 0x0108. The two pre-existing
    // ZK-tier tests (test_verifyZKProof_valid / _invalid) were updated from the
    // 0x0104 `abi.encode(bool)` mock to the 0x0108 `uint256` BE verdict + the
    // 96-byte publicInputs ABI; the rest of this section is new.

    address internal constant INFERENCE_PRECOMPILE = address(0x0108);

    // Canonical inference public inputs (3 × 32B BE Fr commitments).
    bytes32 internal inputCommitment = bytes32(uint256(keccak256("input-commitment")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617); // canonical BN254 scalar (PBA-L2-004)
    bytes32 internal modelCommitment = bytes32(uint256(keccak256("model-commitment")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617); // canonical BN254 scalar (PBA-L2-004)
    bytes32 internal outputCommitment = bytes32(uint256(keccak256("output-commitment")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617); // canonical BN254 scalar (PBA-L2-004)

    /// @dev Etch a verdict-returning mock (1 or 0) over the 0x0108 address.
    function _etch0x0108(bool valid) internal {
        MockInferenceVerifier mock = new MockInferenceVerifier(valid);
        vm.etch(INFERENCE_PRECOMPILE, address(mock).code);
    }

    /// @dev Build a well-formed 96-byte ZK-tier publicInputs blob.
    function _publicInputs96() internal view returns (bytes memory) {
        return abi.encodePacked(inputCommitment, modelCommitment, outputCommitment);
    }

    /// @dev The exact bytes ComputeVerifier must STATICCALL 0x0108 with, per the
    ///      v1 inference wire format:
    ///        commitments(96) ‖ circuit_version=1 (BE u32) ‖ chain_id (BE u32) ‖ proof
    function _expected0x0108Input(bytes memory proof) internal view returns (bytes memory) {
        return abi.encodePacked(
            inputCommitment,
            modelCommitment,
            outputCommitment,
            uint32(1),
            uint32(block.chainid),
            proof
        );
    }

    /// @dev INV-4: ZKProofValid — verifyZKProof() happy path against live 0x0108.
    ///      Updated from the legacy 0x0104 bool-mock to the 0x0108 uint256 verdict
    ///      + 96-byte publicInputs ABI.
    function test_verifyZKProof_valid() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _zkCommit(1, abi.encodePacked(uint256(bytes(hex"AABBCCDD").length), bytes(hex"AABBCCDD"), _publicInputs96()));
        _etch0x0108(true);

        bool valid = verifier.verifyZKProof(1, hex"AABBCCDD", _publicInputs96());
        assertTrue(valid, "Valid 0x0108 verdict should pass");

        ComputeVerifier.VerificationResult result = verifier.getResult(1);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Valid), "Result Valid");
    }

    /// @dev ZK proof failure path: 0x0108 returns 0 => Invalid. Updated from the
    ///      legacy 0x0104 mock.
    function test_verifyZKProof_invalid() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _zkCommit(1, abi.encodePacked(uint256(bytes(hex"BADD0001").length), bytes(hex"BADD0001"), _publicInputs96()));
        _etch0x0108(false);

        bool valid = verifier.verifyZKProof(1, hex"BADD0001", _publicInputs96());
        assertFalse(valid, "0x0108 reject (0) should be invalid");

        ComputeVerifier.VerificationResult result = verifier.getResult(1);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Invalid), "Result Invalid");
    }

    function test_verifyZKProof_wrongTier_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        vm.expectRevert("ComputeVerifier: wrong tier");
        verifier.verifyZKProof(1, hex"AABB", _publicInputs96());
    }

    /// @dev D2 fix: the ZK tier must STATICCALL 0x0108 (NOT the 0x0104 stub) with
    ///      the exact v1 inference ABI. Asserts the precompile address AND the
    ///      exact calldata bytes via vm.expectCall.
    function test_verifyZKProof_callsLive0x0108_withCorrectABI() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _zkCommit(1, abi.encodePacked(uint256(6), hex"DEADBEEFCAFE", _publicInputs96()));
        _etch0x0108(true);

        bytes memory proof = hex"DEADBEEFCAFE";
        bytes memory expectedInput = _expected0x0108Input(proof);

        // Exact-calldata expectation against the LIVE precompile address.
        vm.expectCall(INFERENCE_PRECOMPILE, expectedInput);

        bool valid = verifier.verifyZKProof(1, proof, _publicInputs96());
        assertTrue(valid, "Should verify via 0x0108 with correct ABI");
    }

    /// @dev The legacy 0x0104 stub must NOT be called any more (D2 regression).
    function test_verifyZKProof_neverCalls0x0104Stub() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _zkCommit(1, abi.encodePacked(uint256(bytes(hex"AABBCCDD").length), bytes(hex"AABBCCDD"), _publicInputs96()));
        _etch0x0108(true);

        // expectCall with count 0 => the 0x0104 stub address is never called.
        vm.expectCall(address(0x0104), bytes(""), 0);
        verifier.verifyZKProof(1, hex"AABBCCDD", _publicInputs96());
    }

    /// @dev ZK-tier ABI guard: publicInputs that is not exactly 96 bytes reverts.
    function test_verifyZKProof_badPublicInputsLength_reverts() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _submitCommitment(1);
        _etch0x0108(true);

        // 95 bytes (one short) — must revert before touching the precompile.
        bytes memory shortInputs = new bytes(95);
        vm.expectRevert("ComputeVerifier: bad publicInputs length");
        verifier.verifyZKProof(1, hex"AABB", shortInputs);

        // 97 bytes (one long) — also reverts. Re-configure a fresh job since the
        // prior call marked job 1's proof submitted via the revert? No: a revert
        // rolls back state, so job 1 is still pending. Reuse it.
        bytes memory longInputs = new bytes(97);
        vm.expectRevert("ComputeVerifier: bad publicInputs length");
        verifier.verifyZKProof(1, hex"AABB", longInputs);
    }

    /// @dev staticcall failure (0x0108 reverts) => Invalid, no revert at caller.
    function test_verifyZKProof_precompileReverts_isInvalid() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _zkCommit(1, abi.encodePacked(uint256(bytes(hex"AABBCCDD").length), bytes(hex"AABBCCDD"), _publicInputs96()));

        RevertingInferenceVerifier boom = new RevertingInferenceVerifier();
        vm.etch(INFERENCE_PRECOMPILE, address(boom).code);

        bool valid = verifier.verifyZKProof(1, hex"AABBCCDD", _publicInputs96());
        assertFalse(valid, "Precompile revert => Invalid");

        ComputeVerifier.VerificationResult result = verifier.getResult(1);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Invalid), "Result Invalid on revert");
    }

    /// @dev ZK tier via the verify() dispatcher with well-formed proofData
    ///      (proofLen ‖ proof ‖ 96-byte commitments) => Valid, calling 0x0108
    ///      with the correct ABI.
    function test_verify_zkTier_dispatch_valid() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _zkCommit(1, abi.encodePacked(uint256(8), hex"0102030405060708", _publicInputs96()));
        _etch0x0108(true);

        bytes memory proof = hex"0102030405060708";
        bytes memory publicInputs = _publicInputs96();
        // proofData = proofLen(32) ‖ proof ‖ publicInputs
        bytes memory proofData = abi.encodePacked(uint256(proof.length), proof, publicInputs);

        vm.expectCall(INFERENCE_PRECOMPILE, _expected0x0108Input(proof));

        ComputeVerifier.VerificationResult result = verifier.verify(
            1, ComputeVerifier.VerificationTier.ZKProof, proofData
        );
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Valid), "ZK dispatch => Valid");
    }

    /// @dev verify() ZK dispatch with a non-96-byte publicInputs slice reverts.
    function test_verify_zkTier_dispatch_badPublicInputs_reverts() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _submitCommitment(1);
        _etch0x0108(true);

        bytes memory proof = hex"0102030405060708";
        bytes memory badPublicInputs = new bytes(64); // not 96
        bytes memory proofData = abi.encodePacked(uint256(proof.length), proof, badPublicInputs);

        vm.expectRevert("ComputeVerifier: bad publicInputs length");
        verifier.verify(1, ComputeVerifier.VerificationTier.ZKProof, proofData);
    }

    // ============================================================
    // TEE Attestation Tests (Tier 3)
    // ============================================================

    function test_verifyTEEAttestation_valid() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.TEE);
        _submitCommitment(1);

        bytes memory attestation = hex"AABB0011223344556677889900";
        bytes memory sig = _signAttestation(attestation);

        bool valid = verifier.verifyTEEAttestation(1, attestation, sig);
        assertTrue(valid, "Valid TEE attestation should pass");
    }

    function test_verifyTEEAttestation_invalidOracle() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.TEE);
        _submitCommitment(1);

        bytes memory attestation = hex"AABB0011223344556677889900";

        // Sign with non-oracle key
        uint256 wrongKey = 0xDEAD;
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                verifier.teeAttestationDigest(1, attestation)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bool valid = verifier.verifyTEEAttestation(1, attestation, sig);
        assertFalse(valid, "Non-oracle signature should fail");
    }

    // ============================================================
    // Tiered Dispatch via verify() Tests
    // ============================================================

    function test_verify_commitmentTier() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        bytes memory proof = _buildCommitmentProof(commitmentHash, nonce, outputData);
        ComputeVerifier.VerificationResult result = verifier.verify(
            1, ComputeVerifier.VerificationTier.Commitment, proof
        );
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Valid), "Should verify via dispatch");
    }

    function test_verify_tierMismatch_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        vm.expectRevert("ComputeVerifier: tier mismatch");
        verifier.verify(1, ComputeVerifier.VerificationTier.ZKProof, hex"");
    }

    // ============================================================
    // Dispute Tests (INV-5, INV-6, INV-8)
    // ============================================================

    /// @dev INV-5: DisputeOnlyAfterVerification — can't dispute before verification
    function test_disputeOnlyAfterVerification() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        // Not yet verified (still Pending)
        vm.expectRevert("ComputeVerifier: must verify before dispute");
        verifier.initiateDispute(1);
    }

    function test_disputeAfterVerification_succeeds() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);

        // Now verification is done, dispute should work
        verifier.initiateDispute(1);
        assertTrue(verifier.isDisputeActive(1), "Dispute should be active");
    }

    /// @dev INV-8: DisputeRequiresRound — dispute starts at round 1
    function test_disputeRequiresRound() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
        verifier.initiateDispute(1);

        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertEq(rec.bisectionRound, 1, "Dispute should start at round 1");
    }

    /// @dev INV-6: BisectionTerminates — bisection bounded by MAX_BISECTION_ROUNDS
    function test_bisectionTerminates() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
        verifier.initiateDispute(1);

        // Run bisection steps up to the limit
        uint256 maxRounds = verifier.MAX_BISECTION_ROUNDS();
        for (uint256 i = 1; i < maxRounds; i++) {
            verifier.performBisectionStep(1);
        }

        // One more should revert
        vm.expectRevert("ComputeVerifier: max bisection rounds reached");
        verifier.performBisectionStep(1);
    }

    function test_resolveDispute_updatesResult() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
        verifier.initiateDispute(1);

        verifier.resolveDispute(1, ComputeVerifier.VerificationResult.Invalid);

        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(1);
        assertFalse(rec.disputeActive, "Dispute should be resolved");
        assertEq(uint(rec.result), uint(ComputeVerifier.VerificationResult.Invalid), "Result updated to Invalid");
    }

    // ============================================================
    // Commitment Phase Tests (INV-3, INV-7)
    // ============================================================

    /// @dev INV-3: Commitment must be submitted before proof
    function test_commitmentRequired_beforeVerify() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);

        // Try to verify without commitment
        bytes memory proof = _buildCommitmentProof(commitmentHash, nonce, outputData);
        vm.expectRevert("ComputeVerifier: commitment required first");
        verifier.verify(1, ComputeVerifier.VerificationTier.Commitment, proof);
    }

    /// The assigned provider may replace its commitment until a proof is
    /// submitted; a different provider may not, and nobody may after the proof.
    function test_commitmentReplaceableOnlyBeforeProofBySameProvider() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        _submitCommitment(1); // same provider, no proof yet: allowed

        vm.expectRevert("ComputeVerifier: commitment already submitted");
        verifier.submitCommitment(1, address(0xD1FF), commitmentHash);

        bytes memory proof = _buildCommitmentProof(commitmentHash, nonce, outputData);
        verifier.verify(1, ComputeVerifier.VerificationTier.Commitment, proof);
        vm.expectRevert("ComputeVerifier: proof already submitted");
        _submitCommitment(1);
    }

    function test_emptyCommitment_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);

        vm.expectRevert("ComputeVerifier: empty commitment");
        verifier.submitCommitment(1, provider, bytes32(0));
    }

    // ============================================================
    // Access Control Tests
    // ============================================================

    function test_onlyMarketplace_canConfigureJob() public {
        vm.prank(outsider);
        vm.expectRevert("ComputeVerifier: caller is not marketplace");
        verifier.configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
    }

    function test_onlyMarketplace_canSubmitCommitment() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);

        vm.prank(outsider);
        vm.expectRevert("ComputeVerifier: caller is not marketplace");
        verifier.submitCommitment(1, provider, commitmentHash);
    }

    function test_onlyGovernanceOrMarketplace_canResolveDispute() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);
        verifier.initiateDispute(1);

        vm.prank(outsider);
        vm.expectRevert("ComputeVerifier: caller is not governance or marketplace");
        verifier.resolveDispute(1, ComputeVerifier.VerificationResult.Invalid);
    }

    // ============================================================
    // Governance Tests
    // ============================================================

    function test_addTEEOracle() public {
        address newOracle = address(0x1234);
        verifier.addTEEOracle(newOracle);
        assertTrue(verifier.teeOracles(newOracle), "Oracle should be added");
        assertEq(verifier.teeOracleCount(), 2, "Oracle count should be 2");
    }

    function test_removeTEEOracle() public {
        verifier.removeTEEOracle(teeOracle);
        assertFalse(verifier.teeOracles(teeOracle), "Oracle should be removed");
        assertEq(verifier.teeOracleCount(), 0, "Oracle count should be 0");
    }

    function test_transferGovernance() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        address newGov = address(0x8888);
        verifier.transferGovernance(newGov);
        assertEq(verifier.pendingGovernance(), newGov, "pending recorded");
        assertEq(verifier.governance(), address(this), "still old gov");
        vm.prank(newGov);
        verifier.acceptGovernance();
        assertEq(verifier.governance(), newGov, "Governance transferred");
    }

    function test_setMarketplace() public {
        address newMarketplace = address(0x7777);
        verifier.setMarketplace(newMarketplace);
        assertEq(verifier.marketplace(), newMarketplace, "Marketplace updated");
    }

    // ============================================================
    // View Function Tests
    // ============================================================

    function test_getEffectiveTier_lowValue() public view {
        ComputeVerifier.VerificationTier tier = verifier.getEffectiveTier(
            5 ether, ComputeVerifier.VerificationTier.Commitment
        );
        assertEq(uint(tier), uint(ComputeVerifier.VerificationTier.Commitment), "Low value keeps Commitment");
    }

    function test_getEffectiveTier_highValue() public view {
        ComputeVerifier.VerificationTier tier = verifier.getEffectiveTier(
            15 ether, ComputeVerifier.VerificationTier.Commitment
        );
        assertEq(uint(tier), uint(ComputeVerifier.VerificationTier.ZKProof), "High value upgrades to ZKProof");
    }

    function test_isConfigured() public {
        assertFalse(verifier.isConfigured(1), "Should not be configured");
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        assertTrue(verifier.isConfigured(1), "Should be configured");
    }

    function test_totalVerified_incrementsOnSuccess() public {
        assertEq(verifier.totalVerified(), 0, "Starts at 0");

        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);
        verifier.verifyCommitment(1, commitmentHash, outputData, nonce);

        assertEq(verifier.totalVerified(), 1, "Should be 1 after verification");
    }
}
