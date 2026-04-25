// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputeVerifier} from "../src/ComputeVerifier.sol";
import {Governable} from "../src/lib/Governable.sol";

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
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(attestation)
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
    // ZK Proof Verification Tests (Tier 2)
    // ============================================================

    /// @dev INV-4: ZKProofValid — test ZK verification path (uses precompile mock)
    function test_verifyZKProof_valid() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        // Force tier to ZKProof (auto-upgraded from Commitment)
        _submitCommitment(1);

        // Mock the ZK precompile to return true
        bytes memory anyCalldata = new bytes(0);
        bytes memory mockReturn = abi.encode(true);
        vm.mockCall(
            address(0x0104),
            anyCalldata,
            mockReturn
        );

        bytes memory proof = hex"AABBCCDD";
        bytes memory publicInputs = hex"1122";
        bool valid = verifier.verifyZKProof(1, proof, publicInputs);
        assertTrue(valid, "Mocked ZK proof should be valid");
    }

    /// @dev ZK proof failure path
    function test_verifyZKProof_invalid() public {
        _configureJob(1, 15 ether, ComputeVerifier.VerificationTier.ZKProof);
        _submitCommitment(1);

        // Mock the ZK precompile to return false
        bytes memory anyCalldata2 = new bytes(0);
        bytes memory mockReturn = abi.encode(false);
        vm.mockCall(
            address(0x0104),
            anyCalldata2,
            mockReturn
        );

        bytes memory proof = hex"BADD0001";
        bytes memory publicInputs = hex"1122";
        bool valid = verifier.verifyZKProof(1, proof, publicInputs);
        assertFalse(valid, "Failed ZK proof should be invalid");
    }

    function test_verifyZKProof_wrongTier_reverts() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        vm.expectRevert("ComputeVerifier: wrong tier");
        verifier.verifyZKProof(1, hex"AABB", hex"1122");
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
                keccak256(attestation)
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

    function test_commitmentCannotBeSubmittedTwice() public {
        _configureJob(1, 5 ether, ComputeVerifier.VerificationTier.Commitment);
        _submitCommitment(1);

        vm.expectRevert("ComputeVerifier: commitment already submitted");
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
