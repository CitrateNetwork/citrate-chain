// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";

/// @title RmQ_C016 — ComputeVerifier proof replay across jobs
/// @notice CHAIN-B-C016 (HELD/reroll). Neither the TEE tier nor the ZK tier
///         bound its proof to the job: the TEE tier signs only
///         `keccak(attestation)` with no jobId/expiry/dedup, and the ZK tier's
///         public inputs are provider-supplied and unchecked. One legitimate
///         attestation (or proof) could settle unlimited distinct jobIds by
///         replaying its bytes. Fix: one-time-use proof consumption.
///
/// This test contract is BOTH the marketplace (constructor arg) and governance
/// (Governable(msg.sender)), so it may drive every verifier action directly.
contract RmQ_C016_ComputeVerifier is Test {
    ComputeVerifier internal verifier;
    address internal oracle;
    uint256 internal oraclePk;

    function setUp() public {
        verifier = new ComputeVerifier(address(this), address(this));
        (oracle, oraclePk) = makeAddrAndKey("tee-oracle");
        verifier.addTEEOracle(oracle);
    }

    function _configure(uint256 jobId, ComputeVerifier.VerificationTier tier) internal {
        verifier.configureJob(jobId, 100 ether, tier);
        verifier.submitCommitment(jobId, address(0xBEEF), keccak256(abi.encodePacked("c", jobId)));
    }

    /// PBA-L2-004: the oracle signs a job-bound digest.
    function _sign(uint256 jobId, bytes memory attestation) internal view returns (bytes memory sig) {
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", verifier.teeAttestationDigest(jobId, attestation))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oraclePk, messageHash);
        sig = abi.encodePacked(r, s, v);
    }

    /// GREEN: a replayed TEE attestation cannot settle a second job.
    /// RED (pre-fix): `v2 == true` and job 2 is Valid — one oracle-signed
    /// attestation settles unlimited jobs.
    function test_C016_tee_attestation_cannot_settle_two_jobs() public {
        bytes memory attestation = hex"deadbeefcafe";
        bytes memory sig = _sign(1, attestation);
        _configure(1, ComputeVerifier.VerificationTier.TEE);
        bool v1 = verifier.verifyTEEAttestation(1, attestation, sig);
        assertTrue(v1, "job 1 attestation verifies");

        _configure(2, ComputeVerifier.VerificationTier.TEE);
        bool v2 = verifier.verifyTEEAttestation(2, attestation, sig);

        assertFalse(v2, "C016: replayed attestation must not settle a 2nd job");
        assertEq(
            uint(verifier.getResult(2)),
            uint(ComputeVerifier.VerificationResult.Invalid),
            "C016: job 2 Invalid on replay"
        );
    }

    /// GREEN: a replayed ZK proof cannot settle a second job — even one
    /// with IDENTICAL commitments whose provider commits to the replayed
    /// bytes. PBA-L2-004: ZK proof material is consumed globally and the
    /// replay reverts (so it can never get anyone slashed).
    /// RED (pre-C016): job 2 is Valid.
    function test_C016_zk_proof_cannot_settle_two_jobs() public {
        vm.mockCall(address(0x0108), new bytes(0), abi.encode(uint256(1)));
        bytes memory proof = hex"aabbccdd";
        bytes32 inC = bytes32(uint256(7));
        bytes32 modelC = bytes32(uint256(9));
        bytes memory publicInputs = abi.encode(inC, modelC, bytes32(uint256(11)));
        bytes memory proofData = abi.encodePacked(uint256(proof.length), proof, publicInputs);

        for (uint256 j = 1; j <= 2; j++) {
            verifier.configureJob(j, 100 ether, ComputeVerifier.VerificationTier.ZKProof);
            verifier.bindJob(j, inC, modelC);
            verifier.submitCommitment(j, address(0xBEEF), verifier.zkProofCommitment(j, proofData));
        }
        vm.roll(block.number + 1);
        assertTrue(verifier.verifyZKProof(1, proof, publicInputs), "job 1 proof verifies");
        vm.expectRevert(bytes("ComputeVerifier: proof already used"));
        verifier.verifyZKProof(2, proof, publicInputs);
    }
}
