// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DisputeResolution, IDisputeJobRegistry} from "../../src/DisputeResolution.sol";
import {ComputePoolTraining} from "../../src/ComputePoolTraining.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";
import {InferenceRouter} from "../../src/InferenceRouter.sol";

/// Reverts on any native receive — models a requester contract.
contract RevertingRequesterR2 {
    function request(InferenceRouter r, bytes32 model, uint256 maxPrice) external payable returns (uint256) {
        return r.requestInference{value: msg.value}(model, hex"01", maxPrice);
    }

    receive() external payable {
        revert("no");
    }
}

/// Training requester whose receive reverts (finalize-refund variant).
contract RevertingTrainingRequester {
    function open(ComputePoolTraining t, ComputePoolTraining.TrainingJobSpec calldata spec)
        external
        payable
        returns (uint256)
    {
        return t.requestTrainingJob{value: msg.value}(spec);
    }

    function close(ComputePoolTraining t, uint256 job, address coord) external {
        t.closeRecruitment(job, coord);
    }

    receive() external payable {
        revert("no");
    }
}

/// Minimal job-party registry for DisputeResolution binding tests.
contract MockDisputeJobs is IDisputeJobRegistry {
    mapping(uint256 => address) public req;
    mapping(uint256 => address) public prov;

    function set(uint256 id, address r, address p) external {
        req[id] = r;
        prov[id] = p;
    }

    function jobParties(uint256 id) external view returns (address, address) {
        return (req[id], prov[id]);
    }
}

/// PBA-R2 CONTRACTS-A: the audit's F1 PoCs (evidence/F1/PBA_F1_Compute.t.sol)
/// turned into regression tests at the real entry points, with the
/// assertion INVERTED — each test passes only if the defect is closed.
contract PBA_R2_F1_Compute is Test {
    // ─────────────────────────── DisputeResolution ───────────────────────────

    /// PBA-L2-020 (F1-03 inverted): a challenger that never bisects loses the
    /// timeout; the defender who acknowledged is paid both bonds.
    function test_L2_020_stalling_challenger_loses_timeout() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        address challenger = address(0xC1);
        address defender = address(0xD1);
        vm.deal(challenger, 10 ether);
        vm.deal(defender, 10 ether);

        vm.prank(challenger);
        uint256 id = d.initiateDispute{value: 10 ether}(1, defender, 0, 1024);
        vm.prank(defender);
        d.acknowledgeDispute{value: 10 ether}(id);

        vm.roll(block.number + 151);
        vm.prank(challenger);
        d.timeoutDispute(id);
        assertEq(challenger.balance, 0, "stalling challenger forfeits");
        assertEq(defender.balance, 20 ether, "defender who acked wins both bonds");
        assertEq(uint256(d.getDispute(id).outcome), uint256(DisputeResolution.Outcome.DefenderWon));
    }

    /// PBA-L2-020 tripwire: a timeout never pays the party that owed the move.
    function test_L2_020_defender_that_stalls_after_bisect_loses() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        address challenger = address(0xC1);
        address defender = address(0xD1);
        vm.deal(challenger, 10 ether);
        vm.deal(defender, 10 ether);
        vm.prank(challenger);
        uint256 id = d.initiateDispute{value: 10 ether}(1, defender, 0, 1024);
        vm.prank(defender);
        d.acknowledgeDispute{value: 10 ether}(id);
        vm.prank(challenger);
        d.bisect(id, true); // challenger moved; defender now owes a respond
        assertTrue(d.awaitingDefender(id));
        vm.roll(block.number + 151);
        d.timeoutDispute(id);
        assertEq(challenger.balance, 20 ether, "defender owed the move and lost");
    }

    /// PBA-L2-020: after the defender responds the challenger owes the next
    /// bisect; if it stalls, the defender wins.
    function test_L2_020_challenger_stalls_after_respond_loses() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        address challenger = address(0xC1);
        address defender = address(0xD1);
        vm.deal(challenger, 10 ether);
        vm.deal(defender, 10 ether);
        vm.prank(challenger);
        uint256 id = d.initiateDispute{value: 10 ether}(1, defender, 0, 1024);
        vm.prank(defender);
        d.acknowledgeDispute{value: 10 ether}(id);
        vm.prank(challenger);
        d.bisect(id, true);
        vm.prank(defender);
        d.respond(id, bytes32("h"));
        assertFalse(d.awaitingDefender(id));
        vm.roll(block.number + 151);
        d.timeoutDispute(id);
        assertEq(defender.balance, 20 ether);
    }

    /// PBA-L2-020: governance can now rule at round 0.
    function test_L2_020_governance_resolves_at_round_zero() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        address challenger = address(0xC1);
        address defender = address(0xD1);
        vm.deal(challenger, 10 ether);
        vm.deal(defender, 10 ether);
        vm.prank(challenger);
        uint256 id = d.initiateDispute{value: 10 ether}(1, defender, 0, 1024);
        vm.prank(defender);
        d.acknowledgeDispute{value: 10 ether}(id);
        d.resolve(id, false); // this test contract is governance
        assertEq(defender.balance, 20 ether);
    }

    /// PBA-L2-021 (F1-04 inverted): squatting a jobId with a sock-puppet
    /// defender no longer blocks the real dispute, and resolved disputes free
    /// their slot.
    function test_L2_021_jobId_squat_does_not_block_real_dispute() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        address squatter = address(0x5A);
        address sock = address(0x50C);
        vm.deal(squatter, 10 ether);
        vm.prank(squatter);
        d.initiateDispute{value: 10 ether}(3, sock, 0, 2); // still open
        address realChallenger = address(0xBEEF);
        vm.deal(realChallenger, 10 ether);
        vm.prank(realChallenger);
        d.initiateDispute{value: 10 ether}(3, address(0xBAD), 0, 2); // not blocked
        assertTrue(d.jobDefenderDisputed(3, address(0xBAD)));
    }

    function test_L2_021_resolved_dispute_clears_flag() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        address squatter = address(0x5A);
        address defender = address(0xD1);
        vm.deal(squatter, 20 ether);
        vm.prank(squatter);
        uint256 id = d.initiateDispute{value: 10 ether}(7, defender, 0, 2);
        vm.roll(block.number + 151);
        d.timeoutDispute(id);
        assertFalse(d.jobDefenderDisputed(7, defender), "flag cleared on resolution");
        vm.prank(squatter);
        d.initiateDispute{value: 10 ether}(7, defender, 0, 2); // slot reusable
    }

    /// PBA-L2-021 tripwire: with a job registry bound, a non-party cannot
    /// open a dispute, and the defender must be the assigned provider.
    function test_L2_021_registry_bound_non_party_reverts() public {
        DisputeResolution d = new DisputeResolution(10 ether, 10);
        MockDisputeJobs jobsReg = new MockDisputeJobs();
        jobsReg.set(1, address(0xAA), address(0xBB));
        d.setJobRegistry(address(jobsReg));
        address outsider = address(0xCC);
        vm.deal(outsider, 10 ether);
        vm.prank(outsider);
        vm.expectRevert(bytes("Not job requester"));
        d.initiateDispute{value: 10 ether}(1, address(0xBB), 0, 2);

        vm.deal(address(0xAA), 20 ether);
        vm.prank(address(0xAA));
        vm.expectRevert(bytes("Defender not job provider"));
        d.initiateDispute{value: 10 ether}(1, address(0xDD), 0, 2);

        vm.prank(address(0xAA));
        vm.expectRevert(bytes("Unknown job"));
        d.initiateDispute{value: 10 ether}(99, address(0xBB), 0, 2);

        vm.prank(address(0xAA));
        d.initiateDispute{value: 10 ether}(1, address(0xBB), 0, 2); // the real party
    }

    // ─────────────────────────── ComputePoolTraining ─────────────────────────

    function _trainingJob(ComputePoolTraining t, address requester, address honest, address attacker)
        internal
        returns (uint256 job)
    {
        vm.deal(requester, 100 ether);
        vm.deal(honest, 10 ether);
        vm.deal(attacker, 10 ether);
        ComputePoolTraining.TrainingJobSpec memory spec = ComputePoolTraining.TrainingJobSpec({
            modelStartHash: bytes32("m"),
            datasetHash: bytes32("d"),
            epochCount: 10,
            stepsPerEpoch: 100,
            minWorkers: 2,
            maxWorkers: 2,
            challengeWindowBlocks: 50,
            perEpochBudget: 5 ether,
            perWorkerStake: 1 ether
        });
        vm.prank(requester);
        job = t.requestTrainingJob{value: 50 ether}(spec);
        vm.prank(honest);
        t.joinTrainingJob{value: 1 ether}(job);
        vm.prank(attacker);
        t.joinTrainingJob{value: 1 ether}(job);
        vm.prank(requester);
        t.closeRecruitment(job, honest);
    }

    /// PBA-L2-003 (F1-05 inverted): a co-worker can no longer take over
    /// coordination, so it can never commit (and get paid for) a root.
    function test_L2_003_worker_cannot_hijack_coordination() public {
        ComputePoolTraining t = new ComputePoolTraining(address(this));
        address requester = address(0xAA);
        address honest = address(0x11);
        address attacker = address(0x22);
        uint256 job = _trainingJob(t, requester, honest, attacker);

        vm.roll(block.number + 101);
        vm.prank(attacker);
        vm.expectRevert(bytes("ComputePoolTraining: not authorized"));
        t.reassignCoordinator(job, attacker);

        vm.prank(attacker);
        vm.expectRevert(bytes("ComputePoolTraining: not coordinator"));
        t.commitEpoch(job, 0, keccak256("garbage"));

        // Tripwire: nobody has been credited under a coordinator the
        // requester did not choose.
        assertEq(t.getWorker(job, attacker).paymentEarned, 0);
        assertEq(t.getJob(job).escrowRemaining, 50 ether, "escrow untouched");
    }

    /// PBA-L2-003: the requester (and governance) can still replace a
    /// stalled coordinator.
    function test_L2_003_requester_and_governance_can_reassign() public {
        ComputePoolTraining t = new ComputePoolTraining(address(this));
        address requester = address(0xAA);
        address honest = address(0x11);
        address other = address(0x22);
        uint256 job = _trainingJob(t, requester, honest, other);
        uint256 b0 = block.number; // via_ir: use absolute heights
        vm.roll(b0 + 101);
        vm.prank(requester);
        t.reassignCoordinator(job, other);
        assertEq(t.getJob(job).coordinator, other);
        vm.roll(b0 + 202);
        t.reassignCoordinator(job, honest); // governance (this)
        assertEq(t.getJob(job).coordinator, honest);
    }

    /// PBA-L2-003: worker-side exit when the requester disappears. The job
    /// only moves to Awaiting (challenge window still runs); nothing is paid
    /// early and uncommitted budget returns to the requester.
    function test_L2_003_stalled_job_expires_through_challenge_window() public {
        ComputePoolTraining t = new ComputePoolTraining(address(this));
        address requester = address(0xAA);
        address honest = address(0x11);
        address other = address(0x22);
        uint256 job = _trainingJob(t, requester, honest, other);
        vm.prank(honest);
        t.commitEpoch(job, 0, keccak256("r0"));

        vm.prank(other);
        vm.expectRevert(bytes("ComputePoolTraining: not stalled"));
        t.expireStalledTraining(job);

        vm.roll(block.number + t.STALL_EXPIRY_BLOCKS() + 1);
        vm.prank(address(0x99));
        vm.expectRevert(bytes("ComputePoolTraining: not authorized"));
        t.expireStalledTraining(job);

        vm.prank(other);
        t.expireStalledTraining(job);
        assertEq(uint256(t.getJob(job).state), uint256(ComputePoolTraining.JobState.Awaiting));
        vm.expectRevert(bytes("ComputePoolTraining: challenge window open"));
        t.finalizeTrainingJob(job);

        vm.roll(block.number + 51);
        uint256 before = requester.balance;
        t.finalizeTrainingJob(job);
        assertEq(requester.balance - before, 45 ether, "9 uncommitted epochs refunded");
    }

    /// Variant of PBA-L2-005 / L2-023: a requester that reverts on receive
    /// cannot block finalization for the workers; its refund is deferred.
    function test_variant_reverting_training_requester_cannot_block_finalize() public {
        ComputePoolTraining t = new ComputePoolTraining(address(this));
        RevertingTrainingRequester req = new RevertingTrainingRequester();
        address w1 = address(0x11);
        address w2 = address(0x22);
        vm.deal(address(this), 100 ether);
        vm.deal(w1, 10 ether);
        vm.deal(w2, 10 ether);
        ComputePoolTraining.TrainingJobSpec memory spec = ComputePoolTraining.TrainingJobSpec({
            modelStartHash: bytes32("m"), datasetHash: bytes32("d"), epochCount: 2, stepsPerEpoch: 10,
            minWorkers: 2, maxWorkers: 2, challengeWindowBlocks: 5, perEpochBudget: 1 ether, perWorkerStake: 1 ether
        });
        uint256 job = req.open{value: 2 ether}(t, spec);
        vm.prank(w1);
        t.joinTrainingJob{value: 1 ether}(job);
        vm.prank(w2);
        t.joinTrainingJob{value: 1 ether}(job);
        req.close(t, job, w1);
        vm.prank(w1);
        t.commitEpoch(job, 0, keccak256("r0"));
        uint256 b0 = block.number;
        vm.roll(b0 + t.STALL_EXPIRY_BLOCKS() + 1);
        vm.prank(w2);
        t.expireStalledTraining(job);
        vm.roll(b0 + t.STALL_EXPIRY_BLOCKS() + 10);
        uint256 before = w2.balance;
        t.finalizeTrainingJob(job);
        assertEq(w2.balance - before, 1.5 ether, "worker paid despite reverting requester");
        assertEq(t.requesterRefundPending(job), 1 ether, "requester refund deferred");
    }

    // ─────────────────────── ComputeMarketplace / Verifier ───────────────────

    ComputeMarketplace market;
    ComputeVerifier verifier;
    bytes32 constant MODEL = bytes32(uint256(0xC1));
    bytes constant INPUT = hex"1234";

    function _market() internal {
        verifier = new ComputeVerifier(address(1));
        market = new ComputeMarketplace(address(verifier), address(0x7EA5));
        verifier.setMarketplace(address(market));
    }

    function _provider(address p) internal {
        vm.deal(p, 2000 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(p);
        market.registerProvider{value: 1000 ether}(models);
    }

    function _assignedJob(address requester, address p, uint256 price, ComputeVerifier.VerificationTier tier, bytes memory input)
        internal
        returns (uint256 id)
    {
        vm.deal(requester, requester.balance + price);
        vm.prank(requester);
        id = market.postJob{value: price}(MODEL, input, price, tier, 10, 100);
        vm.prank(p);
        market.bidOnJob(id, price, 1);
        market.assignBestBid(id);
        vm.prank(p);
        market.startExecution(id);
        vm.prank(p);
        market.submitCommitment(id, bytes32(uint256(1)));
    }

    /// PBA-L2-004 (F1-06a inverted): a Commitment-tier result can no longer
    /// be paid in the same block; the requester's dispute lands in time.
    function test_L2_004a_dispute_window_blocks_same_block_completion() public {
        _market();
        address p = address(0x9001);
        address requester = address(0x9002);
        _provider(p);
        vm.deal(requester, 5 ether);
        vm.prank(requester);
        uint256 id = market.postJob{value: 5 ether}(MODEL, INPUT, 5 ether, ComputeVerifier.VerificationTier.Commitment, 10, 100);
        vm.prank(p);
        market.bidOnJob(id, 5 ether, 1);
        market.assignBestBid(id);
        vm.prank(p);
        market.startExecution(id);

        bytes memory garbage = "not the model output";
        bytes32 nonce = bytes32("n");
        bytes32 c = keccak256(abi.encodePacked(garbage, nonce));
        vm.startPrank(p);
        market.submitCommitment(id, c);
        market.submitResult(id, hex"00", abi.encodePacked(c, nonce, garbage));
        vm.expectRevert(bytes("ComputeMarketplace: dispute window open"));
        market.completeJob(id);
        vm.stopPrank();

        vm.deal(requester, 10 ether);
        vm.prank(requester);
        market.disputeResult{value: 10 ether}(id); // lands inside the window
        assertEq(market.disputeFiler(id), requester);

        vm.roll(block.number + market.DISPUTE_WINDOW());
        vm.expectRevert(bytes("ComputeMarketplace: dispute active"));
        market.completeJob(id);
    }

    /// PBA-L2-004 tripwire: completeJob reverts before the window closes and
    /// succeeds after it.
    function test_L2_004a_complete_after_window() public {
        _market();
        address p = address(0x9001);
        address requester = address(0x9002);
        _provider(p);
        vm.deal(requester, 5 ether);
        vm.prank(requester);
        uint256 id = market.postJob{value: 5 ether}(MODEL, INPUT, 5 ether, ComputeVerifier.VerificationTier.Commitment, 10, 100);
        vm.prank(p);
        market.bidOnJob(id, 5 ether, 1);
        market.assignBestBid(id);
        vm.prank(p);
        market.startExecution(id);
        bytes memory out = "out";
        bytes32 nonce = bytes32("n");
        bytes32 c = keccak256(abi.encodePacked(out, nonce));
        vm.startPrank(p);
        market.submitCommitment(id, c);
        market.submitResult(id, hex"00", abi.encodePacked(c, nonce, out));
        vm.stopPrank();
        vm.roll(block.number + market.DISPUTE_WINDOW() - 1);
        vm.expectRevert(bytes("ComputeMarketplace: dispute window open"));
        market.completeJob(id);
        vm.roll(block.number + 1);
        market.completeJob(id);
        assertEq(uint256(market.getJob(id).state), uint256(ComputeMarketplace.JobState.Completed));
    }

    function _zkProofData(bytes memory input, bytes32 model, bytes memory outputHash, bytes memory proof)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory publicInputs = abi.encode(keccak256(input), model, keccak256(outputHash));
        return abi.encodePacked(uint256(proof.length), proof, publicInputs);
    }

    /// PBA-L2-004 (F1-06b inverted): copying an honest provider's pending
    /// proof no longer fails the honest job or slashes the honest provider.
    function test_L2_004b_frontrun_copy_does_not_slash_honest_provider() public {
        _market();
        vm.mockCall(address(0x0108), bytes(""), abi.encode(uint256(1)));
        address honest = address(0xA1);
        address thief = address(0xB1);
        _provider(honest);
        _provider(thief);
        uint256 victimJob = _assignedJob(address(0xCC), honest, 50 ether, ComputeVerifier.VerificationTier.ZKProof, INPUT);
        uint256 thiefJob = _assignedJob(thief, thief, 11 ether, ComputeVerifier.VerificationTier.ZKProof, INPUT);

        bytes memory outputHash = hex"00";
        bytes memory proofData = _zkProofData(INPUT, MODEL, outputHash, hex"0badc0de");

        vm.prank(thief);
        market.submitResult(thiefJob, outputHash, proofData); // front-run copy

        vm.prank(honest);
        market.submitResult(victimJob, outputHash, proofData); // honest submission
        assertEq(uint256(verifier.getResult(victimJob)), uint256(ComputeVerifier.VerificationResult.Valid));
        assertEq(uint256(market.getJob(victimJob).state), uint256(ComputeMarketplace.JobState.Verifying));
        assertEq(market.getProvider(honest).stake, 1000 ether, "honest provider not slashed");
    }

    /// PBA-L2-004 tripwire: a proof valid for job A is Invalid for a job B
    /// whose input differs (and for a different output / model binding).
    function test_L2_004b_proof_bound_to_job_input_and_output() public {
        _market();
        vm.mockCall(address(0x0108), bytes(""), abi.encode(uint256(1)));
        address p = address(0xA1);
        _provider(p);
        uint256 jobB = _assignedJob(address(0xCC), p, 50 ether, ComputeVerifier.VerificationTier.ZKProof, hex"9999");
        // Proof material produced for a job with INPUT (not job B's input).
        bytes memory proofData = _zkProofData(INPUT, MODEL, hex"00", hex"0badc0de");
        vm.prank(p);
        market.submitResult(jobB, hex"00", proofData);
        assertEq(uint256(verifier.getResult(jobB)), uint256(ComputeVerifier.VerificationResult.Invalid));

        uint256 jobC = _assignedJob(address(0xCD), p, 50 ether, ComputeVerifier.VerificationTier.ZKProof, INPUT);
        // Right input + model but the proof commits to a different output.
        bytes memory wrongOut = _zkProofData(INPUT, MODEL, hex"01", hex"0badc0de");
        vm.prank(p);
        market.submitResult(jobC, hex"00", wrongOut);
        assertEq(uint256(verifier.getResult(jobC)), uint256(ComputeVerifier.VerificationResult.Invalid));
    }

    /// PBA-L2-004: a TEE attestation signed for job A does not verify job B.
    function test_L2_004_tee_attestation_bound_to_job() public {
        ComputeVerifier v = new ComputeVerifier(address(this));
        (address oracle, uint256 pk) = makeAddrAndKey("tee");
        v.addTEEOracle(oracle);
        bytes memory att = hex"deadbeef";
        for (uint256 j = 1; j <= 2; j++) {
            v.configureJob(j, 100 ether, ComputeVerifier.VerificationTier.TEE);
            v.submitCommitment(j, address(0xBEEF), bytes32(j));
        }
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", v.teeAttestationDigest(1, att))
        );
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        bytes memory sig = abi.encodePacked(r, s, vv);
        assertFalse(v.verifyTEEAttestation(2, att, sig), "job-1 attestation cannot settle job 2");
        assertTrue(v.verifyTEEAttestation(1, att, sig));
    }

    // ─────────────────────────────── InferenceRouter ─────────────────────────

    function _router() internal returns (InferenceRouter r, address p) {
        r = new InferenceRouter(address(0x1234));
        p = address(0xF00);
        vm.deal(p, 200 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(p);
        r.registerProvider{value: 100 ether}("https://p", 1 ether, models);
    }

    /// PBA-L2-005 (F1-07 inverted): a requester that reverts on receive can
    /// no longer block completion or freeze the provider's stake.
    function test_L2_005_reverting_requester_cannot_freeze_provider() public {
        (InferenceRouter r, address p) = _router();
        RevertingRequesterR2 evil = new RevertingRequesterR2();
        vm.deal(address(this), 20 ether);
        uint256 id = evil.request{value: 1 ether + 1}(r, MODEL, 1 ether + 1);

        vm.prank(p);
        r.completeInference(id, hex"aa");
        assertEq(r.refundOwed(address(evil)), 1, "refund credited, not pushed");

        vm.prank(p);
        r.updateProviderStatus(false);
        uint256 before = p.balance;
        vm.prank(p);
        r.withdrawStake(100 ether);
        assertEq(p.balance - before, 100 ether, "stake withdrawable");
    }

    /// PBA-L2-005 tripwire: a Processing request always has an exit —
    /// `currentLoad` returns to 0 after REQUEST_TIMEOUT whatever the parties do.
    function test_L2_005_processing_request_expires() public {
        (InferenceRouter r, address p) = _router();
        address user = address(0x5E);
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 id = r.requestInference{value: 3 ether}(MODEL, hex"01", 2 ether);
        assertEq(r.refundOwed(user), 1 ether, "excess msg.value credited");

        vm.expectRevert(bytes("Not expired"));
        r.expireRequest(id);
        vm.warp(block.timestamp + r.REQUEST_TIMEOUT() + 1);
        r.expireRequest(id);
        (, , uint256 load, , ) = r.getProviderInfo(p);
        assertEq(load, 0, "load freed");
        assertEq(r.refundOwed(user), 3 ether, "maxPrice refunded to requester");

        vm.prank(p);
        vm.expectRevert(bytes("Invalid status"));
        r.completeInference(id, hex"aa");

        uint256 before = user.balance;
        vm.prank(user);
        r.claimRefund();
        assertEq(user.balance - before, 3 ether);
    }

    receive() external payable {}
}
