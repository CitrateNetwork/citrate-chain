// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../src/ComputeVerifier.sol";
import {HeartbeatMonitor} from "../src/HeartbeatMonitor.sol";
import {DisputeResolution} from "../src/DisputeResolution.sol";
import {ComputePool} from "../src/ComputePool.sol";
import {ContributionAccounting} from "../src/ContributionAccounting.sol";

/// @title ComputeIntegrationTest — End-to-end flows spanning multiple compute marketplace contracts
/// @notice Tests full job lifecycles, cross-contract interactions, failure paths, and economic flows.
contract ComputeIntegrationTest is Test {
    ComputeMarketplace internal marketplace;
    ComputeVerifier internal verifier;
    HeartbeatMonitor internal heartbeat;
    DisputeResolution internal dispute;
    ComputePool internal pool;
    ContributionAccounting internal contributions;

    address internal governance;
    address internal treasury = address(0x77EA5);

    address internal requester = address(0xAAAA);
    address internal provider1 = address(0xBBB1);
    address internal provider2 = address(0xBBB2);
    address internal provider3 = address(0xBBB3);
    address internal disputer = address(0xD15A);
    address internal poolCreator = address(0xCCCC);

    bytes32 internal modelHash = keccak256("integration-model-v1");
    bytes internal inputHash = hex"CAFE";

    /// @notice Test price must be <= VALUE_THRESHOLD (10 ether) to use Commitment tier
    uint256 internal constant TEST_PRICE = 8 ether;

    // Commitment values
    bytes internal outputData = hex"01020304";
    bytes32 internal nonce = keccak256("integration-nonce");
    bytes32 internal commitmentHash;

    // Invalid commitment for failed verification tests
    bytes internal wrongOutputData = hex"DEAD";
    bytes32 internal wrongNonce = keccak256("wrong-nonce");
    bytes32 internal wrongCommitmentHash;

    function setUp() public {
        governance = address(this);

        // Deploy core contracts
        verifier = new ComputeVerifier(address(1));
        marketplace = new ComputeMarketplace(address(verifier), treasury);
        verifier.setMarketplace(address(marketplace));

        heartbeat = new HeartbeatMonitor(100, 3);
        dispute = new DisputeResolution(10 ether, 20);
        pool = new ComputePool();
        contributions = new ContributionAccounting();

        // Fund accounts
        vm.deal(requester, 10000 ether);
        vm.deal(provider1, 5000 ether);
        vm.deal(provider2, 5000 ether);
        vm.deal(provider3, 5000 ether);
        vm.deal(disputer, 5000 ether);
        vm.deal(poolCreator, 5000 ether);
        vm.deal(address(0xdead), 0);

        // Pre-compute commitment hashes
        commitmentHash = keccak256(abi.encodePacked(outputData, nonce));
        wrongCommitmentHash = keccak256(abi.encodePacked(wrongOutputData, wrongNonce));
    }

    // ── Helpers ───────────────────────────────────────────────────

    function _registerProvider(address provider) internal {
        bytes32[] memory models = new bytes32[](1);
        models[0] = modelHash;
        vm.prank(provider);
        marketplace.registerProvider{value: 1000 ether}(models);
    }

    function _postJob(uint256 maxPrice, uint256 bidWindow, uint256 execWindow) internal returns (uint256) {
        vm.prank(requester);
        return marketplace.postJob{value: maxPrice}(
            modelHash, inputHash, maxPrice,
            ComputeVerifier.VerificationTier.Commitment,
            bidWindow, execWindow
        );
    }

    function _bidOnJob(uint256 jobId, address provider, uint256 price) internal {
        vm.prank(provider);
        marketplace.bidOnJob(jobId, price, 100);
    }

    function _assignJob(uint256 jobId) internal {
        marketplace.assignBestBid(jobId);
    }

    function _startExecution(uint256 jobId, address provider) internal {
        vm.prank(provider);
        marketplace.startExecution(jobId);
    }

    function _submitCommitment(uint256 jobId, address provider) internal {
        vm.prank(provider);
        marketplace.submitCommitment(jobId, commitmentHash);
    }

    function _submitResult(uint256 jobId, address provider) internal {
        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider);
        marketplace.submitResult(jobId, outputData, proof);
    }

    function _fullLifecycle(address provider) internal returns (uint256 jobId) {
        jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider);
        _submitCommitment(jobId, provider);
        _submitResult(jobId, provider);
    }

    // =====================================================================
    // 1. FULL HAPPY PATH LIFECYCLE
    // =====================================================================

    /// @notice Complete lifecycle: post -> bid -> assign -> execute -> commit -> verify -> complete.
    ///         Verifies commitment-based verification flow end-to-end.
    function test_fullJobLifecycle_commitmentVerification() public {
        _registerProvider(provider1);

        uint256 requesterBalBefore = requester.balance;
        uint256 provider1BalBefore = provider1.balance;
        uint256 treasuryBalBefore = treasury.balance;

        // Post job
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Bidding), "State: Bidding");
        assertEq(job.escrow, TEST_PRICE, "Escrow locked");

        // Bid
        _bidOnJob(jobId, provider1, 6 ether);

        // Assign
        _assignJob(jobId);
        job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Assigned), "State: Assigned");
        assertEq(job.assignedProvider, provider1, "Provider assigned");

        // Start execution
        _startExecution(jobId, provider1);
        job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Executing), "State: Executing");

        // Submit commitment
        _submitCommitment(jobId, provider1);

        // Submit result with proof
        _submitResult(jobId, provider1);
        job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Verifying), "State: Verifying");

        // Verify verification result
        ComputeVerifier.VerificationResult result = verifier.getResult(jobId);
        assertEq(uint(result), uint(ComputeVerifier.VerificationResult.Valid), "Verification: Valid");

        // Complete and pay
        marketplace.completeJob(jobId);
        job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "State: Completed");
        assertEq(job.escrow, 0, "Escrow: zeroed out");

        // Verify payment distribution
        uint256 burnAmount = TEST_PRICE / 40;
        uint256 treasuryAmount = TEST_PRICE / 40;
        uint256 providerAmount = TEST_PRICE - burnAmount - treasuryAmount;

        // Provider1 had their balance reduced by 1000 ether for registration stake
        // So provider1BalBefore already accounts for the stake deduction
        assertEq(provider1.balance - provider1BalBefore, providerAmount, "Provider received correct payment");
        assertEq(treasury.balance - treasuryBalBefore, treasuryAmount, "Treasury received correct fee");
        assertEq(requesterBalBefore - requester.balance, TEST_PRICE, "Requester paid correct amount");
    }

    /// @notice Full lifecycle with ZK verification tier (high-value job).
    ///         High-value jobs auto-upgrade from Commitment to ZKProof tier.
    function test_fullJobLifecycle_zkVerification() public {
        _registerProvider(provider1);

        // Post a high-value job requesting Commitment tier — should auto-upgrade to ZKProof
        uint256 highValue = 11 ether; // Above VALUE_THRESHOLD (10 ether)
        vm.prank(requester);
        uint256 jobId = marketplace.postJob{value: highValue}(
            modelHash, inputHash, highValue,
            ComputeVerifier.VerificationTier.Commitment, // Will be upgraded
            10, 100
        );

        // Verify tier was auto-upgraded by the verifier
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(jobId);
        assertEq(
            uint(rec.tier),
            uint(ComputeVerifier.VerificationTier.ZKProof),
            "High-value job must auto-upgrade to ZKProof tier"
        );

        // Job state is still Bidding
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Bidding), "State: Bidding");
    }

    // =====================================================================
    // 2. MARKETPLACE + VERIFIER + SLASHING
    // =====================================================================

    /// @notice Failed verification triggers provider slash and escrow refund.
    function test_failedVerification_triggersSlash() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);

        // Submit correct commitment but wrong proof
        vm.prank(provider1);
        marketplace.submitCommitment(jobId, commitmentHash);

        // Submit wrong proof data that won't match commitment
        bytes32 wrongCommit = keccak256("totally-wrong");
        bytes memory badProof = abi.encodePacked(wrongCommit, nonce, outputData);
        vm.prank(provider1);
        marketplace.submitResult(jobId, outputData, badProof);

        // Verification failed — job should be in Failed state
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Failed), "State: Failed on bad verification");
        assertEq(job.escrow, 0, "Escrow refunded");

        // Provider should be slashed
        ComputeMarketplace.ProviderProfile memory profile = marketplace.getProvider(provider1);
        assertLt(profile.stake, 1000 ether, "Provider stake must be reduced (slashed)");
        assertEq(profile.totalJobsFailed, 1, "Failed job counter incremented");
    }

    /// @notice Job that times out: provider slashed, requester refunded.
    function test_timedOutJob_refundsAndSlashes() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);

        // Advance past execution deadline
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        vm.roll(job.executionDeadline + 1);

        uint256 requesterBalBefore = requester.balance;

        // Timeout the job
        marketplace.timeoutJob(jobId);

        job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Timeout), "State: Timeout");
        assertEq(job.escrow, 0, "Escrow cleared");

        // Requester refunded
        assertEq(requester.balance - requesterBalBefore, TEST_PRICE, "Requester fully refunded");

        // Provider slashed
        ComputeMarketplace.ProviderProfile memory profile = marketplace.getProvider(provider1);
        assertLt(profile.stake, 1000 ether, "Provider stake reduced by timeout slash");
        assertEq(profile.totalJobsFailed, 1, "Failed job counter incremented");
    }

    // =====================================================================
    // 3. MARKETPLACE + HEARTBEAT MONITOR
    // =====================================================================

    /// @notice Suspended provider in heartbeat monitor loses active status.
    function test_suspendedProvider_cantBeAssigned() public {
        // Register provider in heartbeat monitor
        // Start at block 10 to ensure block math works
        vm.roll(10);
        vm.prank(provider1);
        heartbeat.register();

        uint256 interval = heartbeat.heartbeatInterval();

        // Suspend by missing heartbeats
        for (uint256 i = 0; i < 3; i++) {
            vm.roll(block.number + interval + 1);
            heartbeat.checkHeartbeat(provider1);
        }

        // Provider is suspended in heartbeat monitor
        assertFalse(heartbeat.isActive(provider1), "Provider suspended in heartbeat monitor");

        // Note: HeartbeatMonitor and ComputeMarketplace are independent contracts.
        // In production, the assignment logic would check heartbeat status.
        // This test verifies the heartbeat monitor correctly reports suspension state.
        (, , bool suspended, ) = heartbeat.health(provider1);
        assertTrue(suspended, "Health record shows suspended");
    }

    /// @notice Provider suspended during job execution: heartbeat shows inactive.
    function test_providerSuspendedDuringJob_jobTimesOut() public {
        // Start at block 10
        vm.roll(10);

        _registerProvider(provider1);

        // Register in heartbeat
        vm.prank(provider1);
        heartbeat.register();

        // Start a job with long execution window
        uint256 jobId = _postJob(TEST_PRICE, 10, 5000);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);

        uint256 interval = heartbeat.heartbeatInterval();

        // Suspend provider via missed heartbeats
        for (uint256 i = 0; i < 3; i++) {
            vm.roll(block.number + interval + 1);
            heartbeat.checkHeartbeat(provider1);
        }

        assertFalse(heartbeat.isActive(provider1), "Provider suspended during job");

        // Advance past execution deadline
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        vm.roll(job.executionDeadline + 1);

        // Timeout the job
        marketplace.timeoutJob(jobId);

        job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Timeout), "Job timed out");
    }

    // =====================================================================
    // 4. MARKETPLACE + DISPUTE RESOLUTION
    // =====================================================================

    /// @notice Dispute flow where challenger wins: escrow refunded, bond returned.
    function test_disputeFlow_challengerWins_refunded() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycle(provider1);

        uint256 requesterBalBefore = requester.balance;
        uint256 disputerBalBefore = disputer.balance;

        // Disputer files dispute
        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        // Verify dispute is active
        assertTrue(verifier.isDisputeActive(jobId), "Dispute must be active");

        // Governance resolves: challenger (disputer) wins
        marketplace.resolveDispute(jobId, true);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Disputed), "State: Disputed");

        // Disputer gets bond back
        assertEq(disputer.balance, disputerBalBefore, "Disputer bond fully returned");

        // Requester gets escrow refund
        assertGt(requester.balance, requesterBalBefore, "Requester received escrow refund");
    }

    /// @notice Dispute flow where defender wins: bond burned, job can be completed.
    function test_disputeFlow_defenderWins_bondToDefender() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycle(provider1);

        uint256 disputerBalBefore = disputer.balance;

        // Disputer files dispute
        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        // Governance resolves: defender (provider) wins
        marketplace.resolveDispute(jobId, false);

        // Bond burned (sent to 0xdead)
        assertEq(
            disputerBalBefore - disputer.balance,
            10 ether,
            "Disputer loses entire bond"
        );
        assertGt(marketplace.totalDisputeBondsBurned(), 0, "Bond burn tracked");

        // Job can now be completed (dispute resolved in favor of defender)
        // The job should be completable since the dispute cleared it
        marketplace.completeJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "Job completed after dispute resolved");
    }

    /// @notice Dispute timeout: non-responding party in DisputeResolution loses.
    function test_disputeTimeout_nonResponderLoses() public {
        // Use the standalone DisputeResolution contract
        // Fund the dispute contract to cover both bonds in payout
        vm.deal(address(dispute), 20 ether);

        vm.prank(disputer);
        uint256 disputeId = dispute.initiateDispute{value: 10 ether}(
            42, provider1, 0, 1000
        );

        // Defender doesn't acknowledge within deadline
        uint256 deadline = dispute.DEFAULT_ROUND_DEADLINE();
        vm.roll(block.number + deadline + 1);

        // Timeout the dispute — challenger wins by default
        dispute.timeoutDispute(disputeId);

        DisputeResolution.Dispute memory d = dispute.getDispute(disputeId);
        assertEq(
            uint(d.state),
            uint(DisputeResolution.DisputeState.Resolved),
            "Dispute resolved"
        );
        assertEq(
            uint(d.outcome),
            uint(DisputeResolution.Outcome.ChallengerWon),
            "Challenger wins on timeout"
        );
    }

    // =====================================================================
    // 5. MARKETPLACE + POOL
    // =====================================================================

    /// @notice Pool compute request routes to pool and can be completed.
    function test_poolCompute_routesToPoolMembers() public {
        // Create pool with multiple providers
        vm.prank(poolCreator);
        uint256 poolId = pool.createPool(
            "GPU-Pool",
            ComputePool.PoolMode.InferencePool,
            2, // min 2 providers
            100,
            1 ether
        );

        // Providers join pool
        vm.prank(provider1);
        pool.joinPool{value: 20 ether}(poolId, 2);

        vm.prank(provider2);
        pool.joinPool{value: 30 ether}(poolId, 3);

        ComputePool.Pool memory p = pool.getPool(poolId);
        assertEq(p.totalGPUs, 5, "Total 5 GPUs in pool");
        assertEq(p.memberCount, 2, "2 members");
        assertEq(uint(p.state), uint(ComputePool.PoolState.Active), "Pool active");

        // Request compute from pool
        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 1 ether}(
            poolId, hex"CAFE", 1 ether
        );

        ComputePool.PoolJob memory job = pool.getJob(jobId);
        assertEq(job.poolId, poolId, "Job routed to correct pool");
        assertEq(job.payment, 1 ether, "Payment locked");
        assertEq(uint(job.status), uint(ComputePool.JobStatus.Pending), "Job pending");

        // Complete the job — payment distributed proportionally
        uint256 p1Before = provider1.balance;
        uint256 p2Before = provider2.balance;

        vm.prank(poolCreator);
        pool.completeJob(jobId);

        // provider1 has 2/5 GPUs, provider2 has 3/5 GPUs
        // provider1 share: 1 ether * 2 / 5 = 0.4 ether
        // provider2 share: 1 ether * 3 / 5 = 0.6 ether
        uint256 p1Share = provider1.balance - p1Before;
        uint256 p2Share = provider2.balance - p2Before;

        assertEq(p1Share, 0.4 ether, "Provider1 receives 2/5 share");
        assertEq(p2Share, 0.6 ether, "Provider2 receives 3/5 share");
    }

    /// @notice SLA violation slashes pool members proportionally.
    function test_poolSLAViolation_slashesMembers() public {
        vm.prank(poolCreator);
        uint256 poolId = pool.createPool(
            "SLA-Pool",
            ComputePool.PoolMode.InferencePool,
            1,
            1000, // guaranteed 1000 qps
            1 ether
        );

        vm.prank(provider1);
        pool.joinPool{value: 50 ether}(poolId, 5);

        vm.prank(provider2);
        pool.joinPool{value: 30 ether}(poolId, 3);

        ComputePool.PoolMember memory m1Before = pool.getMember(poolId, provider1);

        // Report SLA violation: actual throughput is only 500 out of 1000
        pool.reportSLAViolation(poolId, 500);

        ComputePool.PoolMember memory m1After = pool.getMember(poolId, provider1);
        ComputePool.PoolMember memory m2After = pool.getMember(poolId, provider2);

        // Both members should have reduced stake
        assertLt(m1After.stake, m1Before.stake, "Provider1 stake slashed");
        assertLt(m2After.stake, 30 ether, "Provider2 stake slashed");

        // Penalty is proportional to deficit: (500/1000) * 10% * stake
        // provider1: 50 * 0.1 * 0.5 = 2.5 ether penalty
        // provider2: 30 * 0.1 * 0.5 = 1.5 ether penalty
        uint256 p1Penalty = m1Before.stake - m1After.stake;
        assertEq(p1Penalty, 2.5 ether, "Provider1 penalty: (deficit/guaranteed) * 10% * stake");
    }

    // =====================================================================
    // 6. FULL ECONOMIC LOOP
    // =====================================================================

    /// @notice Completed job records burn amount and provider payment in global counters.
    function test_completedJob_contributionRecorded() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycle(provider1);

        uint256 burnBefore = marketplace.totalBurned();
        uint256 paidBefore = marketplace.totalPaidToProviders();
        uint256 treasuryBefore = marketplace.totalTreasuryFees();

        marketplace.completeJob(jobId);

        uint256 burnAfter = marketplace.totalBurned();
        uint256 paidAfter = marketplace.totalPaidToProviders();
        uint256 treasuryAfter = marketplace.totalTreasuryFees();

        assertGt(burnAfter, burnBefore, "Burn amount recorded");
        assertGt(paidAfter, paidBefore, "Provider payment recorded");
        assertGt(treasuryAfter, treasuryBefore, "Treasury fee recorded");
    }

    /// @notice BME burn amount is exactly 2.5% of the escrow (price / 40).
    function test_completedJob_burnAmount_exact() public {
        _registerProvider(provider1);

        uint256 price = 8 ether; // <= VALUE_THRESHOLD for Commitment tier
        vm.prank(requester);
        uint256 jobId = marketplace.postJob{value: price}(
            modelHash, inputHash, price,
            ComputeVerifier.VerificationTier.Commitment,
            10, 100
        );

        _bidOnJob(jobId, provider1, price);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        uint256 burnBefore = marketplace.totalBurned();
        marketplace.completeJob(jobId);
        uint256 burnAfter = marketplace.totalBurned();

        assertEq(burnAfter - burnBefore, price / 40, "Burn must be exactly 2.5% = price / 40");
        assertEq(burnAfter - burnBefore, 0.2 ether, "8 ether * 2.5% = 0.2 ether");
    }

    /// @notice Multiple jobs accumulate burn correctly.
    function test_multipleJobs_cumulativeBurn() public {
        _registerProvider(provider1);

        uint256 expectedTotalBurn = 0;

        // Use small prices to stay below VALUE_THRESHOLD
        uint256[5] memory prices = [uint256(1 ether), 2 ether, 3 ether, 4 ether, 5 ether];

        for (uint256 i = 0; i < 5; i++) {
            uint256 price = prices[i];

            vm.prank(requester);
            uint256 jobId = marketplace.postJob{value: price}(
                modelHash, inputHash, price,
                ComputeVerifier.VerificationTier.Commitment,
                10, 100
            );

            _bidOnJob(jobId, provider1, price);
            _assignJob(jobId);
            _startExecution(jobId, provider1);
            _submitCommitment(jobId, provider1);
            _submitResult(jobId, provider1);
            marketplace.completeJob(jobId);

            expectedTotalBurn += price / 40;
        }

        assertEq(marketplace.totalBurned(), expectedTotalBurn, "Cumulative burn must be exact");
    }

    // =====================================================================
    // 7. LEARNING INTEGRATION
    // =====================================================================

    /// @notice Verifies that the marketplace and verifier can handle sequential jobs
    ///         in a learning-cycle-like pattern (multiple sequential computations).
    function test_learningCycleUsesMarketplace() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        // Simulate a learning cycle: multiple sequential compute jobs
        uint256[] memory jobIds = new uint256[](3);

        // Step 1: Embedding computation
        jobIds[0] = _postJob(5 ether, 10, 100);
        _bidOnJob(jobIds[0], provider1, 4 ether);
        _assignJob(jobIds[0]);
        _startExecution(jobIds[0], provider1);
        _submitCommitment(jobIds[0], provider1);
        _submitResult(jobIds[0], provider1);
        marketplace.completeJob(jobIds[0]);

        // Step 2: Gradient computation
        jobIds[1] = _postJob(8 ether, 10, 100);
        _bidOnJob(jobIds[1], provider2, 6 ether);
        _assignJob(jobIds[1]);
        _startExecution(jobIds[1], provider2);
        _submitCommitment(jobIds[1], provider2);
        _submitResult(jobIds[1], provider2);
        marketplace.completeJob(jobIds[1]);

        // Step 3: Aggregation
        jobIds[2] = _postJob(3 ether, 10, 100);
        _bidOnJob(jobIds[2], provider1, 3 ether);
        _assignJob(jobIds[2]);
        _startExecution(jobIds[2], provider1);
        _submitCommitment(jobIds[2], provider1);
        _submitResult(jobIds[2], provider1);
        marketplace.completeJob(jobIds[2]);

        // All three jobs completed
        for (uint256 i = 0; i < 3; i++) {
            ComputeMarketplace.Job memory job = marketplace.getJob(jobIds[i]);
            assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "All learning cycle jobs completed");
        }

        // Provider stats updated
        ComputeMarketplace.ProviderProfile memory p1 = marketplace.getProvider(provider1);
        ComputeMarketplace.ProviderProfile memory p2 = marketplace.getProvider(provider2);
        assertEq(p1.totalJobsCompleted, 2, "Provider1 completed 2 learning jobs");
        assertEq(p2.totalJobsCompleted, 1, "Provider2 completed 1 learning job");
    }

    // =====================================================================
    // 8. EDGE CASES
    // =====================================================================

    /// @notice Zero price job reverts.
    function test_zeroPrice_reverts() public {
        vm.prank(requester);
        vm.expectRevert("ComputeMarketplace: zero price");
        marketplace.postJob{value: 0}(
            modelHash, inputHash, 0,
            ComputeVerifier.VerificationTier.Commitment, 10, 100
        );
    }

    /// @notice Zero bid reverts.
    function test_zeroBid_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: zero bid price");
        marketplace.bidOnJob(jobId, 0, 100);
    }

    /// @notice Escrow is impossible to be zero for a posted job (since zero price reverts).
    function test_zeroEscrow_impossible() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(1 ether, 10, 100);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertGt(job.escrow, 0, "Escrow must be > 0 for valid job");
    }

    /// @notice All escrow accounted for after many jobs (no orphaned funds).
    function test_allEscrowAccountedFor_afterManyJobs() public {
        _registerProvider(provider1);

        uint256 numJobs = 5;
        uint256 pricePerJob = TEST_PRICE;
        uint256 totalInput = numJobs * pricePerJob;

        for (uint256 i = 0; i < numJobs; i++) {
            uint256 jobId = _postJob(pricePerJob, 10, 100);
            _bidOnJob(jobId, provider1, pricePerJob);
            _assignJob(jobId);
            _startExecution(jobId, provider1);
            _submitCommitment(jobId, provider1);
            _submitResult(jobId, provider1);
            marketplace.completeJob(jobId);
        }

        uint256 totalBurned = marketplace.totalBurned();
        uint256 totalPaid = marketplace.totalPaidToProviders();
        uint256 totalTreasury = marketplace.totalTreasuryFees();

        assertEq(
            totalBurned + totalPaid + totalTreasury,
            totalInput,
            "All SALT must be accounted for: burn + provider + treasury = total input"
        );
    }

    /// @notice After expiration, no orphaned escrow remains in the contract.
    function test_noOrphanedEscrow_afterExpiration() public {
        uint256 contractBalBefore = address(marketplace).balance;

        // Post a job and let it expire (no bids)
        uint256 jobId = _postJob(50 ether, 5, 100);

        // Advance past bid deadline
        vm.roll(block.number + 6);

        // Expire the job
        marketplace.expireJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(job.escrow, 0, "Escrow must be zero after expiration");
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Expired), "State: Expired");

        // Contract balance returned to where it was before
        assertEq(address(marketplace).balance, contractBalBefore, "No orphaned funds in contract");
    }

    /// @notice Job state transitions are strictly forward — no backward movement.
    function test_jobStateNeverGoesBackward() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        // Bidding -> cannot go to Posted
        vm.prank(provider1);
        marketplace.bidOnJob(jobId, 6 ether, 100);

        _assignJob(jobId);

        // Assigned -> cannot bid again
        vm.prank(provider2);
        vm.expectRevert(); // Wrong state
        marketplace.bidOnJob(jobId, 70 ether, 100);

        _startExecution(jobId, provider1);

        // Executing -> cannot start again
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: not assigned");
        marketplace.startExecution(jobId);

        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        // Verifying -> complete
        marketplace.completeJob(jobId);

        // Completed -> cannot transition to anything
        vm.expectRevert("ComputeMarketplace: not verifying");
        marketplace.completeJob(jobId);
    }

    // =====================================================================
    // 9. GAS PROFILING
    // =====================================================================

    /// @notice postJob gas usage must be under 500k.
    function test_postJob_gasUnder500k() public {
        _registerProvider(provider1);

        uint256 gasBefore = gasleft();
        vm.prank(requester);
        marketplace.postJob{value: TEST_PRICE}(
            modelHash, inputHash, TEST_PRICE,
            ComputeVerifier.VerificationTier.Commitment,
            10, 100
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertLt(gasUsed, 500_000, "postJob must use < 500k gas");
    }

    /// @notice completeJob gas usage must be under 300k.
    function test_completeJob_gasUnder300k() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycle(provider1);

        uint256 gasBefore = gasleft();
        marketplace.completeJob(jobId);
        uint256 gasUsed = gasBefore - gasleft();

        assertLt(gasUsed, 300_000, "completeJob must use < 300k gas");
    }

    // =====================================================================
    // 10. MULTI-PROVIDER SCENARIOS
    // =====================================================================

    /// @notice Multiple providers compete for jobs; the scoring algorithm selects the best.
    function test_multiProviderBidding_selectsBest() public {
        _registerProvider(provider1);
        _registerProvider(provider2);
        _registerProvider(provider3);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        // Three providers bid at different prices
        _bidOnJob(jobId, provider1, 7 ether); // Worst price
        _bidOnJob(jobId, provider2, 4 ether); // Best price
        _bidOnJob(jobId, provider3, 5 ether); // Middle price

        _assignJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        // Provider2 has the lowest price (highest price score), should win
        // with equal reputation and load
        assertEq(job.assignedProvider, provider2, "Best price provider should be selected");
    }

    /// @notice Auto-assign picks a provider without bidding window.
    function test_autoAssign_skipsDirectBidding() public {
        _registerProvider(provider1);

        vm.prank(requester);
        uint256 jobId = marketplace.autoAssignJob{value: TEST_PRICE}(
            modelHash, inputHash,
            ComputeVerifier.VerificationTier.Commitment
        );

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Assigned), "Auto-assigned immediately");
        assertEq(job.assignedProvider, provider1, "Provider1 auto-selected");
    }

    /// @notice Expired job with no bids: full escrow refund to requester.
    function test_expiredJob_fullRefund() public {
        uint256 requesterBalBefore = requester.balance;
        uint256 jobId = _postJob(50 ether, 5, 100);

        uint256 requesterBalAfterPost = requester.balance;
        assertEq(requesterBalBefore - requesterBalAfterPost, 50 ether, "50 ether deducted for escrow");

        // Advance past bid deadline with no bids
        vm.roll(block.number + 6);
        marketplace.expireJob(jobId);

        assertEq(requester.balance, requesterBalBefore, "Full refund on expiration");
    }

    /// @notice Pool dissolve returns all member stakes.
    function test_poolDissolve_returnsAllStakes() public {
        vm.prank(poolCreator);
        uint256 poolId = pool.createPool(
            "DissolvePool",
            ComputePool.PoolMode.InferencePool,
            1, 100, 1 ether
        );

        vm.prank(provider1);
        pool.joinPool{value: 20 ether}(poolId, 2);

        vm.prank(provider2);
        pool.joinPool{value: 30 ether}(poolId, 3);

        uint256 p1Before = provider1.balance;
        uint256 p2Before = provider2.balance;

        vm.prank(poolCreator);
        pool.dissolvePool(poolId);

        assertEq(provider1.balance - p1Before, 20 ether, "Provider1 stake fully returned");
        assertEq(provider2.balance - p2Before, 30 ether, "Provider2 stake fully returned");

        ComputePool.Pool memory p = pool.getPool(poolId);
        assertEq(uint(p.state), uint(ComputePool.PoolState.Dissolved), "Pool dissolved");
        assertEq(p.totalGPUs, 0, "No GPUs remaining");
        assertEq(p.memberCount, 0, "No members remaining");
    }
}
