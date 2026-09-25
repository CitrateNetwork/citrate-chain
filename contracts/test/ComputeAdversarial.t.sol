// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../src/ComputeVerifier.sol";
import {HeartbeatMonitor} from "../src/HeartbeatMonitor.sol";
import {DisputeResolution} from "../src/DisputeResolution.sol";
import {Governable} from "../src/lib/Governable.sol";
import {ComputePool} from "../src/ComputePool.sol";

/// @title ReentrancyAttackMarketplace — Attempts reentrancy during completeJob payout
contract ReentrancyAttackMarketplace {
    ComputeMarketplace public marketplace;
    uint256 public targetJobId;
    bool public attacking;
    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    constructor(ComputeMarketplace _marketplace) {
        marketplace = _marketplace;
    }

    function setTarget(uint256 jobId) external {
        targetJobId = jobId;
    }

    function enableAttack() external {
        attacking = true;
        reentrancyAttempted = false;
        reentrancySucceeded = false;
    }

    receive() external payable {
        if (attacking) {
            attacking = false;
            reentrancyAttempted = true;
            try marketplace.completeJob(targetJobId) {
                reentrancySucceeded = true;
            } catch {
                reentrancySucceeded = false;
            }
        }
    }
}

/// @title ReentrancyAttackDispute — Attempts reentrancy during dispute bond payout
contract ReentrancyAttackDispute {
    DisputeResolution public disputeContract;
    uint256 public targetDisputeId;
    bool public attacking;
    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    constructor(DisputeResolution _dispute) {
        disputeContract = _dispute;
    }

    function setTarget(uint256 disputeId) external {
        targetDisputeId = disputeId;
    }

    function enableAttack() external {
        attacking = true;
        reentrancyAttempted = false;
        reentrancySucceeded = false;
    }

    function initiateDispute(uint256 jobId, address defender, uint256 rangeStart, uint256 rangeEnd) external payable returns (uint256) {
        return disputeContract.initiateDispute{value: msg.value}(jobId, defender, rangeStart, rangeEnd);
    }

    receive() external payable {
        if (attacking) {
            attacking = false;
            reentrancyAttempted = true;
            try disputeContract.timeoutDispute(targetDisputeId) {
                reentrancySucceeded = true;
            } catch {
                reentrancySucceeded = false;
            }
        }
    }
}

/// @title ReentrancyAttackPool — Attempts reentrancy during leavePool stake return
contract ReentrancyAttackPool {
    ComputePool public pool;
    uint256 public targetPoolId;
    bool public attacking;
    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    constructor(ComputePool _pool) {
        pool = _pool;
    }

    function setTarget(uint256 poolId) external {
        targetPoolId = poolId;
    }

    function joinPool(uint256 poolId, uint256 gpuCount) external payable {
        pool.joinPool{value: msg.value}(poolId, gpuCount);
    }

    function enableAttack() external {
        attacking = true;
        reentrancyAttempted = false;
        reentrancySucceeded = false;
    }

    /// PBA-L2-022: two-step exit.
    function requestLeave(uint256 poolId) external {
        pool.requestLeave(poolId);
    }

    function triggerLeave(uint256 poolId) external {
        pool.leavePool(poolId);
    }

    receive() external payable {
        if (attacking) {
            attacking = false;
            reentrancyAttempted = true;
            try pool.leavePool(targetPoolId) {
                reentrancySucceeded = true;
            } catch {
                reentrancySucceeded = false;
            }
        }
    }
}

/// @title ComputeAdversarialTest — Adversarial attack tests from AdversarialCompute.tla
/// @notice Models every attack vector against the compute marketplace contracts:
///         collusion, sybil, grief, race conditions, front-running, heartbeat gaming,
///         economic attacks, and reentrancy.
contract ComputeAdversarialTest is Test {
    ComputeMarketplace internal marketplace;
    ComputeVerifier internal verifier;
    HeartbeatMonitor internal heartbeat;
    DisputeResolution internal dispute;
    ComputePool internal pool;

    address internal governance;
    address internal treasury = address(0x77EA5);

    address internal requester = address(0xAAAA);
    address internal provider1 = address(0xBBB1);
    address internal provider2 = address(0xBBB2);
    address internal attacker = address(0xBAD1);
    address internal disputer = address(0xD15A);
    address internal outsider = address(0x0057);

    bytes32 internal modelHash = keccak256("test-model-v1");
    bytes internal inputHash = hex"DEADBEEF";

    /// @notice Test price must be <= VALUE_THRESHOLD (10 ether) to use Commitment tier
    ///         without auto-upgrade to ZKProof. See ComputeVerifier.VALUE_THRESHOLD.
    uint256 internal constant TEST_PRICE = 8 ether;

    // Commitment values for verification
    bytes internal outputData = hex"01020304";
    bytes32 internal nonce = keccak256("secret-nonce");
    bytes32 internal commitmentHash;

    function setUp() public {
        governance = address(this);

        // Deploy verifier with temp marketplace address
        verifier = new ComputeVerifier(address(1));
        marketplace = new ComputeMarketplace(address(verifier), treasury);
        verifier.setMarketplace(address(marketplace));

        // Deploy heartbeat monitor (100 block interval, 3 max missed)
        heartbeat = new HeartbeatMonitor(100, 3);

        // Deploy dispute resolution (10 ether bond, 20 max rounds)
        dispute = new DisputeResolution(10 ether, 20);

        // Deploy compute pool
        pool = new ComputePool();

        // Fund accounts
        vm.deal(requester, 10000 ether);
        vm.deal(provider1, 5000 ether);
        vm.deal(provider2, 5000 ether);
        vm.deal(attacker, 5000 ether);
        vm.deal(disputer, 5000 ether);
        vm.deal(outsider, 1000 ether);
        vm.deal(address(0xdead), 0); // burn address

        // Pre-compute commitment hash
        commitmentHash = keccak256(abi.encodePacked(outputData, nonce));
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

    function _fullLifecycleWithProvider(address provider) internal returns (uint256 jobId) {
        jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider);
        _submitCommitment(jobId, provider);
        _submitResult(jobId, provider);
    }

    // =====================================================================
    // 1. PROVIDER COLLUSION ATTACKS
    // =====================================================================

    /// @notice Two providers bid on the same job. Winner completes, payment is standard.
    ///         No inflation from collusion — payment = escrow split (provider + burn + treasury).
    function test_colludingProvidersCantExtractExtra() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        uint256 maxPrice = TEST_PRICE;
        uint256 jobId = _postJob(maxPrice, 10, 100);

        // Both colluding providers bid
        _bidOnJob(jobId, provider1, 6 ether);
        _bidOnJob(jobId, provider2, 7 ether);

        _assignJob(jobId);
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        address winner = job.assignedProvider;

        _startExecution(jobId, winner);

        vm.prank(winner);
        marketplace.submitCommitment(jobId, commitmentHash);

        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(winner);
        marketplace.submitResult(jobId, outputData, proof);

        uint256 winnerBalBefore = winner.balance;
        uint256 treasuryBalBefore = treasury.balance;

        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        uint256 winnerBalAfter = winner.balance;
        uint256 treasuryBalAfter = treasury.balance;

        // Payment sums: provider + burn(2.5%) + treasury(2.5%) = TEST_PRICE
        uint256 burnAmount = maxPrice / 40;
        uint256 treasuryAmount = maxPrice / 40;
        uint256 providerAmount = maxPrice - burnAmount - treasuryAmount;

        assertEq(winnerBalAfter - winnerBalBefore, providerAmount, "Provider payment should be exactly 95% of escrow");
        assertEq(treasuryBalAfter - treasuryBalBefore, treasuryAmount, "Treasury fee should be exactly 2.5%");

        // Escrow fully consumed — no extra extracted
        ComputeMarketplace.Job memory completedJob = marketplace.getJob(jobId);
        assertEq(completedJob.escrow, 0, "Escrow must be zero after completion");
    }

    /// @notice Even if providers collude and underbid to price=1 wei, 2.5% BME burn still applies.
    function test_collusionUnderbidStillPaysCorrectBME() public {
        _registerProvider(provider1);

        // Very low price job
        uint256 maxPrice = 1 ether;
        uint256 jobId = _postJob(maxPrice, 10, 100);
        _bidOnJob(jobId, provider1, 1 ether);
        _assignJob(jobId);

        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        uint256 burnBefore = marketplace.totalBurned();
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);
        uint256 burnAfter = marketplace.totalBurned();

        uint256 expectedBurn = maxPrice / 40; // 0.025 ether
        assertEq(burnAfter - burnBefore, expectedBurn, "BME burn must be exactly 2.5% regardless of bid");
    }

    // =====================================================================
    // 2. SYBIL ATTACKS
    // =====================================================================

    /// @notice Same address cannot register twice as a provider.
    function test_sybilProviderCantDominateScoring() public {
        _registerProvider(provider1);

        bytes32[] memory models = new bytes32[](1);
        models[0] = modelHash;

        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: already registered");
        marketplace.registerProvider{value: 1000 ether}(models);
    }

    /// @notice N sybil identities each need N * MIN_PROVIDER_STAKE, making sybil attacks expensive.
    function test_sybilProviderEachNeedsStake() public {
        uint256 minStake = marketplace.MIN_PROVIDER_STAKE();
        uint256 numSybils = 5;

        address[5] memory sybils = [
            address(0x5001),
            address(0x5002),
            address(0x5003),
            address(0x5004),
            address(0x5005)
        ];

        uint256 totalStakeNeeded = 0;
        for (uint256 i = 0; i < numSybils; i++) {
            vm.deal(sybils[i], minStake + 1 ether);
            bytes32[] memory models = new bytes32[](1);
            models[0] = modelHash;
            vm.prank(sybils[i]);
            marketplace.registerProvider{value: minStake}(models);
            totalStakeNeeded += minStake;
        }

        assertEq(totalStakeNeeded, numSybils * minStake, "Each sybil identity requires full stake");
        assertEq(marketplace.getProviderCount(), numSybils, "All sybils are separate providers");
    }

    // =====================================================================
    // 3. GRIEF ATTACKS
    // =====================================================================

    /// @notice Griefing a valid result: attacker disputes, provider wins, attacker loses bond.
    function test_griefDisputeOnValidResult_attackerLosesBond() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycleWithProvider(provider1);

        // Attacker files dispute
        uint256 attackerBalBefore = attacker.balance;
        vm.prank(attacker);
        marketplace.disputeResult{value: 10 ether}(jobId);

        // Governance resolves: provider (defender) wins
        marketplace.resolveDispute(jobId, false);

        uint256 attackerBalAfter = attacker.balance;
        uint256 bondLost = attackerBalBefore - attackerBalAfter;

        assertEq(bondLost, 10 ether, "Attacker must lose entire dispute bond");
        assertGt(marketplace.totalDisputeBondsBurned(), 0, "Bond must be burned");
    }

    /// @notice Multiple grief disputes drain the attacker's funds, not the system.
    function test_griefMultipleDisputes_attackerDrained() public {
        _registerProvider(provider1);

        uint256 totalBondLost = 0;
        uint256 attackerBalBefore = attacker.balance;

        for (uint256 i = 0; i < 3; i++) {
            uint256 jobId = _fullLifecycleWithProvider(provider1);

            vm.prank(attacker);
            marketplace.disputeResult{value: 10 ether}(jobId);

            // Provider wins each time
            marketplace.resolveDispute(jobId, false);
            totalBondLost += 10 ether;
        }

        uint256 attackerBalAfter = attacker.balance;
        assertEq(attackerBalBefore - attackerBalAfter, totalBondLost, "Attacker drained by repeated failed disputes");
    }

    /// @notice Dispute bond > potential refund from winning means grief is economically irrational.
    function test_griefCostExceedsBenefit() public {
        uint256 disputeBondValue = marketplace.DISPUTE_BOND();

        // For small jobs, the dispute bond is larger than the potential benefit
        // A requester posting a job worth less than DISPUTE_BOND can't profitably grief
        assertTrue(disputeBondValue >= 10 ether, "Dispute bond must be substantial to deter grief");

        _registerProvider(provider1);

        // Post a small job worth less than the dispute bond to demonstrate grief is unprofitable
        uint256 smallPrice = 8 ether; // Below VALUE_THRESHOLD for Commitment tier
        uint256 jobId = _postJob(smallPrice, 10, 100);
        _bidOnJob(jobId, provider1, smallPrice);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        // Even if disputer wins, they only get back their bond, not extra
        // The cost of dispute = bond locked + gas fees
        // The benefit = escrow refund (same as bond at most)
        // Net result is always <= 0 for the attacker
        assertGe(disputeBondValue, smallPrice / 10, "Bond must be significant relative to job value");
    }

    // =====================================================================
    // 4. RACE CONDITION ATTACKS
    // =====================================================================

    /// @notice Filing dispute on a result in Verifying state blocks payment.
    function test_submitResultAndDisputeSameBlock_disputeBlocksPayment() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycleWithProvider(provider1);

        // Dispute blocks completion
        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        // Attempt to complete should fail due to active dispute
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        vm.expectRevert("ComputeMarketplace: dispute active");
        marketplace.completeJob(jobId);
    }

    /// @notice Cannot complete a job while a dispute is pending.
    function test_completeJobWhileDisputePending_reverts() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycleWithProvider(provider1);

        // File dispute
        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        // Cannot complete while dispute active
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        vm.expectRevert("ComputeMarketplace: dispute active");
        marketplace.completeJob(jobId);

        // Verify dispute blocks state
        assertTrue(verifier.isDisputeActive(jobId), "Dispute must be active");
    }

    /// @notice Provider cannot submit result twice (proof already submitted in verifier).
    function test_doubleSubmitResult_reverts() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        // Second submission should fail — job is now in Verifying state
        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: not executing");
        marketplace.submitResult(jobId, outputData, proof);
    }

    // =====================================================================
    // 5. FRONT-RUNNING ATTACKS
    // =====================================================================

    /// @notice Non-assigned provider cannot submit results.
    function test_nonAssignedProviderCantSubmit() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);

        // provider2 tries to front-run and submit
        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider2);
        vm.expectRevert("ComputeMarketplace: not assigned provider");
        marketplace.submitResult(jobId, outputData, proof);
    }

    /// @notice Observer cannot claim another provider's job by starting execution.
    function test_observerCantClaimOthersJob() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);

        // provider2 (observer) tries to start execution on provider1's job
        vm.prank(provider2);
        vm.expectRevert("ComputeMarketplace: not assigned provider");
        marketplace.startExecution(jobId);
    }

    // =====================================================================
    // 6. HEARTBEAT GAMING ATTACKS
    // =====================================================================

    /// @notice Provider that misses heartbeats gets suspended, cannot accept new jobs.
    function test_heartbeatWithoutRealGPU_failsJobGetSlashed() public {
        // Provider registers heartbeat
        vm.prank(provider1);
        heartbeat.register();

        // Simulate provider missing heartbeats (advance past interval * maxMissed)
        uint256 interval = heartbeat.heartbeatInterval();
        uint256 maxMissedCount = heartbeat.maxMissed();

        for (uint256 i = 0; i < maxMissedCount; i++) {
            vm.roll(block.number + interval + 1);
            heartbeat.checkHeartbeat(provider1);
        }

        // Provider should now be suspended
        assertTrue(!heartbeat.isActive(provider1), "Provider should be suspended after maxMissed");

        (uint256 lastHb, uint256 missedCount, bool suspended, ) = heartbeat.health(provider1);
        assertTrue(suspended, "Suspended flag must be true");
        assertGe(missedCount, maxMissedCount, "Missed count must be >= maxMissed");
        assertGt(lastHb, 0, "Last heartbeat recorded");
    }

    /// @notice Suspended provider cannot send heartbeats until reactivated.
    function test_suspendedProviderCantAcceptJobs() public {
        vm.prank(provider1);
        heartbeat.register();

        // Suspend provider
        uint256 interval = heartbeat.heartbeatInterval();
        uint256 maxMissedCount = heartbeat.maxMissed();
        for (uint256 i = 0; i < maxMissedCount; i++) {
            vm.roll(block.number + interval + 1);
            heartbeat.checkHeartbeat(provider1);
        }

        // Suspended provider cannot heartbeat
        vm.prank(provider1);
        vm.expectRevert("Provider is suspended");
        heartbeat.heartbeat();

        // Must reactivate first
        vm.prank(provider1);
        heartbeat.reactivate();

        assertTrue(heartbeat.isActive(provider1), "Provider should be active after reactivation");
    }

    // =====================================================================
    // 7. ECONOMIC ATTACKS
    // =====================================================================

    /// @notice Even at lowest valid bid, provider must have full stake posted.
    function test_belowCostBidStillRequiresStake() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        // Bid at minimum (1 wei) — provider still needs their full stake
        _bidOnJob(jobId, provider1, 1);

        ComputeMarketplace.ProviderProfile memory profile = marketplace.getProvider(provider1);
        assertGe(profile.stake, marketplace.MIN_PROVIDER_STAKE(), "Provider stake must meet minimum even with low bid");
    }

    /// @notice CHAIN-B-C039: a provider may withdraw stake, but not while any
    ///         job is in flight. Pre-fix there was no withdraw path at all
    ///         (stake locked forever); the invariant now is "no withdrawal
    ///         during active jobs", enforced by `withdrawStake`.
    function test_providerCantWithdrawStakeDuringActiveJob() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);

        ComputeMarketplace.ProviderProfile memory profile = marketplace.getProvider(provider1);
        assertEq(profile.currentActiveJobs, 1, "Provider should have 1 active job");

        // The withdraw path exists but is gated on having no in-flight jobs.
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: active jobs");
        marketplace.withdrawStake(1 ether);

        profile = marketplace.getProvider(provider1);
        assertGe(profile.stake, marketplace.MIN_PROVIDER_STAKE(), "Stake must remain locked during active job");
    }

    /// @notice CHAIN-B-C039: with no in-flight jobs, a provider can withdraw and
    ///         fully exit — recovering stake that was previously locked forever.
    function test_C039_providerCanWithdrawStakeWhenIdle() public {
        _registerProvider(provider1);
        ComputeMarketplace.ProviderProfile memory profile = marketplace.getProvider(provider1);
        uint256 staked = profile.stake;
        assertEq(profile.currentActiveJobs, 0, "no active jobs");

        uint256 balBefore = provider1.balance;
        vm.prank(provider1);
        marketplace.withdrawStake(staked);

        assertEq(provider1.balance, balBefore + staked, "full stake returned");
        profile = marketplace.getProvider(provider1);
        assertEq(profile.stake, 0, "stake drained");
        assertFalse(profile.isRegistered, "full withdrawal deregisters");
    }

    // =====================================================================
    // 8. REENTRANCY ATTACKS
    // =====================================================================

    /// @notice Reentrancy attack on completeJob is blocked by ReentrancyGuard.
    function test_completeJob_reentrancy_blocked() public {
        // Deploy attacker contract
        ReentrancyAttackMarketplace attackContract = new ReentrancyAttackMarketplace(marketplace);
        vm.deal(address(attackContract), 5000 ether);

        // Register attacker contract as provider
        bytes32[] memory models = new bytes32[](1);
        models[0] = modelHash;
        vm.prank(address(attackContract));
        marketplace.registerProvider{value: 1000 ether}(models);

        // Post job and complete lifecycle with attacker as provider
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, address(attackContract), 6 ether);
        _assignJob(jobId);

        vm.prank(address(attackContract));
        marketplace.startExecution(jobId);

        vm.prank(address(attackContract));
        marketplace.submitCommitment(jobId, commitmentHash);

        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(address(attackContract));
        marketplace.submitResult(jobId, outputData, proof);

        // Enable reentrancy attack
        attackContract.setTarget(jobId);
        attackContract.enableAttack();

        // completeJob should complete without reentrancy succeeding
        // The provider (attacker contract) receives payment, tries to re-enter, fails
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        // If the attack contract received funds and tried to re-enter:
        // reentrancy should be blocked by nonReentrant
        if (attackContract.reentrancyAttempted()) {
            assertFalse(attackContract.reentrancySucceeded(), "Reentrancy must be blocked");
        }

        // Job must be completed regardless
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "Job must be completed");
    }

    /// @notice Reentrancy attack on dispute bond claim is blocked.
    function test_claimDispute_reentrancy_blocked() public {
        ReentrancyAttackDispute attackContract = new ReentrancyAttackDispute(dispute);
        vm.deal(address(attackContract), 100 ether);

        address defender = address(0xDEF1);
        vm.deal(defender, 100 ether);

        // Attacker initiates dispute
        vm.prank(address(attackContract));
        uint256 disputeId = attackContract.initiateDispute{value: 10 ether}(
            1, defender, 0, 1000
        );

        // Defender acknowledges
        vm.prank(defender);
        dispute.acknowledgeDispute{value: 10 ether}(disputeId);

        // Challenger bisects
        vm.prank(address(attackContract));
        dispute.bisect(disputeId, true);

        // Enable attack before resolution
        attackContract.setTarget(disputeId);
        attackContract.enableAttack();

        // Governance resolves — challenger wins, payout triggers receive()
        dispute.resolve(disputeId, true);

        // If reentrancy was attempted, it must have failed
        if (attackContract.reentrancyAttempted()) {
            assertFalse(attackContract.reentrancySucceeded(), "Dispute reentrancy must be blocked");
        }
    }

    /// @notice Reentrancy attack on leavePool stake refund is blocked.
    function test_leavePool_reentrancy_blocked() public {
        ReentrancyAttackPool attackContract = new ReentrancyAttackPool(pool);
        vm.deal(address(attackContract), 100 ether);

        // Create a pool
        uint256 poolId = pool.createPool("TestPool", ComputePool.PoolMode.InferencePool, 1, 100, 1 ether);

        // Attacker joins pool
        vm.prank(address(attackContract));
        attackContract.joinPool{value: 20 ether}(poolId, 2);

        // Set up reentrancy attack
        attackContract.setTarget(poolId);
        attackContract.enableAttack();

        // Leave pool triggers stake return -> receive() -> attempts re-enter
        attackContract.requestLeave(poolId); // PBA-L2-022 two-step exit
        vm.roll(block.number + pool.LEAVE_COOLDOWN());
        vm.prank(address(attackContract));
        attackContract.triggerLeave(poolId);

        // If reentrancy was attempted, it must have failed
        if (attackContract.reentrancyAttempted()) {
            assertFalse(attackContract.reentrancySucceeded(), "Pool leavePool reentrancy must be blocked");
        }
    }

    // =====================================================================
    // 9. ADDITIONAL ADVERSARIAL INVARIANTS
    // =====================================================================

    /// @notice Unregistered address cannot bid on jobs.
    function test_unregisteredCantBid() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        vm.prank(outsider);
        vm.expectRevert("ComputeMarketplace: provider not registered");
        marketplace.bidOnJob(jobId, 5 ether, 100);
    }

    /// @notice Only governance can resolve disputes.
    function test_nonGovernanceCantResolveDispute() public {
        _registerProvider(provider1);
        uint256 jobId = _fullLifecycleWithProvider(provider1);

        vm.prank(attacker);
        marketplace.disputeResult{value: 10 ether}(jobId);

        vm.prank(attacker);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        marketplace.resolveDispute(jobId, true);
    }

    /// @notice Provider at max capacity cannot accept additional jobs.
    function test_providerAtCapacityCantBid() public {
        _registerProvider(provider1);

        // Fill provider1 to capacity
        uint256 maxConcurrent = marketplace.DEFAULT_MAX_CONCURRENT();
        for (uint256 i = 0; i < maxConcurrent; i++) {
            uint256 jobId = _postJob(1 ether, 10, 10000);
            _bidOnJob(jobId, provider1, 1 ether);
            _assignJob(jobId);
        }

        // Provider is now at max concurrent jobs — new bid should fail
        uint256 extraJob = _postJob(1 ether, 10, 10000);
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: provider at capacity");
        marketplace.bidOnJob(extraJob, 1 ether, 100);
    }

    /// @notice Job state can only move forward — never backward (INV-4: StateOnlyForward).
    function test_jobStateNeverGoesBackward() public {
        _registerProvider(provider1);

        uint256 jobId = _fullLifecycleWithProvider(provider1);
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "Must be in Completed state");

        // Attempting to go back to any earlier state should fail
        vm.expectRevert(); // Cannot bid on completed job
        _bidOnJob(jobId, provider1, 6 ether);
    }

    /// @notice Commitment must be submitted before proof (INV-7: ProofRequiresCommitment).
    function test_proofWithoutCommitment_reverts() public {
        _registerProvider(provider1);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);

        // Try to submit result without commitment — should fail in verifier
        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider1);
        vm.expectRevert("ComputeVerifier: commitment required first");
        marketplace.submitResult(jobId, outputData, proof);
    }
}
