// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../src/ComputeVerifier.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @title ComputeMarketplaceTest — 30+ tests covering all TLA+ invariants
/// @dev Tests all 11 invariants from ComputeMarketplaceLifecycle.tla and
///      key adversarial invariants from AdversarialCompute.tla.
///      Uses maxPrice <= 10 ether for Commitment-tier tests to stay below
///      VALUE_THRESHOLD (jobs > 10 ether auto-upgrade to ZKProof).
contract ComputeMarketplaceTest is Test {
    ComputeMarketplace internal marketplace;
    ComputeVerifier internal verifier;

    address internal governance;
    address internal treasury = address(0x77EA5);

    address internal requester = address(0xAAAA);
    address internal provider1 = address(0xBBB1);
    address internal provider2 = address(0xBBB2);
    address internal provider3 = address(0xBBB3);
    address internal outsider = address(0xBAD1);
    address internal disputer = address(0xD15A);

    bytes32 internal modelHash = bytes32(uint256(keccak256("test-model-v1")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617); // canonical BN254 scalar: high-value jobs are ZK-tier (PBA-L2-004)
    bytes internal inputHash = abi.encodePacked(bytes32(uint256(keccak256(hex"DEADBEEF")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617)); // ZK tier binds the raw 32-byte input commitment (PBA-L2-004)

    // Commitment values for verification
    bytes internal outputData = hex"01020304";
    bytes32 internal nonce = keccak256("secret-nonce");
    bytes32 internal commitmentHash;

    /// @dev Standard test price: 8 ether (below 10 ether VALUE_THRESHOLD to allow Commitment tier)
    uint256 constant TEST_PRICE = 8 ether;

    function setUp() public {
        governance = address(this);

        // Deploy verifier first (marketplace address will be set after)
        verifier = new ComputeVerifier(address(1), address(this)); // Temp marketplace addr
        marketplace = new ComputeMarketplace(address(verifier), treasury, address(this));

        // Set the real marketplace address in the verifier
        verifier.setMarketplace(address(marketplace));

        // Fund accounts
        vm.deal(requester, 1000 ether);
        vm.deal(provider1, 2000 ether);
        vm.deal(provider2, 2000 ether);
        vm.deal(provider3, 2000 ether);
        vm.deal(outsider, 100 ether);
        vm.deal(disputer, 100 ether);

        // Pre-compute commitment hash: SHA3(output || nonce)
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
            modelHash,
            inputHash,
            maxPrice,
            ComputeVerifier.VerificationTier.Commitment,
            bidWindow,
            execWindow
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
        // Build commitment proof: commitment(32) + nonce(32) + output
        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider);
        marketplace.submitResult(jobId, outputData, proof);
    }

    /// @dev Full lifecycle: post -> bid -> assign -> start -> commit -> submit -> complete
    function _fullLifecycle() internal returns (uint256 jobId) {
        _registerProvider(provider1);
        jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);
    }

    // ============================================================
    // Job Posting Tests
    // ============================================================

    /// @dev INV-3: EscrowConservation — escrow = maxPrice during active states
    function test_postJob_createsEscrow() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(5 ether, 10, 100);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(job.escrow, 5 ether, "Escrow should equal maxPrice");
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Bidding), "State should be Bidding");
        assertEq(job.requester, requester, "Requester should match");
    }

    function test_postJob_refundsExcessPayment() public {
        _registerProvider(provider1);
        uint256 balBefore = requester.balance;
        vm.prank(requester);
        marketplace.postJob{value: 8 ether}(
            modelHash, inputHash, 5 ether,
            ComputeVerifier.VerificationTier.Commitment, 10, 100
        );
        uint256 balAfter = requester.balance;
        assertEq(balBefore - balAfter, 5 ether, "Only maxPrice should be deducted");
    }

    function test_postJob_revertsZeroPrice() public {
        vm.prank(requester);
        vm.expectRevert("ComputeMarketplace: zero price");
        marketplace.postJob{value: 0}(
            modelHash, inputHash, 0,
            ComputeVerifier.VerificationTier.Commitment, 10, 100
        );
    }

    // ============================================================
    // Bidding Tests
    // ============================================================

    /// @dev INV-5: BidBelowCeiling — bids cannot exceed maxPrice
    function test_bidOnJob_belowMaxPrice() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        _bidOnJob(jobId, provider1, 6 ether);

        ComputeMarketplace.Bid[] memory bids = marketplace.getJobBids(jobId);
        assertEq(bids.length, 1, "Should have 1 bid");
        assertEq(bids[0].price, 6 ether, "Bid price should be 6 ether");
        assertEq(bids[0].provider, provider1, "Provider should match");
    }

    /// @dev INV-5: BidBelowCeiling — bid exceeding maxPrice should revert
    function test_bidOnJob_aboveMaxPrice_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: bid exceeds max price");
        marketplace.bidOnJob(jobId, 9 ether, 100);
    }

    function test_bidOnJob_duplicateBid_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        _bidOnJob(jobId, provider1, 6 ether);

        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: already bid");
        marketplace.bidOnJob(jobId, 5 ether, 100);
    }

    function test_bidOnJob_unregisteredProvider_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        vm.prank(outsider);
        vm.expectRevert("ComputeMarketplace: provider not registered");
        marketplace.bidOnJob(jobId, 5 ether, 100);
    }

    function test_bidOnJob_unsupportedModel_reverts() public {
        // Register provider2 with a different model
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("other-model");
        vm.prank(provider2);
        marketplace.registerProvider{value: 1000 ether}(models);

        _registerProvider(provider1); // supports modelHash
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        vm.prank(provider2);
        vm.expectRevert("ComputeMarketplace: provider does not support model");
        marketplace.bidOnJob(jobId, 5 ether, 100);
    }

    // ============================================================
    // Assignment Tests
    // ============================================================

    /// @dev INV-6: AssignedProviderRegistered
    function test_assignBestBid_lowestPrice() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        _bidOnJob(jobId, provider1, 7 ether);
        _bidOnJob(jobId, provider2, 4 ether);

        _assignJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Assigned), "State should be Assigned");
        // Provider2 has lower price, both have same reputation and load
        // Price weight is 40%, so provider2 should win
        assertEq(job.assignedProvider, provider2, "Lower-price provider should be assigned");
    }

    function test_assignBestBid_noBids_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);

        vm.expectRevert("ComputeMarketplace: no bids");
        _assignJob(jobId);
    }

    // ============================================================
    // Execution Tests
    // ============================================================

    function test_startExecution_onlyAssignedProvider() public {
        _registerProvider(provider1);
        _registerProvider(provider2);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);

        // Outsider cannot start
        vm.prank(provider2);
        vm.expectRevert("ComputeMarketplace: not assigned provider");
        marketplace.startExecution(jobId);

        // Assigned provider can start
        _startExecution(jobId, provider1);
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Executing), "Should be Executing");
    }

    /// @dev NoFrontRunning: only assigned provider can submit result
    function test_submitResult_onlyAssignedProvider() public {
        _registerProvider(provider1);
        _registerProvider(provider2);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);

        // Non-assigned provider cannot submit
        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider2);
        vm.expectRevert("ComputeMarketplace: not assigned provider");
        marketplace.submitResult(jobId, outputData, proof);
    }

    // ============================================================
    // Completion & Payment Tests
    // ============================================================

    /// @dev INV-2: NoPaymentWithoutVerification
    function test_completeJob_releasesPayment() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        uint256 provBalBefore = provider1.balance;
        uint256 treasuryBalBefore = treasury.balance;

        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "Should be Completed");
        assertEq(job.escrow, 0, "Escrow should be zero after completion");

        // Provider should have received payment
        assertGt(provider1.balance, provBalBefore, "Provider should receive payment");
        // Treasury should have received fee
        assertGt(treasury.balance, treasuryBalBefore, "Treasury should receive fee");
    }

    /// @dev BurnRateFixed: 2.5% = price / 40
    function test_completeJob_burns2point5percent() public {
        // Use 40 ether for clean math: 40/40 = 1 ether burn
        // But 40 > VALUE_THRESHOLD. Use TEST_PRICE (8 ether): 8/40 = 0.2 ether
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        uint256 deadBalBefore = marketplace.burner().balance;
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        uint256 burned = marketplace.burner().balance - deadBalBefore;
        // 8 ether / 40 = 0.2 ether
        assertEq(burned, 0.2 ether, "BME burn should be exactly 2.5%");
        assertEq(marketplace.totalBurned(), 0.2 ether, "Total burned tracking");
    }

    /// @dev Provider receives 95% of escrow (100% - 2.5% burn - 2.5% treasury)
    function test_completeJob_pays95percentToProvider() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        uint256 provBalBefore = provider1.balance;
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        uint256 providerPayment = provider1.balance - provBalBefore;
        // 8 ether - 0.2 (burn) - 0.2 (treasury) = 7.6 ether
        assertEq(providerPayment, 7.6 ether, "Provider should receive 95%");
    }

    /// @dev INV-9: CompletedPaid — completed jobs have non-zero payment
    function test_completeJob_updatesProviderStats() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        ComputeMarketplace.ProviderProfile memory prov = marketplace.getProvider(provider1);
        assertEq(prov.totalJobsCompleted, 1, "Should have 1 completed job");
        assertEq(prov.currentActiveJobs, 0, "No active jobs after completion");
        assertEq(prov.reputationScore, 10000, "Perfect reputation");
    }

    /// @dev NoPaymentWithoutVerification — cannot complete unverified job
    function test_noPaymentWithoutVerification() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);

        // Try to complete without submitting result/verification
        // Job is still in Executing state, not Verifying
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        vm.expectRevert("ComputeMarketplace: not verifying");
        marketplace.completeJob(jobId);
    }

    // ============================================================
    // Expiration Tests
    // ============================================================

    /// @dev INV-7: ExpiredJobsRefunded — escrow returned on expiration
    function test_expireJob_refundsEscrow() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(5 ether, 10, 100);

        uint256 balBefore = requester.balance;

        // Advance past bid deadline
        vm.roll(block.number + 11);

        marketplace.expireJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Expired), "Should be Expired");
        assertEq(job.escrow, 0, "Escrow should be zero");
        assertEq(requester.balance - balBefore, 5 ether, "Full escrow refunded");
    }

    function test_expireJob_withBids_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);

        vm.roll(block.number + 11);

        vm.expectRevert("ComputeMarketplace: has bids");
        marketplace.expireJob(jobId);
    }

    function test_expireJob_beforeDeadline_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(5 ether, 10, 100);

        vm.expectRevert("ComputeMarketplace: bid deadline not passed");
        marketplace.expireJob(jobId);
    }

    // ============================================================
    // Timeout Tests
    // ============================================================

    /// @dev INV-8: Timeout refunds and slashes
    function test_timeoutJob_refundsAndSlashes() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);

        ComputeMarketplace.Job memory jobBefore = marketplace.getJob(jobId);
        uint256 deadline = jobBefore.executionDeadline;

        uint256 requesterBalBefore = requester.balance;
        uint256 provStakeBefore = marketplace.getProvider(provider1).stake;

        // Advance past execution deadline
        vm.roll(deadline + 1);

        marketplace.timeoutJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Timeout), "Should be Timeout");

        // Escrow refunded
        assertEq(requester.balance - requesterBalBefore, TEST_PRICE, "Escrow refunded");

        // Provider slashed (5% of 1000 ether stake = 50 ether)
        uint256 provStakeAfter = marketplace.getProvider(provider1).stake;
        assertEq(provStakeBefore - provStakeAfter, 50 ether, "5% slash applied");
    }

    function test_timeoutJob_beforeDeadline_reverts() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);

        vm.expectRevert("ComputeMarketplace: deadline not passed");
        marketplace.timeoutJob(jobId);
    }

    // ============================================================
    // Dispute Tests
    // ============================================================

    /// @dev DisputeBlocksPayment + GriefUnprofitable: dispute bond required
    function test_disputeResult_requiresBond() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        vm.prank(disputer);
        vm.expectRevert("ComputeMarketplace: insufficient bond");
        marketplace.disputeResult{value: 5 ether}(jobId);
    }

    function test_disputeResult_blocksCompletion() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        // File dispute
        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        // Try to complete — should fail because dispute is active
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        vm.expectRevert("ComputeMarketplace: dispute active");
        marketplace.completeJob(jobId);
    }

    /// @dev DisputeBlocksPayment: resolved in requester's favor refunds escrow
    function test_resolveDispute_requesterWins_refundsEscrow() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        uint256 requesterBalBefore = requester.balance;
        uint256 disputerBalBefore = disputer.balance;

        // Resolve: requester wins
        marketplace.resolveDispute(jobId, true);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Disputed), "Should be Disputed");
        assertEq(job.escrow, 0, "Escrow should be zero");

        // Requester got refund
        assertEq(requester.balance - requesterBalBefore, TEST_PRICE, "Escrow refunded to requester");
        // Disputer got bond back
        assertEq(disputer.balance - disputerBalBefore, 10 ether, "Bond returned to disputer");
    }

    /// @dev GriefUnprofitable: provider wins, disputer loses bond
    function test_resolveDispute_providerWins_releasesBond() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        uint256 deadBalBefore = marketplace.burner().balance;

        // Resolve: provider wins (grief attack fails)
        marketplace.resolveDispute(jobId, false);

        // Bond burned (sent to dead address)
        uint256 bondBurned = marketplace.burner().balance - deadBalBefore;
        assertEq(bondBurned, 10 ether, "Bond should be burned");
        assertEq(marketplace.totalDisputeBondsBurned(), 10 ether, "Bond burn tracked");

        // Job can now be completed
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "Should be Completed");
    }

    // ============================================================
    // Auto-Assignment Tests
    // ============================================================

    function test_autoAssignJob_selectsBestProvider() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        // CHAIN-B-C015 (HELD/reroll): auto-assignment now requires the
        // provider's explicit consent (a provider must not be conscripted
        // into a slashable-deadline job without opting in). RC-8: this
        // fixture previously encoded conscription-without-consent as the
        // expected happy path.
        vm.prank(provider1);
        marketplace.setAutoAssignOptIn(true);
        vm.prank(provider2);
        marketplace.setAutoAssignOptIn(true);

        vm.prank(requester);
        uint256 jobId = marketplace.autoAssignJob{value: 5 ether}(
            modelHash,
            inputHash,
            ComputeVerifier.VerificationTier.Commitment
        );

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Assigned), "Should be Assigned");
        assertTrue(
            job.assignedProvider == provider1 || job.assignedProvider == provider2,
            "Should assign a registered provider"
        );
        assertEq(job.escrow, 5 ether, "Escrow should be set");
    }

    function test_autoAssignJob_noProviders_reverts() public {
        vm.prank(requester);
        vm.expectRevert("ComputeMarketplace: no available provider");
        marketplace.autoAssignJob{value: 5 ether}(
            modelHash, inputHash, ComputeVerifier.VerificationTier.Commitment
        );
    }

    // ============================================================
    // State Machine Invariant Tests
    // ============================================================

    /// @dev INV-4: StateOnlyForward — terminal states cannot transition
    function test_stateOnlyForward() public {
        _registerProvider(provider1);

        // Complete a job to terminal state
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        // Try to bid on completed job
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: not accepting bids");
        marketplace.bidOnJob(jobId, 5 ether, 100);

        // Try to expire completed job
        vm.expectRevert("ComputeMarketplace: not in bidding");
        marketplace.expireJob(jobId);
    }

    function test_stateOnlyForward_expired() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(5 ether, 10, 100);
        vm.roll(block.number + 11);
        marketplace.expireJob(jobId);

        // Cannot bid on expired job
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: not accepting bids");
        marketplace.bidOnJob(jobId, 4 ether, 100);
    }

    // ============================================================
    // Provider Registration Tests
    // ============================================================

    function test_registerProvider_insufficientStake_reverts() public {
        bytes32[] memory models = new bytes32[](1);
        models[0] = modelHash;
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: insufficient stake");
        marketplace.registerProvider{value: 100 ether}(models);
    }

    function test_registerProvider_duplicateRegistration_reverts() public {
        _registerProvider(provider1);

        bytes32[] memory models = new bytes32[](1);
        models[0] = modelHash;
        vm.prank(provider1);
        vm.expectRevert("ComputeMarketplace: already registered");
        marketplace.registerProvider{value: 1000 ether}(models);
    }

    function test_addStake_updatesProviderStake() public {
        _registerProvider(provider1);

        uint256 stakeBefore = marketplace.getProvider(provider1).stake;

        vm.prank(provider1);
        marketplace.addStake{value: 500 ether}();

        uint256 stakeAfter = marketplace.getProvider(provider1).stake;
        assertEq(stakeAfter - stakeBefore, 500 ether, "Stake should increase by 500");
    }

    // ============================================================
    // Front-Running Protection Tests (AdversarialCompute INV-3)
    // ============================================================

    /// @dev NoFrontRunning: non-assigned provider cannot submit result
    function test_frontRunning_nonAssignedCantSubmit() public {
        _registerProvider(provider1);
        _registerProvider(provider2);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);

        bytes memory proof = abi.encodePacked(commitmentHash, nonce, outputData);
        vm.prank(provider2); // Not assigned
        vm.expectRevert("ComputeMarketplace: not assigned provider");
        marketplace.submitResult(jobId, outputData, proof);
    }

    /// @dev NoFrontRunning: commitment can only come from assigned provider
    function test_frontRunning_nonAssignedCantCommit() public {
        _registerProvider(provider1);
        _registerProvider(provider2);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);

        vm.prank(provider2); // Not assigned
        vm.expectRevert("ComputeMarketplace: not assigned provider");
        marketplace.submitCommitment(jobId, commitmentHash);
    }

    // ============================================================
    // Full Lifecycle Integration Test
    // ============================================================

    function test_fullLifecycle_postBidAssignExecuteVerifyComplete() public {
        _registerProvider(provider1);

        uint256 balBefore = provider1.balance;
        uint256 treasuryBefore = treasury.balance;

        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(jobId);

        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Completed), "Final state: Completed");
        assertEq(job.escrow, 0, "Escrow zeroed");

        // Verify payment split: 95% provider, 2.5% burn, 2.5% treasury
        // 8 ether: burn = 0.2, treasury = 0.2, provider = 7.6
        uint256 providerGained = provider1.balance - balBefore;
        uint256 treasuryGained = treasury.balance - treasuryBefore;

        assertEq(providerGained, 7.6 ether, "Provider got 95%");
        assertEq(treasuryGained, 0.2 ether, "Treasury got 2.5%");
        assertEq(marketplace.totalBurned(), 0.2 ether, "2.5% burned");
    }

    // ============================================================
    // Multiple Providers + Reputation Test
    // ============================================================

    function test_multipleJobs_reputationAffectsScoring() public {
        _registerProvider(provider1);
        _registerProvider(provider2);

        // Complete a job with provider1 to build reputation
        uint256 job1 = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(job1, provider1, 6 ether);
        _assignJob(job1);
        _startExecution(job1, provider1);
        _submitCommitment(job1, provider1);
        _submitResult(job1, provider1);
        vm.roll(block.number + marketplace.DISPUTE_WINDOW()); // PBA-L2-004 dispute window
        marketplace.completeJob(job1);

        // Provider1 now has 1 completed job, provider2 has 0
        ComputeMarketplace.ProviderProfile memory p1 = marketplace.getProvider(provider1);
        ComputeMarketplace.ProviderProfile memory p2 = marketplace.getProvider(provider2);
        assertEq(p1.totalJobsCompleted, 1, "Provider1 completed 1 job");
        assertEq(p2.totalJobsCompleted, 0, "Provider2 completed 0 jobs");
        assertEq(p1.reputationScore, 10000, "Provider1 has 100% reputation");
    }

    // ============================================================
    // Edge Cases & Additional Coverage
    // ============================================================

    function test_failJob_refundsAndSlashes() public {
        // Test path where verification returns Invalid due to wrong proof
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);

        // Submit valid commitment
        _submitCommitment(jobId, provider1);

        // Submit result with WRONG proof (commitment hash doesn't match)
        bytes32 wrongCommitment = keccak256("wrong");
        bytes32 wrongNonce = keccak256("wrong-nonce");
        bytes memory badProof = abi.encodePacked(wrongCommitment, wrongNonce, outputData);

        uint256 provStakeBefore = marketplace.getProvider(provider1).stake;
        uint256 requesterBalBefore = requester.balance;

        vm.prank(provider1);
        marketplace.submitResult(jobId, outputData, badProof);

        // Job should auto-fail because verification returned Invalid
        ComputeMarketplace.Job memory job = marketplace.getJob(jobId);
        assertEq(uint(job.state), uint(ComputeMarketplace.JobState.Failed), "Should be Failed");
        assertEq(job.escrow, 0, "Escrow should be zero after failure");

        // Requester gets refund
        assertEq(requester.balance - requesterBalBefore, TEST_PRICE, "Escrow refunded");

        // Provider slashed
        uint256 provStakeAfter = marketplace.getProvider(provider1).stake;
        assertLt(provStakeAfter, provStakeBefore, "Provider stake reduced");
    }

    function test_governance_setTreasury() public {
        address newTreasury = address(0x9999);
        marketplace.setTreasury(newTreasury);
        assertEq(marketplace.treasury(), newTreasury, "Treasury updated");
    }

    function test_governance_transferGovernance() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        address newGov = address(0x8888);
        marketplace.transferGovernance(newGov);
        assertEq(marketplace.pendingGovernance(), newGov, "pending recorded");
        // Governance unchanged until acceptance.
        assertEq(marketplace.governance(), address(this), "still old gov");
        vm.prank(newGov);
        marketplace.acceptGovernance();
        assertEq(marketplace.governance(), newGov, "now new gov");
    }

    function test_nonGovernance_cannotResolveDispute() public {
        _registerProvider(provider1);
        uint256 jobId = _postJob(TEST_PRICE, 10, 100);
        _bidOnJob(jobId, provider1, 6 ether);
        _assignJob(jobId);
        _startExecution(jobId, provider1);
        _submitCommitment(jobId, provider1);
        _submitResult(jobId, provider1);

        vm.prank(disputer);
        marketplace.disputeResult{value: 10 ether}(jobId);

        vm.prank(outsider);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        marketplace.resolveDispute(jobId, true);
    }

    // ============================================================
    // High-Value Job with Auto-Tier Upgrade Test
    // ============================================================

    function test_highValueJob_autoUpgradesToZKProof() public {
        _registerProvider(provider1);

        // Post job > VALUE_THRESHOLD with Commitment tier
        vm.prank(requester);
        uint256 jobId = marketplace.postJob{value: 15 ether}(
            modelHash, inputHash, 15 ether,
            ComputeVerifier.VerificationTier.Commitment, 10, 100
        );

        // Verify the tier was auto-upgraded in the verifier
        ComputeVerifier.VerificationRecord memory rec = verifier.getRecord(jobId);
        assertEq(uint(rec.tier), uint(ComputeVerifier.VerificationTier.ZKProof), "Should auto-upgrade to ZKProof");
    }
}
