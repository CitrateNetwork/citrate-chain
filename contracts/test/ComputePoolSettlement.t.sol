// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputePool} from "../src/ComputePool.sol";

/// @title ComputePoolSettlement.t.sol — INFER-S2 (chain)
/// @notice Spec-first tests for the ComputePool settlement-authority +
///         requester timeout-refund work. Written to FAIL against the
///         contract as it stands (no executor-completion, no
///         reclaimExpiredJob) and pass once the WP lands.
///
/// WP: citrate-labs/handoffs/INFER_COMPUTEPOOL_SETTLEMENT_WP.md (PR #11)
/// BDD: specs/gherkin/computepool_settlement.feature
/// Sprint: .agentile/sprints/active/INFER-S2-computepool-settlement.md
///
/// G1 — completeJob/failJob must also accept job.dispatchedBy (the
///      VRF-elected coordinator that actually ran the job).
/// G2 — reclaimExpiredJob lets the requester reclaim escrow after a hard
///      JOB_DEADLINE while the job is still Pending/Executing.
contract ComputePoolSettlementTest is Test {
    ComputePool internal pool;

    address internal governance = address(this); // deployer == governance
    address internal creator = address(0xC001);
    address internal provider1 = address(0xA001);
    address internal provider2 = address(0xA002);
    address internal requester = address(0xB001);
    address internal outsider = address(0xBAD1);

    uint256 internal constant MIN_PROVIDERS = 2;
    uint256 internal constant THROUGHPUT = 100;
    uint256 internal constant PRICE = 1 ether;
    uint256 internal constant PAYMENT = 10 ether;

    event JobReclaimed(uint256 indexed jobId, uint256 indexed poolId, address indexed requester, uint256 refund);

    function setUp() public {
        pool = new ComputePool();
        vm.deal(creator, 1000 ether);
        vm.deal(provider1, 1000 ether);
        vm.deal(provider2, 1000 ether);
        vm.deal(requester, 1000 ether);
        vm.deal(outsider, 100 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _createAndPopulate() internal returns (uint256 poolId) {
        vm.prank(creator);
        poolId = pool.createPool("settle-pool", ComputePool.PoolMode.InferencePool, MIN_PROVIDERS, THROUGHPUT, PRICE);
        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);
        vm.prank(provider2);
        pool.joinPool{value: 100 ether}(poolId, 10);
    }

    function _request(uint256 poolId) internal returns (uint256 jobId) {
        vm.prank(requester);
        jobId = pool.requestPoolCompute{value: PAYMENT}(poolId, "spec", PAYMENT);
    }

    /// Record a dispatch as the VRF-elected coordinator for the current
    /// epoch, returning the coordinator that the contract recorded.
    function _dispatch(uint256 poolId, uint256 jobId) internal returns (address coord) {
        uint256 epoch = block.number / pool.EPOCH_LENGTH();
        coord = pool.coordinatorFor(poolId, epoch);
        vm.prank(coord);
        pool.recordDispatch(jobId);
        assertEq(pool.getJob(jobId).dispatchedBy, coord, "dispatchedBy not set");
    }

    // ══════════════════════════════════════════════════════════════════
    // G1 — settlement-authority asymmetry
    // ══════════════════════════════════════════════════════════════════

    /// The executor of record (job.dispatchedBy) can complete its own job.
    function test_g1_coordinator_can_completeJob() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        address coord = _dispatch(poolId, jobId);

        uint256 p1Before = provider1.balance;
        uint256 p2Before = provider2.balance;

        vm.prank(coord);
        pool.completeJob(jobId);

        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Completed, "not Completed");
        assertEq(provider1.balance, p1Before + 5 ether, "p1 share");
        assertEq(provider2.balance, p2Before + 5 ether, "p2 share");
        assertEq(pool.getPool(poolId).activeJobCount, 0, "activeJobCount");
    }

    /// The executor of record can fail its own job (refunds the requester).
    function test_g1_coordinator_can_failJob() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        address coord = _dispatch(poolId, jobId);

        uint256 reqBefore = requester.balance;
        vm.prank(coord);
        pool.failJob(jobId);

        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Failed, "not Failed");
        assertEq(requester.balance, reqBefore + PAYMENT, "requester refund");
    }

    /// Backwards compatibility: governance can still complete.
    function test_g1_governance_still_completes() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        pool.completeJob(jobId); // governance == address(this)
        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Completed, "gov complete");
    }

    /// Backwards compatibility: pool creator can still complete.
    function test_g1_creator_still_completes() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        vm.prank(creator);
        pool.completeJob(jobId);
        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Completed, "creator complete");
    }

    /// The requester must NOT be able to self-complete (would let a buyer
    /// trigger provider payment for work that may not have happened).
    function test_g1_requester_cannot_complete() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        _dispatch(poolId, jobId);

        vm.prank(requester);
        vm.expectRevert("Not authorized");
        pool.completeJob(jobId);
    }

    /// An unrelated outsider can settle neither path.
    function test_g1_outsider_cannot_complete() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        _dispatch(poolId, jobId);
        vm.prank(outsider);
        vm.expectRevert("Not authorized");
        pool.completeJob(jobId);
    }

    function test_g1_outsider_cannot_fail() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        _dispatch(poolId, jobId);
        vm.prank(outsider);
        vm.expectRevert("Not authorized");
        pool.failJob(jobId);
    }

    // ══════════════════════════════════════════════════════════════════
    // G2 — requester reclaim after a hard deadline
    // ══════════════════════════════════════════════════════════════════

    function test_g2_requester_reclaims_after_deadline_pending() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);

        vm.roll(block.number + pool.JOB_DEADLINE() + 1);

        uint256 reqBefore = requester.balance;
        vm.expectEmit(true, true, true, true);
        emit JobReclaimed(jobId, poolId, requester, PAYMENT);
        vm.prank(requester);
        pool.reclaimExpiredJob(jobId);

        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Failed, "not Failed");
        assertEq(requester.balance, reqBefore + PAYMENT, "exact refund");
        assertEq(pool.getPool(poolId).activeJobCount, 0, "activeJobCount decremented");
    }

    /// Reclaim is allowed while Executing (dispatched but never settled).
    function test_g2_requester_reclaims_while_executing() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        _dispatch(poolId, jobId);

        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        uint256 reqBefore = requester.balance;
        vm.prank(requester);
        pool.reclaimExpiredJob(jobId);

        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Failed, "not Failed");
        assertEq(requester.balance, reqBefore + PAYMENT, "exact refund");
    }

    function test_g2_reclaim_before_deadline_reverts() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        // one block before the deadline boundary
        vm.roll(block.number + pool.JOB_DEADLINE());
        vm.prank(requester);
        vm.expectRevert("Not expired");
        pool.reclaimExpiredJob(jobId);
    }

    function test_g2_non_requester_cannot_reclaim() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        vm.prank(outsider);
        vm.expectRevert("Not requester");
        pool.reclaimExpiredJob(jobId);
    }

    function test_g2_completed_job_cannot_be_reclaimed() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        pool.completeJob(jobId); // governance completes
        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        vm.prank(requester);
        vm.expectRevert("Not open");
        pool.reclaimExpiredJob(jobId);
    }

    function test_g2_failed_job_cannot_be_reclaimed() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        pool.failJob(jobId); // governance fails -> refunds
        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        vm.prank(requester);
        vm.expectRevert("Not open");
        pool.reclaimExpiredJob(jobId);
    }

    function test_g2_double_reclaim_reverts() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        vm.prank(requester);
        pool.reclaimExpiredJob(jobId);
        vm.prank(requester);
        vm.expectRevert("Not open");
        pool.reclaimExpiredJob(jobId);
    }

    /// Refund conservation: the contract pays out exactly the escrow, no more.
    function test_g2_refund_is_exact_and_conserved() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        uint256 poolBalBefore = address(pool).balance;
        uint256 reqBefore = requester.balance;

        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        vm.prank(requester);
        pool.reclaimExpiredJob(jobId);

        assertEq(requester.balance - reqBefore, PAYMENT, "requester delta exact");
        assertEq(poolBalBefore - address(pool).balance, PAYMENT, "pool delta exact");
    }

    // ══════════════════════════════════════════════════════════════════
    // Adversarial — reentrancy on the reclaim refund path
    // ══════════════════════════════════════════════════════════════════

    function test_adv_reentrant_reclaim_cannot_double_spend() public {
        uint256 poolId = _createAndPopulate();
        ReentrantRequester attacker = new ReentrantRequester(pool);
        vm.deal(address(attacker), 1000 ether);

        uint256 jobId = attacker.request{value: PAYMENT}(poolId, PAYMENT);
        vm.roll(block.number + pool.JOB_DEADLINE() + 1);

        uint256 poolBalBefore = address(pool).balance;
        // The reentrant receive() re-enters reclaimExpiredJob; nonReentrant
        // must make the inner call revert, which fails the refund transfer
        // and reverts the whole reclaim. No funds move; escrow is intact.
        attacker.arm(jobId);
        vm.expectRevert();
        attacker.reclaim(jobId);

        assertEq(address(pool).balance, poolBalBefore, "escrow must be untouched");
        assertTrue(pool.getJob(jobId).status != ComputePool.JobStatus.Failed, "job must not be settled");
    }

    /// Once reclaimed (terminal Failed), no actor can re-settle the job.
    function test_adv_settle_after_reclaim_reverts() public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        address coord = _dispatch(poolId, jobId);

        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        vm.prank(requester);
        pool.reclaimExpiredJob(jobId);

        vm.prank(coord);
        vm.expectRevert("Invalid job status");
        pool.completeJob(jobId);

        vm.prank(coord);
        vm.expectRevert("Invalid job status");
        pool.failJob(jobId);
    }

    // ══════════════════════════════════════════════════════════════════
    // Fuzz — reclaim refund-exactness + deadline gating
    // ══════════════════════════════════════════════════════════════════

    /// Refund conservation under arbitrary escrow amounts.
    function testFuzz_reclaim_refunds_exactly(uint256 payment) public {
        payment = bound(payment, PRICE, 500 ether);
        uint256 poolId = _createAndPopulate();
        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: payment}(poolId, "spec", payment);

        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        uint256 before = requester.balance;
        vm.prank(requester);
        pool.reclaimExpiredJob(jobId);

        assertEq(requester.balance - before, payment, "refund must equal escrow exactly");
        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Failed, "terminal Failed");
    }

    /// Reclaim succeeds iff strictly past createdAt + JOB_DEADLINE, never before.
    function testFuzz_reclaim_gated_on_deadline(uint256 wait) public {
        uint256 poolId = _createAndPopulate();
        uint256 jobId = _request(poolId);
        uint256 createdAt = pool.getJob(jobId).createdAt;
        uint256 deadline = pool.JOB_DEADLINE(); // read before pranking

        wait = bound(wait, 0, 5000);
        vm.roll(createdAt + wait);
        bool expired = block.number > createdAt + deadline;

        vm.prank(requester);
        if (expired) {
            pool.reclaimExpiredJob(jobId);
            assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Failed, "should reclaim");
        } else {
            vm.expectRevert("Not expired");
            pool.reclaimExpiredJob(jobId);
        }
    }
}

/// @notice Malicious requester that attempts to re-enter reclaimExpiredJob
///         from its receive() hook to double-spend the escrow.
contract ReentrantRequester {
    ComputePool public immutable pool;
    uint256 internal armedJob;
    bool internal armed;

    constructor(ComputePool _pool) {
        pool = _pool;
    }

    function request(uint256 poolId, uint256 maxPrice) external payable returns (uint256) {
        return pool.requestPoolCompute{value: msg.value}(poolId, "spec", maxPrice);
    }

    function arm(uint256 jobId) external {
        armedJob = jobId;
        armed = true;
    }

    function reclaim(uint256 jobId) external {
        pool.reclaimExpiredJob(jobId);
    }

    receive() external payable {
        if (armed) {
            armed = false; // single re-entry attempt
            pool.reclaimExpiredJob(armedJob); // must revert (nonReentrant)
        }
    }
}
