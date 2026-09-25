// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputePool} from "../src/ComputePool.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @notice Mock NematocystSlashing for pool SLA integration testing.
contract MockSlashingForPool {
    struct SlashRecord {
        address provider;
        uint8 tier;
    }

    SlashRecord[] public slashes;

    function slash(address provider, uint8 tier, bytes calldata) external {
        slashes.push(SlashRecord(provider, tier));
    }

    function slashCount() external view returns (uint256) {
        return slashes.length;
    }
}

contract ComputePoolTest is Test {
    ComputePool internal pool;
    MockSlashingForPool internal mockSlashing;

    address internal governance = address(this);
    address internal creator = address(0xC001);
    address internal provider1 = address(0xA001);
    address internal provider2 = address(0xA002);
    address internal provider3 = address(0xA003);
    address internal requester = address(0xB001);
    address internal outsider = address(0xBAD1);

    uint256 internal constant MIN_PROVIDERS = 2;
    uint256 internal constant THROUGHPUT = 100;
    uint256 internal constant PRICE = 1 ether;

    function setUp() public {
        pool = new ComputePool(address(this));
        mockSlashing = new MockSlashingForPool();
        pool.setSlashingContract(address(mockSlashing));

        vm.deal(creator, 1000 ether);
        vm.deal(provider1, 1000 ether);
        vm.deal(provider2, 1000 ether);
        vm.deal(provider3, 1000 ether);
        vm.deal(requester, 1000 ether);
        vm.deal(outsider, 100 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _createPool() internal returns (uint256 poolId) {
        vm.prank(creator);
        poolId = pool.createPool("Test Pool", ComputePool.PoolMode.InferencePool, MIN_PROVIDERS, THROUGHPUT, PRICE);
    }

    function _createAndPopulate() internal returns (uint256 poolId) {
        poolId = _createPool();

        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);

        vm.prank(provider2);
        pool.joinPool{value: 100 ether}(poolId, 10);
    }

    // ══════════════════════════════════════════════════════════════════
    // Pool Creation Tests
    // ══════════════════════════════════════════════════════════════════

    function test_createPool() public {
        uint256 poolId = _createPool();

        ComputePool.Pool memory p = pool.getPool(poolId);
        assertEq(p.id, 0);
        assertEq(keccak256(bytes(p.name)), keccak256("Test Pool"));
        assertTrue(p.mode == ComputePool.PoolMode.InferencePool);
        assertEq(p.creator, creator);
        assertTrue(p.state == ComputePool.PoolState.Active);
        assertEq(p.minProviders, MIN_PROVIDERS);
        assertEq(p.totalGPUs, 0);
        assertEq(p.guaranteedThroughput, THROUGHPUT);
        assertEq(p.pricePerUnit, PRICE);
        assertEq(p.memberCount, 0);
    }

    function test_createPool_empty_name_reverts() public {
        vm.prank(creator);
        vm.expectRevert("Empty name");
        pool.createPool("", ComputePool.PoolMode.InferencePool, 2, 100, 1 ether);
    }

    function test_createPool_zero_minProviders_reverts() public {
        vm.prank(creator);
        vm.expectRevert("Min providers must be >= 1");
        pool.createPool("Test", ComputePool.PoolMode.InferencePool, 0, 100, 1 ether);
    }

    function test_createPool_zero_throughput_reverts() public {
        vm.prank(creator);
        vm.expectRevert("Throughput must be > 0");
        pool.createPool("Test", ComputePool.PoolMode.InferencePool, 2, 0, 1 ether);
    }

    function test_createPool_zero_price_reverts() public {
        vm.prank(creator);
        vm.expectRevert("Price must be > 0");
        pool.createPool("Test", ComputePool.PoolMode.InferencePool, 2, 100, 0);
    }

    function test_createPool_all_modes() public {
        vm.startPrank(creator);
        uint256 p1 = pool.createPool("Inference", ComputePool.PoolMode.InferencePool, 1, 100, 1 ether);
        uint256 p2 = pool.createPool("DataPar", ComputePool.PoolMode.DataParallel, 1, 100, 1 ether);
        uint256 p3 = pool.createPool("Pipeline", ComputePool.PoolMode.PipelineParallel, 1, 100, 1 ether);
        vm.stopPrank();

        assertTrue(pool.getPool(p1).mode == ComputePool.PoolMode.InferencePool);
        assertTrue(pool.getPool(p2).mode == ComputePool.PoolMode.DataParallel);
        assertTrue(pool.getPool(p3).mode == ComputePool.PoolMode.PipelineParallel);
    }

    // ══════════════════════════════════════════════════════════════════
    // GPUCountAccurate Invariant — totalGPUs = sum of provider GPUs
    // ══════════════════════════════════════════════════════════════════

    function test_joinPool_updates_gpu_count() public {
        uint256 poolId = _createPool();

        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);
        assertEq(pool.getPoolGPUCount(poolId), 10);

        vm.prank(provider2);
        pool.joinPool{value: 50 ether}(poolId, 5);
        assertEq(pool.getPoolGPUCount(poolId), 15);
    }

    function test_leavePool_decrements_gpu_count() public {
        uint256 poolId = _createAndPopulate();
        assertEq(pool.getPoolGPUCount(poolId), 20);

        vm.prank(provider1);
        pool.leavePool(poolId);
        assertEq(pool.getPoolGPUCount(poolId), 10);
    }

    function test_joinPool_insufficient_stake_reverts() public {
        uint256 poolId = _createPool();

        vm.prank(provider1);
        vm.expectRevert("Insufficient stake for GPUs");
        pool.joinPool{value: 5 ether}(poolId, 10); // needs 100 ether
    }

    function test_joinPool_zero_gpus_reverts() public {
        uint256 poolId = _createPool();

        vm.prank(provider1);
        vm.expectRevert("Must contribute at least 1 GPU");
        pool.joinPool{value: 10 ether}(poolId, 0);
    }

    function test_joinPool_already_member_reverts() public {
        uint256 poolId = _createPool();

        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);

        vm.prank(provider1);
        vm.expectRevert("Already a member");
        pool.joinPool{value: 100 ether}(poolId, 10);
    }

    // ══════════════════════════════════════════════════════════════════
    // ProviderCooldown Invariant — can't leave during active job
    // ══════════════════════════════════════════════════════════════════

    function test_leavePool_returns_stake() public {
        uint256 poolId = _createAndPopulate();

        uint256 balBefore = provider1.balance;
        vm.prank(provider1);
        pool.leavePool(poolId);
        assertEq(provider1.balance, balBefore + 100 ether);
    }

    function test_C012_leaveAndRejoin_doesNotDuplicatePayoutMember() public {
        uint256 poolId = _createPool();

        vm.startPrank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);
        pool.leavePool(poolId);
        pool.joinPool{value: 100 ether}(poolId, 10);
        vm.stopPrank();

        address[] memory memberList = pool.getPoolMembers(poolId);
        assertEq(memberList.length, 1);
        assertEq(memberList[0], provider1);
    }

    function test_leavePool_not_member_reverts() public {
        uint256 poolId = _createPool();

        vm.prank(outsider);
        vm.expectRevert("Not a member");
        pool.leavePool(poolId);
    }

    // ══════════════════════════════════════════════════════════════════
    // MinProvidersMaintained — pool auto-pauses below minimum
    // ══════════════════════════════════════════════════════════════════

    function test_pool_auto_pauses_below_min_providers() public {
        uint256 poolId = _createAndPopulate();
        assertTrue(pool.getPool(poolId).state == ComputePool.PoolState.Active);

        // Provider 1 leaves — now below min (1 < 2)
        vm.prank(provider1);
        pool.leavePool(poolId);

        assertTrue(pool.getPool(poolId).state == ComputePool.PoolState.Paused);
    }

    function test_resume_requires_min_providers() public {
        uint256 poolId = _createAndPopulate();

        // Leave until paused
        vm.prank(provider1);
        pool.leavePool(poolId);
        assertTrue(pool.getPool(poolId).state == ComputePool.PoolState.Paused);

        // Can't resume without enough providers
        vm.prank(creator);
        vm.expectRevert("Below min providers");
        pool.resumePool(poolId);

        // Add provider back
        vm.prank(provider3);
        pool.joinPool{value: 100 ether}(poolId, 10);

        // Now can resume
        vm.prank(creator);
        pool.resumePool(poolId);
        assertTrue(pool.getPool(poolId).state == ComputePool.PoolState.Active);
    }

    // ══════════════════════════════════════════════════════════════════
    // Compute Request Tests
    // ══════════════════════════════════════════════════════════════════

    function test_requestPoolCompute() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 1 ether}(poolId, "job_spec_data", 1 ether);

        ComputePool.PoolJob memory job = pool.getJob(jobId);
        assertEq(job.poolId, poolId);
        assertEq(job.requester, requester);
        assertEq(job.payment, 1 ether);
        assertTrue(job.status == ComputePool.JobStatus.Pending);

        assertEq(pool.getPool(poolId).activeJobCount, 1);
    }

    function test_requestCompute_inactive_pool_reverts() public {
        uint256 poolId = _createPool(); // no providers, but state is Active

        // Actually need to test paused pool
        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);
        vm.prank(creator);
        pool.pausePool(poolId);

        vm.prank(requester);
        vm.expectRevert("Pool not active");
        pool.requestPoolCompute{value: 1 ether}(poolId, "spec", 1 ether);
    }

    function test_requestCompute_insufficient_providers_reverts() public {
        uint256 poolId = _createPool();

        // Only 1 provider joined, need 2
        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);

        vm.prank(requester);
        vm.expectRevert("Insufficient providers");
        pool.requestPoolCompute{value: 1 ether}(poolId, "spec", 1 ether);
    }

    function test_requestCompute_insufficient_payment_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        vm.expectRevert("Insufficient payment");
        pool.requestPoolCompute{value: 0.5 ether}(poolId, "spec", 0.5 ether);
    }

    function test_requestCompute_empty_jobspec_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        vm.expectRevert("Empty job spec");
        pool.requestPoolCompute{value: 1 ether}(poolId, "", 1 ether);
    }

    // ══════════════════════════════════════════════════════════════════
    // Job Completion — Payment Distribution
    // ══════════════════════════════════════════════════════════════════

    function test_completeJob_distributes_payment() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 10 ether}(poolId, "spec", 10 ether);

        uint256 p1Before = provider1.balance;
        uint256 p2Before = provider2.balance;

        // Both providers have 10 GPUs each (50/50 split)
        vm.prank(creator);
        pool.completeJob(jobId);

        // Each gets 5 ether
        assertEq(provider1.balance, p1Before + 5 ether);
        assertEq(provider2.balance, p2Before + 5 ether);

        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Completed);
        assertEq(pool.getPool(poolId).activeJobCount, 0);
    }

    function test_failJob_refunds_requester() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 10 ether}(poolId, "spec", 10 ether);

        uint256 reqBefore = requester.balance;

        vm.prank(creator);
        pool.failJob(jobId);

        assertEq(requester.balance, reqBefore + 10 ether);
        assertTrue(pool.getJob(jobId).status == ComputePool.JobStatus.Failed);
    }

    function test_completeJob_unauthorized_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 1 ether}(poolId, "spec", 1 ether);

        vm.prank(outsider);
        vm.expectRevert("Not authorized");
        pool.completeJob(jobId);
    }

    // ══════════════════════════════════════════════════════════════════
    // SLAEnforced — actual < guarantee => proportional slash
    // ══════════════════════════════════════════════════════════════════

    function test_sla_violation_slashes_members() public {
        uint256 poolId = _createAndPopulate();

        // Report SLA violation: actual 50 vs guaranteed 100 (50% deficit)
        pool.reportSLAViolation(poolId, 50);

        // Check that stakes were reduced
        ComputePool.PoolMember memory m1 = pool.getMember(poolId, provider1);
        ComputePool.PoolMember memory m2 = pool.getMember(poolId, provider2);

        // Penalty per member = stake * SLA_PENALTY_BPS * deficit / (BPS * guaranteed)
        // = 100e18 * 1000 * 50 / (10000 * 100) = 100e18 * 50000 / 1000000 = 5e18
        assertEq(m1.stake, 95 ether);
        assertEq(m2.stake, 95 ether);
    }

    function test_sla_violation_no_violation_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.expectRevert("No violation");
        pool.reportSLAViolation(poolId, THROUGHPUT); // actual == guaranteed
    }

    function test_sla_violation_only_governance() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(outsider);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        pool.reportSLAViolation(poolId, 50);
    }

    function test_sla_violation_triggers_nematocyst_slash() public {
        uint256 poolId = _createAndPopulate();

        pool.reportSLAViolation(poolId, 50);

        // Two providers should each be slashed
        assertEq(mockSlashing.slashCount(), 2);
    }

    // ══════════════════════════════════════════════════════════════════
    // Pool Dissolution
    // ══════════════════════════════════════════════════════════════════

    function test_dissolvePool_returns_all_stakes() public {
        uint256 poolId = _createAndPopulate();

        uint256 p1Before = provider1.balance;
        uint256 p2Before = provider2.balance;

        vm.prank(creator);
        pool.dissolvePool(poolId);

        assertEq(provider1.balance, p1Before + 100 ether);
        assertEq(provider2.balance, p2Before + 100 ether);

        ComputePool.Pool memory p = pool.getPool(poolId);
        assertTrue(p.state == ComputePool.PoolState.Dissolved);
        assertEq(p.memberCount, 0);
        assertEq(p.totalGPUs, 0);
        assertEq(p.totalStaked, 0);
    }

    function test_dissolvePool_not_creator_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(outsider);
        vm.expectRevert("Not pool creator");
        pool.dissolvePool(poolId);
    }

    function test_dissolvePool_already_dissolved_reverts() public {
        uint256 poolId = _createPool();

        vm.prank(creator);
        pool.dissolvePool(poolId);

        vm.prank(creator);
        vm.expectRevert("Already dissolved");
        pool.dissolvePool(poolId);
    }

    function test_dissolvePool_with_active_jobs_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(requester);
        pool.requestPoolCompute{value: 1 ether}(poolId, "spec", 1 ether);

        vm.prank(creator);
        vm.expectRevert("Has active jobs");
        pool.dissolvePool(poolId);
    }

    // ══════════════════════════════════════════════════════════════════
    // Pool Pause/Resume
    // ══════════════════════════════════════════════════════════════════

    function test_pausePool() public {
        uint256 poolId = _createPool();

        vm.prank(creator);
        pool.pausePool(poolId);

        assertTrue(pool.getPool(poolId).state == ComputePool.PoolState.Paused);
    }

    function test_pausePool_not_active_reverts() public {
        uint256 poolId = _createPool();

        vm.prank(creator);
        pool.pausePool(poolId);

        vm.prank(creator);
        vm.expectRevert("Not active");
        pool.pausePool(poolId);
    }

    function test_resumePool_not_paused_reverts() public {
        uint256 poolId = _createAndPopulate();

        vm.prank(creator);
        vm.expectRevert("Not paused");
        pool.resumePool(poolId);
    }

    // ══════════════════════════════════════════════════════════════════
    // PoolSolvent Invariant
    // ══════════════════════════════════════════════════════════════════

    function test_isPoolSolvent() public {
        uint256 poolId = _createAndPopulate();

        // Total staked = 200 ether
        // Min required = throughput * price * SLA_PENALTY_BPS / BPS = 100 * 1e18 * 1000 / 10000 = 10e18
        assertTrue(pool.isPoolSolvent(poolId));
    }

    function test_pool_becomes_insolvent_after_slashes() public {
        // Create pool with high throughput to make solvency tight
        vm.prank(creator);
        uint256 poolId = pool.createPool("High", ComputePool.PoolMode.InferencePool, 1, 10000, 1 ether);

        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);

        // Min required = 10000 * 1e18 * 1000 / 10000 = 1000e18 = 1000 ether
        // Total staked = 100 ether < 1000 ether
        assertFalse(pool.isPoolSolvent(poolId));
    }

    // ══════════════════════════════════════════════════════════════════
    // View Functions
    // ══════════════════════════════════════════════════════════════════

    function test_getPoolMembers() public {
        uint256 poolId = _createAndPopulate();

        address[] memory memberList = pool.getPoolMembers(poolId);
        assertEq(memberList.length, 2);
        assertEq(memberList[0], provider1);
        assertEq(memberList[1], provider2);
    }

    function test_getMember() public {
        uint256 poolId = _createPool();

        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);

        ComputePool.PoolMember memory m = pool.getMember(poolId, provider1);
        assertEq(m.gpuCount, 10);
        assertEq(m.stake, 100 ether);
        assertTrue(m.active);
    }

    // ══════════════════════════════════════════════════════════════════
    // Governance
    // ══════════════════════════════════════════════════════════════════

    function test_transferGovernance() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        pool.transferGovernance(creator);
        assertEq(pool.pendingGovernance(), creator);
        vm.prank(creator);
        pool.acceptGovernance();
        assertEq(pool.governance(), creator);
    }

    function test_transferGovernance_zero_address_reverts() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        pool.transferGovernance(address(0));
    }

    // ══════════════════════════════════════════════════════════════════
    // Adversarial: Pool Dissolution Edge Cases
    // ══════════════════════════════════════════════════════════════════

    function test_join_dissolved_pool_reverts() public {
        uint256 poolId = _createPool();
        vm.prank(creator);
        pool.dissolvePool(poolId);

        vm.prank(provider1);
        vm.expectRevert("Pool dissolved");
        pool.joinPool{value: 100 ether}(poolId, 10);
    }

    function test_request_compute_dissolved_pool_reverts() public {
        uint256 poolId = _createAndPopulate();

        // Complete any jobs first, then dissolve
        vm.prank(creator);
        pool.dissolvePool(poolId);

        vm.prank(requester);
        vm.expectRevert("Pool not active");
        pool.requestPoolCompute{value: 1 ether}(poolId, "spec", 1 ether);
    }

    // ══════════════════════════════════════════════════════════════════
    // Adversarial: Proportional Payment with Unequal GPUs
    // ══════════════════════════════════════════════════════════════════

    function test_unequal_gpu_payment_distribution() public {
        uint256 poolId = _createPool();

        // Provider 1: 30 GPUs, Provider 2: 10 GPUs (3:1 ratio)
        vm.prank(provider1);
        pool.joinPool{value: 300 ether}(poolId, 30);

        vm.prank(provider2);
        pool.joinPool{value: 100 ether}(poolId, 10);

        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 40 ether}(poolId, "spec", 40 ether);

        uint256 p1Before = provider1.balance;
        uint256 p2Before = provider2.balance;

        vm.prank(creator);
        pool.completeJob(jobId);

        // Provider 1 gets 30/40 * 40 = 30 ether
        assertEq(provider1.balance, p1Before + 30 ether);
        // Provider 2 gets 10/40 * 40 = 10 ether
        assertEq(provider2.balance, p2Before + 10 ether);
    }

    // ══════════════════════════════════════════════════════════════════
    // Join Paused Pool (providers can still join to help resume)
    // ══════════════════════════════════════════════════════════════════

    function test_join_paused_pool_succeeds() public {
        uint256 poolId = _createPool();
        vm.prank(creator);
        pool.pausePool(poolId);

        // Providers can join paused pools so the pool can be resumed
        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);

        ComputePool.PoolMember memory m = pool.getMember(poolId, provider1);
        assertTrue(m.active);
        assertEq(m.gpuCount, 10);
    }
}
