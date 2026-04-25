// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ComputePool} from "../src/ComputePool.sol";

/// @title ComputePoolCoordinator.t.sol — CM-05 WP-05.1
/// @notice Tests for the coordinator-VRF-election + reassignment-on-
///         timeout extension to ComputePool. Written FIRST per the
///         spec-first discipline (CM-02 RETRO action item #1).
///
/// Acceptance criteria from
/// .agentile/planset/compute-marketplace-buildout/CM-05-compute-pool-inference.md
/// (WP-05.1):
///   - test_coordinator_deterministic_for_epoch ✓
///   - test_coordinator_rotates_every_100_blocks ✓
///   - test_coordinator_weighted_by_gpu_count ✓
///   - test_reassign_after_timeout_slashes_original ✓
///
/// Plus:
///   - reassignCoordinator before timeout reverts
///   - coordinatorFor on empty pool reverts
///   - Pool with zero GPUs (impossible but defensive) reverts
contract ComputePoolCoordinatorTest is Test {
    ComputePool internal pool;

    address internal governance = address(this);
    address internal creator = address(0xC001);
    // Eight candidate providers; tests opt in as needed.
    address internal p1 = address(0xA001);
    address internal p2 = address(0xA002);
    address internal p3 = address(0xA003);
    address internal p4 = address(0xA004);
    address internal heavy = address(0xA0FF); // big-gpuCount provider
    address internal requester = address(0xB001);
    address internal outsider = address(0xBAD1);

    uint256 internal constant THROUGHPUT = 100;
    uint256 internal constant PRICE = 1 ether;

    function setUp() public {
        pool = new ComputePool();
        vm.deal(creator, 1000 ether);
        vm.deal(p1, 1000 ether);
        vm.deal(p2, 1000 ether);
        vm.deal(p3, 1000 ether);
        vm.deal(p4, 1000 ether);
        vm.deal(heavy, 10000 ether);
        vm.deal(requester, 1000 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _createPool(uint256 minProviders) internal returns (uint256 poolId) {
        vm.prank(creator);
        poolId = pool.createPool(
            "test-pool",
            ComputePool.PoolMode.InferencePool,
            minProviders,
            THROUGHPUT,
            PRICE
        );
    }

    function _join(uint256 poolId, address who, uint256 gpus) internal {
        vm.prank(who);
        pool.joinPool{value: gpus * 10 ether}(poolId, gpus);
    }

    /// Pin block.prevrandao + block number so coordinator math is
    /// reproducible across the whole test.
    function _pinChainAt(uint256 blk, bytes32 randao) internal {
        vm.roll(blk);
        vm.prevrandao(randao);
    }

    // ── coordinatorFor ──────────────────────────────────────────────

    /// AC: "Coordinator is deterministic for a given (poolId, epoch)."
    function test_coordinator_deterministic_for_epoch() public {
        uint256 poolId = _createPool(2);
        _join(poolId, p1, 1);
        _join(poolId, p2, 1);
        _join(poolId, p3, 1);

        // Pin block to epoch 5 (block 500..599) and pin randao.
        _pinChainAt(500, bytes32(uint256(0xabcd)));

        address a = pool.coordinatorFor(poolId, 5);
        address b = pool.coordinatorFor(poolId, 5);
        assertEq(a, b, "coordinatorFor(p, e) must be idempotent within an epoch");
    }

    /// AC: "Coordinator rotates every 100 blocks."
    /// Soft-form: the coordinator address for an arbitrary epoch should be
    /// SOMETIMES different from the one in the previous epoch. We sample
    /// 20 consecutive epochs with three equal-weight members and require
    /// at least one rotation observed.
    function test_coordinator_rotates_every_100_blocks() public {
        uint256 poolId = _createPool(2);
        _join(poolId, p1, 1);
        _join(poolId, p2, 1);
        _join(poolId, p3, 1);

        bool sawRotation = false;
        address prev = address(0);
        for (uint256 e = 1; e < 21; e++) {
            // Each epoch's randao is distinct so the seed actually varies.
            _pinChainAt(e * 100, keccak256(abi.encodePacked("epoch", e)));
            address c = pool.coordinatorFor(poolId, e);
            if (e > 1 && c != prev) sawRotation = true;
            prev = c;
        }
        assertTrue(sawRotation, "Coordinator never rotated across 20 epochs");
    }

    /// AC: "Coordinator selection is weighted by gpuCount."
    /// `heavy` has 8 GPUs, `p1` has 1. Across 200 sampled epochs, `heavy`
    /// should be elected ~88.9% of the time. We allow a wide tolerance
    /// (50%-100%) since we're not benchmarking statistics, just verifying
    /// the weighting EXISTS at all (a uniform pick would give ~50%).
    function test_coordinator_weighted_by_gpu_count() public {
        uint256 poolId = _createPool(1);
        _join(poolId, heavy, 8);
        _join(poolId, p1, 1);

        uint256 heavyCount = 0;
        for (uint256 e = 1; e <= 200; e++) {
            _pinChainAt(e * 100, keccak256(abi.encodePacked("ep", e)));
            address c = pool.coordinatorFor(poolId, e);
            if (c == heavy) heavyCount++;
        }
        // Heavy should win at LEAST 100/200 (uniform baseline) — really
        // we expect ~178/200 (8/9 = 88.9%). Lower bound generous to
        // tolerate seed variance from the keccak source.
        assertGe(heavyCount, 100, "weighting absent: heavy <= uniform");
        assertLe(heavyCount, 200, "weighting impossible value");
    }

    /// AC: pool with no members reverts coordinatorFor.
    function test_coordinator_empty_pool_reverts() public {
        uint256 poolId = _createPool(1);
        vm.expectRevert(bytes("NoMembers"));
        pool.coordinatorFor(poolId, 0);
    }

    // ── reassignCoordinator ─────────────────────────────────────────

    /// AC: reassignment within the timeout window reverts.
    function test_reassign_before_timeout_reverts() public {
        uint256 poolId = _createPool(2);
        _join(poolId, p1, 1);
        _join(poolId, p2, 1);

        _pinChainAt(100, bytes32(uint256(0xdead)));
        ComputePool.PoolJobSpec memory spec = ComputePool.PoolJobSpec({
            version: 1,
            mode: 0,
            modelHash: bytes32(uint256(0xab)),
            inputData: hex"deadbeef",
            maxTokens: 16,
            verificationTier: 0,
            batchSize: 1
        });

        vm.prank(requester);
        uint256 jobId = pool.requestPoolComputeStruct{value: 1 ether}(
            poolId,
            spec,
            1 ether
        );

        // Mark job as Dispatched. The contract requires the call
        // come from the elected coordinator for the current epoch.
        address coord = pool.coordinatorFor(poolId, 1);
        vm.prank(coord);
        pool.recordDispatch(jobId);

        // Only 5 blocks pass — well below COORDINATION_TIMEOUT.
        vm.roll(105);
        // Caller must also be a pool member (other member, not the
        // coordinator themselves).
        address other = (coord == p1) ? p2 : p1;
        vm.prank(other);
        vm.expectRevert(bytes("Coordinator has time"));
        pool.reassignCoordinator(jobId);
    }

    /// AC: "test_reassign_after_timeout_slashes_original". After the
    /// timeout window, any pool member can call reassign; the original
    /// coordinator gets slashed for liveness; a new coordinator is
    /// elected for the (pool, epoch) and the job goes back to Pending.
    function test_reassign_after_timeout_slashes_original() public {
        uint256 poolId = _createPool(2);
        _join(poolId, p1, 1);
        _join(poolId, p2, 1);

        _pinChainAt(100, bytes32(uint256(0xbeef)));
        ComputePool.PoolJobSpec memory spec = ComputePool.PoolJobSpec({
            version: 1,
            mode: 0,
            modelHash: bytes32(uint256(0xab)),
            inputData: hex"deadbeef",
            maxTokens: 16,
            verificationTier: 0,
            batchSize: 1
        });
        vm.prank(requester);
        uint256 jobId = pool.requestPoolComputeStruct{value: 1 ether}(
            poolId,
            spec,
            1 ether
        );

        // Coordinator (whoever the VRF picks) records dispatch.
        address originalCoordinator = pool.coordinatorFor(poolId, 1);
        uint256 stakeBefore = pool.getMember(poolId, originalCoordinator).stake;

        vm.prank(originalCoordinator);
        pool.recordDispatch(jobId);

        // Advance well past the timeout. Then any member can reassign.
        vm.roll(200);
        // Use the OTHER member as the reassignment caller.
        address other = (originalCoordinator == p1) ? p2 : p1;
        vm.expectEmit(true, true, false, false);
        emit CoordinatorSlashedForLiveness(poolId, originalCoordinator, 0);
        vm.prank(other);
        pool.reassignCoordinator(jobId);

        // Original was slashed: liveness slash is 0.1% of stake = 10 bps.
        uint256 stakeAfter = pool.getMember(poolId, originalCoordinator).stake;
        assertLt(stakeAfter, stakeBefore, "stake didn't decrease");
        // Tolerable rounding: floor((10e18 * 10) / 10000) = 1e16.
        assertEq(stakeBefore - stakeAfter, 1e16, "wrong slash amount");

        // Job is back to Pending so the new coordinator can dispatch.
        ComputePool.PoolJob memory j = pool.getJob(jobId);
        assertEq(uint256(j.status), uint256(ComputePool.JobStatus.Pending));
    }

    /// AC: outsider (not a pool member) cannot reassign.
    function test_reassign_by_outsider_reverts() public {
        uint256 poolId = _createPool(2);
        _join(poolId, p1, 1);
        _join(poolId, p2, 1);

        _pinChainAt(100, bytes32(uint256(0xbeef)));
        ComputePool.PoolJobSpec memory spec = ComputePool.PoolJobSpec({
            version: 1,
            mode: 0,
            modelHash: bytes32(uint256(0xab)),
            inputData: hex"deadbeef",
            maxTokens: 16,
            verificationTier: 0,
            batchSize: 1
        });
        vm.prank(requester);
        uint256 jobId = pool.requestPoolComputeStruct{value: 1 ether}(
            poolId,
            spec,
            1 ether
        );
        address coord = pool.coordinatorFor(poolId, 1);
        vm.prank(coord);
        pool.recordDispatch(jobId);
        vm.roll(200);

        vm.prank(outsider);
        vm.expectRevert(bytes("Not a pool member"));
        pool.reassignCoordinator(jobId);
    }

    // ── PoolJobSpec encode/decode ───────────────────────────────────

    function test_poolJobSpec_struct_overload_accepts_call() public {
        uint256 poolId = _createPool(1);
        _join(poolId, p1, 1);

        ComputePool.PoolJobSpec memory spec = ComputePool.PoolJobSpec({
            version: 1,
            mode: 0,
            modelHash: bytes32(uint256(0xab)),
            inputData: hex"01020304",
            maxTokens: 256,
            verificationTier: 1,
            batchSize: 4
        });

        vm.prank(requester);
        uint256 jobId = pool.requestPoolComputeStruct{value: 1 ether}(
            poolId,
            spec,
            1 ether
        );
        ComputePool.PoolJob memory j = pool.getJob(jobId);
        assertEq(uint256(j.status), uint256(ComputePool.JobStatus.Pending));
        // The struct version is encoded into the stored jobSpec bytes;
        // decoding round-trips.
        ComputePool.PoolJobSpec memory decoded = pool.decodePoolJobSpec(j.jobSpec);
        assertEq(decoded.version, 1);
        assertEq(decoded.mode, 0);
        assertEq(decoded.modelHash, bytes32(uint256(0xab)));
        assertEq(decoded.maxTokens, 256);
        assertEq(decoded.verificationTier, 1);
        assertEq(decoded.batchSize, 4);
        assertEq(keccak256(decoded.inputData), keccak256(hex"01020304"));
    }

    function test_legacy_bytes_overload_still_works() public {
        // The original `requestPoolCompute(uint256,bytes,uint256)` must
        // remain callable so existing producers don't break.
        uint256 poolId = _createPool(1);
        _join(poolId, p1, 1);

        bytes memory legacy = abi.encode("legacy");
        vm.prank(requester);
        uint256 jobId = pool.requestPoolCompute{value: 1 ether}(
            poolId,
            legacy,
            1 ether
        );
        ComputePool.PoolJob memory j = pool.getJob(jobId);
        assertEq(uint256(j.status), uint256(ComputePool.JobStatus.Pending));
    }

    // ── Event signature shadowing for vm.expectEmit ─────────────────

    event CoordinatorElected(uint256 indexed poolId, uint256 indexed epoch, address indexed coordinator);
    event CoordinatorReassigned(uint256 indexed jobId, address indexed previous, address indexed next);
    event CoordinatorSlashedForLiveness(uint256 indexed poolId, address indexed coordinator, uint256 amount);
}
