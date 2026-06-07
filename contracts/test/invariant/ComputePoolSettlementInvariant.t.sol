// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ComputePool} from "../../src/ComputePool.sol";

/// @title ComputePoolSettlementInvariant.t.sol — INFER-S2 (chain)
/// @notice The four settlement invariants from
///         citrate-labs/handoffs/INFER_COMPUTEPOOL_SETTLEMENT_WP.md §4c,
///         encoded as a handler-driven Foundry invariant suite (PIN-style,
///         128k randomized calls, 0 reverts). The same four properties are
///         stated formally in specs/tla/compute/ComputePoolSettlement.tla.
///
///   1. NoDoubleSpendEscrow   — a job's escrow is settled at most once.
///   2. RefundConservation    — failJob/reclaimExpiredJob refund exactly job.payment.
///   3. TerminalMonotonicity  — once Completed/Failed, status never changes again.
///   4. ExecutorOnlyCompletion— completeJob/failJob succeed only for
///                              {governance, creator, dispatchedBy}.

/// @dev Drives a populated ComputePool through random request / dispatch /
///      complete / fail / reclaim / reassign / roll sequences and records
///      ghost state the invariants read.
contract SettlementHandler is Test {
    ComputePool public pool;
    uint256 public poolId;

    address public gov;
    address internal creator = address(0xC001);
    address internal provider1 = address(0xA001);
    address internal provider2 = address(0xA002);
    address internal requester = address(0xB001);
    address internal outsider = address(0xBAD1);

    uint256 internal constant PRICE = 1 ether;

    uint256[] public jobIds;
    // 0 = never terminal; otherwise uint8(status)+1 recorded at first sighting.
    mapping(uint256 => uint8) public recordedTerminal;
    mapping(uint256 => uint256) public settleCount;

    bool public completionAuthViolation;
    bool public refundConservationViolation;
    bool public terminalMonotonicityViolation;

    constructor() {
        pool = new ComputePool();
        gov = pool.governance();

        vm.deal(creator, 1_000_000 ether);
        vm.prank(creator);
        poolId = pool.createPool("inv-pool", ComputePool.PoolMode.InferencePool, 2, 100, PRICE);

        vm.deal(provider1, 1_000_000 ether);
        vm.prank(provider1);
        pool.joinPool{value: 100 ether}(poolId, 10);
        vm.deal(provider2, 1_000_000 ether);
        vm.prank(provider2);
        pool.joinPool{value: 100 ether}(poolId, 10);
    }

    function jobCount() external view returns (uint256) {
        return jobIds.length;
    }

    function _pick(uint256 seed) internal view returns (bool ok, uint256 jobId) {
        uint256 n = jobIds.length;
        if (n == 0) return (false, 0);
        return (true, jobIds[bound(seed, 0, n - 1)]);
    }

    function _caller(uint256 seed, address dispatchedBy) internal view returns (address) {
        uint256 k = bound(seed, 0, 6);
        if (k == 0) return gov;
        if (k == 1) return creator;
        if (k == 2) return dispatchedBy == address(0) ? outsider : dispatchedBy;
        if (k == 3) return provider1;
        if (k == 4) return provider2;
        if (k == 5) return requester;
        return outsider;
    }

    function _sync(uint256 jobId) internal {
        ComputePool.JobStatus s = pool.getJob(jobId).status;
        bool terminal = (s == ComputePool.JobStatus.Completed || s == ComputePool.JobStatus.Failed);
        uint8 rec = recordedTerminal[jobId];
        if (rec == 0) {
            if (terminal) recordedTerminal[jobId] = uint8(s) + 1;
        } else {
            // already terminal once — must never differ now
            if (uint8(s) + 1 != rec) terminalMonotonicityViolation = true;
        }
    }

    // ── Fuzz actions ────────────────────────────────────────────────

    function act_request(uint256 seed) external {
        uint256 payment = bound(seed, PRICE, 50 ether);
        vm.deal(requester, 1_000_000 ether);
        vm.prank(requester);
        try pool.requestPoolCompute{value: payment}(poolId, "spec", payment) returns (uint256 jobId) {
            jobIds.push(jobId);
        } catch {}
    }

    function act_dispatch(uint256 seed) external {
        (bool ok, uint256 jobId) = _pick(seed);
        if (!ok) return;
        uint256 epoch = block.number / pool.EPOCH_LENGTH();
        address coord = pool.coordinatorFor(poolId, epoch);
        vm.prank(coord);
        try pool.recordDispatch(jobId) {} catch {}
        _sync(jobId);
    }

    function act_complete(uint256 jobSeed, uint256 callerSeed) external {
        (bool ok, uint256 jobId) = _pick(jobSeed);
        if (!ok) return;
        address dispatchedBy = pool.getJob(jobId).dispatchedBy;
        address caller = _caller(callerSeed, dispatchedBy);
        vm.prank(caller);
        try pool.completeJob(jobId) {
            settleCount[jobId] += 1;
            if (!(caller == gov || caller == creator || caller == dispatchedBy)) {
                completionAuthViolation = true;
            }
        } catch {}
        _sync(jobId);
    }

    function act_fail(uint256 jobSeed, uint256 callerSeed) external {
        (bool ok, uint256 jobId) = _pick(jobSeed);
        if (!ok) return;
        address dispatchedBy = pool.getJob(jobId).dispatchedBy;
        address caller = _caller(callerSeed, dispatchedBy);
        uint256 paymentBefore = pool.getJob(jobId).payment;
        uint256 balBefore = requester.balance;
        vm.prank(caller);
        try pool.failJob(jobId) {
            settleCount[jobId] += 1;
            if (!(caller == gov || caller == creator || caller == dispatchedBy)) {
                completionAuthViolation = true;
            }
            if (requester.balance - balBefore != paymentBefore) refundConservationViolation = true;
        } catch {}
        _sync(jobId);
    }

    function act_reclaim(uint256 jobSeed) external {
        (bool ok, uint256 jobId) = _pick(jobSeed);
        if (!ok) return;
        // ensure the hard deadline has elapsed so a valid reclaim can succeed
        vm.roll(block.number + pool.JOB_DEADLINE() + 1);
        uint256 paymentBefore = pool.getJob(jobId).payment;
        uint256 balBefore = requester.balance;
        vm.prank(requester);
        try pool.reclaimExpiredJob(jobId) {
            settleCount[jobId] += 1;
            if (requester.balance - balBefore != paymentBefore) refundConservationViolation = true;
        } catch {}
        _sync(jobId);
    }

    function act_reassign(uint256 jobSeed) external {
        (bool ok, uint256 jobId) = _pick(jobSeed);
        if (!ok) return;
        vm.roll(block.number + pool.COORDINATION_TIMEOUT() + 1);
        vm.prank(provider1);
        try pool.reassignCoordinator(jobId) {} catch {}
        _sync(jobId);
    }

    function act_roll(uint256 seed) external {
        vm.roll(block.number + bound(seed, 1, 50));
    }
}

/// forge-config: default.invariant.runs = 256
/// forge-config: default.invariant.depth = 500
/// forge-config: default.invariant.fail-on-revert = false
contract ComputePoolSettlementInvariant is StdInvariant, Test {
    SettlementHandler internal handler;

    function setUp() public {
        handler = new SettlementHandler();

        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = handler.act_request.selector;
        selectors[1] = handler.act_dispatch.selector;
        selectors[2] = handler.act_complete.selector;
        selectors[3] = handler.act_fail.selector;
        selectors[4] = handler.act_reclaim.selector;
        selectors[5] = handler.act_reassign.selector;
        selectors[6] = handler.act_roll.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// (1) A job's escrow is settled at most once — no double-spend.
    function invariant_NoDoubleSpendEscrow() public view {
        uint256 n = handler.jobCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 jobId = handler.jobIds(i);
            assertLe(handler.settleCount(jobId), 1, "escrow settled more than once");
        }
    }

    /// (2) Refund paths return exactly job.payment, never more or less.
    function invariant_RefundConservation() public view {
        assertFalse(handler.refundConservationViolation(), "refund != escrowed payment");
    }

    /// (3) Once Completed/Failed, a job's status never transitions again.
    function invariant_TerminalMonotonicity() public view {
        assertFalse(handler.terminalMonotonicityViolation(), "terminal status changed");
    }

    /// (4) completeJob/failJob succeed only for {governance, creator, dispatchedBy}.
    function invariant_ExecutorOnlyCompletion() public view {
        assertFalse(handler.completionAuthViolation(), "unauthorized settlement succeeded");
    }
}
