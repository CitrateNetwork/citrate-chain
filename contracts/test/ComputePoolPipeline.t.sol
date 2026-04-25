// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../src/TEEAttestationRegistry.sol";
import {ComputePoolPipeline} from "../src/ComputePoolPipeline.sol";

/// @title ComputePoolPipelineTest — CM-08 WP-08.1 acceptance
/// @notice Covers the pipeline-parallel lifecycle + the
///         PipelineParallelInference.tla invariants. TEE-registry
///         integration exercised via a helper that pre-attests
///         workers against a trusted-signer whitelist.
contract ComputePoolPipelineTest is Test {
    TEEAttestationRegistry internal registry;
    ComputePoolPipeline internal pool;

    address internal governance = address(this);
    address internal creator = address(0xA11CE);
    address internal requester = address(0xB0B);

    address internal w1 = address(0xCAFE1);
    address internal w2 = address(0xCAFE2);
    address internal w3 = address(0xCAFE3);
    address internal w4 = address(0xCAFE4);
    address internal w5 = address(0xCAFE5);

    bytes32 internal constant MODEL_HASH = keccak256("llama-3.1-70b");
    bytes32 internal constant MAA_KEY = keccak256("azure-maa-prod");
    bytes32 internal constant NRAS_KEY = keccak256("nvidia-nras-prod");

    uint128 internal constant PAYMENT = 4 ether; // divisible by 4 stages
    uint128 internal constant STAGE_STAKE = 2 ether;

    function setUp() public {
        registry = new TEEAttestationRegistry(governance);
        pool = new ComputePoolPipeline(governance, address(registry));

        // Whitelist signer hashes — governance-curated in production.
        registry.setMaaSigner(MAA_KEY, true);
        registry.setNrasSigner(NRAS_KEY, true);

        // Pre-attest every candidate worker.
        for (uint160 i = 1; i <= 5; i++) {
            address w = address(uint160(0xCAFE0) + i);
            _attest(w);
        }

        vm.deal(creator, 100 ether);
        vm.deal(requester, 100 ether);
        for (uint160 i = 1; i <= 5; i++) {
            address w = address(uint160(0xCAFE0) + i);
            vm.deal(w, 100 ether);
        }
    }

    function _attest(address worker) internal {
        vm.prank(worker);
        registry.submitAttestation(
            keccak256(abi.encode("vm", worker)),
            keccak256(abi.encode("gpu", worker)),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function _createJob() internal returns (uint256 jobId) {
        vm.prank(creator);
        jobId = pool.createPipelineJob(4, PAYMENT, STAGE_STAKE, MODEL_HASH);
    }

    function _assignFour(uint256 jobId) internal {
        vm.prank(w1);
        pool.assignStage{value: STAGE_STAKE}(jobId, 0);
        vm.prank(w2);
        pool.assignStage{value: STAGE_STAKE}(jobId, 1);
        vm.prank(w3);
        pool.assignStage{value: STAGE_STAKE}(jobId, 2);
        vm.prank(w4);
        pool.assignStage{value: STAGE_STAKE}(jobId, 3);
    }

    // ── Test #1: Full lifecycle, 4 stages ─────────────────────────

    function test_happy_path_four_stage_request() public {
        uint256 jobId = _createJob();
        _assignFour(jobId);
        pool.activateJob(jobId);

        vm.prank(requester);
        uint256 reqId = pool.submitRequest{value: PAYMENT}(jobId);

        vm.prank(w1);
        pool.advanceRequest(reqId);
        vm.prank(w2);
        pool.advanceRequest(reqId);
        vm.prank(w3);
        pool.advanceRequest(reqId);
        vm.prank(w4);
        pool.advanceRequest(reqId);

        ComputePoolPipeline.Request memory r = pool.getRequest(reqId);
        assertEq(uint8(r.state), uint8(ComputePoolPipeline.RequestState.Completed));
        assertEq(r.progress, 4);
        assertEq(r.escrow, 0);

        // Each stage earned payment/4 = 1 ether
        assertEq(pool.paymentEarned(jobId, w1), 1 ether);
        assertEq(pool.paymentEarned(jobId, w4), 1 ether);
    }

    // ── Test #2: StageOwnershipUnique — same worker can't hold two ─

    function test_stage_ownership_unique() public {
        uint256 jobId = _createJob();
        vm.prank(w1);
        pool.assignStage{value: STAGE_STAKE}(jobId, 0);

        vm.prank(w1);
        vm.expectRevert("Pipeline: worker holds another stage");
        pool.assignStage{value: STAGE_STAKE}(jobId, 1);
    }

    // ── Test #3: Non-attested worker rejected at assign ────────────

    function test_non_attested_worker_cannot_assign() public {
        uint256 jobId = _createJob();

        address unattested = address(0xDEAD);
        vm.deal(unattested, 100 ether);
        vm.prank(unattested);
        vm.expectRevert("Pipeline: not attested");
        pool.assignStage{value: STAGE_STAKE}(jobId, 0);
    }

    // ── Test #4: Progress strictly monotonic ──────────────────────

    function test_progress_strictly_monotonic() public {
        uint256 jobId = _createJob();
        _assignFour(jobId);
        pool.activateJob(jobId);

        vm.prank(requester);
        uint256 reqId = pool.submitRequest{value: PAYMENT}(jobId);

        // Only stage 0 owner can advance from progress 0.
        vm.prank(w2);
        vm.expectRevert("Pipeline: caller not stage owner");
        pool.advanceRequest(reqId);

        vm.prank(w1);
        pool.advanceRequest(reqId); // now progress 1

        // w1 can't serve stage 1
        vm.prank(w1);
        vm.expectRevert("Pipeline: caller not stage owner");
        pool.advanceRequest(reqId);
    }

    // ── Test #5: Fault + reassign ─────────────────────────────────

    function test_fault_and_reassign() public {
        uint256 jobId = _createJob();
        _assignFour(jobId);
        pool.activateJob(jobId);

        // Fault stage 2 (w3).
        vm.prank(w1); // any stage owner can trigger
        pool.faultStage(jobId, 2);
        assertEq(pool.stageOwner(jobId, 2), address(0));

        // Reassign to w5 (the spare, attested).
        vm.prank(w5);
        pool.reassignStage{value: STAGE_STAKE}(jobId, 2);
        assertEq(pool.stageOwner(jobId, 2), w5);
    }

    // ── Test #6: Payment divisibility constraint ──────────────────

    function test_payment_must_divide_stagecount() public {
        // 5 wei ÷ 4 stages does not divide evenly.
        // (Note: 5 ether = 5e18 IS divisible by 4 since 1e18 is.)
        vm.prank(creator);
        vm.expectRevert("Pipeline: payment not divisible");
        pool.createPipelineJob(4, 5, STAGE_STAKE, MODEL_HASH);
    }

    // ── Test #7: Fail request refunds remaining escrow ────────────

    function test_fail_request_refunds_unserved() public {
        uint256 jobId = _createJob();
        _assignFour(jobId);
        pool.activateJob(jobId);

        vm.prank(requester);
        uint256 reqId = pool.submitRequest{value: PAYMENT}(jobId);

        // Serve 2 of 4 stages, then fail.
        vm.prank(w1);
        pool.advanceRequest(reqId);
        vm.prank(w2);
        pool.advanceRequest(reqId);

        uint256 reqBefore = requester.balance;
        vm.prank(requester);
        pool.failRequest(reqId);
        // Refund: 2 of 4 unspent stages × 1 ether = 2 ether.
        assertEq(requester.balance - reqBefore, 2 ether);

        ComputePoolPipeline.Request memory r = pool.getRequest(reqId);
        assertEq(uint8(r.state), uint8(ComputePoolPipeline.RequestState.Failed));
    }

    // ── Test #8: Drain then terminate returns stakes + earnings ───

    function test_drain_terminate_returns_stake_and_earnings() public {
        uint256 jobId = _createJob();
        _assignFour(jobId);
        pool.activateJob(jobId);

        vm.prank(requester);
        uint256 reqId = pool.submitRequest{value: PAYMENT}(jobId);
        vm.prank(w1); pool.advanceRequest(reqId);
        vm.prank(w2); pool.advanceRequest(reqId);
        vm.prank(w3); pool.advanceRequest(reqId);
        vm.prank(w4); pool.advanceRequest(reqId);

        vm.prank(creator);
        pool.drainJob(jobId);

        uint256 w1Before = w1.balance;
        pool.terminateJob(jobId);
        // w1 receives: stake (2e) + earned (1e) = 3e
        assertEq(w1.balance - w1Before, 3 ether);
    }

    // ── Test #9: Expired attestation blocks advance ───────────────

    function test_expired_attestation_blocks_advance() public {
        uint256 jobId = _createJob();
        _assignFour(jobId);
        pool.activateJob(jobId);

        vm.prank(requester);
        uint256 reqId = pool.submitRequest{value: PAYMENT}(jobId);

        // Roll past attestation expiry (28,800 blocks).
        vm.roll(block.number + 30_000);

        vm.prank(w1);
        vm.expectRevert("Pipeline: stage not attested");
        pool.advanceRequest(reqId);
    }

    // ── Test #10: Stage count bounds ──────────────────────────────

    function test_stage_count_bounds() public {
        vm.prank(creator);
        vm.expectRevert("Pipeline: bad stageCount");
        pool.createPipelineJob(1, PAYMENT, STAGE_STAKE, MODEL_HASH);

        vm.prank(creator);
        vm.expectRevert("Pipeline: bad stageCount");
        pool.createPipelineJob(33, PAYMENT, STAGE_STAKE, MODEL_HASH);
    }
}
