// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputePool} from "../../src/ComputePool.sol";
import {ComputePoolTraining} from "../../src/ComputePoolTraining.sol";
import {ComputePoolPipeline} from "../../src/ComputePoolPipeline.sol";
import {TEEAttestationRegistry} from "../../src/TEEAttestationRegistry.sol";
import {AggregationChallenge} from "../../src/AggregationChallenge.sol";
import {ComputePricingOracle} from "../../src/ComputePricingOracle.sol";
import {StablecoinTreasury} from "../../src/StablecoinTreasury.sol";
import {BulkComputeGateway} from "../../src/BulkComputeGateway.sol";
import {InferenceRouter} from "../../src/InferenceRouter.sol";
import {FacilitySBT} from "../../src/cit_agent/FacilitySBT.sol";
import {BenchmarkRegistry} from "../../src/cit_agent/BenchmarkRegistry.sol";
import {MockERC20} from "../StablecoinTreasury.t.sol";

/// A pool member / stage owner / recipient whose receive always reverts.
contract RevertingMember {
    function join(ComputePool p, uint256 poolId) external payable {
        p.joinPool{value: msg.value}(poolId, 1);
    }

    function assign(ComputePoolPipeline p, uint256 jobId, uint32 stage) external payable {
        p.assignStage{value: msg.value}(jobId, stage);
    }

    receive() external payable {
        revert("no");
    }
}

/// Slashing hook that always reverts (e.g. "Not staked").
contract RevertingSlashing {
    function slash(address, uint8, bytes calldata) external pure {
        revert("Not staked");
    }
}

/// Fee-on-transfer 6-decimal token: delivers 99% of every transfer.
contract FeeToken {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a * 99 / 100;
        return true;
    }

    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a;
        balanceOf[f] -= a;
        balanceOf[to] += a * 99 / 100;
        return true;
    }
}

contract SlotHarness is FacilitySBT {
    function slot() external pure returns (bytes32) {
        return STORAGE_SLOT;
    }
}

contract PBA_R2_ContractsA_Misc is Test {
    // ── ComputePool (PBA-L2-022 / L2-023 / L2-042) ─────────────────────

    ComputePool pool;
    uint256 poolId;
    address m1 = address(0xA1);
    address m2 = address(0xA2);
    address buyer = address(0xB1);

    function _pool() internal {
        pool = new ComputePool(); // governance = this
        poolId = pool.createPool("p", ComputePool.PoolMode.InferencePool, 1, 100, 1 ether);
        vm.deal(m1, 100 ether);
        vm.deal(m2, 100 ether);
        vm.deal(buyer, 100 ether);
        vm.prank(m1);
        pool.joinPool{value: 10 ether}(poolId, 1);
        vm.prank(m2);
        pool.joinPool{value: 10 ether}(poolId, 1);
    }

    function _dispatchedJob() internal returns (uint256 jobId, address coord) {
        vm.prank(buyer);
        jobId = pool.requestPoolCompute{value: 1 ether}(poolId, hex"01", 1 ether);
        coord = pool.coordinatorFor(poolId, block.number / pool.EPOCH_LENGTH());
        vm.prank(coord);
        pool.recordDispatch(jobId);
    }

    /// PBA-L2-022: a dispatched coordinator cannot leave (activeJobs is
    /// live), and every exit needs requestLeave + LEAVE_COOLDOWN.
    function test_L2_022_dispatched_coordinator_cannot_escape() public {
        _pool();
        (uint256 jobId, address coord) = _dispatchedJob();
        assertEq(pool.getMember(poolId, coord).activeJobs, 1, "activeJobs written on dispatch");
        vm.prank(coord);
        pool.requestLeave(poolId);
        vm.roll(block.number + pool.LEAVE_COOLDOWN());
        vm.prank(coord);
        vm.expectRevert(bytes("Has active jobs"));
        pool.leavePool(poolId);

        // Coordinator stalls: reassignment slashes it and keeps totalStaked
        // consistent with member stakes.
        vm.roll(block.number + pool.COORDINATION_TIMEOUT() + 1);
        address other = coord == m1 ? m2 : m1;
        vm.prank(other);
        pool.reassignCoordinator(jobId);
        assertEq(pool.getMember(poolId, coord).activeJobs, 0);
        uint256 sum = pool.getMember(poolId, m1).stake + pool.getMember(poolId, m2).stake;
        assertEq(pool.getPool(poolId).totalStaked, sum, "totalStaked == sum(member.stake)");
        assertEq(pool.slashedStakeRetained(), 20 ether - sum, "slash has a sink");
    }

    function test_L2_022_leave_requires_request_and_cooldown() public {
        _pool();
        vm.prank(m1);
        vm.expectRevert(bytes("Leave not requested"));
        pool.leavePool(poolId);
        vm.prank(m1);
        pool.requestLeave(poolId);
        vm.prank(m1);
        vm.expectRevert(bytes("Leave cooldown"));
        pool.leavePool(poolId);
        // Still slashable while the exit is pending (SLA report lands).
        pool.reportSLAViolation(poolId, 50);
        vm.roll(block.number + pool.LEAVE_COOLDOWN());
        uint256 stakeLeft = pool.getMember(poolId, m1).stake;
        assertLt(stakeLeft, 10 ether, "slash applied during cooldown");
        uint256 before = m1.balance;
        vm.prank(m1);
        pool.leavePool(poolId);
        assertEq(m1.balance - before, stakeLeft);
        assertGt(pool.slashedStakeRetained(), 0, "SLA slash retained, sweepable");
        vm.expectRevert(bytes("Zero address"));
        pool.sweepSlashedStake(address(0));
    }

    /// PBA-L2-023: a member that reverts on receive no longer blocks
    /// settlement; its share is credited for `claimPayout`.
    function test_L2_023_reverting_member_does_not_block_completion() public {
        _pool();
        RevertingMember evil = new RevertingMember();
        evil.join{value: 10 ether}(pool, poolId);
        (uint256 jobId, address coord) = _dispatchedJob();
        vm.prank(coord);
        pool.completeJob(jobId);
        assertGt(pool.payoutPending(address(evil)), 0, "evil share deferred");
        // dissolve also completes despite the reverting member.
        pool.dissolvePool(poolId); // creator == this
        assertGt(pool.payoutPending(address(evil)), 10 ether);
    }

    /// PBA-L2-023 (Pipeline): one reverting stage owner no longer freezes
    /// the others at terminateJob; PBA-L2-042: no stage can be served
    /// after termination.
    function test_L2_023_pipeline_terminate_with_reverting_owner() public {
        TEEAttestationRegistry reg = new TEEAttestationRegistry(address(this));
        ComputePoolPipeline pp = new ComputePoolPipeline(address(this), address(reg));
        reg.setStrictCryptographicMode(false);
        bytes32 maa = keccak256("maa");
        bytes32 nras = keccak256("nras");
        bytes32 model = keccak256("m");
        reg.setMaaSigner(maa, true);
        reg.setNrasSigner(nras, true);
        RevertingMember evil = new RevertingMember();
        address good = address(0xCAFE1);
        address[2] memory ws = [address(evil), good];
        for (uint256 i = 0; i < 2; i++) {
            vm.prank(ws[i]);
            reg.submitAttestation(keccak256(abi.encode("vm", ws[i])), keccak256(abi.encode("gpu", ws[i])), model, maa, nras);
        }
        vm.deal(address(this), 100 ether);
        vm.deal(good, 10 ether);
        uint256 jobId = pp.createPipelineJob(2, 2 ether, 1 ether, model);
        evil.assign{value: 1 ether}(pp, jobId, 0);
        vm.prank(good);
        pp.assignStage{value: 1 ether}(jobId, 1);
        pp.activateJob(jobId);
        uint256 reqId = pp.submitRequest{value: 2 ether}(jobId);
        pp.drainJob(jobId);
        pp.terminateJob(jobId);
        assertEq(pp.payoutPending(address(evil)), 1 ether);
        assertEq(good.balance, 10 ether, "good owner paid its stake back");
        vm.prank(address(evil));
        vm.expectRevert(bytes("Pipeline: job terminated"));
        pp.advanceRequest(reqId);
    }

    // ── ComputePoolTraining (PBA-L2-042) ───────────────────────────────

    /// A re-opened challenge on the same slot can reach quorum again, and
    /// forfeited bonds are sweepable (not stranded).
    function test_L2_042_training_revote_and_sweep() public {
        ComputePoolTraining t = new ComputePoolTraining(address(this));
        address requester = address(0xAA);
        address w1 = address(0x11);
        address w2 = address(0x22);
        address ch = address(0xC0);
        vm.deal(requester, 100 ether);
        vm.deal(w1, 10 ether);
        vm.deal(w2, 10 ether);
        vm.deal(ch, 10 ether);
        ComputePoolTraining.TrainingJobSpec memory spec = ComputePoolTraining.TrainingJobSpec({
            modelStartHash: bytes32("m"), datasetHash: bytes32("d"), epochCount: 2, stepsPerEpoch: 10,
            minWorkers: 2, maxWorkers: 2, challengeWindowBlocks: 50, perEpochBudget: 1 ether, perWorkerStake: 1 ether
        });
        vm.prank(requester);
        uint256 job = t.requestTrainingJob{value: 2 ether}(spec);
        vm.prank(w1);
        t.joinTrainingJob{value: 1 ether}(job);
        vm.prank(w2);
        t.joinTrainingJob{value: 1 ether}(job);
        vm.prank(requester);
        t.closeRecruitment(job, w1);
        bytes32 leaf = bytes32("leaf");
        bytes32 root = keccak256(abi.encodePacked(bytes1(0x00), leaf));
        vm.prank(w1);
        t.commitEpoch(job, 0, root);
        t.setCommittee(address(0xE1), true);
        t.setCommittee(address(0xE2), true);
        for (uint256 round = 0; round < 2; round++) {
            vm.prank(ch);
            t.challengeStep{value: 1 ether}(job, 0, 0, w2, leaf, new bytes32[](0));
            vm.prank(address(0xE1));
            t.voteChallenge(job, 0, 0, w2, false);
            vm.prank(address(0xE2));
            t.voteChallenge(job, 0, 0, w2, false); // round 2 must reach quorum too
        }
        assertEq(t.retainedSlashAndBonds(), 2 ether, "both forfeited bonds retained");
        uint256 before = address(0x7EA).balance;
        t.sweepRetained(address(0x7EA));
        assertEq(address(0x7EA).balance - before, 2 ether);
    }

    // ── InferenceRouter (PBA-L2-042) ───────────────────────────────────

    function test_L2_042_cache_fee_is_accounted() public {
        InferenceRouter r = new InferenceRouter(address(0x1234));
        address p = address(0xF00);
        bytes32 model = bytes32(uint256(7));
        vm.deal(p, 200 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;
        vm.prank(p);
        r.registerProvider{value: 100 ether}("https://p", 1 ether, models);
        r.setCaching(model, true);
        address u = address(0x5E);
        vm.deal(u, 10 ether);
        vm.prank(u);
        uint256 id = r.requestInference{value: 1 ether}(model, hex"01", 1 ether);
        vm.prank(p);
        r.completeInference(id, hex"aa");
        uint256 feesBefore = r.accruedPlatformFees();
        vm.prank(u);
        r.requestInference{value: 1 ether}(model, hex"01", 1 ether); // cache hit
        assertEq(r.accruedPlatformFees() - feesBefore, 0.01 ether, "cache fee credited");
    }

    // ── AggregationChallenge (PBA-L2-041) ──────────────────────────────

    function test_L2_041_reverting_slash_hook_does_not_brick_resolution() public {
        AggregationChallenge ac = new AggregationChallenge(1 ether, 50);
        ac.setSlashingContract(address(new RevertingSlashing()));
        address coordinator = address(0xC001);
        address challenger = address(0xCA11);
        vm.deal(challenger, 10 ether);
        bytes32 roundId = keccak256("r");
        vm.prank(coordinator);
        ac.commitAggregate(roundId, keccak256(abi.encodePacked(uint256(1), uint256(2))), 2);
        vm.prank(challenger);
        ac.challenge{value: 1 ether}(roundId, 0);
        vm.roll(block.number + 51);
        vm.expectEmit(true, true, false, false);
        emit AggregationChallenge.SlashHookFailed(roundId, coordinator);
        ac.timeoutChallenge(roundId); // pre-fix: reverted "Not staked" forever
    }

    // ── Oracle (PBA-L2-044) ────────────────────────────────────────────

    function test_L2_044_divergent_member_cannot_stall_update() public {
        ComputePricingOracle o = new ComputePricingOracle(100, 100);
        address a = address(0x01);
        address b = address(0x02);
        address c = address(0x03);
        o.addOracleMember(a);
        o.addOracleMember(b);
        o.addOracleMember(c);
        vm.prank(a);
        o.proposeComputePrice(102); // first value no longer locks the round
        vm.prank(b);
        o.proposeComputePrice(105); // pre-fix: "price mismatch"
        vm.prank(c);
        o.proposeComputePrice(109); // divergent member
        assertEq(o.computePriceUsdCents(), 105, "median of the quorum");
    }

    // ── Stablecoins (PBA-L2-043) ───────────────────────────────────────

    function test_L2_043_non_six_decimal_token_rejected() public {
        StablecoinTreasury tr = new StablecoinTreasury(address(this));
        MockERC20 dai = new MockERC20("DAI", "DAI", 18);
        vm.expectRevert(bytes("StablecoinTreasury: token must have 6 decimals"));
        tr.addStablecoin(address(dai));
    }

    function test_L2_043_fee_on_transfer_not_over_credited() public {
        StablecoinTreasury tr = new StablecoinTreasury(address(this));
        FeeToken fee = new FeeToken();
        tr.addStablecoin(address(fee));
        fee.mint(address(this), 100_000_000);
        fee.approve(address(tr), 100_000_000);
        vm.expectRevert(bytes("StablecoinTreasury: received amount mismatch"));
        tr.deposit(address(fee), 100_000_000);
    }

    // ── Hygiene (PBA-L2-061) ───────────────────────────────────────────

    function test_L2_061_erc7201_slot_matches_formula() public {
        bytes32 expected = keccak256(abi.encode(uint256(keccak256("citrate.storage.OrgScopedSBT")) - 1))
            & ~bytes32(uint256(0xff));
        assertEq(new SlotHarness().slot(), expected);
    }

    function test_L2_061_benchmark_records_namespaced_by_committer() public {
        BenchmarkRegistry br = new BenchmarkRegistry();
        vm.prank(address(0xD0C));
        br.record(1, bytes32("cap"), bytes32("lat"), 10);
        vm.prank(address(0xBAD));
        br.record(1, bytes32("cap"), bytes32("lat"), 99999); // forgery attempt
        assertEq(br.metricCount(address(0xD0C), 1, bytes32("cap"), bytes32("lat")), 1);
        BenchmarkRegistry.BenchmarkRecord[] memory page =
            br.getMetric(address(0xD0C), 1, bytes32("cap"), bytes32("lat"), 0, 10);
        assertEq(page.length, 1);
        assertEq(page[0].value, 10);
    }

    receive() external payable {}
}
