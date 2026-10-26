// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";
import {X402Facilitator} from "../../src/X402Facilitator.sol";
import {ModelMarketplace} from "../../src/ModelMarketplace.sol";

/// After DeployAll the deploy account holds nothing: no fee recipient, no
/// bound caller, no role. The compute stack it leaves behind is wired, so a
/// job can be posted and settled straight away, with the protocol fee paid to
/// the treasury the ceremony named.
contract DeployAllPrivilegedSlotsTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender = the deployer

    address governance = makeAddr("governance");
    address guardian = makeAddr("guardian");

    DeployAll.Deployed d;

    // Commitment-tier job (value <= ComputeVerifier.VALUE_THRESHOLD).
    uint256 constant PRICE = 8 ether;
    bytes32 constant MODEL = keccak256("deployall-e2e-model");
    bytes constant OUTPUT = hex"01020304";
    bytes32 constant NONCE = keccak256("deployall-e2e-nonce");

    function setUp() public {
        d = new DeployAll().deployWith(SENDER, governance, guardian);
    }

    function test_feeRecipients_areNotTheDeployer() public view {
        assertTrue(X402Facilitator(d.facilitator).treasury() != SENDER, "X402Facilitator.treasury is the deployer");
        assertTrue(
            ModelMarketplace(payable(d.modelMarketplace)).treasuryAddress() != SENDER,
            "ModelMarketplace.treasuryAddress is the deployer"
        );
        assertTrue(
            ComputeMarketplace(payable(d.computeMarketplace)).treasury() != SENDER,
            "ComputeMarketplace.treasury is the deployer"
        );
    }

    function test_computeVerifier_isBoundToTheDeployedMarketplace() public view {
        assertEq(
            ComputeVerifier(d.verifier).marketplace(), d.computeMarketplace, "verifier's caller is the marketplace"
        );
    }

    /// Post -> bid -> assign -> execute -> commit -> verify -> complete on the
    /// stack exactly as DeployAll left it (no governance step in between).
    function test_computeMarketplace_jobRunsEndToEnd() public {
        ComputeMarketplace cm = ComputeMarketplace(payable(d.computeMarketplace));
        address requester = makeAddr("requester");
        address provider = makeAddr("provider");
        vm.deal(requester, 100 ether);
        vm.deal(provider, 2_000 ether);

        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(provider);
        cm.registerProvider{value: 1_000 ether}(models);

        vm.prank(requester);
        (bool posted, bytes memory ret) = address(cm).call{value: PRICE}(
            abi.encodeCall(
                cm.postJob, (MODEL, abi.encodePacked(bytes32(uint256(1))), PRICE, ComputeVerifier.VerificationTier.Commitment, 10, 100)
            )
        );
        assertTrue(posted, "a job can be posted on the deployed marketplace");
        uint256 jobId = abi.decode(ret, (uint256));

        vm.prank(provider);
        cm.bidOnJob(jobId, 6 ether, 100);
        cm.assignBestBid(jobId);
        vm.prank(provider);
        cm.startExecution(jobId);
        bytes32 commitment = keccak256(abi.encodePacked(OUTPUT, NONCE));
        vm.prank(provider);
        cm.submitCommitment(jobId, commitment);
        uint256 h = block.number + 1; // via-IR: track the height locally
        vm.roll(h);
        vm.prank(provider);
        cm.submitResult(jobId, OUTPUT, abi.encodePacked(commitment, NONCE, OUTPUT));
        assertEq(
            uint256(ComputeVerifier(d.verifier).getResult(jobId)), uint256(ComputeVerifier.VerificationResult.Valid)
        );

        address feeTo = cm.treasury();
        uint256 before = feeTo.balance;
        vm.roll(h + cm.DISPUTE_WINDOW());
        cm.completeJob(jobId);
        assertEq(uint256(cm.getJob(jobId).state), uint256(ComputeMarketplace.JobState.Completed));
        assertEq(feeTo.balance - before, PRICE / 40, "protocol fee paid to the treasury");
        assertTrue(feeTo != SENDER, "fee went to the deployer");
    }
}
