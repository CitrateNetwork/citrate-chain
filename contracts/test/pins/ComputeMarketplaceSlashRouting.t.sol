// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";

/// Stake slashed from a provider on a job timeout leaves the marketplace for
/// the treasury, so the contract's balance is exactly escrow plus live stake.
contract ComputeMarketplaceSlashRoutingTest is Test {
    ComputeMarketplace internal marketplace;
    ComputeVerifier internal verifier;
    address internal constant TREASURY = address(0x77EA5);
    address internal constant REQUESTER = address(0xAAAA);
    address internal constant PROVIDER = address(0xBBB1);
    bytes32 internal constant MODEL = keccak256("test-model-v1");

    function setUp() public {
        verifier = new ComputeVerifier(address(1), address(this));
        marketplace = new ComputeMarketplace(address(verifier), TREASURY, address(this));
        verifier.setMarketplace(address(marketplace));
        vm.deal(REQUESTER, 100 ether);
        vm.deal(PROVIDER, 2000 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(PROVIDER);
        marketplace.registerProvider{value: 1000 ether}(models);
    }

    function _timedOutJob() internal returns (uint256 jobId) {
        vm.prank(REQUESTER);
        jobId = marketplace.postJob{value: 8 ether}(
            MODEL, hex"DEADBEEF", 8 ether, ComputeVerifier.VerificationTier.Commitment, 10, 100
        );
        vm.prank(PROVIDER);
        marketplace.bidOnJob(jobId, 8 ether, 100);
        marketplace.assignBestBid(jobId);
        vm.roll(marketplace.getJob(jobId).executionDeadline + 1);
        marketplace.timeoutJob(jobId);
    }

    function test_timeoutSlashIsPaidToTheTreasury() public {
        uint256 stakeBefore = marketplace.getProvider(PROVIDER).stake;
        uint256 treasuryBefore = TREASURY.balance;
        _timedOutJob();
        uint256 slashed = stakeBefore - marketplace.getProvider(PROVIDER).stake;
        assertGt(slashed, 0, "timeout slashes stake");
        assertEq(TREASURY.balance - treasuryBefore, slashed, "slashed stake goes to the treasury");
    }

    function test_marketplaceHoldsOnlyLiveStakeAfterSlash() public {
        _timedOutJob();
        assertEq(
            address(marketplace).balance,
            marketplace.getProvider(PROVIDER).stake,
            "no slashed principal left commingled on the marketplace"
        );
    }
}
