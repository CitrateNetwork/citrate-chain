// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../../src/cit_agent/MultisigTimelock2of3.sol";
import "../../src/cit_agent/OrganizationSBT.sol";
import "../../src/cit_agent/CapsuleRegistry.sol";

/// CIT-AGENT-6b Foundry tests for the 2-of-3 timelock + its
/// integration as admin of the CIT-AGENT-6a contracts.
contract MultisigTimelockTest is Test {
    MultisigTimelock2of3 internal timelock;
    OrganizationSBT internal org;
    CapsuleRegistry internal capsules;

    address internal alice;
    address internal bob;
    address internal carol;
    address internal eve; // non-owner

    uint256 internal constant DELAY_SECS = 2 days;

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carol = makeAddr("carol");
        eve = makeAddr("eve");

        address[3] memory owners = [alice, bob, carol];
        timelock = new MultisigTimelock2of3(owners, DELAY_SECS);

        // Deploy cit-agent contracts owned by the test, then
        // transfer ownership to the timelock — the canonical
        // 6a → 6b admin migration.
        org = new OrganizationSBT(address(this));
        org.transferOwnership(address(timelock));
        capsules = new CapsuleRegistry(address(this));
        capsules.transferOwnership(address(timelock));
    }

    // ── Timelock-only tests ────────────────────────────────────────

    function testTimelock_proposeIsFirstApproval() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        (, , MultisigTimelock2of3.OpState state, , uint8 approvalCount, address proposer) =
            timelock.getOperation(opId);
        assertEq(uint256(state), uint256(MultisigTimelock2of3.OpState.Proposed));
        assertEq(approvalCount, 1);
        assertEq(proposer, alice);
        assertTrue(timelock.hasApproved(opId, alice));
    }

    function testTimelock_secondApprovalSetsExecutableAt() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        vm.prank(bob);
        timelock.approve(opId);
        (, , MultisigTimelock2of3.OpState state, uint256 execAt, uint8 count, ) =
            timelock.getOperation(opId);
        assertEq(uint256(state), uint256(MultisigTimelock2of3.OpState.Approved));
        assertEq(count, 2);
        assertEq(execAt, block.timestamp + DELAY_SECS);
    }

    function testTimelock_sameOwnerCannotApproveTwice() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        vm.prank(alice);
        vm.expectRevert(MultisigTimelock2of3.AlreadyApprovedBySigner.selector);
        timelock.approve(opId);
    }

    function testTimelock_nonOwnerCannotPropose() public {
        vm.prank(eve);
        vm.expectRevert(MultisigTimelock2of3.NotOwner.selector);
        timelock.propose(address(org), hex"");
    }

    function testTimelock_nonOwnerCannotApprove() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        vm.prank(eve);
        vm.expectRevert(MultisigTimelock2of3.NotOwner.selector);
        timelock.approve(opId);
    }

    function testTimelock_executeBeforeDelayReverts() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        vm.prank(bob);
        timelock.approve(opId);
        vm.prank(alice);
        vm.expectRevert(MultisigTimelock2of3.TimelockNotElapsed.selector);
        timelock.execute(opId);
    }

    function testTimelock_executeWithOnlyOneApprovalReverts() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        vm.warp(block.timestamp + DELAY_SECS + 1);
        vm.prank(alice);
        vm.expectRevert(MultisigTimelock2of3.InvalidState.selector);
        timelock.execute(opId);
    }

    function testTimelock_cancelAnyOwner() public {
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), hex"");
        vm.prank(carol);
        timelock.cancel(opId);
        (, , MultisigTimelock2of3.OpState state, , , ) = timelock.getOperation(opId);
        assertEq(uint256(state), uint256(MultisigTimelock2of3.OpState.Cancelled));
    }

    // ── Integration tests ──────────────────────────────────────────

    function testIntegration_timelockMintsOrgViaOrganizationSBT() public {
        bytes32 did = keccak256("did:citrate:org:boeing");
        bytes32[] memory overlays = new bytes32[](0);
        bytes memory payload = abi.encodeWithSelector(
            OrganizationSBT.mintOrg.selector,
            eve, // recipient
            did,
            bob,
            overlays
        );
        vm.prank(alice);
        bytes32 opId = timelock.propose(address(org), payload);
        vm.prank(bob);
        timelock.approve(opId);
        vm.warp(block.timestamp + DELAY_SECS + 1);
        vm.prank(alice);
        timelock.execute(opId);
        assertEq(org.ownerOf(0), eve);
        OrganizationSBT.Org memory o = org.getOrg(0);
        assertEq(o.did, did);
    }

    function testIntegration_timelockRevokeCapsule() public {
        // First mint a capsule via the timelock (Bundled tier requires
        // admin = timelock now).
        uint256 capsule_id = uint256(keccak256("c-1"));
        bytes memory mintPayload = abi.encodeWithSelector(
            CapsuleRegistry.registerCapsule.selector,
            capsule_id,
            keccak256("m"),
            keccak256("p"),
            CapsuleRegistry.SigningTier.Bundled
        );
        vm.prank(alice);
        bytes32 mintOp = timelock.propose(address(capsules), mintPayload);
        vm.prank(bob);
        timelock.approve(mintOp);
        vm.warp(block.timestamp + DELAY_SECS + 1);
        // The capsule is minted to the TIMELOCK itself (msg.sender of
        // the eventual call), not to alice — that's the intentional
        // shape: the timelock holds the supply, individual operators
        // get capabilities via other mechanisms.
        vm.prank(alice);
        timelock.execute(mintOp);

        // Now revoke — same 2-of-3 flow. Use a far-future warp so
        // the second op's executableAt is unambiguously in the past.
        bytes memory revokePayload = abi.encodeWithSelector(
            CapsuleRegistry.revokeCapsule.selector,
            capsule_id
        );
        vm.prank(alice);
        bytes32 revokeOp = timelock.propose(address(capsules), revokePayload);
        vm.prank(carol);
        timelock.approve(revokeOp);
        // Approve set executableAt = block.timestamp + DELAY_SECS.
        // Warp to that exact instant + 1.
        (, , , uint256 execAt, , ) = timelock.getOperation(revokeOp);
        vm.warp(execAt + 1);
        vm.prank(alice);
        timelock.execute(revokeOp);
        assertTrue(capsules.isRevoked(capsule_id));
    }

    function testIntegration_directAdminCallRevertsAfterTransfer() public {
        // After transferOwnership, calling mintOrg directly from a
        // non-timelock address MUST revert — that's the whole point
        // of the migration.
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert();
        org.mintOrg(eve, keccak256("did"), bob, empty);
    }
}
