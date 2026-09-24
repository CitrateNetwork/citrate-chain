// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LearningPool} from "../src/LearningPool.sol";

contract LearningPoolTest is Test {
    LearningPool public lp;

    address public alice;
    address public bob;
    address public charlie;
    address public dave;

    function setUp() public {
        lp = new LearningPool();

        alice = address(0xA11CE);
        bob = address(0xB0B);
        charlie = address(0xC4A21E);
        dave = address(0xDA7E);

        vm.deal(alice, 1000 ether);
        vm.deal(bob, 1000 ether);
        vm.deal(charlie, 1000 ether);
        vm.deal(dave, 1000 ether);
    }

    // ============================================================
    // Pool Creation Tests
    // ============================================================

    function test_create_pool_open() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 1 ether}(
            "Global Pool",
            "Open to everyone",
            LearningPool.AccessType.Open,
            1 ether
        );

        // Pool #0 is reserved for the constructor-created Genesis pool —
        // the first user pool is #1.
        assertEq(poolId, 1, "First user pool should have ID 1 (ID 0 = Genesis)");
        assertEq(lp.nextPoolId(), 2, "nextPoolId should increment");

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(pool.id, 1);
        assertEq(pool.name, "Global Pool");
        assertEq(pool.description, "Open to everyone");
        assertEq(pool.creator, alice);
        assertEq(uint256(pool.state), uint256(LearningPool.PoolState.Active));
        assertEq(uint256(pool.access), uint256(LearningPool.AccessType.Open));
        assertEq(pool.minStake, 1 ether);
        assertEq(pool.memberCount, 1, "Creator should be first member");

        // INV-2: Creator is a member
        assertTrue(lp.isMember(poolId, alice), "Creator must be member");

        // INV-3: Creator has positive stake
        assertEq(lp.stakes(poolId, alice), 1 ether, "Creator must have staked");
    }

    function test_create_pool_invite_only() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 2 ether}(
            "School District",
            "Restricted pool",
            LearningPool.AccessType.InviteOnly,
            2 ether
        );

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(uint256(pool.access), uint256(LearningPool.AccessType.InviteOnly));
        assertEq(pool.minStake, 2 ether);
        assertTrue(lp.isMember(poolId, alice));
    }

    function test_create_pool_empty_name_reverts() public {
        vm.prank(alice);
        vm.expectRevert("Empty name");
        lp.createPool{value: 1 ether}("", "desc", LearningPool.AccessType.Open, 1 ether);
    }

    function test_create_pool_below_min_stake_reverts() public {
        vm.prank(alice);
        vm.expectRevert("Creator must meet min stake");
        lp.createPool{value: 0.5 ether}("Pool", "desc", LearningPool.AccessType.Open, 1 ether);
    }

    function test_create_pool_zero_min_stake() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 0}(
            "Free Pool",
            "No stake needed",
            LearningPool.AccessType.Open,
            0
        );

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(pool.minStake, 0);
        assertEq(pool.memberCount, 1);
        assertTrue(lp.isMember(poolId, alice));
        // INV-3: Even with zero minStake, creator staked msg.value (0)
        assertEq(lp.stakes(poolId, alice), 0);
    }

    // ============================================================
    // Join Open Pool Tests
    // ============================================================

    function test_join_open_pool() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        assertTrue(lp.isMember(poolId, bob), "Bob should be member");
        assertEq(lp.stakes(poolId, bob), 1 ether, "Bob stake recorded");

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 2, "Member count should be 2");
    }

    function test_join_below_min_stake_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert("Below min stake");
        lp.joinPool{value: 0.5 ether}(poolId);
    }

    function test_join_closed_pool_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        lp.closePool(poolId);

        vm.prank(bob);
        vm.expectRevert("Pool not active");
        lp.joinPool{value: 1 ether}(poolId);
    }

    function test_join_invite_pool_without_code_reverts() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 1 ether}(
            "Invite Pool",
            "Restricted",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        // Attempt to join via joinPool (open path) — should fail
        vm.prank(bob);
        vm.expectRevert("Not open pool");
        lp.joinPool{value: 1 ether}(poolId);
    }

    function test_double_join_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        vm.prank(bob);
        vm.expectRevert("Already member");
        lp.joinPool{value: 1 ether}(poolId);
    }

    function test_join_nonexistent_pool_reverts() public {
        vm.prank(bob);
        vm.expectRevert("Pool does not exist");
        lp.joinPool{value: 1 ether}(999);
    }

    // ============================================================
    // Join With Invite Tests
    // ============================================================

    function test_join_with_valid_invite() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 1 ether}(
            "Invite Pool",
            "Code required",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 codeHash = keccak256(abi.encodePacked("secret-invite-2026"));
        vm.prank(alice);
        lp.addInviteCode(poolId, codeHash);

        vm.prank(bob);
        lp.joinWithInvite{value: 1 ether}(poolId, codeHash);

        assertTrue(lp.isMember(poolId, bob), "Bob should be member after invite");
        assertEq(lp.stakes(poolId, bob), 1 ether);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 2);
    }

    function test_join_with_invalid_invite_reverts() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 1 ether}(
            "Invite Pool",
            "Code required",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 badCodeHash = keccak256(abi.encodePacked("wrong-code"));

        vm.prank(bob);
        vm.expectRevert("Invalid invite code");
        lp.joinWithInvite{value: 1 ether}(poolId, badCodeHash);
    }

    function test_join_invite_on_open_pool_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        bytes32 codeHash = keccak256(abi.encodePacked("code"));

        vm.prank(bob);
        vm.expectRevert("Not invite pool");
        lp.joinWithInvite{value: 1 ether}(poolId, codeHash);
    }

    // ============================================================
    // Leave Pool Tests
    // ============================================================

    function test_leave_pool_returns_stake() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 5 ether}(poolId);

        uint256 balBefore = bob.balance;
        vm.prank(bob);
        lp.leavePool(poolId);

        assertEq(bob.balance, balBefore + 5 ether, "Stake should be returned");
        assertFalse(lp.isMember(poolId, bob), "Should no longer be member");

        // INV-6: NonMemberNoStake
        assertEq(lp.stakes(poolId, bob), 0, "Stake should be zeroed after leaving");

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 1, "Member count decremented");
    }

    function test_creator_cannot_leave() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        vm.expectRevert("Creator cannot leave");
        lp.leavePool(poolId);
    }

    function test_non_member_cannot_leave() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert("Not member");
        lp.leavePool(poolId);
    }

    function test_cannot_leave_during_active_cycle() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        vm.prank(alice);
        lp.startCycle(poolId);

        vm.prank(bob);
        vm.expectRevert("Cannot leave during active cycle");
        lp.leavePool(poolId);
    }

    // ============================================================
    // Close / Reopen Pool Tests
    // ============================================================

    function test_close_pool() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        lp.closePool(poolId);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(uint256(pool.state), uint256(LearningPool.PoolState.Closed));
    }

    function test_non_creator_cannot_close() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert("Not creator");
        lp.closePool(poolId);
    }

    function test_close_already_closed_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        lp.closePool(poolId);

        vm.prank(alice);
        vm.expectRevert("Not active");
        lp.closePool(poolId);
    }

    function test_reopen_pool() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        lp.closePool(poolId);

        vm.prank(alice);
        lp.reopenPool(poolId);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(uint256(pool.state), uint256(LearningPool.PoolState.Active));
    }

    function test_reopen_non_closed_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        vm.expectRevert("Not closed");
        lp.reopenPool(poolId);
    }

    // ============================================================
    // Cycle Management Tests
    // ============================================================

    function test_start_cycle() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        vm.prank(alice);
        lp.startCycle(poolId);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(uint256(pool.state), uint256(LearningPool.PoolState.ActiveCycle));
    }

    function test_start_cycle_needs_2_members() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        // Only 1 member (creator)
        vm.prank(alice);
        vm.expectRevert("Need at least 2 members");
        lp.startCycle(poolId);
    }

    function test_end_cycle() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        vm.prank(alice);
        lp.startCycle(poolId);

        vm.prank(alice);
        lp.endCycle(poolId);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(uint256(pool.state), uint256(LearningPool.PoolState.Active));
    }

    function test_end_cycle_when_not_active_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(alice);
        vm.expectRevert("No active cycle");
        lp.endCycle(poolId);
    }

    // ============================================================
    // Model Whitelist Tests
    // ============================================================

    function test_whitelist_model() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);
        bytes32 modelHash = keccak256("STEM-tutor-v2");

        vm.prank(alice);
        lp.whitelistModel(poolId, modelHash);

        assertTrue(lp.isModelWhitelisted(poolId, modelHash), "Model should be whitelisted");
    }

    function test_remove_model() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);
        bytes32 modelHash = keccak256("STEM-tutor-v2");

        vm.prank(alice);
        lp.whitelistModel(poolId, modelHash);

        vm.prank(alice);
        lp.removeModel(poolId, modelHash);

        assertFalse(lp.isModelWhitelisted(poolId, modelHash), "Model should be removed");
    }

    function test_non_creator_cannot_whitelist() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);
        bytes32 modelHash = keccak256("STEM-tutor-v2");

        vm.prank(bob);
        vm.expectRevert("Not creator");
        lp.whitelistModel(poolId, modelHash);
    }

    function test_non_creator_cannot_remove_model() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);
        bytes32 modelHash = keccak256("STEM-tutor-v2");

        vm.prank(alice);
        lp.whitelistModel(poolId, modelHash);

        vm.prank(bob);
        vm.expectRevert("Not creator");
        lp.removeModel(poolId, modelHash);
    }

    // ============================================================
    // Member Count Tracking Tests
    // ============================================================

    function test_pool_member_count_tracks() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 1, "Start with 1 (creator)");

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);
        pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 2, "After Bob joins");

        vm.prank(charlie);
        lp.joinPool{value: 1 ether}(poolId);
        pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 3, "After Charlie joins");

        vm.prank(bob);
        lp.leavePool(poolId);
        pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 2, "After Bob leaves");

        vm.prank(charlie);
        lp.leavePool(poolId);
        pool = lp.getPool(poolId);
        assertEq(pool.memberCount, 1, "After Charlie leaves, only creator remains");
    }

    // ============================================================
    // Invite Code Management Tests
    // ============================================================

    function test_add_invite_code() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 1 ether}(
            "Invite Pool",
            "desc",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 codeHash = keccak256(abi.encodePacked("my-secret"));
        vm.prank(alice);
        lp.addInviteCode(poolId, codeHash);

        assertTrue(lp.validInviteCodes(poolId, codeHash), "Code should be valid");
    }

    function test_non_creator_cannot_add_invite_code() public {
        vm.prank(alice);
        uint256 poolId = lp.createPool{value: 1 ether}(
            "Invite Pool",
            "desc",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 codeHash = keccak256(abi.encodePacked("code"));
        vm.prank(bob);
        vm.expectRevert("Not creator");
        lp.addInviteCode(poolId, codeHash);
    }

    // ============================================================
    // TLA+ Invariant Verification Tests
    // ============================================================

    /// @dev INV-2: CreatorIsMember — creator is always a member of their pool
    function test_inv2_creator_is_always_member() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        // After creation
        assertTrue(lp.isMember(poolId, alice));

        // After others join and leave, creator still a member
        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);
        vm.prank(bob);
        lp.leavePool(poolId);

        assertTrue(lp.isMember(poolId, alice), "INV-2: Creator must remain member");
    }

    /// @dev INV-6: NonMemberNoStake — non-members have zero stake
    function test_inv6_non_member_no_stake() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        // Bob is not a member — should have zero stake
        assertEq(lp.stakes(poolId, bob), 0, "INV-6: Non-member should have zero stake");

        // Bob joins, then leaves — stake should be zero
        vm.prank(bob);
        lp.joinPool{value: 3 ether}(poolId);
        assertEq(lp.stakes(poolId, bob), 3 ether, "Member should have stake");

        vm.prank(bob);
        lp.leavePool(poolId);
        assertEq(lp.stakes(poolId, bob), 0, "INV-6: After leaving, stake must be zero");
    }

    /// @dev INV-7: CreatedPoolHasCreator — every created pool has a real creator
    function test_inv7_created_pool_has_creator() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        LearningPool.Pool memory pool = lp.getPool(poolId);
        assertTrue(pool.creator != address(0), "INV-7: Creator must not be zero address");
        assertEq(pool.creator, alice);
    }

    /// @dev INV-8: UncreatedPoolEmpty — uncreated pools have no members
    function test_inv8_uncreated_pool_empty() public {
        // Pool 42 was never created
        assertFalse(lp.isMember(42, alice), "INV-8: No members in uncreated pool");
        assertEq(lp.stakes(42, alice), 0, "INV-8: No stakes in uncreated pool");
    }

    // ============================================================
    // View Function Tests
    // ============================================================

    function test_get_member_stake() public {
        uint256 poolId = _createOpenPool(alice, 2 ether);

        vm.prank(bob);
        lp.joinPool{value: 5 ether}(poolId);

        assertEq(lp.getMemberStake(poolId, alice), 2 ether);
        assertEq(lp.getMemberStake(poolId, bob), 5 ether);
        assertEq(lp.getMemberStake(poolId, charlie), 0, "Non-member should have zero");
    }

    // ============================================================
    // Multiple Pools Test
    // ============================================================

    function test_multiple_pools_independent() public {
        uint256 pool1 = _createOpenPool(alice, 1 ether);
        uint256 pool2 = _createOpenPool(bob, 2 ether);

        // Pool #0 is the Genesis pool reserved by the constructor.
        assertEq(pool1, 1);
        assertEq(pool2, 2);

        // Alice is member of pool1 only
        assertTrue(lp.isMember(pool1, alice));
        assertFalse(lp.isMember(pool2, alice));

        // Bob is member of pool2 only
        assertFalse(lp.isMember(pool1, bob));
        assertTrue(lp.isMember(pool2, bob));

        // Bob joins pool1 — doesn't affect pool2
        vm.prank(bob);
        lp.joinPool{value: 1 ether}(pool1);
        assertTrue(lp.isMember(pool1, bob));
        assertTrue(lp.isMember(pool2, bob));

        LearningPool.Pool memory p1 = lp.getPool(pool1);
        LearningPool.Pool memory p2 = lp.getPool(pool2);
        assertEq(p1.memberCount, 2);
        assertEq(p2.memberCount, 1);
    }

    // ============================================================
    // Edge Case: Join During Active Cycle
    // ============================================================

    function test_join_during_active_cycle_reverts() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        vm.prank(alice);
        lp.startCycle(poolId);

        // Charlie tries to join during active cycle
        vm.prank(charlie);
        vm.expectRevert("Pool not active");
        lp.joinPool{value: 1 ether}(poolId);
    }

    // ============================================================
    // Edge Case: Leave After Cycle Ends
    // ============================================================

    function test_leave_after_cycle_ends() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        // Start and end a cycle
        vm.prank(alice);
        lp.startCycle(poolId);
        vm.prank(alice);
        lp.endCycle(poolId);

        // Bob can leave after cycle ends
        uint256 balBefore = bob.balance;
        vm.prank(bob);
        lp.leavePool(poolId);
        assertEq(bob.balance, balBefore + 1 ether);
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _createOpenPool(address creator, uint256 minStake) internal returns (uint256 poolId) {
        vm.prank(creator);
        poolId = lp.createPool{value: minStake}(
            "Test Pool",
            "A test learning pool",
            LearningPool.AccessType.Open,
            minStake
        );
        // RFI-05: pools require ≥1 whitelisted model to start a cycle.
        // Whitelist a default test model so the existing tests don't
        // need to be rewritten with explicit whitelisting.
        vm.prank(creator);
        lp.whitelistModel(poolId, keccak256("default-test-model"));
    }

    // ── CHAIN-B-C042: the creator can reclaim their stake by dissolving ──
    //
    // RED (pre-fix): leavePool forbids the creator and nothing else refunds
    // them, so a creator's stake was locked forever. GREEN: once the creator is
    // the last member, dissolvePool returns it.
    function test_C042_creatorCanDissolveAndReclaim() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);

        // Someone joins then leaves; creator is once again the only member.
        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);
        vm.prank(bob);
        lp.leavePool(poolId);

        // Creator still cannot use the ordinary leave path.
        vm.prank(alice);
        vm.expectRevert("Creator cannot leave");
        lp.leavePool(poolId);

        uint256 bal = alice.balance;
        vm.prank(alice);
        lp.dissolvePool(poolId);

        assertEq(alice.balance, bal + 1 ether, "creator reclaims stake");
        assertFalse(lp.isMember(poolId, alice), "creator no longer a member");
        assertEq(lp.stakes(poolId, alice), 0, "stake cleared");
    }

    /// The creator may not dissolve while other members remain.
    function test_C042_cannotDissolveWithMembersRemaining() public {
        uint256 poolId = _createOpenPool(alice, 1 ether);
        vm.prank(bob);
        lp.joinPool{value: 1 ether}(poolId);

        vm.prank(alice);
        vm.expectRevert("Members remain");
        lp.dissolvePool(poolId);
    }
}
