// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ClassroomRegistry} from "../src/ClassroomRegistry.sol";
import {LearningPool} from "../src/LearningPool.sol";

/// @title RmE3InviteTtl — RM-E3 WP-E3.1 + WP-E3.2 (audit GUI-L-03)
/// @notice Acceptance tests for invite-code TTL on ClassroomRegistry
///         and LearningPool. Pre-fix invite codes lived forever; a
///         leaked code from January was equally usable in October.
contract RmE3InviteTtlTest is Test {
    ClassroomRegistry internal registry;
    LearningPool internal pool;

    address internal teacher = address(0xE4C4E5);
    address internal student = address(0x57D);
    address internal creator = address(0xC4E47);
    address internal joiner = address(0x101);

    function setUp() public {
        registry = new ClassroomRegistry();
        pool = new LearningPool();
        vm.deal(joiner, 100 ether);
        vm.deal(creator, 100 ether);
    }

    // ── ClassroomRegistry / WP-E3.1 ─────────────────────────────────

    function test_guil03_classroom_invite_default_ttl_set() public {
        bytes32 code = keccak256("class-code");
        vm.prank(teacher);
        registry.createClassroom("Algebra I", 30, code);
        // Default TTL = 7 days. expiresAt = now + 7 days.
        uint64 expected = uint64(block.timestamp) + registry.DEFAULT_INVITE_TTL();
        assertEq(registry.inviteExpiresAt(code), expected, "default TTL set on create");
    }

    function test_guil03_classroom_enroll_works_within_ttl() public {
        bytes32 code = keccak256("class-code");
        vm.prank(teacher);
        registry.createClassroom("Algebra I", 30, code);

        // Within TTL → succeeds.
        vm.prank(student);
        registry.enrollWithCode(bytes("class-code"));
        assertTrue(registry.isEnrolled(teacher, student));
    }

    function test_guil03_classroom_enroll_rejected_after_expiry() public {
        bytes32 code = keccak256("class-code");
        vm.prank(teacher);
        registry.createClassroom("Algebra I", 30, code);

        // Warp past the TTL.
        vm.warp(block.timestamp + uint256(registry.DEFAULT_INVITE_TTL()) + 1);

        vm.prank(student);
        vm.expectRevert("Invite code expired");
        registry.enrollWithCode(bytes("class-code"));
    }

    function test_guil03_classroom_rotate_with_explicit_ttl() public {
        bytes32 code = keccak256("class-code");
        vm.prank(teacher);
        registry.createClassroom("Algebra I", 30, code);

        bytes32 newCode = keccak256("rotated-code");
        uint64 ttl = 1 days;
        vm.prank(teacher);
        registry.rotateInviteCodeWithTtl(newCode, ttl);

        uint64 expected = uint64(block.timestamp) + ttl;
        assertEq(registry.inviteExpiresAt(newCode), expected);

        // Old code's TTL was zeroed.
        assertEq(registry.inviteExpiresAt(code), 0);
    }

    function test_guil03_classroom_rotate_max_ttl_capped() public {
        bytes32 code = keccak256("class-code");
        vm.prank(teacher);
        registry.createClassroom("Algebra I", 30, code);

        bytes32 newCode = keccak256("rotated-code");
        // 91 days > MAX_INVITE_TTL (90 days).
        vm.prank(teacher);
        vm.expectRevert("TTL exceeds MAX_INVITE_TTL");
        registry.rotateInviteCodeWithTtl(newCode, 91 days);
    }

    function test_guil03_classroom_rotate_zero_ttl_uses_default() public {
        bytes32 code = keccak256("class-code");
        vm.prank(teacher);
        registry.createClassroom("Algebra I", 30, code);

        bytes32 newCode = keccak256("rotated-code");
        vm.prank(teacher);
        registry.rotateInviteCodeWithTtl(newCode, 0);

        uint64 expected = uint64(block.timestamp) + registry.DEFAULT_INVITE_TTL();
        assertEq(registry.inviteExpiresAt(newCode), expected);
    }

    // ── LearningPool / WP-E3.2 ──────────────────────────────────────

    function test_guil03_pool_invite_default_ttl_set() public {
        vm.prank(creator);
        uint256 poolId = pool.createPool{value: 1 ether}(
            "Math Pool",
            "An invite-only learning pool",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 code = keccak256("pool-code");
        vm.prank(creator);
        pool.addInviteCode(poolId, code);

        uint64 expected = uint64(block.timestamp) + pool.DEFAULT_INVITE_TTL();
        assertEq(pool.inviteExpiresAt(poolId, code), expected);
    }

    function test_guil03_pool_join_rejected_after_expiry() public {
        vm.prank(creator);
        uint256 poolId = pool.createPool{value: 1 ether}(
            "Math Pool",
            "An invite-only learning pool",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 code = keccak256("pool-code");
        vm.prank(creator);
        pool.addInviteCode(poolId, code);

        // Warp past TTL.
        vm.warp(block.timestamp + uint256(pool.DEFAULT_INVITE_TTL()) + 1);

        vm.prank(joiner);
        vm.expectRevert("Invite code expired");
        pool.joinWithInvite{value: 1 ether}(poolId, code);
    }

    function test_guil03_pool_join_works_within_ttl() public {
        vm.prank(creator);
        uint256 poolId = pool.createPool{value: 1 ether}(
            "Math Pool",
            "An invite-only learning pool",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 code = keccak256("pool-code");
        vm.prank(creator);
        pool.addInviteCode(poolId, code);

        vm.prank(joiner);
        pool.joinWithInvite{value: 1 ether}(poolId, code);
        assertTrue(pool.isMember(poolId, joiner));
    }

    function test_guil03_pool_addInviteWithTtl_explicit() public {
        vm.prank(creator);
        uint256 poolId = pool.createPool{value: 1 ether}(
            "Math Pool",
            "An invite-only learning pool",
            LearningPool.AccessType.InviteOnly,
            1 ether
        );

        bytes32 code = keccak256("pool-code");
        vm.prank(creator);
        pool.addInviteCodeWithTtl(poolId, code, 1 days);

        uint64 expected = uint64(block.timestamp) + 1 days;
        assertEq(pool.inviteExpiresAt(poolId, code), expected);
    }
}
