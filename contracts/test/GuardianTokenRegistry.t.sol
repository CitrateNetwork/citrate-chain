// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {GuardianTokenRegistry} from "../src/edu/GuardianTokenRegistry.sol";

/// @title GuardianTokenRegistry tests — WP-A10.4
/// @notice Verifies the on-chain consume-once invariant for guardian
///         setup tokens. State machine:
///           Unclaimed → Claimed → {Consumed | Expired | Revoked}
///         Each terminal state is unreachable from itself; once a token
///         leaves Claimed it cannot be consumed again, expired again, or
///         revoked again — all terminal transitions revert with the
///         matching `TokenAlready*` error.
contract GuardianTokenRegistryTest is Test {
    GuardianTokenRegistry public registry;

    address public districtA = address(0xD15A);
    address public districtB = address(0xD15B);
    address public guardianPortal = address(0x901);

    // CHAIN-B-C010 RC-8: consumeToken now takes the RAW token and hashes
    // it internally with SHA-256, so the on-chain commitment (the hash)
    // is no longer the credential. The district commits sha256(raw); the
    // guardian presents the raw token.
    string internal constant RAW1 = "guardian-token-1";
    string internal constant RAW2 = "guardian-token-2";
    string internal constant RAW3 = "guardian-token-3";

    bytes32 public token1Hash = sha256(bytes(RAW1));
    bytes32 public token2Hash = sha256(bytes(RAW2));
    bytes32 public token3Hash = sha256(bytes(RAW3));

    address internal governance = address(this);

    function setUp() public {
        registry = new GuardianTokenRegistry(governance);
        // CHAIN-B-C010: claimToken is now district-gated. Authorize the
        // two districts used across these fixtures.
        registry.setDistrict(districtA, true);
        registry.setDistrict(districtB, true);
        // Start at a non-zero block timestamp so expiresAt math is sane
        vm.warp(1_700_000_000);
    }

    // ============================================================
    // Claim flow
    // ============================================================

    function test_claim_token_records_district_and_expiry() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);

        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        (
            address district,
            uint64 issuedAt,
            uint64 storedExpiresAt,
            GuardianTokenRegistry.TokenState state
        ) = registry.tokens(token1Hash);
        assertEq(district, districtA);
        assertEq(issuedAt, uint64(block.timestamp));
        assertEq(storedExpiresAt, expiresAt);
        assertEq(uint8(state), uint8(GuardianTokenRegistry.TokenState.Claimed));
        assertEq(registry.totalClaimed(), 1);
    }

    function test_claim_emits_event() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);

        vm.expectEmit(true, true, false, true);
        emit GuardianTokenRegistry.TokenClaimed(token1Hash, districtA, expiresAt);

        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);
    }

    function test_claim_rejects_double_claim() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyClaimed.selector);
        registry.claimToken(token1Hash, expiresAt);

        // Another district also can't re-claim the same hash
        vm.prank(districtB);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyClaimed.selector);
        registry.claimToken(token1Hash, expiresAt);
    }

    function test_claim_rejects_past_expiry() public {
        // expiresAt in the past — refuse
        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.ExpiryInPast.selector);
        registry.claimToken(token1Hash, uint64(block.timestamp));

        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.ExpiryInPast.selector);
        registry.claimToken(token1Hash, uint64(block.timestamp - 1));
    }

    function test_claim_rejects_expiry_beyond_max_window() public {
        // 14-day cap (per planset 01_A10 Decision 4)
        uint64 expiresAt = uint64(block.timestamp + 15 days);
        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.ExpiryTooLong.selector);
        registry.claimToken(token1Hash, expiresAt);

        // Exactly at the cap — accepted
        vm.prank(districtA);
        registry.claimToken(token1Hash, uint64(block.timestamp + 14 days));
    }

    // ============================================================
    // Consume flow
    // ============================================================

    function test_consume_token_burns_it_and_returns_district() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.prank(guardianPortal);
        address returnedDistrict = registry.consumeToken(bytes(RAW1));
        assertEq(returnedDistrict, districtA);

        (, , , GuardianTokenRegistry.TokenState state) = registry.tokens(token1Hash);
        assertEq(uint8(state), uint8(GuardianTokenRegistry.TokenState.Consumed));
    }

    function test_consume_emits_event() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.expectEmit(true, false, false, false);
        emit GuardianTokenRegistry.TokenConsumed(token1Hash);

        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW1));
    }

    function test_consume_rejects_double_consume() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW1));

        // Second consume — refused
        vm.prank(guardianPortal);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyConsumed.selector);
        registry.consumeToken(bytes(RAW1));
    }

    function test_consume_rejects_unclaimed_token() public {
        // Never claimed — refuse with TokenNotClaimed
        vm.prank(guardianPortal);
        vm.expectRevert(GuardianTokenRegistry.TokenNotClaimed.selector);
        registry.consumeToken(bytes(RAW1));
    }

    function test_consume_rejects_after_expiry() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        // Warp past expiry
        vm.warp(expiresAt + 1);

        vm.prank(guardianPortal);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyExpired.selector);
        registry.consumeToken(bytes(RAW1));
    }

    // ============================================================
    // Expire flow
    // ============================================================

    function test_expire_token_burns_after_deadline() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        // Warp past expiry; anyone can call expireToken
        vm.warp(expiresAt);

        vm.expectEmit(true, false, false, false);
        emit GuardianTokenRegistry.TokenExpired(token1Hash);
        registry.expireToken(token1Hash);

        (, , , GuardianTokenRegistry.TokenState state) = registry.tokens(token1Hash);
        assertEq(uint8(state), uint8(GuardianTokenRegistry.TokenState.Expired));
    }

    function test_expire_rejects_before_deadline() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        // Don't warp; expire too early
        vm.expectRevert(GuardianTokenRegistry.NotYetExpired.selector);
        registry.expireToken(token1Hash);
    }

    function test_expire_rejects_unclaimed() public {
        vm.expectRevert(GuardianTokenRegistry.TokenNotClaimed.selector);
        registry.expireToken(token1Hash);
    }

    function test_expire_rejects_already_expired() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.warp(expiresAt + 1);
        registry.expireToken(token1Hash);

        // Second expire — refused
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyExpired.selector);
        registry.expireToken(token1Hash);
    }

    function test_expire_rejects_already_consumed() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW1));

        // Try to expire after consume — refused
        vm.warp(expiresAt + 1);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyConsumed.selector);
        registry.expireToken(token1Hash);
    }

    // ============================================================
    // Revoke flow (right-to-erasure)
    // ============================================================

    function test_revoke_burns_token_when_called_by_issuer() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.expectEmit(true, true, false, false);
        emit GuardianTokenRegistry.TokenRevoked(token1Hash, districtA);

        vm.prank(districtA);
        registry.revokeToken(token1Hash);

        (, , , GuardianTokenRegistry.TokenState state) = registry.tokens(token1Hash);
        assertEq(uint8(state), uint8(GuardianTokenRegistry.TokenState.Revoked));
    }

    function test_revoke_rejects_non_issuer() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        // districtB tries to revoke districtA's token — refused
        vm.prank(districtB);
        vm.expectRevert(GuardianTokenRegistry.NotTokenIssuer.selector);
        registry.revokeToken(token1Hash);
    }

    function test_revoke_rejects_already_consumed() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW1));

        // Try to revoke after consume — refused
        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyConsumed.selector);
        registry.revokeToken(token1Hash);
    }

    function test_revoke_rejects_unclaimed() public {
        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.TokenNotClaimed.selector);
        registry.revokeToken(token1Hash);
    }

    function test_revoke_blocks_subsequent_consume() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);

        vm.prank(districtA);
        registry.revokeToken(token1Hash);

        // Even if guardian gets the link, consume fails
        vm.prank(guardianPortal);
        vm.expectRevert(GuardianTokenRegistry.TokenAlreadyRevoked.selector);
        registry.consumeToken(bytes(RAW1));
    }

    // ============================================================
    // View functions
    // ============================================================

    function test_isRedeemable_returns_true_for_fresh_claim() public {
        vm.prank(districtA);
        registry.claimToken(token1Hash, uint64(block.timestamp + 7 days));
        assertTrue(registry.isRedeemable(token1Hash));
    }

    function test_isRedeemable_returns_false_for_unclaimed() public {
        assertFalse(registry.isRedeemable(token1Hash));
    }

    function test_isRedeemable_returns_false_after_consume() public {
        vm.prank(districtA);
        registry.claimToken(token1Hash, uint64(block.timestamp + 7 days));
        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW1));
        assertFalse(registry.isRedeemable(token1Hash));
    }

    function test_isRedeemable_returns_false_past_expiry() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);
        vm.warp(expiresAt + 1);
        assertFalse(registry.isRedeemable(token1Hash));
    }

    function test_getTokenState_returns_lifecycle_state() public {
        // Unclaimed → 0
        assertEq(uint8(registry.getTokenState(token1Hash)), uint8(GuardianTokenRegistry.TokenState.Unclaimed));

        vm.prank(districtA);
        registry.claimToken(token1Hash, uint64(block.timestamp + 7 days));
        assertEq(uint8(registry.getTokenState(token1Hash)), uint8(GuardianTokenRegistry.TokenState.Claimed));

        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW1));
        assertEq(uint8(registry.getTokenState(token1Hash)), uint8(GuardianTokenRegistry.TokenState.Consumed));
    }

    // ============================================================
    // Multi-token + multi-district scenarios
    // ============================================================

    function test_multiple_tokens_per_district_independent() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);
        vm.prank(districtA);
        registry.claimToken(token2Hash, expiresAt);
        vm.prank(districtA);
        registry.claimToken(token3Hash, expiresAt);

        assertEq(registry.totalClaimed(), 3);

        // Consume one; others remain claimed
        vm.prank(guardianPortal);
        registry.consumeToken(bytes(RAW2));

        assertTrue(registry.isRedeemable(token1Hash));
        assertFalse(registry.isRedeemable(token2Hash));
        assertTrue(registry.isRedeemable(token3Hash));
    }

    function test_two_districts_separate_token_spaces() public {
        uint64 expiresAt = uint64(block.timestamp + 7 days);
        vm.prank(districtA);
        registry.claimToken(token1Hash, expiresAt);
        vm.prank(districtB);
        registry.claimToken(token2Hash, expiresAt);

        // Each district can revoke only their own
        vm.prank(districtA);
        vm.expectRevert(GuardianTokenRegistry.NotTokenIssuer.selector);
        registry.revokeToken(token2Hash);

        vm.prank(districtB);
        vm.expectRevert(GuardianTokenRegistry.NotTokenIssuer.selector);
        registry.revokeToken(token1Hash);

        // But each can revoke their own
        vm.prank(districtA);
        registry.revokeToken(token1Hash);
        vm.prank(districtB);
        registry.revokeToken(token2Hash);
    }
}
