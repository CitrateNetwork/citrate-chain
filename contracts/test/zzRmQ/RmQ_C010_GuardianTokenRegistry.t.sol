// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {GuardianTokenRegistry} from "../../src/edu/GuardianTokenRegistry.sol";

/// @title RM-Q · CHAIN-B-C010 — guardian tokens burnable by any observer
/// @notice RED→GREEN tripwire. Before the fix, `consumeToken` took the
///         SHA-256 hash — which is the mapping key AND an indexed
///         `TokenClaimed` topic — so any observer could burn a live
///         guardian token. `claimToken` was likewise unauthenticated.
///         After the fix `consumeToken` takes the RAW token (hashed
///         internally) and `claimToken` is district-gated.
contract RmQ_C010 is Test {
    GuardianTokenRegistry internal reg;
    address internal governance = address(0x6010);
    address internal district = address(0xD15);
    address internal attacker = address(0xBAD);
    address internal portal = address(0x901);

    string internal constant RAW = "guardian-raw-token-xyz";
    bytes32 internal hashedToken;

    function setUp() public {
        reg = new GuardianTokenRegistry(governance);
        vm.prank(governance);
        reg.setDistrict(district, true);
        hashedToken = sha256(bytes(RAW));
        vm.warp(1_700_000_000);
        vm.prank(district);
        reg.claimToken(hashedToken, uint64(block.timestamp + 7 days));
    }

    /// RED: an observer sees the indexed `hashedToken` topic and tries to
    /// consume it. Pre-fix consumeToken(hash) burned the token; post-fix
    /// the argument is the RAW token, so passing the hash bytes hashes to
    /// something else and the real token stays Claimed.
    function test_C010_observer_cannot_burn_with_hash() public {
        vm.prank(attacker);
        vm.expectRevert(GuardianTokenRegistry.TokenNotClaimed.selector);
        reg.consumeToken(bytes(abi.encodePacked(hashedToken)));
        // GREEN: the real token is untouched, still redeemable.
        assertTrue(reg.isRedeemable(hashedToken));
    }

    /// GREEN: the guardian who holds the raw token consumes it once.
    function test_C010_raw_token_consumes() public {
        vm.prank(portal);
        address d = reg.consumeToken(bytes(RAW));
        assertEq(d, district);
        assertEq(
            uint8(reg.getTokenState(hashedToken)),
            uint8(GuardianTokenRegistry.TokenState.Consumed)
        );
    }

    /// RED (claim path): an unauthorized district cannot become the
    /// district-of-record by front-running claimToken.
    function test_C010_unauthorized_district_cannot_claim() public {
        bytes32 other = sha256(bytes("another-token"));
        vm.prank(attacker);
        vm.expectRevert(GuardianTokenRegistry.NotAuthorizedDistrict.selector);
        reg.claimToken(other, uint64(block.timestamp + 7 days));
    }
}
