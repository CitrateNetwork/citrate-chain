// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {CrossOrgEnvelope} from "../../src/defense_prime/CrossOrgEnvelope.sol";

/// @title RM-Q · CHAIN-B-C026 — one recorder forges every org's sigs;
///         permissionless delivery skips the rejection window
/// @notice RED→GREEN tripwire.
///         (a) `sign` gated on the GLOBAL recorder allowlist while taking
///             `org_root` from calldata, so one recorder key satisfied
///             every org's threshold. Now `sign` requires a recorder
///             registered for that specific org.
///         (b) `markDelivered`/`accept`/`close` were permissionless, so
///             anyone could drive a Signed envelope to terminal `Closed`,
///             removing the rejection window. Now recorder-gated.
contract RmQ_C026 is Test {
    CrossOrgEnvelope internal env;
    address internal governance = address(0x6026);
    address internal defense_primeRec = address(0xB0E);
    address internal attacker = address(0xBAD);

    bytes32 internal constant ENV_1 = keccak256("env-1");
    bytes32 internal constant DEFENSE_PRIME = keccak256("defense_prime-root");
    bytes32 internal constant TIER1 = keccak256("tier1-root");
    bytes32 internal constant SIG_B1 = keccak256("defense_prime-co");
    bytes32 internal constant SIG_T1 = keccak256("tier1-sales");

    function setUp() public {
        vm.prank(governance);
        env = new CrossOrgEnvelope(governance);
        // A recorder authorized ONLY for the DefensePrime org.
        vm.prank(governance);
        env.setOrgRecorder(DEFENSE_PRIME, defense_primeRec, true);
        _draft();
    }

    function _draft() internal {
        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = DEFENSE_PRIME;
        orgs[1] = TIER1;
        uint8[] memory ths = new uint8[](2);
        ths[0] = 1;
        ths[1] = 1;
        bytes32[][] memory signers = new bytes32[][](2);
        signers[0] = new bytes32[](1);
        signers[0][0] = SIG_B1;
        signers[1] = new bytes32[](1);
        signers[1][0] = SIG_T1;
        vm.prank(governance);
        env.setRecorder(governance, true); // governance drafts
        vm.prank(governance);
        env.draft(ENV_1, keccak256("ar"), keccak256("cid"), orgs, ths, signers, 0, keccak256("scope"), 0);
    }

    /// RED (a): the DefensePrime recorder key tries to also satisfy Tier-1.
    /// Pre-fix `_allOrgsMet` would go true off one key; post-fix signing
    /// for TIER1 reverts NotOrgRecorder.
    function test_C026_recorder_cannot_forge_other_orgs_signature() public {
        vm.prank(defense_primeRec);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1); // legitimate for its own org

        vm.prank(defense_primeRec);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotOrgRecorder.selector, TIER1, defense_primeRec)
        );
        env.sign(ENV_1, TIER1, SIG_T1);

        // GREEN: Tier-1 threshold NOT met off the DefensePrime key alone.
        assertFalse(env.isAllOrgsMet(ENV_1));
    }

    /// RED (b): anyone driving Signed → Delivered is now blocked. First
    /// reach Signed with each org's own recorder, then an anonymous
    /// caller attempts markDelivered.
    function test_C026_anon_cannot_advance_delivery() public {
        vm.prank(governance);
        env.setOrgRecorder(TIER1, defense_primeRec, true); // give a real per-org path
        vm.startPrank(defense_primeRec);
        env.sign(ENV_1, DEFENSE_PRIME, SIG_B1);
        env.sign(ENV_1, TIER1, SIG_T1);
        vm.stopPrank();
        assertEq(env.getEnvelope(ENV_1).state, 3); // Signed

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(CrossOrgEnvelope.NotRecorder.selector, attacker)
        );
        env.markDelivered(ENV_1);
        // GREEN: still Signed; the rejection window is intact.
        assertEq(env.getEnvelope(ENV_1).state, 3);
    }
}
