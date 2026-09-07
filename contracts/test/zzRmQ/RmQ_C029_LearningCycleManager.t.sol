// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {LearningCycleManager} from "../../src/LearningCycleManager.sol";

/// @title RM-Q · CHAIN-B-C029 — sybil registerParticipant capture / DoS
/// @notice RED→GREEN tripwire. Before the fix, registration was
///         permissionless with no stake, fee or allowlist, so a sybil
///         could dilute the 40% participant pool arbitrarily and, past
///         the block gas limit on the `finalizeCycle` participant loop,
///         brick the contract permanently (openCycle requires the prior
///         cycle Finalized). After the fix registration is gated on a
///         governance-managed eligibility allowlist.
contract RmQ_C029 is Test {
    LearningCycleManager internal lcm;
    // Governance is address(this) (constructor sets msg.sender).
    address internal sybil = address(0x5B11);
    address internal honest = address(0x600D);

    function setUp() public {
        lcm = new LearningCycleManager();
        lcm.openCycle(1000);
    }

    /// RED: an unauthorized sybil registers in the open cycle. Pre-fix the
    /// call SUCCEEDED (diluting the pool); post-fix it reverts.
    function test_C029_sybil_cannot_register() public {
        uint256 cid = lcm.currentCycleId();
        vm.prank(sybil);
        vm.expectRevert("Not eligible participant");
        lcm.registerParticipant(cid);
        assertFalse(lcm.isParticipant(cid, sybil));
    }

    /// GREEN: a governance-authorized participant registers normally.
    function test_C029_eligible_participant_can_register() public {
        uint256 cid = lcm.currentCycleId();
        lcm.setParticipantEligibility(honest, true);
        vm.prank(honest);
        lcm.registerParticipant(cid);
        assertTrue(lcm.isParticipant(cid, honest));
    }
}
