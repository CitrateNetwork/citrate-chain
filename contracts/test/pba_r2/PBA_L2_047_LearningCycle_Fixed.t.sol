// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LearningCycleManager} from "../../src/LearningCycleManager.sol";

/// Mutation hardening (PBA-L2-047) through the fixed API.
contract PBA_L2_047_Fixed is Test {
    function test_L2_047_singleParticipantCannotAggregate_andCancelIsGovernanceOnly() public {
        LearningCycleManager lcm = new LearningCycleManager(address(this));
        address p = makeAddr("p");
        lcm.setParticipantEligibility(p, true);
        lcm.openCycle(100);
        vm.prank(p);
        lcm.registerParticipant(1);
        vm.expectRevert("Need at least 2 participants");
        lcm.advanceToAggregating(1);
        vm.prank(p);
        vm.expectRevert();
        lcm.cancelCycle(1);
        vm.expectRevert("Not the current cycle");
        lcm.cancelCycle(2);
        lcm.cancelCycle(1);
        vm.expectRevert("Already finalized");
        lcm.cancelCycle(1);
    }
}
