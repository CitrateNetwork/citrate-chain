// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LearningCycleManager} from "../../src/LearningCycleManager.sol";

/// Regression for PBA-L2-047 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_047_Regression is Test {
    function _create(bytes memory initCode) internal returns (address a) {
        assembly {
            a := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(a != address(0), "create failed");
    }

    function test_L2_047_cycleCannotWedgeOpenCycleForever() public {
        LearningCycleManager lcm = LearningCycleManager(
            payable(_create(abi.encodePacked(type(LearningCycleManager).creationCode, abi.encode(address(this)))))
        );
        address p = makeAddr("p");
        lcm.setParticipantEligibility(p, true);
        lcm.openCycle(100);
        vm.prank(p);
        lcm.registerParticipant(1);
        vm.prank(p);
        lcm.submitEmbeddingCommitment(1, keccak256("e"));
        try lcm.advanceToAggregating(1) {} catch {}
        (bool ok,) = address(lcm).call(abi.encodeWithSignature("cancelCycle(uint256)", uint256(1)));
        ok;
        try lcm.openCycle(200) {} catch {}
        assertEq(lcm.currentCycleId(), 2, "a single-participant cycle must not wedge openCycle forever");
    }
}
