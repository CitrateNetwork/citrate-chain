// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @dev Shared setup for the AMC suites. GOVERNANCE is a real OZ TimelockController with the
///      genesis delay (48 h), as DeployGenesisGovernance deploys it; `govMultisig` stands in for
///      the 3-of-5 MultisigProposer (its only proposer / executor / canceller). The GUARDIAN seat
///      holds NO role on this timelock (RT-15): its powers are local to ProviderRegistry.
///      Tests read time with `vm.getBlockTimestamp()`: under via-IR a test body may reuse a
///      `block.timestamp` read across `vm.warp`.
abstract contract AmcTestBase is Test {
    uint256 internal constant GOV_DELAY = 48 hours;

    TimelockController internal timelock;
    address internal govMultisig = makeAddr("govMultisig");
    address internal guardian = makeAddr("guardian");
    address internal stranger = makeAddr("stranger");

    function _deployTimelock() internal {
        address[] memory proposers = new address[](1);
        proposers[0] = govMultisig;
        address[] memory executors = new address[](1);
        executors[0] = govMultisig;
        timelock = new TimelockController(GOV_DELAY, proposers, executors, address(0));
    }

    /// Schedule `data` on `target` through GOVERNANCE, wait the delay and execute.
    function _govCall(address target, bytes memory data) internal {
        bytes32 salt = keccak256(abi.encode(target, data, vm.getBlockTimestamp(), gasleft()));
        vm.prank(govMultisig);
        timelock.schedule(target, 0, data, bytes32(0), salt, GOV_DELAY);
        vm.warp(vm.getBlockTimestamp() + GOV_DELAY);
        vm.prank(govMultisig);
        timelock.execute(target, 0, data, bytes32(0), salt);
    }

    /// Schedule only; returns the operation id and salt.
    function _govSchedule(address target, bytes memory data) internal returns (bytes32 id, bytes32 salt) {
        salt = keccak256(abi.encode("schedule", target, data, vm.getBlockTimestamp()));
        vm.prank(govMultisig);
        timelock.schedule(target, 0, data, bytes32(0), salt, GOV_DELAY);
        id = timelock.hashOperation(target, 0, data, bytes32(0), salt);
    }

    /// Every AMC contract holds no value: a plain transfer and a call with value both fail.
    function _assertRejectsValue(address c) internal {
        vm.deal(address(this), 1 ether);
        (bool ok,) = c.call{value: 1 wei}("");
        assertFalse(ok, "accepted a plain value transfer");
        (ok,) = c.call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok, "accepted value with calldata");
        assertEq(c.balance, 0);
    }
}
