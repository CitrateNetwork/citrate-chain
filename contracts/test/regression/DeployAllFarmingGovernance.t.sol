// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {TestnetFarmingAccounting} from "../../src/TestnetFarmingAccounting.sol";
import {Governable} from "../../src/lib/Governable.sol";

/// @notice After a full DeployAll run, TestnetFarmingAccounting is born
///         governed by the GOVERNANCE key, with no pending transfer and no
///         authority left with the deployer. Pinned with a dedicated
///         assertion on the deployed contract, independent of the script's
///         own post-deploy checks.
contract DeployAllFarmingGovernanceTest is Test {
    address constant DEPLOYER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address multisig = makeAddr("multisig");

    function _deploy() internal returns (DeployAll a, TestnetFarmingAccounting farming) {
        a = new DeployAll();
        DeployAll.Deployed memory d = a.deployWith(DEPLOYER, multisig, multisig);
        farming = TestnetFarmingAccounting(payable(d.farming));
        assertGt(address(farming).code.length, 0, "farming deployed");
    }

    function test_farmingAccounting_isBornGovernanceOwned() public {
        (DeployAll a, TestnetFarmingAccounting farming) = _deploy();
        assertEq(farming.governance(), multisig, "farming governance must be the GOVERNANCE key");
        assertTrue(farming.governance() != DEPLOYER, "deployer EOA must not govern farming");
        assertTrue(farming.governance() != address(a), "deploy script must not govern farming");
        assertEq(farming.pendingGovernance(), address(0), "no manual handoff may be pending");
    }

    function test_farmingAccounting_deployerHoldsNoGovernancePower() public {
        (, TestnetFarmingAccounting farming) = _deploy();
        address[] memory participants = new address[](1);
        participants[0] = address(0xBEEF);

        vm.prank(DEPLOYER);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        farming.takeSnapshot(participants);

        vm.prank(DEPLOYER);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        farming.transferGovernance(DEPLOYER);

        // Positive control: the governance key does hold the power.
        vm.prank(multisig);
        farming.transferGovernance(address(0xD00D));
        assertEq(farming.pendingGovernance(), address(0xD00D), "governance can start a transfer");
    }
}
