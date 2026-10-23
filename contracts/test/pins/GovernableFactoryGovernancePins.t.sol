// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";
import {Governable} from "../../src/lib/Governable.sol";

/// @notice Pins Governable's constructor refusal of the CREATE2 factory as
///         governance. LiquidStakingPool passes its argument straight to
///         Governable, so this check is the only guard on that path. The
///         existing factory test still passed with the check removed: the
///         trace shows the constructor deploying with factory governance while
///         the test's `vm.expectRevert` did not fail. Here each deployment is
///         checked with a plain low-level call, so the result is the
///         constructor's own.
contract GovernableFactoryGovernancePinsTest is Test {
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// External so the constructor revert can be observed with a plain call.
    function deployDirect(address governance) external returns (address) {
        return address(new LiquidStakingPool(governance));
    }

    function test_directDeployNamingTheFactoryReverts() public {
        (bool ok, bytes memory reason) = address(this).call(abi.encodeCall(this.deployDirect, (FACTORY)));
        assertFalse(ok, "a pool with the factory as governance must not deploy");
        assertEq(bytes4(reason), Governable.Governable_Create2Factory.selector, "wrong revert");
    }

    function test_deployThroughTheFactoryWithItselfAsGovernanceFails() public {
        bytes memory initCode = abi.encodePacked(type(LiquidStakingPool).creationCode, abi.encode(FACTORY));
        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(bytes32(uint256(7)), initCode));
        assertFalse(ok && ret.length >= 20, "a factory-governed pool must not be created");
    }

    /// Control: a real key is accepted and becomes governance.
    function test_aRealKeyIsAccepted() public {
        address gov = makeAddr("governance");
        LiquidStakingPool p = LiquidStakingPool(payable(this.deployDirect(gov)));
        assertEq(p.governance(), gov);
    }
}
