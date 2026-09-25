// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";
import {ModelRegistry} from "../../src/ModelRegistry.sol";
import {Governable} from "../../src/lib/Governable.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";

/// Stand-in for a contract deployed by the pre-fix ceremony: its governance
/// getter returns the CREATE2 factory (what 21 live contracts return today).
contract OrphanedByFactory {
    function governance() external pure returns (address) {
        return 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    }
}

contract AdminChecksHarness is AdminChecks {
    function problem(address t) external view returns (string memory) {
        return _factoryAdminProblem(t);
    }
}

/// PBA-L2-002: fixed behaviour (constructor guard, DeployAll post-deploy
/// assertion run in-process, and the AdminChecks sweep used by
/// script/CheckDeployedAdmins.s.sol).
contract PBA_L2_002_Fixed is Test {
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address intended = makeAddr("multisig");

    function _viaFactory(bytes memory initCode, bytes32 salt) internal returns (bool ok, address deployed) {
        bytes memory ret;
        (ok, ret) = FACTORY.call(abi.encodePacked(salt, initCode));
        if (ok && ret.length >= 20) deployed = address(bytes20(ret));
    }

    /// Naming the factory itself as governance is refused at construction.
    function test_L2_002_factoryAsGovernance_reverts() public {
        vm.expectRevert(Governable.Governable_Create2Factory.selector);
        new LiquidStakingPool(FACTORY);
        bytes memory initCode = abi.encodePacked(type(LiquidStakingPool).creationCode, abi.encode(FACTORY));
        (bool ok,) = _viaFactory(initCode, bytes32(uint256(2)));
        assertFalse(ok, "factory-governed deploy must fail");
    }

    /// DeployAll runs end-to-end in-process and its own post-deploy assertion
    /// (`_assertAdmins`) passes; every slot names the GOVERNANCE key.
    function test_L2_002_deployAll_assertsNoFactoryAdmin() public {
        // The in-test broadcaster is forge's default sender; the script's own
        // post-deploy wiring calls (treasury/mentor) are made by it.
        address sender = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(sender));
        vm.setEnv("GOVERNANCE", vm.toString(intended));
        vm.setEnv("GUARDIAN", vm.toString(intended));
        DeployAll script = new DeployAll();
        DeployAll.Deployed memory d = script.deploy();
        AdminChecksHarness h = new AdminChecksHarness();
        assertEq(h.problem(d.stakingPool), "");
        assertEq(h.problem(d.registry), "");
        assertEq(h.problem(d.paywall), "");
        assertEq(LiquidStakingPool(payable(d.stakingPool)).governance(), intended);
        assertEq(Governable(d.computePool).governance(), intended);
        assertTrue(ModelRegistry(d.registry).hasRole(0x00, intended));
    }

    /// The sweep used by DeployAll and CheckDeployedAdmins flags the defect.
    function test_L2_002_adminCheck_flagsFactoryGovernance() public {
        AdminChecksHarness h = new AdminChecksHarness();
        OrphanedByFactory o = new OrphanedByFactory();
        assertEq(h.problem(address(o)), "governance() is the CREATE2 factory");
        assertEq(h.problem(address(0x1234)), "no code at address");
    }
}
