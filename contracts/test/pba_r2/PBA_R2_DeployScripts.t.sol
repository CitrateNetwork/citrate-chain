// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {DeployFederatedLearning} from "../../script/DeployFederatedLearning.s.sol";
import {DeployDpf13Procurement} from "../../script/DeployDpf13Procurement.s.sol";
import {TinaWorkpaperRegistry} from "../../src/defense_prime/TinaWorkpaperRegistry.sol";

/// Release-prep follow-ups for the ceremony scripts (lane CONTRACTS-B).
contract PBA_R2_DeployScripts is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address multisig = makeAddr("multisig");

    /// DeployAll is re-runnable: a second run over a chain where the stack is
    /// already live reuses every contract (no CREATE2 collision) and returns
    /// the same addresses.
    function test_deployAll_rerunReusesLiveContracts() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("GOVERNANCE", vm.toString(multisig));
        vm.setEnv("GUARDIAN", vm.toString(multisig));
        DeployAll a = new DeployAll();
        DeployAll.Deployed memory d1 = a.deploy();
        DeployAll b = new DeployAll();
        DeployAll.Deployed memory d2 = b.deploy();
        assertEq(d1.wsalt, d2.wsalt);
        assertEq(d1.registry, d2.registry);
        assertEq(d1.governor, d2.governor);
        assertEq(d1.stakingPool, d2.stakingPool);
    }

    /// DeployFederatedLearning has no TEE-registry default any more.
    function test_federatedLearning_requiresTeeRegistry() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("TEE_REGISTRY", "0x0000000000000000000000000000000000000000");
        DeployFederatedLearning s = new DeployFederatedLearning();
        vm.expectRevert(bytes("TEE_REGISTRY must be set (no default)"));
        s.run();
        vm.setEnv("TEE_REGISTRY", "0x000000000000000000000000000000000000dEaD");
        DeployFederatedLearning s2 = new DeployFederatedLearning();
        vm.expectRevert(bytes("TEE_REGISTRY has no code on this chain"));
        s2.run();
    }

    /// DPF scripts complete with a multisig as governance: the governance-gated
    /// wiring is emitted for the multisig instead of reverting the run.
    function test_dpf_multisigGovernanceDoesNotRevert() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("GOVERNANCE", vm.toString(multisig));
        DeployDpf13Procurement s = new DeployDpf13Procurement();
        TinaWorkpaperRegistry reg = TinaWorkpaperRegistry(s.run());
        assertEq(reg.governance(), multisig);
        assertFalse(reg.is_recorder(SENDER), "not wired: queued for the multisig");
    }

    /// With governance == the broadcaster the wiring is executed directly.
    function test_dpf_selfGovernanceWiresDirectly() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("GOVERNANCE", vm.toString(SENDER));
        DeployDpf13Procurement s = new DeployDpf13Procurement();
        TinaWorkpaperRegistry reg = TinaWorkpaperRegistry(s.run());
        assertTrue(reg.is_recorder(SENDER), "wired directly");
    }
}
