// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {DeployFederatedLearning} from "../../script/DeployFederatedLearning.s.sol";
import {DeployDpf13Procurement} from "../../script/DeployDpf13Procurement.s.sol";
import {TinaWorkpaperRegistry} from "../../src/defense_prime/TinaWorkpaperRegistry.sol";
import {GovernanceOps} from "../../script/lib/GovernanceOps.sol";

/// Release-prep follow-ups for the ceremony scripts (lane CONTRACTS-B).
contract PBA_R2_DeployScripts is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address multisig = makeAddr("multisig");

    /// DeployAll is re-runnable: a second run over a chain where the stack is
    /// already live reuses every contract (no CREATE2 collision) and returns
    /// the same addresses.
    function test_deployAll_rerunReusesLiveContracts() public {
        DeployAll a = new DeployAll();
        DeployAll.Deployed memory d1 = a.deployWith(SENDER, multisig, multisig);
        DeployAll b = new DeployAll();
        DeployAll.Deployed memory d2 = b.deployWith(SENDER, multisig, multisig);
        assertEq(d1.wsalt, d2.wsalt);
        assertEq(d1.registry, d2.registry);
        assertEq(d1.stakingPool, d2.stakingPool);
        assertEq(d1.treasury, d2.treasury);
        assertEq(d1.governor, d2.governor);
    }

    /// DeployFederatedLearning has no TEE-registry default any more.
    function test_federatedLearning_requiresTeeRegistry() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("GOVERNANCE", vm.toString(multisig));
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
    /// (Exercised through a harness: forge runs tests in parallel and
    /// vm.setEnv is process-global, so every test here uses the SAME env.)
    function test_dpf_selfGovernanceWiresDirectly() public {
        GovOpsHarness h = new GovOpsHarness();
        TinaWorkpaperRegistry reg = new TinaWorkpaperRegistry(address(h));
        h.wire(address(h), address(reg), SENDER);
        assertTrue(reg.is_recorder(SENDER), "wired directly");
        TinaWorkpaperRegistry reg2 = new TinaWorkpaperRegistry(multisig);
        h.wire(multisig, address(reg2), SENDER); // governance is someone else: queued, no revert
        assertFalse(reg2.is_recorder(SENDER));
    }
}

contract GovOpsHarness is GovernanceOps {
    function wire(address governance, address target, address recorder) external {
        _govCall(
            governance, address(this), target, abi.encodeWithSignature("setRecorder(address,bool)", recorder, true), "setRecorder"
        );
    }
}
