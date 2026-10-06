// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import "forge-std/Script.sol";
import {MultisigTimelock2of3} from "../src/cit_agent/MultisigTimelock2of3.sol";
contract DeployR2Multisigs is Script {
    // Signer sets are ceremony inputs, not baked in. Every env var is REQUIRED
    // (vm.envAddress reverts if unset) so a misconfigured ceremony fails loudly
    // rather than deploying a multisig with the wrong / stale signer set.
    // The multisig ADDRESSES derive from deployer nonce (0,1) — unaffected by the
    // signer set — but the signers they carry must be the fresh ceremony keys.
    function run() external {
        address[3] memory gov = [
            vm.envAddress("GOV_SIGNER_1"),
            vm.envAddress("GOV_SIGNER_2"),
            vm.envAddress("GOV_SIGNER_3")
        ];
        address[3] memory grd = [
            vm.envAddress("GRD_SIGNER_1"),
            vm.envAddress("GRD_SIGNER_2"),
            vm.envAddress("GRD_SIGNER_3")
        ];
        uint256 timelock = vm.envOr("MULTISIG_TIMELOCK", uint256(7200));
        vm.startBroadcast();
        MultisigTimelock2of3 g = new MultisigTimelock2of3(gov, timelock);
        MultisigTimelock2of3 d = new MultisigTimelock2of3(grd, timelock);
        vm.stopBroadcast();
        console2.log("GOVERNANCE", address(g));
        console2.log("GUARDIAN", address(d));
    }
}
