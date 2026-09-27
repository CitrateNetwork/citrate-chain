// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import "forge-std/Script.sol";
import {MultisigTimelock2of3} from "../src/cit_agent/MultisigTimelock2of3.sol";
contract DeployR2Multisigs is Script {
    function run() external {
        address[3] memory gov = [address(0xB4E186CBeab88C8220F3D69f4263FfFCf4C6aDA9), 0xa6BB945bD72684951721ff99AecFDdb48aE22B8b, 0xe154af73bb03bC6073A4f08d6868184774014daf];
        address[3] memory grd = [address(0xcC9eE1f2c11C53E2B9C30C61848Ee50F12a690Dc), 0x1B0C84e457605a065Beb0B2306efa0Fb54B33e8A, 0x8547D47D144877a75dE0097D5E35DA8A355C8E3F];
        vm.startBroadcast();
        MultisigTimelock2of3 g = new MultisigTimelock2of3(gov, 7200);
        MultisigTimelock2of3 d = new MultisigTimelock2of3(grd, 7200);
        vm.stopBroadcast();
        console2.log("GOVERNANCE", address(g));
        console2.log("GUARDIAN", address(d));
    }
}
