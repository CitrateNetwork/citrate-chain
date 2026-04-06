// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;
import "forge-std/Script.sol";
import "../src/edu/Forwarder.sol";
contract DeployForwarderPilot is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address cluster = 0xe0B39353F69b54e945364ffcdDD7901697Ca0166;
        address vault = 0x20Fbd46DeEd5EEDEB6e5c87eeB31924e9CA312ad;
        vm.startBroadcast(pk);
        Forwarder f = new Forwarder(deployer, cluster, vault);
        console.log("Forwarder (pilot):", address(f));
        f.addRelayer(deployer);
        console.log("Relayer authorized:", deployer);
        vm.stopBroadcast();
    }
}
