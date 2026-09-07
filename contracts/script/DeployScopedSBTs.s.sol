// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Salts} from "./Salts.sol";
import {FacilitySBT} from "../src/cit_agent/FacilitySBT.sol";
import {NetworkSBT} from "../src/cit_agent/NetworkSBT.sol";

/// Deploys the org-scoped SBTs behind UUPS proxies with deterministic CREATE2
/// addresses. The PROXY address is the canonical, address-book entry — it is
/// what freezes at the reroll; the implementation behind it can be upgraded by
/// GOVERNOR_ROLE (the 2-of-3 timelocked controller) without changing the address
/// or re-minting. `ROOT_GOVERNANCE` is the governor/upgrade authority; the
/// minter defaults to governance unless `SBT_MINTER` is set to the publisher path.
contract DeployScopedSBTs is Script {
    function run() external returns (address facilitySBT, address networkSBT) {
        address governance = vm.envAddress("ROOT_GOVERNANCE");
        address minter = vm.envOr("SBT_MINTER", governance);

        vm.startBroadcast();

        FacilitySBT facImpl = new FacilitySBT{salt: Salts.salt("FacilitySBTImpl")}();
        ERC1967Proxy facProxy = new ERC1967Proxy{salt: Salts.salt("FacilitySBTProxy")}(
            address(facImpl),
            abi.encodeCall(FacilitySBT.initialize, (governance, minter))
        );

        NetworkSBT netImpl = new NetworkSBT{salt: Salts.salt("NetworkSBTImpl")}();
        ERC1967Proxy netProxy = new ERC1967Proxy{salt: Salts.salt("NetworkSBTProxy")}(
            address(netImpl),
            abi.encodeCall(NetworkSBT.initialize, (governance, minter))
        );

        vm.stopBroadcast();

        facilitySBT = address(facProxy);
        networkSBT = address(netProxy);
        console2.log("FacilitySBT (proxy)", facilitySBT);
        console2.log("FacilitySBT impl   ", address(facImpl));
        console2.log("NetworkSBT  (proxy)", networkSBT);
        console2.log("NetworkSBT  impl   ", address(netImpl));
    }
}
