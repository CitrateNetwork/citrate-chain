// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OrangeSeedV0} from "../src/genesis/OrangeSeedV0.sol";

/// @title DeployOrangeSeed: local/devnet deploy of the OrangeSeed proxy
/// @notice For local testing (anvil, a devnet). On chain 40204 OrangeSeed exists only as the
///         genesis predeploy (`script/GenesisOrangeSeed.s.sol`), so this script refuses
///         there rather than put a second copy beside it.
///
///         The proxy constructor calls `initialize`, so the proxy is planted in the same
///         transaction that creates it: there is no window in which someone else could
///         initialize it first.
///
///           ORANGESEED_GOVERNANCE=<timelock> [ORANGESEED_PLANTER=<addr>] \
///             forge script script/DeployOrangeSeed.s.sol --rpc-url <local> --broadcast <signer flags>
contract DeployOrangeSeed is Script {
    uint256 internal constant CITRATE_CHAIN_ID = 40204;
    string internal constant REFUSED_ON_CITRATE =
        "OrangeSeed on chain 40204 is the genesis predeploy: use script/GenesisOrangeSeed.s.sol";

    function run() external returns (address proxy, address implementation) {
        address governance = vm.envAddress("ORANGESEED_GOVERNANCE");
        address planter = governance;
        try vm.envAddress("ORANGESEED_PLANTER") returns (address p) {
            planter = p;
        } catch {}

        vm.startBroadcast();
        (proxy, implementation) = deploy(governance, planter);
        vm.stopBroadcast();

        console.log("OrangeSeed proxy           :", proxy);
        console.log("OrangeSeedV0 implementation:", implementation);
    }

    function deploy(address governance, address planter) public returns (address proxy, address implementation) {
        require(block.chainid != CITRATE_CHAIN_ID, REFUSED_ON_CITRATE);
        implementation = address(new OrangeSeedV0());
        proxy = address(
            new ERC1967Proxy(implementation, abi.encodeCall(OrangeSeedV0.initialize, (governance, planter)))
        );
    }
}
