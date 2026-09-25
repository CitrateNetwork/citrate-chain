// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {P256} from "../../src/aa/lib/webauthn/P256.sol";

/// @title DeployP256Verifier — provision the P-256 verifier the passkey validator calls (PBA-L2-011)
/// @notice `P256.VERIFIER` (0xc2b7…De4) is Daimo's canonical P256Verifier, a
///         CREATE2 deployment through the Arachnid deployer (0x4e59…956C),
///         which is genesis-allocated on 40204. On the live chain that address
///         has NO code, so every passkey (WebAuthnP256Validator) signature
///         fails closed and passkey-rooted wallets cannot sign.
///
///         This script deploys it permissionlessly and SAFELY: the CREATE2
///         address is a function of the exact init code, so the script first
///         recomputes `create2(0x4e59…, salt, keccak(initcode))` and refuses to
///         broadcast unless it equals `P256.VERIFIER`. Supplying the wrong
///         bytes cannot put anything else at that address.
///
///         Env (the canonical init code is NOT vendored in this repo):
///           P256_VERIFIER_INITCODE  hex init code of daimo-eth/p256-verifier
///                                   (the exact bytes Daimo deployed)
///           P256_VERIFIER_SALT      bytes32 salt Daimo used (default 0x0)
///         Run:
///           forge script script/aa/DeployP256Verifier.s.sol --rpc-url $RPC --broadcast --account deployer
///         Then gate: forge script script/CheckDeployedAdmins.s.sol --rpc-url $RPC
contract DeployP256Verifier is Script {
    address internal constant ARACHNID_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external {
        if (P256.VERIFIER.code.length != 0) {
            console.log("P256 verifier already has code at", P256.VERIFIER);
            return;
        }
        require(ARACHNID_FACTORY.code.length != 0, "Arachnid CREATE2 deployer missing");
        bytes memory initCode = vm.envBytes("P256_VERIFIER_INITCODE");
        bytes32 salt = vm.envOr("P256_VERIFIER_SALT", bytes32(0));
        address predicted = computeAddress(salt, initCode);
        console.log("predicted:", predicted);
        require(predicted == P256.VERIFIER, "init code/salt do not produce P256.VERIFIER; refusing");

        vm.startBroadcast();
        (bool ok,) = ARACHNID_FACTORY.call(abi.encodePacked(salt, initCode));
        vm.stopBroadcast();
        require(ok, "CREATE2 deploy failed");
        require(P256.VERIFIER.code.length != 0, "no code at P256.VERIFIER after deploy");
        console.log("P256 verifier deployed at", P256.VERIFIER);
    }

    function computeAddress(bytes32 salt, bytes memory initCode) public pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), ARACHNID_FACTORY, salt, keccak256(initCode)))))
        );
    }
}
