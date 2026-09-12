// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "../src/SkillRegistry.sol";

/// @title DeploySkillRegistry — reroll-stable CREATE2 deploy for chain 40204
/// @notice Deploys `SkillRegistry` via the genesis Arachnid CREATE2 factory
///         (0x4e59…4956C) at `Salts.salt("SkillRegistry")`, so the address is a
///         pure function of (factory, salt, init_code) and is reroll-stable.
///
/// @dev  The ORIGINAL SkillRegistry (0x896cd293…) was a PLAIN CREATE deploy —
///       its address depended on the deployer nonce and is therefore NOT
///       reproducible across a reroll (it is empty on the srp-s5-diskfix chain).
///       This script makes SkillRegistry reroll-stable going forward, matching
///       ValidatorRegistry / ModelRegistry. SkillRegistry has a no-arg
///       constructor, so the init_code is just its creationCode — nothing here
///       fixes the address except the salt + the compiled bytecode
///       (solc 0.8.36 + optimizer(200) + bytecode_hash=none, per foundry.toml).
///
/// Usage (dry-run / simulate):
///   forge script script/DeploySkillRegistry.s.sol \
///     --rpc-url $CITRATE_TESTNET_RPC --sender $DEPLOYER_ADDRESS
/// Broadcast:
///   forge script script/DeploySkillRegistry.s.sol \
///     --rpc-url $CITRATE_TESTNET_RPC --broadcast \
///     --private-key $DEPLOYER_PRIVATE_KEY
contract DeploySkillRegistry is ScriptEnv {
    // Canonical Arachnid deterministic CREATE2 factory (EIP-2470), pre-stamped
    // in every Citrate genesis profile. Forge routes `new X{salt:}` through it.
    address public constant ARACHNID_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// The canonical CREATE2 salt for the registry.
    function registrySalt() public pure returns (bytes32) {
        return Salts.salt("SkillRegistry");
    }

    /// Full CREATE2 init_code = creationCode (no ctor args). `bytecode_hash =
    /// "none"` (foundry.toml) strips solc metadata so this is byte-reproducible.
    function initCode() public pure returns (bytes memory) {
        return type(SkillRegistry).creationCode;
    }

    /// Pure CREATE2 address projection for a given deployer:
    ///   keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:].
    function projectedAddress(address deployer) public pure returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), deployer, registrySalt(), keccak256(initCode()))
        );
        return address(uint160(uint256(h)));
    }

    function run() external {
        address deployer = deployerAddress();
        address projected = projectedAddress(ARACHNID_FACTORY);

        console.log("=== SkillRegistry CREATE2 deploy ===");
        console.log("chainid                :", block.chainid);
        console.log("signer (deployer)      :", deployer);
        console.log("Arachnid factory       :", ARACHNID_FACTORY);
        console.log("PROJECTED registry addr:", projected);

        vm.startBroadcast();
        SkillRegistry registry = new SkillRegistry{salt: registrySalt()}();
        vm.stopBroadcast();

        console.log("DEPLOYED registry addr :", address(registry));
        require(
            address(registry) == projected,
            "deployed address != CREATE2 projection (salt/init_code drift)"
        );

        console.log("");
        console.log("=== BOOK PIN (contracts/addresses/40204.json .contracts.SkillRegistry) ===");
        console.log("SkillRegistry=", address(registry));
    }
}
