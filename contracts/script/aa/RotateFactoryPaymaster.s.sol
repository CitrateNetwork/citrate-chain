// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../ScriptEnv.sol";
import "../Salts.sol";

import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {IEntryPoint as IAaEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

/**
 * @title RotateFactoryPaymaster — E-8 partial AA rotation on a LIVE chain
 * @notice Redeploys ONLY the two contracts whose bytecode changed in E-8
 *   (`CitrateWalletFactory` — atomic registration; `CitratePaymaster` — new
 *   constructor with sponsor signer + WEI caps). It REUSES the existing,
 *   unchanged `CitrateWallet` implementation, validators, and recovery module:
 *   those have identical bytecode, so a full `DeployAA` re-run CREATE2-collides
 *   on them on a live chain. Same `Salts` as `DeployAA`, so the produced
 *   factory/paymaster addresses are the canonical ones a clean deploy would
 *   yield. The paymaster registrar is the new factory (E-8 self-registration);
 *   `setPaymaster` is auto-wired when the broadcaster is the factory owner.
 *
 * Env:
 *   CITRATE_AA_ENTRY_POINT    — EntryPoint v0.7 (existing)
 *   CITRATE_AA_IDENTITY_SIGNER — EOA authorising factory deploys (reuse the live one)
 *   CITRATE_AA_OWNER          — factory + paymaster owner (broadcast as this to auto-wire)
 *   CITRATE_AA_SPONSOR_SIGNER  — sponsorship signer (defaults to identity signer)
 *   CITRATE_AA_WALLET_IMPL    — existing CitrateWallet implementation to reuse
 *   CITRATE_AA_{DAILY,RECOVERY,FIRST_OP}_CAP / _MAX_FEE_CEIL / _GLOBAL_CAP — caps (defaults)
 *
 * Broadcast (owner holds SALT for gas):
 *   forge script script/aa/RotateFactoryPaymaster.s.sol \
 *     --rpc-url https://rpc.citrate.ai --private-key 0x.. --broadcast --slow
 */
contract RotateFactoryPaymaster is Script, ScriptEnv {
    function run() external {
        address entryPoint = envAddressOr("CITRATE_AA_ENTRY_POINT", address(0));
        address identitySigner = envAddressOr("CITRATE_AA_IDENTITY_SIGNER", address(0));
        address owner = envAddressOr("CITRATE_AA_OWNER", address(0));
        address sponsorSigner = envAddressOr("CITRATE_AA_SPONSOR_SIGNER", identitySigner);
        address walletImpl = envAddressOr("CITRATE_AA_WALLET_IMPL", address(0));
        uint256 dailyCap = envUintOr("CITRATE_AA_DAILY_CAP", 0.01 ether);
        uint256 recoveryCap = envUintOr("CITRATE_AA_RECOVERY_CAP", 0.01 ether);
        uint256 firstOpCap = envUintOr("CITRATE_AA_FIRST_OP_CAP", 0.02 ether);
        uint256 maxFeeCeiling = envUintOr("CITRATE_AA_MAX_FEE_CEIL", 20 gwei);
        uint256 globalDailyCap = envUintOr("CITRATE_AA_GLOBAL_CAP", 5 ether);

        require(block.chainid == 40204, "refusing to rotate off chain 40204");
        require(entryPoint.code.length > 0, "EntryPoint not deployed on this chain");
        require(walletImpl.code.length > 0, "CitrateWallet impl has no code (reuse the existing one)");
        require(identitySigner != address(0), "identity signer not set");
        require(owner != address(0), "owner not set");
        require(sponsorSigner != address(0), "sponsor signer not set");

        vm.startBroadcast();

        CitrateWalletFactory factory =
            new CitrateWalletFactory{salt: Salts.salt("CitrateWalletFactory")}(walletImpl, identitySigner, owner);

        CitratePaymaster paymaster = new CitratePaymaster{salt: Salts.salt("CitratePaymaster")}(
            IAaEntryPoint(entryPoint),
            owner,
            address(factory),
            sponsorSigner,
            dailyCap,
            recoveryCap,
            firstOpCap,
            maxFeeCeiling,
            globalDailyCap
        );

        (, address broadcaster,) = vm.readCallers();
        if (broadcaster == owner) {
            factory.setPaymaster(address(paymaster));
        }

        vm.stopBroadcast();

        console2.log("=== E-8 factory+paymaster rotation on chain", block.chainid, "===");
        console2.log("reused CitrateWallet impl :", walletImpl);
        console2.log("NEW CitrateWalletFactory  :", address(factory));
        console2.log("NEW CitratePaymaster      :", address(paymaster));
        console2.log("registrar (= new factory) :", address(factory));
        console2.log("sponsorSigner             :", sponsorSigner);
        console2.log("identitySigner            :", identitySigner);
        console2.log("owner                     :", owner);
        if (broadcaster != owner) {
            console2.log("ACTION REQUIRED: owner must call factory.setPaymaster(paymaster) before any deployFor.");
        }
    }
}
