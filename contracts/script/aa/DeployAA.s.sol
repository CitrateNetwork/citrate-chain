// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../ScriptEnv.sol";

// AA contracts shipped by WP-1
import {WebAuthnP256Validator} from "../../src/aa/validators/WebAuthnP256Validator.sol";
import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";

// Vendored Kernel v3 implementation + EntryPoint
// NB: Kernel and @account-abstraction each ship their own IEntryPoint
// interface (same signature, distinct Solidity types). Import each
// under a distinct alias so the type checker can match constructors.
import {Kernel} from "@kernel/Kernel.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";
import {IEntryPoint as IAaEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

/**
 * @title DeployAA
 * @notice Deploys the EW-S1 embedded-wallet AA stack to chain 40204.
 *
 * Run:
 *   forge script script/aa/DeployAA.s.sol \
 *     --rpc-url https://rpc.citrate.ai \
 *     --account ceremony-deployer \
 *     --sender 0x4250675F9015E65fC866F3a373F82bb9DFc000c6 \
 *     --broadcast
 *
 * Environment variables (read by ScriptEnv):
 *   CITRATE_AA_ENTRY_POINT   — EntryPoint v0.7 address to wire the paymaster against
 *   CITRATE_AA_IDENTITY_SIGNER — operator EOA whose signature authorises factory deploys
 *   CITRATE_AA_OWNER         — owner of the factory + paymaster (operator multisig in prod)
 *   CITRATE_AA_DAILY_CAP     — paymaster daily gas cap (default 100_000)
 *   CITRATE_AA_RECOVERY_CAP  — paymaster recovery event cap (default 200_000)
 *   CITRATE_AA_FIRST_OP_CAP  — paymaster first-op cap (default 300_000)
 */
contract DeployAA is Script, ScriptEnv {
    struct Deployment {
        WebAuthnP256Validator webauthn;
        CitrateECDSAValidator ecdsa;
        GuardianRecoveryModule recovery;
        Kernel kernelImpl;
        CitrateWalletFactory factory;
        CitratePaymaster paymaster;
    }

    function run() external returns (Deployment memory d) {
        address entryPoint = envAddressOr("CITRATE_AA_ENTRY_POINT", address(0));
        address identitySigner = envAddressOr("CITRATE_AA_IDENTITY_SIGNER", address(0));
        address owner = envAddressOr("CITRATE_AA_OWNER", address(0));
        uint256 dailyCap = envUintOr("CITRATE_AA_DAILY_CAP", 100_000);
        uint256 recoveryCap = envUintOr("CITRATE_AA_RECOVERY_CAP", 200_000);
        uint256 firstOpCap = envUintOr("CITRATE_AA_FIRST_OP_CAP", 300_000);

        require(entryPoint.code.length > 0, "EntryPoint not deployed on this chain");
        require(identitySigner != address(0), "identity signer not set");
        require(owner != address(0), "owner not set");

        vm.startBroadcast();

        d.webauthn = new WebAuthnP256Validator();
        d.ecdsa = new CitrateECDSAValidator();
        d.recovery = new GuardianRecoveryModule();

        // Kernel implementation: constructor takes the EntryPoint address
        // (per @kernel/Kernel.sol). Each smart wallet is a minimal ERC-1967
        // proxy of this implementation.
        d.kernelImpl = new Kernel(IKernelEntryPoint(entryPoint));

        // Factory needs the implementation address + identity signer + owner.
        d.factory = new CitrateWalletFactory(address(d.kernelImpl), identitySigner, owner);

        // Paymaster wired to the EntryPoint + factory as registrar.
        d.paymaster = new CitratePaymaster(
            IAaEntryPoint(entryPoint),
            owner,
            address(d.factory),
            dailyCap,
            recoveryCap,
            firstOpCap
        );

        vm.stopBroadcast();

        // Emit a compact table for the operator runbook.
        console2.log("=== EW-S1 AA stack deployed on chain", block.chainid, "===");
        console2.log("WebAuthnP256Validator: %s", address(d.webauthn));
        console2.log("CitrateECDSAValidator: %s", address(d.ecdsa));
        console2.log("GuardianRecoveryModule: %s", address(d.recovery));
        console2.log("Kernel implementation: %s", address(d.kernelImpl));
        console2.log("CitrateWalletFactory: %s", address(d.factory));
        console2.log("CitratePaymaster: %s", address(d.paymaster));
        console2.log("EntryPoint (existing): %s", entryPoint);
        console2.log("Identity signer: %s", identitySigner);
        console2.log("Owner: %s", owner);
    }
}
