// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../ScriptEnv.sol";
import "../Salts.sol";
// WS-3: deterministic CREATE2 EntryPoint (deploy-if-absent). Inheriting
// EntryPointDeployer gives DeployAA `projectedEntryPoint()` + `_ensureEntryPoint()`.
import {EntryPointDeployer} from "./DeployEntryPoint.s.sol";

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
import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
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
 *   CITRATE_AA_SPONSOR_SIGNER — EOA whose signature authorises sponsorship (E8-1)
 *   CITRATE_AA_DAILY_CAP     — paymaster daily spend cap, WEI (default 0.01 ether)
 *   CITRATE_AA_RECOVERY_CAP  — paymaster recovery event cap, WEI (default 0.01 ether)
 *   CITRATE_AA_FIRST_OP_CAP  — paymaster first-op cap, WEI (default 0.02 ether)
 *   CITRATE_AA_MAX_FEE_CEIL  — paymaster maxFeePerGas ceiling, WEI/gas (default 20 gwei)
 *   CITRATE_AA_GLOBAL_CAP    — paymaster global daily spend backstop, WEI (default 5 ether)
 *
 * E8-2 cap math (40204 min_gas_price = 1 gwei; devnet-config.toml L38):
 *   ceiling = 20 gwei  → 20x the 1-gwei floor; bounds per-op drain.
 *   first-op = 0.02 ether = 800k gas x 20 gwei  (counterfactual proxy
 *     deploy + Kernel init + first action ~500k gas, +headroom to 800k).
 *   recovery = 0.01 ether = ~300k gas x 20 gwei (guardian recovery flow).
 *   daily    = 0.01 ether = ~500k gas x 20 gwei (a few standard ops/day).
 *   global   = 5 ether/day aggregate across ALL accounts — a drain
 *     backstop; at the realistic 1-gwei price a first-op costs ~0.0005-
 *     0.0008 ether, so 5 ether/day tolerates thousands of onboardings
 *     while capping a fee-inflation drain to 5 ether before the day's
 *     sponsorship fails closed. Owner re-tunes via setters.
 */
contract DeployAA is Script, ScriptEnv, EntryPointDeployer {
    struct Deployment {
        // WS-3: the deterministic CREATE2 EntryPoint every downstream AA
        // contract embeds. Captured here so the human + pin tables report the
        // address actually deployed, not a (possibly stale) env value.
        address entryPoint;
        WebAuthnP256Validator webauthn;
        CitrateECDSAValidator ecdsa;
        GuardianRecoveryModule recovery;
        CitrateWallet walletImpl;
        CitrateWalletFactory factory;
        CitratePaymaster paymaster;
    }

    function run() external virtual returns (Deployment memory d) {
        d = _deploy();
        _emitHumanTable(d);
    }

    // Deploy logic factored out so the WP-D redeploy wrapper
    // (script/aa/DeployAndPinAA.s.sol) can reuse it without duplicating
    // contract instantiation. The wrapper emits the machine-parseable
    // `EW_S1_PIN:` lines the `scripts/ops/post-reroll-redeploy.sh`
    // script greps for, in addition to the human table this script logs.
    function _deploy() internal returns (Deployment memory d) {
        // WS-3: the EntryPoint is no longer read from env as a free variable —
        // it is deployed deterministically via CREATE2 (Salts.salt("EntryPoint"))
        // and always lands at `projectedEntryPoint()`. We still READ the env pin
        // as a fail-closed guard: if an operator has a stale
        // CITRATE_AA_ENTRY_POINT wired, refuse rather than silently embed a
        // different EntryPoint than the one we deploy.
        address projectedEp = projectedEntryPoint();
        address pinnedEp = envAddressOr("CITRATE_AA_ENTRY_POINT", address(0));
        require(
            pinnedEp == address(0) || pinnedEp == projectedEp,
            "CITRATE_AA_ENTRY_POINT != deterministic EntryPoint; unset it or repin to projectedEntryPoint()"
        );
        address identitySigner = envAddressOr("CITRATE_AA_IDENTITY_SIGNER", address(0));
        address owner = envAddressOr("CITRATE_AA_OWNER", address(0));
        // E8-1: the sponsorship signer defaults to the identity signer if
        // unset (single-key operators), but SHOULD be a dedicated key in
        // prod so a leaked deploy-permit signer cannot also drain the
        // paymaster deposit (separation of duties — see ADR).
        address sponsorSigner = envAddressOr("CITRATE_AA_SPONSOR_SIGNER", identitySigner);
        // E8-2: caps in WEI (see header math). 40204 floor = 1 gwei.
        uint256 dailyCap = envUintOr("CITRATE_AA_DAILY_CAP", 0.01 ether);
        uint256 recoveryCap = envUintOr("CITRATE_AA_RECOVERY_CAP", 0.01 ether);
        uint256 firstOpCap = envUintOr("CITRATE_AA_FIRST_OP_CAP", 0.02 ether);
        uint256 maxFeeCeiling = envUintOr("CITRATE_AA_MAX_FEE_CEIL", 20 gwei);
        uint256 globalDailyCap = envUintOr("CITRATE_AA_GLOBAL_CAP", 5 ether);

        require(identitySigner != address(0), "identity signer not set");
        require(owner != address(0), "owner not set");
        require(sponsorSigner != address(0), "sponsor signer not set");

        vm.startBroadcast();

        // WS-3: deploy the deterministic EntryPoint first (idempotent — skipped
        // if already present at its projected address), then embed THAT address
        // in walletImpl / factory / paymaster so the whole cascade is stable.
        d.entryPoint = _ensureEntryPoint();
        require(d.entryPoint == projectedEp, "EntryPoint not at projected address");
        address entryPoint = d.entryPoint;

        d.webauthn = new WebAuthnP256Validator{salt: Salts.salt("WebAuthnP256Validator")}();
        d.ecdsa = new CitrateECDSAValidator{salt: Salts.salt("CitrateECDSAValidator")}();
        d.recovery = new GuardianRecoveryModule{salt: Salts.salt("GuardianRecoveryModule")}();

        // CitrateWallet implementation: thin adapter over Kernel v3.3 with
        // EIP-712 domain separation (see contracts/src/aa/wallet/CitrateWallet.sol).
        // Each user smart wallet is an ERC-1967 minimal proxy of this
        // implementation, deployed via the factory.
        d.walletImpl = new CitrateWallet{salt: Salts.salt("CitrateWallet")}(IKernelEntryPoint(entryPoint));

        // Factory needs the implementation address + identity signer + owner.
        d.factory = new CitrateWalletFactory{salt: Salts.salt("CitrateWalletFactory")}(address(d.walletImpl), identitySigner, owner);

        // Paymaster wired to the EntryPoint + factory as registrar.
        d.paymaster = new CitratePaymaster{salt: Salts.salt("CitratePaymaster")}(
            IAaEntryPoint(entryPoint),
            owner,
            address(d.factory),
            sponsorSigner,
            dailyCap,
            recoveryCap,
            firstOpCap,
            maxFeeCeiling,
            globalDailyCap
        );

        // E-8: wire the registry direction factory → paymaster so every
        // deploy registers its wallet atomically
        // (ADR-2026-07-11-e8-atomic-factory-registration). `setPaymaster`
        // is owner-gated; when the ceremony broadcaster is not the owner
        // (prod multisig), the owner must perform this call before ANY
        // wallet deploy — `deployFor` fails closed (PaymasterNotSet)
        // until then.
        (, address broadcaster,) = vm.readCallers();
        if (broadcaster == owner) {
            d.factory.setPaymaster(address(d.paymaster));
        }

        vm.stopBroadcast();

        if (broadcaster != owner) {
            console2.log("ACTION REQUIRED: factory owner %s must call", owner);
            console2.log("  CitrateWalletFactory(%s).setPaymaster(%s)", address(d.factory), address(d.paymaster));
            console2.log("  before any wallet deploy (deployFor fails closed until wired).");
        }
    }

    /// Human-readable summary the operator reads at the end of a ceremony.
    function _emitHumanTable(Deployment memory d) internal view {
        // WS-3: report the EntryPoint actually deployed (deterministic), not env.
        address entryPoint = d.entryPoint;
        address identitySigner = envAddressOr("CITRATE_AA_IDENTITY_SIGNER", address(0));
        address owner = envAddressOr("CITRATE_AA_OWNER", address(0));

        console2.log("=== EW-S1 AA stack deployed on chain", block.chainid, "===");
        console2.log("WebAuthnP256Validator: %s", address(d.webauthn));
        console2.log("CitrateECDSAValidator: %s", address(d.ecdsa));
        console2.log("GuardianRecoveryModule: %s", address(d.recovery));
        console2.log("CitrateWallet implementation: %s", address(d.walletImpl));
        console2.log("CitrateWalletFactory: %s", address(d.factory));
        console2.log("CitratePaymaster: %s", address(d.paymaster));
        console2.log("EntryPoint (deterministic CREATE2): %s", entryPoint);
        console2.log("Identity signer: %s", identitySigner);
        console2.log("Owner: %s", owner);
    }
}
