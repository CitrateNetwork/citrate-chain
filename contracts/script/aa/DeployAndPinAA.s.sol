// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {DeployAA} from "./DeployAA.s.sol";

/**
 * @title DeployAndPinAA
 * @notice WP-D thin wrapper around DeployAA: runs the same EW-S1 ERC-4337
 *         v0.7 deploy, then emits a machine-parseable `EW_S1_PIN:` block
 *         on stdout that the operator script
 *         `scripts/ops/post-reroll-redeploy.sh` greps for + writes back
 *         to `.env.testnet`.
 *
 * The shape of every emitted line is:
 *
 *     EW_S1_PIN: CITRATE_AA_<NAME>=<address>
 *
 * Exactly one space between the marker prefix `EW_S1_PIN:` and the
 * `CITRATE_AA_*=value` pair. The marker prefix exists so the parser
 * never confuses a deploy log line with a coincidental env-var-shaped
 * Solidity console2.log call.
 *
 * Run:
 *
 *     RPC_URL=$(grep '^RPC_URL=' /home/saul/Projects/Citrate-Labs/.env.testnet \
 *               | head -1 | cut -d= -f2-)
 *     forge script script/aa/DeployAndPinAA.s.sol \
 *       --rpc-url "$RPC_URL" \
 *       --account ceremony-deployer \
 *       --sender 0x4250675F9015E65fC866F3a373F82bb9DFc000c6 \
 *       --broadcast
 *
 * Used end-to-end by scripts/ops/post-reroll-redeploy.sh.
 */
contract DeployAndPinAA is DeployAA {
    /// Returning an explicit struct keeps forge's --json output stable,
    /// which a tooling consumer can use instead of grepping the console.
    function run() external override returns (Deployment memory d) {
        d = _deploy();
        _emitHumanTable(d);
        _emitPinTable(d);
    }

    /// Emit one `EW_S1_PIN: CITRATE_AA_<NAME>=<addr>` line per AA
    /// contract the redeploy ceremony produces. The bash wrapper greps
    /// for `^EW_S1_PIN:` and rewrites `.env.testnet` in place from these.
    function _emitPinTable(Deployment memory d) internal view {
        address entryPoint = envAddressOr("CITRATE_AA_ENTRY_POINT", address(0));
        // EntryPoint is vendored (not redeployed by this script); pinning
        // it back unchanged makes the parser idempotent on a no-op rerun.
        _pin("CITRATE_AA_ENTRY_POINT", entryPoint);
        _pin("CITRATE_AA_WEBAUTHN_VALIDATOR", address(d.webauthn));
        _pin("CITRATE_AA_ECDSA_VALIDATOR", address(d.ecdsa));
        _pin("CITRATE_AA_GUARDIAN_RECOVERY", address(d.recovery));
        _pin("CITRATE_AA_WALLET_IMPL", address(d.walletImpl));
        _pin("CITRATE_AA_FACTORY", address(d.factory));
        _pin("CITRATE_AA_PAYMASTER", address(d.paymaster));
    }

    function _pin(string memory key, address addr) internal view {
        console2.log(string.concat("EW_S1_PIN: ", key, "=", vm.toString(addr)));
    }
}
