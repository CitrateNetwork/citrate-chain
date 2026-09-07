// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../Salts.sol";

// Vendored account-abstraction v0.7.0 canonical EntryPoint.
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";

/**
 * @title EntryPointDeployer — deterministic CREATE2 deploy of the AA v0.7 EntryPoint
 * @notice WS-3 of the chain-40204 reroll: make the ERC-4337 EntryPoint land at a
 *         reroll-STABLE address so the whole AA cascade (walletImpl → factory →
 *         paymaster → guardian) stops moving on every re-roll.
 *
 *   Owner decision = Option 1 (custom salt): the EntryPoint is deployed via
 *
 *       new EntryPoint{salt: Salts.salt("EntryPoint")}()
 *
 *   which Foundry routes through the genesis Arachnid CREATE2 factory
 *   (0x4e59b44847b379578588920cA78FbF26c0B4956C). The resulting address is
 *
 *       keccak256(0xff ++ 0x4e59… ++ salt ++ keccak256(creationCode))[12:]
 *
 *   and depends ONLY on (deployer=0x4e59…, salt, creationCode) — NOT on the
 *   broadcasting EOA's nonce or deploy order. Every reroll that deploys the
 *   same EntryPoint bytecode with the same salt therefore lands it at the same
 *   permanent address.
 *
 *   The v0.7 EntryPoint has NO explicit constructor; the only in-ctor work is
 *   `SenderCreator private immutable _senderCreator = new SenderCreator()`, an
 *   internal CREATE that spawns SenderCreator at a nonce-derived address but
 *   does NOT affect the EntryPoint's own CREATE2 address (creationCode already
 *   embeds SenderCreator's creationCode). So `new EntryPoint{salt}()` is fully
 *   deterministic.
 *
 *   DETERMINISM INPUTS (must be pinned; same set as script/Salts.sol):
 *     1. deployer — the Arachnid 0x4e59… factory (CREATE2 ignores broadcaster nonce).
 *     2. salt — Salts.salt("EntryPoint").
 *     3. creationCode — solc 0.8.36 + optimizer(200) + via_ir + bytecode_hash=none
 *        (foundry.toml [profile.default]). Do NOT deploy under FOUNDRY_PROFILE=citrate
 *        (optimizer_runs=10000) — that yields different bytecode and a different address.
 */
abstract contract EntryPointDeployer is Script {
    /// Deterministic CREATE2 address of the EntryPoint as deployed through the
    /// Arachnid factory (0x4e59…). Pure so consumers/tests can project it
    /// without a deploy. `CREATE2_FACTORY` is inherited from forge-std's
    /// CommonBase (= 0x4e59b44847b379578588920cA78FbF26c0B4956C).
    function projectedEntryPoint() public pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            CREATE2_FACTORY,
                            Salts.salt("EntryPoint"),
                            keccak256(type(EntryPoint).creationCode)
                        )
                    )
                )
            )
        );
    }

    /// Deploy-if-absent. Idempotent: if the projected address already holds
    /// code (prior reroll step, or a re-run of this script) it is returned
    /// unchanged — re-issuing the CREATE2 would revert on the live address.
    /// MUST be called inside an active `vm.startBroadcast()` for the deploy
    /// to be broadcast.
    function _ensureEntryPoint() internal returns (address ep) {
        ep = projectedEntryPoint();
        if (ep.code.length == 0) {
            EntryPoint deployed = new EntryPoint{salt: Salts.salt("EntryPoint")}();
            require(address(deployed) == ep, "EntryPoint CREATE2 address mismatch");
        }
    }
}

/**
 * @notice Standalone runner: deploy the deterministic EntryPoint on its own.
 *
 * Run:
 *   forge script script/aa/DeployEntryPoint.s.sol \
 *     --rpc-url "$RPC_URL" \
 *     --account ceremony-deployer \
 *     --sender 0x4250675F9015E65fC866F3a373F82bb9DFc000c6 \
 *     --broadcast
 *
 * `script/aa/DeployAA.s.sol` calls `_ensureEntryPoint()` itself, so a separate
 * run of this script is optional — it exists so the EntryPoint can be stood up
 * (or its address printed) independently of the rest of the AA cascade.
 */
contract DeployEntryPoint is EntryPointDeployer {
    function run() external returns (address ep) {
        vm.startBroadcast();
        ep = _ensureEntryPoint();
        vm.stopBroadcast();
        console2.log("EntryPoint (deterministic, chain %s): %s", block.chainid, ep);
    }
}
