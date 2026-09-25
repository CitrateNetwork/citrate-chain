// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "../src/KYCRegistry.sol";
import "../src/IPFSIncentivesV3.sol";

/// @title RedeployIPFSIncentivesV3 — targeted redeploy for citrate-chain#170
/// @notice IPFSIncentivesV3 is immutable, so the sound-CommD-bond fix (#170) requires a REDEPLOY: the
///         old bytecode (grief-slashable `challengeWrongCommD(cid, data, recomputedCommD)`, 4-arg
///         `registerModel`) stays at its old address; the new bytecode (proof-verified challenge,
///         5-arg `registerModel` with `dataCommit`, `foldVerifier`) lands at a FRESH CREATE2 address.
///
///         This deploys ONLY IPFSIncentivesV3 — it reuses the EXISTING canonical KYCRegistry (unlike
///         the full `DeployFederatedLearning`, which redeploys the whole stack). The economic
///         constants are the D3-corrected literals from `DeployFederatedLearning` (MIN_MODEL_BOND
///         55 ether, MODEL_CHALLENGE_WINDOW 302400); `foldVerifier` defaults to the `0x0130` precompile.
///
/// @dev DETERMINISM: `new IPFSIncentivesV3{salt: Salts.salt("IPFSIncentivesV3")}(...)` through the
///      Arachnid factory ⇒ the address is a pure function of (salt, creationCode, constructor args).
///      With the same KYC + params + foldVerifier this lands at the SAME address a full-stack redeploy
///      would produce for V3. Changing ANY arg here moves the address.
///
///      ⚠️ SEQUENCING (#170): `foldVerifier = 0x0130` is the fold-verifier precompile, which is
///      feature-gated OFF and NOT fleet-activated yet. So after this deploy, `registerModel` works
///      (unblocking CX-S2.2), but `challengeWrongCommD` will REVERT (0x0130 returns "feature absent")
///      until the trusted-setup ceremony + fleet activation land. Honest owners are safe (unslashable);
///      the enforcement path is dormant until activation. This ordering is intended.
///
/// Usage:
///   # Dry-run (simulate; prints the deterministic new address — send nothing):
///   forge script script/RedeployIPFSIncentivesV3.s.sol --rpc-url $CITRATE_RPC_URL --sender $DEPLOYER_ADDRESS
///   # Broadcast (requires the deployer key):
///   forge script script/RedeployIPFSIncentivesV3.s.sol --rpc-url $CITRATE_RPC_URL \
///     --private-key $DEPLOYER_PRIVATE_KEY --broadcast
///
/// Env overrides (all optional; defaults are the canonical 40204 values):
///   KYC_REGISTRY   existing KYCRegistry (default 0xcf41a81c8dfcdb6e61febfc34670964d226b33ed)
///   FOLD_VERIFIER  fold-verifier precompile (default 0x0130)
contract RedeployIPFSIncentivesV3 is ScriptEnv, AdminChecks {
    // Canonical 40204 KYCRegistry (deterministic CREATE2 output of DeployFederatedLearning).
    address internal constant KYC_REGISTRY_40204 =
        0xcf41A81c8dFCDb6E61FeBfC34670964D226B33ED;

    // ── V2-inherited economic params (unchanged; mirror DeployFederatedLearning) ──
    uint256 internal constant IPFS_BOND = 10 ether;
    uint256 internal constant IPFS_REWARD = 4 ether;
    uint256 internal constant IPFS_ROUNDS = 4;
    uint256 internal constant IPFS_MAX_MISSED = 1;
    uint256 internal constant IPFS_CHALLENGER_BPS = 5000; // 50%
    uint256 internal constant IPFS_QUORUM = 2;
    uint256 internal constant IPFS_WINDOW = 10;
    uint256 internal constant IPFS_CHALLENGE_N = 32;

    // ── V3 CommD-challenge params (D3-corrected per ADR-2026-08-27) ──
    uint256 internal constant IPFS3_CHALLENGER_BOND = 1 ether;
    uint256 internal constant IPFS3_REVEAL_DELAY = 32;
    uint256 internal constant IPFS3_MIN_MODEL_BOND = 55 ether; // D3: 5 -> 55
    uint256 internal constant IPFS3_MODEL_CHALLENGE_WINDOW = 302400; // D3: 100 -> 302400 (~1 week)
    uint256 internal constant IPFS3_MODEL_CHALLENGER_BPS = 5000; // 50/50

    address internal constant FOLD_VERIFIER_PRECOMPILE = address(0x0130);

    function run() external {
        address kyc = envAddressOr("KYC_REGISTRY", KYC_REGISTRY_40204);
        address foldVerifier = envAddressOr("FOLD_VERIFIER", FOLD_VERIFIER_PRECOMPILE);
        address admin = envAddressOr("GOVERNANCE", deployerAddress());

        console.log("=== citrate-chain#170: redeploy IPFSIncentivesV3 (sound CommD bond) ===");
        console.log("KYCRegistry (existing):", kyc);
        console.log("foldVerifier (0x0130):", foldVerifier);
        console.log("MIN_MODEL_BOND (wei):", IPFS3_MIN_MODEL_BOND);
        console.log("MODEL_CHALLENGE_WINDOW (blocks):", IPFS3_MODEL_CHALLENGE_WINDOW);
        require(kyc != address(0), "KYC unset");

        vm.startBroadcast();
        IPFSIncentivesV3 v3 = new IPFSIncentivesV3{salt: Salts.salt("IPFSIncentivesV3")}(
            KYCRegistry(kyc),
            IPFS_BOND,
            IPFS_REWARD,
            IPFS_ROUNDS,
            IPFS_MAX_MISSED,
            IPFS_CHALLENGER_BPS,
            IPFS_QUORUM,
            IPFS_WINDOW,
            IPFS_CHALLENGE_N,
            IPFS3_CHALLENGER_BOND,
            IPFS3_REVEAL_DELAY,
            IPFS3_MIN_MODEL_BOND,
            IPFS3_MODEL_CHALLENGE_WINDOW,
            IPFS3_MODEL_CHALLENGER_BPS,
            foldVerifier,
            admin // PBA-L2-002: explicit DEFAULT_ADMIN (never the CREATE2 factory)
        );
        vm.stopBroadcast();
        _assertAdminRole("IPFSIncentivesV3", address(v3), admin);

        console.log("IPFSIncentivesV3 (NEW #170 address):", address(v3));
        console.log("Update contracts/addresses/40204.json + packages/chain-config to this address.");
    }
}
