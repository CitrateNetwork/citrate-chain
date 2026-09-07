// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "../src/AggregationChallenge.sol";
import "../src/KYCRegistry.sol";
import "../src/ComputePoolPipeline.sol";
import "../src/IPFSIncentivesV2.sol";
import "../src/IPFSIncentivesV3.sol";

/// @title DeployFederatedLearning — I64-S1 Phase B / WP-B1
/// @notice Deterministic-deploy ceremony for the five federated-learning
///         contracts that joined the surface after the last reroll:
///           AggregationChallenge, KYCRegistry, ComputePoolPipeline,
///           IPFSIncentivesV2, IPFSIncentivesV3.
///         Each is deployed `new X{salt: Salts.salt("X")}(...)` through the
///         genesis Arachnid CREATE2 factory (0x4e59…), so every reroll that
///         deploys the same bytecode + same constructor args lands each
///         contract at the SAME address — no VERSION bump, so the existing
///         45 addresses are untouched (additions only).
///
/// @dev DETERMINISM INPUTS (Salts.sol §4): every constructor arg below is a
///      pinned literal, because the CREATE2 address = keccak(… ++ init_code)
///      and init_code = creationCode ++ abi.encode(args). Changing ANY value
///      here moves that contract's address. The economic parameters are
///      seeded from each contract's canonical test fixtures.
///
///      ⚠️ OWNER CONFIRM BEFORE REROLL: the economic constants
///      (bonds/rewards/rounds/windows/quorums) are governance decisions AND
///      address-determining. Confirm them, or adjust here, before the
///      ceremony — the dry-run address table reflects whatever is pinned.
///
/// @dev Dependency order (deploy KYCRegistry first; IPFS V2/V3 consume it):
///        KYCRegistry → IPFSIncentivesV2, IPFSIncentivesV3
///        TEEAttestationRegistry (existing) → ComputePoolPipeline
///        NematocystSlashing (existing) → AggregationChallenge (post-deploy
///          governance setter `setSlashingContract`, NOT a constructor arg)
///
/// Usage:
///   # Dry-run (simulate; prints deterministic addresses)
///   forge script script/DeployFederatedLearning.s.sol --rpc-url $RPC --sender $DEPLOYER_ADDRESS
///   # Broadcast (ceremony; requires keystore/HSM signer)
///   forge script script/DeployFederatedLearning.s.sol --rpc-url $RPC --broadcast --account deployer
///
/// Env:
///   - CEREMONY_DEPLOYER_ADDRESS | DEPLOYER_ADDRESS — the canonical genesis
///     deployer 0x4250675F… (ScriptEnv; also used as governance/KYC-updater).
///   - GOVERNANCE — owner of ComputePoolPipeline (default: deployer).
///   - TEE_REGISTRY — existing TEEAttestationRegistry address (default: the
///     canonical 40204 address; must equal the reroll's TEE CREATE2 output —
///     the dry-run diff verifies this).
contract DeployFederatedLearning is ScriptEnv {
    // ── AggregationChallenge (GATE4 referee) ─────────────────────────────
    uint256 internal constant AGG_CHALLENGE_BOND = 1 ether;
    uint256 internal constant AGG_CHALLENGE_WINDOW = 150; // = AggregationChallenge.DEFAULT_WINDOW

    // ── IPFSIncentivesV2 (storage incentives) ────────────────────────────
    uint256 internal constant IPFS_BOND = 10 ether;
    uint256 internal constant IPFS_REWARD = 4 ether;
    uint256 internal constant IPFS_ROUNDS = 4;
    uint256 internal constant IPFS_MAX_MISSED = 1;
    uint256 internal constant IPFS_CHALLENGER_BPS = 5000; // 50%
    uint256 internal constant IPFS_QUORUM = 2;
    uint256 internal constant IPFS_WINDOW = 10;
    uint256 internal constant IPFS_CHALLENGE_N = 32;

    // ── IPFSIncentivesV3 (adds model-CommD challenge layer) ──────────────
    uint256 internal constant IPFS3_CHALLENGER_BOND = 1 ether;
    uint256 internal constant IPFS3_REVEAL_DELAY = 32; // commit→reveal gap (blocks)
    // citrate-chain#170 D3: align with ADR-2026-08-27. MIN_MODEL_BOND 5→55 ether (meaningful skin in
    // the game for a model-owner CommD bond) and the challenge window 100→302400 blocks (~1 week @
    // 2s/block), so a wrong-CommD proof has a realistic window to be produced and submitted.
    uint256 internal constant IPFS3_MIN_MODEL_BOND = 55 ether;
    uint256 internal constant IPFS3_MODEL_CHALLENGE_WINDOW = 302400; // blocks (~1 week)
    uint256 internal constant IPFS3_MODEL_CHALLENGER_BPS = 5000; // 50/50

    // citrate-chain#170 (M3): the recursive-fold CommD proof verifier precompile. 0x0107–0x0109 are
    // taken (tensor-commit / halo2 proof / merkle-tensor); this new family verifies the Nova/Spartan
    // fold proof. Env-overridable so the precompile address can be finalized when M3 lands + activates.
    address internal constant FOLD_VERIFIER_PRECOMPILE = address(0x0130);

    /// Canonical 40204 TEEAttestationRegistry (the LIVE deployed one, = book / DeployTEEAttestationRegistry
    /// output; `cast code` confirms it has bytecode). ComputePoolPipeline binds to this in its constructor.
    /// Fixed 2026-08-27: was 0xc1c0d858…E777E, which has NO code on-chain — ComputePoolPipeline was wired
    /// to a dead registry. Correcting it moves ComputePoolPipeline's own CREATE2 address (its init_code
    /// changes); the address book is updated to the new value. Override via TEE_REGISTRY only if it moves.
    address internal constant TEE_REGISTRY_40204 =
        0x4dF26aae3619f449a142d237ed818Ebf7C186Ed5;

    function run() external {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);
        address teeRegistry = envAddressOr("TEE_REGISTRY", TEE_REGISTRY_40204);

        console.log("=== I64-S1 WP-B1: federated-learning contract deploy ===");
        console.log("Deployer (genesis):", deployer);
        console.log("Governance:        ", governance);
        console.log("TEE registry (dep):", teeRegistry);
        require(teeRegistry != address(0), "TEE registry unset");

        vm.startBroadcast();

        // 1. KYCRegistry — initial authorized updater = deployer (admin can
        //    add the production IDP updater post-deploy). DEFAULT_ADMIN_ROLE
        //    goes to the constructor caller per the contract.
        KYCRegistry kyc = new KYCRegistry{salt: Salts.salt("KYCRegistry")}(deployer);

        // 2. IPFSIncentivesV2 — consumes KYCRegistry.
        IPFSIncentivesV2 ipfsV2 = new IPFSIncentivesV2{salt: Salts.salt("IPFSIncentivesV2")}(
            kyc,
            IPFS_BOND,
            IPFS_REWARD,
            IPFS_ROUNDS,
            IPFS_MAX_MISSED,
            IPFS_CHALLENGER_BPS,
            IPFS_QUORUM,
            IPFS_WINDOW,
            IPFS_CHALLENGE_N
        );

        // 3. IPFSIncentivesV3 — V2 params + model-CommD challenge layer.
        IPFSIncentivesV3 ipfsV3 = new IPFSIncentivesV3{salt: Salts.salt("IPFSIncentivesV3")}(
            kyc,
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
            envAddressOr("FOLD_VERIFIER", FOLD_VERIFIER_PRECOMPILE)
        );
        // citrate-chain#170 (P3): IPFSIncentivesV3 is deployable by BOTH this script and
        // RedeployIPFSIncentivesV3.s.sol under the SAME salt. On a from-main build both land at the
        // canonical #170 address; assert it here so a stale-bytecode build FAILS LOUDLY instead of
        // silently forking V3. (Deterministic given kyc + these params + FOLD_VERIFIER default 0x0130.)
        // Re-armed for the solc-0.8.36 reroll (2026-09-07): the compiler bump moves
        // the deterministic address; the contract is still the sound #170 build from
        // main. Pinned to the 0.8.36 deployed address.
        require(
            address(ipfsV3) == 0xC27a867b8d076d77cf17981f235c64A0D0203a68,
            "IPFSIncentivesV3 address drift: not the #170 sound-CommD-bond bytecode/args"
        );

        // 4. AggregationChallenge — Governable(msg.sender) like NematocystSlashing;
        //    governance + the slashing contract are wired post-deploy (see checklist).
        AggregationChallenge agg = new AggregationChallenge{salt: Salts.salt("AggregationChallenge")}(
            AGG_CHALLENGE_BOND,
            AGG_CHALLENGE_WINDOW
        );

        // 5. ComputePoolPipeline — governance + existing TEE registry.
        ComputePoolPipeline pipeline = new ComputePoolPipeline{salt: Salts.salt("ComputePoolPipeline")}(
            governance,
            teeRegistry
        );

        vm.stopBroadcast();

        console.log("KYCRegistry:        ", address(kyc));
        console.log("IPFSIncentivesV2:   ", address(ipfsV2));
        console.log("IPFSIncentivesV3:   ", address(ipfsV3));
        console.log("AggregationChallenge:", address(agg));
        console.log("ComputePoolPipeline:", address(pipeline));
        console.log("");
        console.log("=== Post-deploy governance wiring (NOT in the deterministic set) ===");
        console.log("1. AggregationChallenge.setSlashingContract(NematocystSlashing 0xfeb2...)");
        console.log("2. AggregationChallenge governance bootstrap (transferGovernance/accept),");
        console.log("   matching the existing NematocystSlashing pattern.");
        console.log("3. KYCRegistry: grant updater role to the production IDP signer.");
        console.log("4. emit-address-table.sh, then sync-addresses across the federation.");
    }
}
