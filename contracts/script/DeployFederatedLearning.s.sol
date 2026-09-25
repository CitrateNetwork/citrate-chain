// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
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
///         Each is deployed `new X{salt: Salts.salt("X")}(...)` (or reused when
///         already live, see script/lib/Create2Deploy.sol) through the
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
///   - TEE_REGISTRY — REQUIRED, no default: the reviewed TEEAttestationRegistry
///     address (must have code; the run refuses otherwise).
contract DeployFederatedLearning is ScriptEnv, AdminChecks, Create2Deploy {
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

    /// TEEAttestationRegistry that ComputePoolPipeline binds to in its constructor.
    /// There is deliberately NO baked-in default: the previous default
    /// (0x4dF2…6Ed5) has no code on 40204, and the registry is redeployed with
    /// the PBA-R2 hardening, so the ceremony must name the reviewed address.
    /// TEE_REGISTRY is REQUIRED and must have code.

    function run() external {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);
        address teeRegistry = envAddressOr("TEE_REGISTRY", address(0));

        console.log("=== I64-S1 WP-B1: federated-learning contract deploy ===");
        console.log("Deployer (genesis):", deployer);
        console.log("Governance:        ", governance);
        console.log("TEE registry (dep):", teeRegistry);
        require(teeRegistry != address(0), "TEE_REGISTRY must be set (no default)");
        require(teeRegistry.code.length != 0, "TEE_REGISTRY has no code on this chain");

        vm.startBroadcast();

        // 1. KYCRegistry — initial authorized updater = deployer (admin can
        //    add the production IDP updater post-deploy). PBA-L2-002:
        //    DEFAULT_ADMIN_ROLE is the explicit `governance` argument, NOT the
        //    constructor caller (which is the CREATE2 factory here).
        KYCRegistry kyc = (_isLive("KYCRegistry", abi.encodePacked(type(KYCRegistry).creationCode, abi.encode(deployer, governance)))
            ? KYCRegistry(payable(_create2Address("KYCRegistry", abi.encodePacked(type(KYCRegistry).creationCode, abi.encode(deployer, governance)))))
            : new KYCRegistry{salt: Salts.salt("KYCRegistry")}(deployer, governance));

        // 2. IPFSIncentivesV2 — consumes KYCRegistry.
        IPFSIncentivesV2 ipfsV2 = (_isLive("IPFSIncentivesV2", abi.encodePacked(type(IPFSIncentivesV2).creationCode, abi.encode(
            kyc,
            IPFS_BOND,
            IPFS_REWARD,
            IPFS_ROUNDS,
            IPFS_MAX_MISSED,
            IPFS_CHALLENGER_BPS,
            IPFS_QUORUM,
            IPFS_WINDOW,
            IPFS_CHALLENGE_N,
            governance // PBA-L2-002: explicit DEFAULT_ADMIN
        )))
            ? IPFSIncentivesV2(payable(_create2Address("IPFSIncentivesV2", abi.encodePacked(type(IPFSIncentivesV2).creationCode, abi.encode(
            kyc,
            IPFS_BOND,
            IPFS_REWARD,
            IPFS_ROUNDS,
            IPFS_MAX_MISSED,
            IPFS_CHALLENGER_BPS,
            IPFS_QUORUM,
            IPFS_WINDOW,
            IPFS_CHALLENGE_N,
            governance // PBA-L2-002: explicit DEFAULT_ADMIN
        )))))
            : new IPFSIncentivesV2{salt: Salts.salt("IPFSIncentivesV2")}(
            kyc,
            IPFS_BOND,
            IPFS_REWARD,
            IPFS_ROUNDS,
            IPFS_MAX_MISSED,
            IPFS_CHALLENGER_BPS,
            IPFS_QUORUM,
            IPFS_WINDOW,
            IPFS_CHALLENGE_N,
            governance // PBA-L2-002: explicit DEFAULT_ADMIN
        ));

        // 3. IPFSIncentivesV3 — V2 params + model-CommD challenge layer.
        IPFSIncentivesV3 ipfsV3 = (_isLive("IPFSIncentivesV3", abi.encodePacked(type(IPFSIncentivesV3).creationCode, abi.encode(
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
            envAddressOr("FOLD_VERIFIER", FOLD_VERIFIER_PRECOMPILE),
            governance // PBA-L2-002: explicit DEFAULT_ADMIN
        )))
            ? IPFSIncentivesV3(payable(_create2Address("IPFSIncentivesV3", abi.encodePacked(type(IPFSIncentivesV3).creationCode, abi.encode(
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
            envAddressOr("FOLD_VERIFIER", FOLD_VERIFIER_PRECOMPILE),
            governance // PBA-L2-002: explicit DEFAULT_ADMIN
        )))))
            : new IPFSIncentivesV3{salt: Salts.salt("IPFSIncentivesV3")}(
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
            envAddressOr("FOLD_VERIFIER", FOLD_VERIFIER_PRECOMPILE),
            governance // PBA-L2-002: explicit DEFAULT_ADMIN
        ));
        // citrate-chain#170 (P3): IPFSIncentivesV3 is deployable by BOTH this script and
        // RedeployIPFSIncentivesV3.s.sol under the SAME salt. On a from-main build both land at the
        // canonical #170 address; assert it here so a stale-bytecode build FAILS LOUDLY instead of
        // silently forking V3. (Deterministic given kyc + these params + FOLD_VERIFIER default 0x0130.)
        // Re-armed for the solc-0.8.36 reroll (2026-09-07): the compiler bump moves
        // the deterministic address; the contract is still the sound #170 build from
        // main. Pinned to the 0.8.36 deployed address.
        // PBA-L2-002 (2026-09-24): the old pin (0xC27a…3a68) is the V3 whose
        // DEFAULT_ADMIN is the CREATE2 factory; the explicit-admin constructor
        // necessarily moves the address, and it moves again with the governance
        // key. The pin is now supplied by the ceremony: on 40204 the run REFUSES
        // to proceed unless EXPECTED_IPFS_V3 is set to the reviewed dry-run
        // address and matches. Off 40204 (dev/test dry-runs) it is checked when set.
        address expectedV3 = envAddressOr("EXPECTED_IPFS_V3", address(0));
        if (block.chainid == 40204) {
            require(expectedV3 != address(0), "EXPECTED_IPFS_V3 must be pinned on 40204");
        }
        if (expectedV3 != address(0)) {
            require(
                address(ipfsV3) == expectedV3,
                "IPFSIncentivesV3 address drift: not the reviewed bytecode/args"
            );
        }

        // 4. AggregationChallenge — PBA-L2-002: governance is explicit (it was
        //    Governable(msg.sender) = the CREATE2 factory). The slashing contract
        //    is still wired post-deploy by governance (see checklist).
        AggregationChallenge agg = (_isLive("AggregationChallenge", abi.encodePacked(type(AggregationChallenge).creationCode, abi.encode(
            AGG_CHALLENGE_BOND,
            AGG_CHALLENGE_WINDOW,
            governance
        )))
            ? AggregationChallenge(payable(_create2Address("AggregationChallenge", abi.encodePacked(type(AggregationChallenge).creationCode, abi.encode(
            AGG_CHALLENGE_BOND,
            AGG_CHALLENGE_WINDOW,
            governance
        )))))
            : new AggregationChallenge{salt: Salts.salt("AggregationChallenge")}(
            AGG_CHALLENGE_BOND,
            AGG_CHALLENGE_WINDOW,
            governance
        ));

        // 5. ComputePoolPipeline — governance + existing TEE registry.
        ComputePoolPipeline pipeline = (_isLive("ComputePoolPipeline", abi.encodePacked(type(ComputePoolPipeline).creationCode, abi.encode(
            governance,
            teeRegistry
        )))
            ? ComputePoolPipeline(payable(_create2Address("ComputePoolPipeline", abi.encodePacked(type(ComputePoolPipeline).creationCode, abi.encode(
            governance,
            teeRegistry
        )))))
            : new ComputePoolPipeline{salt: Salts.salt("ComputePoolPipeline")}(
            governance,
            teeRegistry
        ));

        vm.stopBroadcast();

        // PBA-L2-002 tripwire: every admin slot names `governance`, never the factory.
        _assertAdminRole("KYCRegistry", address(kyc), governance);
        _assertAdminRole("IPFSIncentivesV2", address(ipfsV2), governance);
        _assertAdminRole("IPFSIncentivesV3", address(ipfsV3), governance);
        _assertGovernance("AggregationChallenge", address(agg), governance);
        _assertNoFactoryAdmin("ComputePoolPipeline", address(pipeline));

        console.log("KYCRegistry:        ", address(kyc));
        console.log("IPFSIncentivesV2:   ", address(ipfsV2));
        console.log("IPFSIncentivesV3:   ", address(ipfsV3));
        console.log("AggregationChallenge:", address(agg));
        console.log("ComputePoolPipeline:", address(pipeline));
        console.log("");
        console.log("=== Post-deploy governance wiring (NOT in the deterministic set) ===");
        console.log("1. AggregationChallenge.setSlashingContract(NematocystSlashing 0xfeb2...)");
        console.log("2. (PBA-L2-002) governance is already the GOVERNANCE key; no bootstrap.");
        console.log("3. KYCRegistry: grant updater role to the production IDP signer.");
        console.log("4. emit-address-table.sh, then sync-addresses across the federation.");
    }
}
