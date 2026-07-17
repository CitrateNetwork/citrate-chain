// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "../src/ValidatorRegistry.sol";

/// @title DeployValidatorRegistry — VALIDATOR-S1 (v5) reroll-stable deploy (WS-5)
/// @notice Deploys the `ValidatorRegistry` for chain 40204 via the genesis
///         Arachnid CREATE2 factory (0x4e59…4956C) at
///         `Salts.salt("ValidatorRegistry")`, so the address is a pure
///         function of (factory, salt, init_code) and is reroll-stable /
///         pre-pinnable. Mirrors the business-contract deploy pattern
///         (see DeployComputePoolTraining.s.sol) — the signer is supplied by
///         the forge CLI (`--account`/`--keystore`/`--private-key`), never
///         embedded here.
///
/// @dev  THE CONSTRUCTOR ARGS FIX THE CREATE2 ADDRESS PERMANENTLY. Every byte
///       of the init_code — including the 7 abi-encoded constructor args below
///       — feeds `keccak256(init_code)`. Change ANY of them and the deployed
///       address moves. They are therefore literal constants here (no env
///       overrides), so the address is deterministic and reproducible on any
///       box. The address the fleet pins (`CITRATE_VALIDATOR_REGISTRY`) is
///       `projectedAddress(ARACHNID_FACTORY)` for the exact constant values
///       committed in this file.
///
///       RE-PROJECTION RECIPE (finalize owner-decision values → final address):
///         1. Edit the OWNER-DECISION constants below to the final values.
///         2. `cd contracts && forge test --mp test/ValidatorRegistryCreate2.t.sol -vv`
///            The test logs `projected (Arachnid factory) address = 0x…` — that
///            is the final `CITRATE_VALIDATOR_REGISTRY` to bake into every node.
///         3. Deploy at the reroll:
///            `forge script script/DeployValidatorRegistry.s.sol \
///               --rpc-url $CITRATE_TESTNET_RPC --broadcast \
///               --account deployer --sender $DEPLOYER_ADDRESS`
///
/// Usage (dry-run / simulate):
///   forge script script/DeployValidatorRegistry.s.sol \
///     --rpc-url $CITRATE_TESTNET_RPC --sender $DEPLOYER_ADDRESS
contract DeployValidatorRegistry is ScriptEnv {
    // ─────────────────────────────────────────────────────────────────────────
    // Canonical genesis DEPLOYER (0x4250675F…000c6) — the genesis root of trust
    // (10M SALT, deploys everything). See core/economics/src/genesis.rs
    // TESTNET_DEPLOYER_ADDRESS. Used as the default admin trio below.
    // ─────────────────────────────────────────────────────────────────────────
    address public constant GENESIS_DEPLOYER = 0x4250675F9015E65fC866F3a373F82bb9DFc000c6;

    // Canonical Arachnid deterministic CREATE2 factory (EIP-2470), pre-stamped in
    // every Citrate genesis profile. Forge routes `new X{salt:}` through it, so
    // the REROLL address is projected against THIS deployer (not the broadcaster).
    address public constant ARACHNID_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    // ═════════════════════════════════════════════════════════════════════════
    // ADMIN TRIO (constructor args 1–3) — address-fixing.
    //   governance_ : timelocked param/slasher governor. Two-step Governable;
    //                 swappable later to a timelock/multisig WITHOUT moving the
    //                 address (it is mutable state, not the ctor-encoded value's
    //                 effect — but the ctor VALUE still fixes the address, so it
    //                 must stay constant across rerolls of the SAME registry).
    //   slasher_    : authorizes Latency/Inconsistency slash tiers. Governance
    //                 can re-point it post-deploy (queueSlasher/executeSlasher).
    //   rewardMinter_ : IMMUTABLE in the contract — the execution-layer system
    //                 address allowed to call creditReward(). See RECONCILE note.
    // Defaulting all three to the genesis DEPLOYER is the recommended bootstrap.
    // ═════════════════════════════════════════════════════════════════════════
    address public constant GOVERNANCE = GENESIS_DEPLOYER;
    address public constant SLASHER = GENESIS_DEPLOYER;

    // ── rewardMinter_ — RECONCILE WITH WS-4 §R' (built in parallel) ─────────────
    // rewardMinter is IMMUTABLE in ValidatorRegistry and is the ONLY address that
    // may call `creditReward(pubkey, amount)` (the §R' stake-weighted reward
    // vesting path). WS-4 owns the execution→registry reward call and therefore
    // dictates the msg.sender that call uses — REWARD_MINTER MUST equal that
    // address or every creditReward reverts `NotMinter()`.
    //
    // At the reroll §R' is INERT: under CITRATE_BLOCK_V2=1 the producer is forced
    // onto the deterministic basic-reward path (canonical_reward_config), and §R'
    // is a *future* deterministic reward policy that slots into that same seam
    // (docs/consensus/REROLL_ADDENDUM_… §A). So a placeholder is safe for the
    // reroll, but because it is immutable it MUST be finalized to WS-4's value
    // BEFORE the address is pinned. Default: genesis DEPLOYER.
    //   >>> RECONCILE WITH WS-4 §R' — see build/ws4 report <<<
    address public constant REWARD_MINTER = GENESIS_DEPLOYER;

    // ═════════════════════════════════════════════════════════════════════════
    // ECONOMIC POLICY (constructor args 4–7) — IMMUTABLE + address-fixing.
    // These are OWNER DECISIONS. They fix the CREATE2 address. The values below
    // are PLACEHOLDERS chosen only to be self-consistent and within the
    // contract's immutable bounds — do NOT treat them as final money policy.
    // Finalize them, then re-project the address (recipe in the contract docs).
    //
    //   MIN_STAKE            (bounds: [1_000, 1_000_000] ether)
    //     Minimum bond to enter the active set. OWNER-DECIDED = 32_000 SALT
    //     (threshold locked 2026-07-16, CITRATE_CORE_DGX_WORKORDER). Governance
    //     may raise it later (prospective; sitting validators grandfathered).
    //
    //   BLOCK_SUBSIDY        (bounds: <= 1_000 ether)  [PLACEHOLDER]
    //     Per-selected-block validator subsidy the §R' path will emit. Placeholder
    //     10 SALT/block. FINAL = owner economic decision.
    //
    //   PRIORITY_FEE_SHARE_BPS (bounds: < 10_000)      [PLACEHOLDER]
    //     Share (bps) of priority fees routed to the validator reward path.
    //     Placeholder 5_000 (50%). FINAL = owner economic decision.
    //
    //   MAX_EPOCH_EMISSION   (bounds: <= 1_000_000 ether) [PLACEHOLDER]
    //     Hard anti-hyperinflation cap on reward emission per 1_000-block epoch.
    //     Placeholder 10_000 SALT (= BLOCK_SUBSIDY × 1_000 blocks). FINAL = owner.
    // ═════════════════════════════════════════════════════════════════════════
    uint256 public constant MIN_STAKE = 32_000 ether;                 // OWNER-DECIDED (locked 32k)
    uint256 public constant BLOCK_SUBSIDY = 10 ether;                 // OWNER-DECISION placeholder
    uint256 public constant PRIORITY_FEE_SHARE_BPS = 5_000;           // OWNER-DECISION placeholder
    uint256 public constant MAX_EPOCH_EMISSION = 10_000 ether;        // OWNER-DECISION placeholder

    /// The canonical CREATE2 salt for the registry.
    function registrySalt() public pure returns (bytes32) {
        return Salts.salt("ValidatorRegistry");
    }

    /// abi-encoded constructor args (the tail of the init_code). Single source of
    /// truth consumed by run(), projectedAddress(), and the determinism test.
    function ctorArgs() public pure returns (bytes memory) {
        return abi.encode(
            GOVERNANCE,
            SLASHER,
            REWARD_MINTER,
            MIN_STAKE,
            BLOCK_SUBSIDY,
            PRIORITY_FEE_SHARE_BPS,
            MAX_EPOCH_EMISSION
        );
    }

    /// Full CREATE2 init_code = creationCode ++ abi.encode(args). `bytecode_hash =
    /// "none"` (foundry.toml) strips solc metadata so this is byte-reproducible.
    function initCode() public pure returns (bytes memory) {
        return abi.encodePacked(type(ValidatorRegistry).creationCode, ctorArgs());
    }

    /// Pure CREATE2 address projection for a given deployer:
    ///   keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:].
    /// `projectedAddress(ARACHNID_FACTORY)` is the reroll address the fleet pins.
    function projectedAddress(address deployer) public pure returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), deployer, registrySalt(), keccak256(initCode()))
        );
        return address(uint160(uint256(h)));
    }

    function run() external {
        address deployer = deployerAddress();
        address projected = projectedAddress(ARACHNID_FACTORY);

        console.log("=== ValidatorRegistry (VALIDATOR-S1) CREATE2 deploy ===");
        console.log("chainid                :", block.chainid);
        console.log("signer (deployer)      :", deployer);
        console.log("Arachnid factory       :", ARACHNID_FACTORY);
        console.log("governance_            :", GOVERNANCE);
        console.log("slasher_               :", SLASHER);
        console.log("rewardMinter_ (WS-4!)  :", REWARD_MINTER);
        console.log("minStake_        (wei) :", MIN_STAKE);
        console.log("blockSubsidy_    (wei) :", BLOCK_SUBSIDY);
        console.log("priorityFeeShareBps_   :", PRIORITY_FEE_SHARE_BPS);
        console.log("maxEpochEmission_(wei) :", MAX_EPOCH_EMISSION);
        console.log("PROJECTED registry addr:", projected);

        vm.startBroadcast();
        ValidatorRegistry registry = new ValidatorRegistry{salt: registrySalt()}(
            GOVERNANCE,
            SLASHER,
            REWARD_MINTER,
            MIN_STAKE,
            BLOCK_SUBSIDY,
            PRIORITY_FEE_SHARE_BPS,
            MAX_EPOCH_EMISSION
        );
        vm.stopBroadcast();

        console.log("DEPLOYED registry addr :", address(registry));
        require(
            address(registry) == projected,
            "deployed address != CREATE2 projection (salt/init_code drift)"
        );

        console.log("");
        console.log("=== FLEET ENV BLOCK (identical on ALL 4 nodes; a single drift forks) ===");
        console.log("CITRATE_BLOCK_V2=1");
        console.log("CITRATE_VALIDATOR_ACTIVATION_HEIGHT=1000");
        console.log("CITRATE_VALIDATOR_REGISTRY=", address(registry));
        console.log("");
        console.log("=== SEED TIMING (CRITICAL) ===");
        console.log("Run the registration ceremony (register 4 fleet validators)");
        console.log("BEFORE snapshot S(1)=800 (~height 800). Validators not in the");
        console.log("registry by S(1) are excluded from the epoch-1 active set and");
        console.log("cannot propose at/after the 1000 activation height.");
    }
}
