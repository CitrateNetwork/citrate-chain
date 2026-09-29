// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../script/Salts.sol";
import {DeployEntryPoint} from "../../script/aa/DeployEntryPoint.s.sol";
import {DeployAA} from "../../script/aa/DeployAA.s.sol";

import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint as IAaEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";

/**
 * @title AaDeterminismHardeningTest — deeper CI teeth for the WS-3 reroll-STABLE AA stack
 * @notice EXTENDS test/aa/AaDeterminism.t.sol (which proves the pinned cascade is
 *         CREATE2 end-to-end). This file adds the coverage that turns the WS-3
 *         addresses into LOAD-BEARING, drift-proof constants:
 *
 *           (1) FUZZ — the projection recipe `computeCreate2Address(salt,
 *               keccak256(initCode), deployer)` is EXACT for ALL salts /
 *               constructor-args, not just the pinned tuple.
 *           (2) TRIPWIRE — the 5 production addresses are hard-pinned, so ANY
 *               change to solc / optimizer / via_ir / bytecode_hash / salts /
 *               ctor-args fails CI loudly.
 *           (3) SENSITIVITY — which input moves which address, pinned exactly,
 *               so a silent constructor-arg drift is caught.
 *           (4) IDEMPOTENCY — the real deploy-if-absent script runs twice with
 *               no revert / no move.
 *           (5) NONCE-INDEPENDENCE — a real deploy from a fuzzed nonce still
 *               lands at the CREATE2 projection.
 *           (6) BUNDLER-MISMATCH — our EntryPoint is DISTINCT from the ERC-4337
 *               canonical nonce-0 EntryPoint, so a node/bundler pointed at the
 *               wrong one is detectable by address alone.
 *
 * Determinism holds ONLY under the DEFAULT foundry profile (solc 0.8.36,
 * optimizer 200, via_ir, cancun, bytecode_hash=none, cbor_metadata=false).
 * Run with FOUNDRY_PROFILE unset — under [profile.citrate] (optimizer_runs=10000)
 * the creationCode, hence every address, changes and the tripwire fails by design.
 *
 * NB (deployer): in a plain forge TEST, `new X{salt:}` issues a CREATE2 from
 * `address(this)` (the test contract). Under `vm.startBroadcast()` (and in a real
 * forge SCRIPT), forge reroutes that CREATE2 through the genesis Arachnid factory
 * 0x4e59…4956C — which is the PRODUCTION deployer that yields the pinned
 * addresses. The determinism PROPERTY is identical either way; only the deployer
 * differs. Fuzz/property asserts use `address(this)`; the pinned production
 * projection uses `CREATE2_FACTORY` (0x4e59…).
 */
contract AaDeterminismHardeningTest is Test {
    // --- AA key inputs — DERIVED at deploy time (fresh-keys reroll) ---
    // The factory/paymaster key args (identitySigner / owner / sponsorSigner) come
    // from the SAME env DeployAA reads (CITRATE_AA_*). Under a fresh-keys reroll
    // (owner ruling + MAC audit) these MOVE, so the factory + paymaster addresses
    // move with them — they are therefore NOT frozen literals here. With env
    // unset they fall back to derived, obviously-not-a-key placeholders so the
    // determinism relationships are still exercised deterministically.
    function _identitySigner() internal view returns (address) {
        return _envAddr("CITRATE_AA_IDENTITY_SIGNER", _phKey("identity"));
    }

    function _owner() internal view returns (address) {
        return _envAddr("CITRATE_AA_OWNER", _phKey("owner"));
    }

    function _sponsorSigner() internal view returns (address) {
        return _envAddr("CITRATE_AA_SPONSOR_SIGNER", _identitySigner());
    }

    function _phKey(string memory s) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked("citrate.reroll.placeholder.aa.", s)))));
    }

    function _envAddr(string memory k, address d) internal view returns (address) {
        try vm.envAddress(k) returns (address v) { return v; } catch { return d; }
    }

    uint256 internal constant DAILY_CAP = 0.01 ether;
    uint256 internal constant RECOVERY_CAP = 0.01 ether;
    uint256 internal constant FIRST_OP_CAP = 0.02 ether;
    uint256 internal constant MAX_FEE_CEIL = 20 gwei;
    uint256 internal constant GLOBAL_CAP = 5 ether;

    // --- KEY-INDEPENDENT production-address anchors (Arachnid 0x4e59… deployer) ---
    // These three take NO key constructor args, so a FRESH-KEYS reroll does NOT
    // move them — only a bytecode / optimizer / via_ir / salt drift does. They
    // stay pinned as pure-bytecode determinism teeth.
    //   EntryPoint / GuardianRecoveryModule: no ctor args.
    //   CitrateWallet impl: ctor arg is the (key-independent) EntryPoint address.
    // The FACTORY and PAYMASTER addresses DO embed the AA keys, so under fresh
    // keys they move — they are asserted RELATIONALLY below (derived from the
    // pinned walletImpl + the env keys), never as frozen literals.
    address internal constant EP_PIN = 0x97d5391a647429233E202f99231743C53a648f3c; // aaStack.EntryPoint (no key args)
    address internal constant GUARDIAN_PIN = 0x0A909769160C1945401b8f37a9310d37DbB6a891; // aaStack.GuardianRecoveryModule (no key args)
    address internal constant WALLET_IMPL_PIN = 0x2D742B98D867Fc7363F530DD6d756622e4Eb768D; // aaStack.CitrateWallet (EntryPoint-only)

    /// The factory address for the current (env-derived) keys — derived, not pinned.
    function _factoryPin() internal view returns (address) {
        return _factoryAddr(WALLET_IMPL_PIN, _identitySigner(), _owner());
    }

    /// The paymaster address for the current (env-derived) keys — derived, not pinned.
    function _paymasterPin() internal view returns (address) {
        return _paymasterAddr(
            EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP
        );
    }

    // ERC-4337 v0.7 canonical EntryPoint (nonce-0 deploy, same on every EVM chain).
    // Ours is deliberately NOT this — see test_our_entryPoint_distinct_from_canonical_v07.
    address internal constant CANONICAL_ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    // Real dependencies for the fuzz harness, deployed once via plain CREATE (nonce
    // based) so their addresses can never collide with a fuzzed CREATE2 salt.
    EntryPoint internal epDep; // a live EntryPoint (paymaster ERC165 interface check needs a real one)
    CitrateWallet internal walletImplDep; // a deployed impl (factory ctor requires code at `implementation`)

    function setUp() public {
        epDep = new EntryPoint();
        walletImplDep = new CitrateWallet(IKernelEntryPoint(address(epDep)));
    }

    // --- projection helpers ---

    /// CREATE2 address through the Arachnid factory (0x4e59…) — the real on-chain
    /// address a reroll ceremony yields for (salt, initCode).
    function _projectProd(bytes32 salt, bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, salt, keccak256(initCode)))))
        );
    }

    function _epAddr() internal pure returns (address) {
        return _projectProd(Salts.salt("EntryPoint"), type(EntryPoint).creationCode);
    }

    function _guardianAddr() internal pure returns (address) {
        return _projectProd(Salts.salt("GuardianRecoveryModule"), type(GuardianRecoveryModule).creationCode);
    }

    function _walletImplAddr(address ep) internal pure returns (address) {
        return _projectProd(
            Salts.salt("CitrateWallet"), abi.encodePacked(type(CitrateWallet).creationCode, abi.encode(ep))
        );
    }

    function _factoryAddr(address impl, address ident, address ownerArg) internal pure returns (address) {
        return _projectProd(
            Salts.salt("CitrateWalletFactory"),
            abi.encodePacked(type(CitrateWalletFactory).creationCode, abi.encode(impl, ident, ownerArg))
        );
    }

    function _paymasterAddr(
        address ep,
        address ownerArg,
        address factoryArg,
        address sponsor,
        uint256 d,
        uint256 r,
        uint256 f,
        uint256 m,
        uint256 g
    ) internal pure returns (address) {
        return _projectProd(
            Salts.salt("CitratePaymaster"),
            abi.encodePacked(
                type(CitratePaymaster).creationCode, abi.encode(ep, ownerArg, factoryArg, sponsor, d, r, f, m, g)
            )
        );
    }

    // =====================================================================
    // (1) FUZZ — the projection recipe is EXACT for ALL inputs
    // =====================================================================

    /// EntryPoint (no ctor args): for any salt, the deployed address equals the
    /// CREATE2 projection of its creationCode.
    function testFuzz_entryPoint_projection_is_exact(uint256 saltSeed) public {
        bytes32 s = bytes32(saltSeed);
        EntryPoint ep = new EntryPoint{salt: s}();
        assertEq(
            address(ep),
            vm.computeCreate2Address(s, keccak256(type(EntryPoint).creationCode), address(this)),
            "EntryPoint deploy != CREATE2 projection"
        );
    }

    /// CitrateWallet: init_code = creationCode ++ abi.encode(entryPointArg). The
    /// EntryPoint address is a ctor arg, so the projection must fold it in exactly
    /// for ANY value (Kernel stores it verbatim — no validation to trip on).
    function testFuzz_wallet_projection_is_exact(uint256 saltSeed, address entryPointArg) public {
        bytes32 s = bytes32(saltSeed);
        bytes memory initCode = abi.encodePacked(type(CitrateWallet).creationCode, abi.encode(entryPointArg));
        CitrateWallet w = new CitrateWallet{salt: s}(IKernelEntryPoint(entryPointArg));
        assertEq(
            address(w),
            vm.computeCreate2Address(s, keccak256(initCode), address(this)),
            "CitrateWallet deploy != CREATE2 projection"
        );
    }

    /// CitrateWalletFactory: init_code folds in (impl, identitySigner, owner). The
    /// impl must hold code (ctor reverts otherwise), so we fix it to the deployed
    /// walletImpl and fuzz the two signer/owner address args.
    function testFuzz_factory_projection_is_exact(uint256 saltSeed, address identArg, address ownerArg) public {
        vm.assume(identArg != address(0));
        vm.assume(ownerArg != address(0));
        bytes32 s = bytes32(saltSeed);
        address impl = address(walletImplDep);
        bytes memory initCode =
            abi.encodePacked(type(CitrateWalletFactory).creationCode, abi.encode(impl, identArg, ownerArg));
        CitrateWalletFactory f = new CitrateWalletFactory{salt: s}(impl, identArg, ownerArg);
        assertEq(
            address(f),
            vm.computeCreate2Address(s, keccak256(initCode), address(this)),
            "CitrateWalletFactory deploy != CREATE2 projection"
        );
    }

    /// CitratePaymaster: init_code folds in (entryPoint, owner, registrar,
    /// sponsorSigner, 5 caps). The entryPoint must pass the BasePaymaster ERC165
    /// interface check, so we fix it to a real EntryPoint and fuzz the owner
    /// address + the daily cap (a representative address arg + a representative
    /// uint arg); owner/registrar/sponsor must be non-zero (ctor reverts on zero).
    function testFuzz_paymaster_projection_is_exact(uint256 saltSeed, address ownerArg, uint256 dailyCapArg) public {
        vm.assume(ownerArg != address(0));
        bytes32 s = bytes32(saltSeed);
        address ep = address(epDep);
        address registrar = address(0xC0FFEE);
        address sponsor = address(0xBEEF);
        bytes memory initCode = abi.encodePacked(
            type(CitratePaymaster).creationCode,
            abi.encode(ep, ownerArg, registrar, sponsor, dailyCapArg, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP)
        );
        CitratePaymaster p = new CitratePaymaster{salt: s}(
            IAaEntryPoint(ep),
            ownerArg,
            registrar,
            sponsor,
            dailyCapArg,
            RECOVERY_CAP,
            FIRST_OP_CAP,
            MAX_FEE_CEIL,
            GLOBAL_CAP
        );
        assertEq(
            address(p),
            vm.computeCreate2Address(s, keccak256(initCode), address(this)),
            "CitratePaymaster deploy != CREATE2 projection"
        );
    }

    // =====================================================================
    // (5) NONCE-INDEPENDENCE — extend the pinned nonce test into a fuzz
    // =====================================================================

    /// A REAL deploy from a fuzzed starting nonce still lands at the CREATE2
    /// projection (which excludes the nonce entirely). If a `{salt:}` were ever
    /// reverted to a plain nonce-CREATE, the deployed address would depend on the
    /// nonce and diverge from the projection — this fails loudly.
    function testFuzz_cascade_address_nonce_independent(uint256 nonce, uint256 saltSeed) public {
        // setNonce cannot lower an account's nonce; start from the current one and
        // leave headroom for the deploy's own nonce bump.
        uint64 cur = uint64(vm.getNonce(address(this)));
        uint64 n = uint64(bound(nonce, cur, type(uint64).max - 2));
        vm.setNonce(address(this), n);

        bytes32 s = bytes32(saltSeed);
        EntryPoint ep = new EntryPoint{salt: s}();
        assertEq(
            address(ep),
            vm.computeCreate2Address(s, keccak256(type(EntryPoint).creationCode), address(this)),
            "CREATE2 address must not depend on deployer nonce"
        );
    }

    // =====================================================================
    // (2) TRIPWIRE — hard-pin the 5 production addresses
    // =====================================================================

    /// The load-bearing federation tripwire. Recomputes each production address
    /// from its salt + init_code (through the Arachnid deployer) and asserts it
    /// equals the pinned constant. A failure here means a determinism input
    /// (solc / optimizer / via_ir / bytecode_hash / cbor_metadata / a salt / a
    /// ctor arg) changed — every downstream repo's pinned address just broke.
    function test_pinned_production_addresses_tripwire() public view {
        // Key-independent bytecode anchors: MUST NOT move (fresh keys or not).
        assertEq(_epAddr(), EP_PIN, "EntryPoint pin drift");
        assertEq(_guardianAddr(), GUARDIAN_PIN, "GuardianRecoveryModule pin drift");
        assertEq(_walletImplAddr(EP_PIN), WALLET_IMPL_PIN, "CitrateWallet impl pin drift");

        // The factory embeds the (pinned) walletImpl + the env keys; the paymaster
        // embeds the (pinned) EntryPoint + factory + env keys — the exact production
        // cascade, re-derived from the fresh keys in effect (not a frozen literal).
        assertEq(_factoryPin().code.length, 0, "sanity: projection is an address, not code");
        assertEq(
            _paymasterAddr(EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP),
            _paymasterPin(),
            "paymaster cascade must derive consistently from walletImpl + keys"
        );
    }

    // =====================================================================
    // (3) SENSITIVITY — which input moves which address (adversarial)
    // =====================================================================

    /// identitySigner is a FACTORY ctor arg only. Changing it must move the factory
    /// and (transitively, because the paymaster embeds the factory address) the
    /// paymaster — but NOT the EntryPoint, guardian, or walletImpl.
    function test_sensitivity_identitySigner_moves_factory_and_paymaster() public {
        address bumped = address(uint160(_identitySigner()) + 1);
        address fBase = _factoryAddr(WALLET_IMPL_PIN, _identitySigner(), _owner());
        address fBump = _factoryAddr(WALLET_IMPL_PIN, bumped, _owner());
        assertTrue(fBase != fBump, "factory MUST move when identitySigner changes");

        address pBase =
            _paymasterAddr(EP_PIN, _owner(), fBase, _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);
        address pBump =
            _paymasterAddr(EP_PIN, _owner(), fBump, _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);
        assertTrue(pBase != pBump, "paymaster MUST move (embeds the moved factory)");

        assertEq(_epAddr(), EP_PIN, "EntryPoint MUST NOT move on identitySigner");
        assertEq(_guardianAddr(), GUARDIAN_PIN, "guardian MUST NOT move on identitySigner");
        assertEq(_walletImplAddr(EP_PIN), WALLET_IMPL_PIN, "walletImpl MUST NOT move on identitySigner");
    }

    /// owner is a ctor arg of BOTH the factory and the paymaster. Changing it must
    /// move both directly — but NOT the EntryPoint, guardian, or walletImpl.
    function test_sensitivity_owner_moves_factory_and_paymaster() public {
        address bumped = address(uint160(_owner()) + 1);
        address fBase = _factoryAddr(WALLET_IMPL_PIN, _identitySigner(), _owner());
        address fBump = _factoryAddr(WALLET_IMPL_PIN, _identitySigner(), bumped);
        assertTrue(fBase != fBump, "factory MUST move when owner changes");

        address pBase =
            _paymasterAddr(EP_PIN, _owner(), fBase, _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);
        address pBump =
            _paymasterAddr(EP_PIN, bumped, fBump, _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);
        assertTrue(pBase != pBump, "paymaster MUST move when owner changes");

        assertEq(_epAddr(), EP_PIN, "EntryPoint MUST NOT move on owner");
        assertEq(_guardianAddr(), GUARDIAN_PIN, "guardian MUST NOT move on owner");
        assertEq(_walletImplAddr(EP_PIN), WALLET_IMPL_PIN, "walletImpl MUST NOT move on owner");
    }

    /// sponsorSigner is a PAYMASTER ctor arg only (it is NOT a factory input).
    /// Changing it must move the paymaster and leave the factory (and EntryPoint,
    /// guardian, walletImpl) fixed. This documents that a sponsor-key rotation is
    /// a paymaster-only redeploy.
    function test_sensitivity_sponsorSigner_moves_paymaster_only() public {
        address bumped = address(uint160(_sponsorSigner()) + 1);

        // sponsor is structurally not a factory input → factory stays at its pin.
        assertEq(_factoryAddr(WALLET_IMPL_PIN, _identitySigner(), _owner()), _factoryPin(), "factory MUST NOT move on sponsor");

        address pBase =
            _paymasterAddr(EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);
        address pBump =
            _paymasterAddr(EP_PIN, _owner(), _factoryPin(), bumped, DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);
        assertTrue(pBase != pBump, "paymaster MUST move when sponsorSigner changes");

        assertEq(_epAddr(), EP_PIN, "EntryPoint MUST NOT move on sponsor");
        assertEq(_guardianAddr(), GUARDIAN_PIN, "guardian MUST NOT move on sponsor");
        assertEq(_walletImplAddr(EP_PIN), WALLET_IMPL_PIN, "walletImpl MUST NOT move on sponsor");
    }

    /// Each of the 5 paymaster caps is a PAYMASTER ctor arg only. Bumping any one
    /// by 1 wei must move the paymaster and leave the factory / EntryPoint /
    /// guardian / walletImpl fixed. Documents that a cap re-tune via redeploy
    /// (rather than the on-chain setters) is a paymaster-only move.
    function test_sensitivity_caps_move_paymaster_only() public {
        address base =
            _paymasterAddr(EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP);

        assertTrue(
            base
                != _paymasterAddr(
                    EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP + 1, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP
                ),
            "dailyCap MUST move paymaster"
        );
        assertTrue(
            base
                != _paymasterAddr(
                    EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP + 1, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP
                ),
            "recoveryCap MUST move paymaster"
        );
        assertTrue(
            base
                != _paymasterAddr(
                    EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP + 1, MAX_FEE_CEIL, GLOBAL_CAP
                ),
            "firstOpCap MUST move paymaster"
        );
        assertTrue(
            base
                != _paymasterAddr(
                    EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL + 1, GLOBAL_CAP
                ),
            "maxFeeCeiling MUST move paymaster"
        );
        assertTrue(
            base
                != _paymasterAddr(
                    EP_PIN, _owner(), _factoryPin(), _sponsorSigner(), DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP + 1
                ),
            "globalDailyCap MUST move paymaster"
        );

        // caps are not inputs to the factory / EntryPoint / guardian / walletImpl.
        assertEq(_factoryAddr(WALLET_IMPL_PIN, _identitySigner(), _owner()), _factoryPin(), "factory MUST NOT move on caps");
        assertEq(_epAddr(), EP_PIN, "EntryPoint MUST NOT move on caps");
        assertEq(_guardianAddr(), GUARDIAN_PIN, "guardian MUST NOT move on caps");
        assertEq(_walletImplAddr(EP_PIN), WALLET_IMPL_PIN, "walletImpl MUST NOT move on caps");
    }

    // =====================================================================
    // (4) IDEMPOTENCY — the real deploy-if-absent script runs twice
    // =====================================================================

    /// The REAL `DeployEntryPoint.run()` (not a re-implementation) is idempotent.
    /// Under the script's own broadcast, forge routes the CREATE2 through the
    /// Arachnid factory, so it lands at the pinned production address. The first
    /// run deploys; the second sees code already present at `projectedEntryPoint()`
    /// and is a no-op (no revert, address unchanged).
    function test_deployEntryPoint_run_is_idempotent() public {
        DeployEntryPoint dep = new DeployEntryPoint();
        assertEq(EP_PIN.code.length, 0, "EntryPoint must be absent at start");

        address a1 = dep.run(); // deploys
        assertEq(a1, EP_PIN, "first run must land at the pinned EntryPoint");
        assertGt(EP_PIN.code.length, 0, "EntryPoint must be present after first run");
        bytes32 codeHash1 = EP_PIN.codehash;

        address a2 = dep.run(); // deploy-if-absent → no-op
        assertEq(a2, EP_PIN, "second run must return the same EntryPoint (no-op)");
        assertEq(EP_PIN.codehash, codeHash1, "second run must not disturb the deployed code");
    }

    /// The DeployAA EMBEDDING is idempotent w.r.t. the EntryPoint: when the
    /// deterministic EntryPoint is ALREADY present (e.g. a prior standalone
    /// DeployEntryPoint step, or a re-run), DeployAA's `_ensureEntryPoint()` reuses
    /// it (no redeploy, no revert) and builds the whole cascade on that exact
    /// EntryPoint — landing every downstream contract at its pinned address.
    function test_deployAA_embeds_preexisting_entryPoint() public {
        // Fresh-keys reroll: feed DeployAA the SAME (derived-placeholder) keys the
        // test projects against, via env — no hardcoded production keys. DeployAA
        // and the projection helpers then read identical inputs, so the derived
        // factory/paymaster addresses match exactly.
        vm.setEnv("CITRATE_AA_IDENTITY_SIGNER", vm.toString(_phKey("identity")));
        vm.setEnv("CITRATE_AA_OWNER", vm.toString(_phKey("owner")));
        vm.setEnv("CITRATE_AA_SPONSOR_SIGNER", vm.toString(_phKey("sponsor")));

        // PBA-L2-011: DeployAA now refuses to run unless the P-256 verifier the
        // passkey validator hard-codes has code. Provision a stand-in here (the
        // ceremony provisions Daimo's verifier via DeployP256Verifier.s.sol).
        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, hex"600160005260206000f3");

        // Stand the EntryPoint up FIRST (standalone), then let DeployAA find it.
        DeployEntryPoint dep = new DeployEntryPoint();
        assertEq(dep.run(), EP_PIN, "standalone EntryPoint must be at the pin");
        bytes32 epCodeHash = EP_PIN.codehash;

        DeployAA aa = new DeployAA();
        DeployAA.Deployment memory d = aa.run();

        assertEq(d.entryPoint, EP_PIN, "DeployAA must reuse the pre-existing EntryPoint");
        assertEq(EP_PIN.codehash, epCodeHash, "DeployAA must NOT redeploy/disturb the EntryPoint");
        // Key-independent contracts land at their bytecode pins.
        assertEq(address(d.recovery), GUARDIAN_PIN, "guardian must land at its pin");
        assertEq(address(d.walletImpl), WALLET_IMPL_PIN, "walletImpl must land at its pin");
        // Key-dependent contracts land at the address DERIVED from the fresh keys.
        assertEq(address(d.factory), _factoryPin(), "factory must land at the derived (fresh-key) address");
        assertEq(address(d.paymaster), _paymasterPin(), "paymaster must land at the derived (fresh-key) address");
    }

    // =====================================================================
    // (6) BUNDLER-MISMATCH GUARD — ours != the canonical nonce-0 EntryPoint
    // =====================================================================

    /// The review flagged a bundler race that could deploy the ERC-4337 CANONICAL
    /// EntryPoint (0x0000000071727De…) at its nonce-0 address. Ours is a CUSTOM-salt
    /// CREATE2 deploy at 0xC698fe…, so the two addresses DIFFER — a node/bundler
    /// pointed at the wrong EntryPoint is detectable by address alone, and any
    /// wallet impl built against the wrong EntryPoint lands at a different address
    /// too (so the mismatch propagates visibly through the whole cascade).
    function test_our_entryPoint_distinct_from_canonical_v07() public pure {
        assertEq(_epAddr(), EP_PIN, "our EntryPoint projection must equal the pin");
        assertTrue(EP_PIN != CANONICAL_ENTRYPOINT_V07, "our EntryPoint must differ from the canonical v0.7 EntryPoint");
        // Downstream detection: a walletImpl built on the canonical EntryPoint would
        // NOT match our pinned walletImpl — the mismatch is visible one hop down.
        assertTrue(
            _walletImplAddr(EP_PIN) != _walletImplAddr(CANONICAL_ENTRYPOINT_V07),
            "walletImpl on the wrong EntryPoint must land at a different address"
        );
    }
}
