// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";

import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";
import {WebAuthnP256Validator} from "../../src/aa/validators/WebAuthnP256Validator.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {P256} from "../../src/aa/lib/webauthn/P256.sol";
import {Base64URL} from "../../src/aa/lib/webauthn/Base64URL.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";

/// The Daimo P256 lib staticcalls a verifier at a fixed CREATE2 address
/// with `abi.encode(messageHash, r, s, x, y)`. The real verifier is
/// deployed on chain 40204; forge has no RIP-7212 and the repo vendors
/// only the CALLER half. This fixture accepts iff the calldata matches
/// the exact expected tuple (baked as an immutable so `vm.etch`'d
/// runtime keeps it) — proving the validator passed precisely the
/// message + signature + pubkey we constructed, while `vm.signP256`
/// guarantees the curve math itself. On-chain the audited Daimo
/// verifier is authoritative.
contract ExactArgsP256Verifier {
    bytes32 private immutable EXPECTED_ARGS_HASH;

    constructor(bytes32 expectedArgsHash) {
        EXPECTED_ARGS_HASH = expectedArgsHash;
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        return abi.encode(keccak256(data) == EXPECTED_ARGS_HASH ? uint256(1) : uint256(0));
    }
}

/// WP-10 / EW-S1 — the recovery flow, end-to-end through the REAL
/// EntryPoint v0.7 (sprint item 33; planset scenario "rotate to a fresh
/// passkey via M-of-N guardian signatures; the new passkey authorizes a
/// subsequent UserOp"):
///
///   1. Wallet deploys via the permit-gated factory with an ECDSA root
///      validator AND the GuardianRecoveryModule installed at deploy
///      time through Kernel's `initConfig` (a self-call to
///      `installModule`) — the same wire shape the identity service's
///      guardian-enrollment flow produces (sprint item 31), including
///      the `execute`-selector grant non-root validators require.
///   2. 2-of-3 guardians co-sign `keccak256(userOpHash ++ wallet)` and
///      the recovery UserOp (nonce-keyed to the module) executes
///      `changeRootValidator` to a FRESH WebAuthn passkey.
///   3. The fresh passkey signs a subsequent UserOp (full WebAuthn
///      assertion: authenticatorData, clientDataJSON, challenge =
///      base64url(userOpHash), low-s P-256 — the exact encoding
///      citrate-sdk-js `webauthn.ts` produces) and it executes.
///   4. The OLD root signer can no longer authorize ops (AA24).
///   5. 1-of-3 signatures cannot recover (AA24).
contract GuardianRecoveryE2ETest is Test {
    using MessageHashUtils for bytes32;

    uint256 internal constant IDENTITY_PK = 0x59E7;
    uint256 internal constant OLD_OWNER_PK = 0xA11A;
    uint256 internal constant G1_PK = 0x6001;
    uint256 internal constant G2_PK = 0x6002;
    uint256 internal constant G3_PK = 0x6003;
    // Fresh-passkey P-256 private key (vm.signP256 / vm.publicKeyP256).
    uint256 internal constant PASSKEY_PK = 0x7E57;

    uint256 internal constant P256_N =
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

    EntryPoint internal entryPoint;
    CitrateWallet internal walletImpl;
    CitrateWalletFactory internal factory;
    CitrateECDSAValidator internal ecdsaValidator;
    WebAuthnP256Validator internal webauthnValidator;
    GuardianRecoveryModule internal recoveryModule;

    address internal oldOwner;
    address payable internal wallet;
    address payable internal beneficiary = payable(address(0xFEE));

    bytes32 internal constant USER_ID = keccak256("recovery-e2e-user");

    function setUp() public {
        entryPoint = new EntryPoint();
        walletImpl = new CitrateWallet(IKernelEntryPoint(address(entryPoint)));
        ecdsaValidator = new CitrateECDSAValidator();
        webauthnValidator = new WebAuthnP256Validator();
        recoveryModule = new GuardianRecoveryModule();
        oldOwner = vm.addr(OLD_OWNER_PK);
        factory = new CitrateWalletFactory(address(walletImpl), vm.addr(IDENTITY_PK), address(0xA11CE));

        // E-8: deployFor fails closed until the paymaster registry is
        // wired (registrar = factory, as in script/aa/DeployAA.s.sol).
        // Wired against the REAL EntryPoint this suite already runs.
        CitratePaymaster pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)),
            address(0xA11CE),
            address(factory),
            vm.addr(IDENTITY_PK), // sponsorSigner (unused in this suite)
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(address(0xA11CE));
        factory.setPaymaster(address(pm));

        wallet = payable(_deployWalletWithGuardians());
        // Prefund the account's EntryPoint deposit so it pays its own gas
        // (the live-chain path uses the CitratePaymaster instead).
        entryPoint.depositTo{value: 10 ether}(wallet);
    }

    // ── deploy: ECDSA root + guardians installed via initConfig ──────

    function _deployWalletWithGuardians() internal returns (address) {
        // Guardian module install data: threshold 2 of [g1, g2, g3].
        bytes memory guardianData = abi.encodePacked(
            uint8(2), uint8(3), vm.addr(G1_PK), vm.addr(G2_PK), vm.addr(G3_PK)
        );
        // Kernel installModule initData for a validator-type module:
        //   hook(20 bytes, 0 → no hook) ++ abi.encode(validatorData,
        //   hookData, selectorData). The 4-byte selectorData grants the
        //   module access to `execute` — REQUIRED for non-root
        //   validators (Kernel checks allowedSelectors on validateUserOp).
        bytes memory installRecovery = abi.encodeWithSignature(
            "installModule(uint256,address,bytes)",
            uint256(1),
            address(recoveryModule),
            abi.encodePacked(
                address(0),
                abi.encode(guardianData, bytes(""), abi.encodePacked(bytes4(keccak256("execute(bytes32,bytes)"))))
            )
        );
        bytes[] memory initConfig = new bytes[](1);
        initConfig[0] = installRecovery;

        bytes memory initData = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            bytes21(abi.encodePacked(bytes1(0x01), address(ecdsaValidator))),
            address(0),
            abi.encodePacked(oldOwner, uint8(1)),
            bytes(""),
            initConfig
        );

        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 digest = factory.permitDigest(USER_ID, initData, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(IDENTITY_PK, digest.toEthSignedMessageHash());
        address account =
            factory.deployFor(USER_ID, address(ecdsaValidator), initData, expiresAt, abi.encodePacked(r, s, v));

        // The enrollment took: threshold + guardians readable on-chain
        // (this is what the identity dashboard renders).
        (uint8 threshold, address[] memory guardians) = recoveryModule.configOf(account);
        assertEq(threshold, 2);
        assertEq(guardians.length, 3);
        return account;
    }

    // ── UserOp plumbing ───────────────────────────────────────────────

    function _packedOp(address sender, uint256 nonce, bytes memory callData)
        internal
        pure
        returns (PackedUserOperation memory op)
    {
        op = PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(2 gwei))),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// Kernel nonce KEY routing validation to an installed validator:
    /// `mode(1B=0x00) | vType(1B=0x01) | validator(20B) | 2B key`.
    function _validatorNonceKey(address validator) internal pure returns (uint192) {
        return uint192(bytes24(abi.encodePacked(bytes1(0x00), bytes1(0x01), validator, bytes2(0))));
    }

    function _executeSingle(address target, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "execute(bytes32,bytes)", bytes32(0), abi.encodePacked(target, value, data)
        );
    }

    function _rotateToPasskeyCallData(uint256 x, uint256 y) internal view returns (bytes memory) {
        // changeRootValidator to the WebAuthn validator with the FRESH
        // passkey — the exact call citrate-sdk-js buildRotateSignerCall
        // encodes (recovery.ts).
        bytes memory rotate = abi.encodeWithSignature(
            "changeRootValidator(bytes21,address,bytes,bytes)",
            bytes21(abi.encodePacked(bytes1(0x01), address(webauthnValidator))),
            address(0),
            abi.encodePacked(keccak256("fresh-credential-id"), x, y, uint8(0)),
            bytes("")
        );
        return _executeSingle(wallet, 0, rotate);
    }

    function _guardianSign(uint256 pk, bytes32 userOpHash) internal view returns (bytes memory) {
        // The module's digest: keccak256(userOpHash ++ account) — bound
        // to the wallet so a guardian's signature for one user cannot be
        // replayed on another wallet (same scheme as sdk-js recovery.ts).
        bytes32 digest = keccak256(abi.encodePacked(userOpHash, wallet));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest.toEthSignedMessageHash());
        return abi.encodePacked(r, s, v);
    }

    function _recoveryOp(uint256 x, uint256 y) internal view returns (PackedUserOperation memory op) {
        uint192 key = _validatorNonceKey(address(recoveryModule));
        op = _packedOp(wallet, entryPoint.getNonce(wallet, key), _rotateToPasskeyCallData(x, y));
    }

    /// Build the WebAuthn assertion blob over a userOpHash — the byte
    /// layout citrate-sdk-js webauthn.ts produces and the validator
    /// abi.decodes. Also wires the exact-args P256 fixture for it.
    function _passkeySign(bytes32 userOpHash, uint256 x, uint256 y) internal returns (bytes memory) {
        string memory clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64URL.encode(abi.encodePacked(userOpHash)),
            '","origin":"https://auth.citrate.ai"}'
        );
        // 37-byte authenticatorData; flags byte (index 32) = 0x01 (UP).
        bytes memory authenticatorData = new bytes(37);
        authenticatorData[32] = 0x01;

        bytes32 messageHash =
            sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(PASSKEY_PK, messageHash);
        uint256 sUint = uint256(s);
        if (sUint > P256_N / 2) {
            sUint = P256_N - sUint; // low-s normalization (verifier rejects high-s)
        }

        // Arm the verifier fixture for exactly this verification tuple.
        ExactArgsP256Verifier shim = new ExactArgsP256Verifier(
            keccak256(abi.encode(messageHash, uint256(r), sUint, x, y))
        );
        vm.etch(P256.VERIFIER, address(shim).code);

        // `responseTypeLocation` = index of `"type":"webauthn.get"` (1);
        // `challengeLocation` = index of `"challenge":"…"` (23).
        return abi.encode(authenticatorData, clientDataJSON, uint256(23), uint256(1), uint256(r), sUint);
    }

    function _handleOps(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    // ── the WP-10 gate, end to end ────────────────────────────────────

    function test_recovery_2of3RotatesToFreshPasskey_andNewPasskeySigns() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // 1. Guardians g1 + g2 co-sign the rotation op.
        PackedUserOperation memory op = _recoveryOp(x, y);
        bytes32 opHash = entryPoint.getUserOpHash(op);
        op.signature = bytes.concat(_guardianSign(G1_PK, opHash), _guardianSign(G2_PK, opHash));
        _handleOps(op);

        // 2. Root validator is now the WebAuthn validator with the fresh key.
        (, bytes memory rootRaw) =
            wallet.staticcall(abi.encodeWithSignature("rootValidator()"));
        assertEq(
            bytes21(rootRaw),
            bytes21(abi.encodePacked(bytes1(0x01), address(webauthnValidator))),
            "root must be the WebAuthn validator"
        );
        (uint256 pkX, uint256 pkY,,) = webauthnValidator.passkeyOf(wallet);
        assertEq(pkX, x);
        assertEq(pkY, y);

        // 3. The FRESH PASSKEY authorizes a subsequent UserOp (root nonce
        //    key 0): send 1 ether from the wallet to a recipient.
        vm.deal(wallet, 2 ether);
        address recipient = address(0xCAFE);
        PackedUserOperation memory sendOp =
            _packedOp(wallet, entryPoint.getNonce(wallet, 0), _executeSingle(recipient, 1 ether, ""));
        bytes32 sendOpHash = entryPoint.getUserOpHash(sendOp);
        sendOp.signature = _passkeySign(sendOpHash, x, y);
        _handleOps(sendOp);
        assertEq(recipient.balance, 1 ether, "the fresh passkey must authorize real execution");

        // 4. The OLD root signer is locked out: a root-keyed op signed by
        //    the old ECDSA owner fails validation. (The root is now the
        //    WebAuthn validator, whose abi.decode of a 65-byte ECDSA blob
        //    reverts → the EntryPoint surfaces AA23; either AA23 or AA24
        //    is a validation lockout — the op can never execute.)
        PackedUserOperation memory oldOp =
            _packedOp(wallet, entryPoint.getNonce(wallet, 0), _executeSingle(recipient, 1, ""));
        bytes32 oldOpHash = entryPoint.getUserOpHash(oldOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OLD_OWNER_PK, oldOpHash);
        oldOp.signature = abi.encodePacked(r, s, v);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = oldOp;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", bytes("")
            )
        );
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_recovery_rejectsBelowThreshold() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        PackedUserOperation memory op = _recoveryOp(x, y);
        bytes32 opHash = entryPoint.getUserOpHash(op);
        // Only ONE guardian signs (threshold is 2).
        op.signature = _guardianSign(G1_PK, opHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_recovery_rejectsNonGuardianCosigner() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        PackedUserOperation memory op = _recoveryOp(x, y);
        bytes32 opHash = entryPoint.getUserOpHash(op);
        // g1 + a non-guardian key.
        op.signature = bytes.concat(_guardianSign(G1_PK, opHash), _guardianSign(0xDEAD, opHash));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_recovery_signaturesAreWalletBound() public {
        // A guardian blob produced for ANOTHER wallet must not validate
        // here (digest commits to the account address).
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        PackedUserOperation memory op = _recoveryOp(x, y);
        bytes32 opHash = entryPoint.getUserOpHash(op);
        bytes32 foreignDigest = keccak256(abi.encodePacked(opHash, address(0xD15EA5E)));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(G1_PK, foreignDigest.toEthSignedMessageHash());
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(G2_PK, foreignDigest.toEthSignedMessageHash());
        op.signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );
        entryPoint.handleOps(ops, beneficiary);
    }
}
