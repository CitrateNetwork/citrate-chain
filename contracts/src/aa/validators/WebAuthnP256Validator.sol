// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IValidator, IHook} from "@kernel/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";

import {WebAuthn} from "../lib/webauthn/WebAuthn.sol";

/// WP-1 / EW-S1 — WebAuthn (passkey) validator plug-in for the
/// Citrate Kernel-fork smart wallet.
///
/// Each Kernel account that installs this validator stores ONE registered
/// passkey: a secp256r1 (P-256) public key `(x, y)` and the bytes-blob
/// `credentialId` the browser uses to address the credential.
///
/// `validateUserOp` decodes the `userOp.signature` field (packed by the
/// frontend as `abi.encode(authenticatorData, clientDataJSON,
/// challengeLocation, responseTypeLocation, r, s)`) and delegates to
/// Daimo's WebAuthn library, which:
///
///   1. asserts authenticatorData flags (UP set; UV if required)
///   2. asserts the clientDataJSON `type` is `"webauthn.get"`
///   3. asserts the challenge in clientDataJSON equals `userOpHash`
///   4. verifies P-256 signature over `sha256(authData || sha256(clientDataJSON))`
///
/// See ADR-2026-06-05-ew-wallet-stack §"On-chain P-256 verification" and
/// ADR-2026-06-05-ew-surface-interop §"Per-surface validator binding".
contract WebAuthnP256Validator is IValidator, IHook {
    // --- Errors ---
    // NB: `NotInitialized(address)` is declared on Kernel's IValidator
    // interface and inherited here; we MUST NOT redeclare it.
    error AlreadyInstalled(address smartAccount);
    error InvalidInstallData();
    error PreCheckSenderMismatch();

    // --- Events ---
    event PasskeyRegistered(
        address indexed kernel,
        bytes32 indexed credentialIdHash,
        uint256 x,
        uint256 y,
        bool requireUserVerification
    );
    event PasskeyUninstalled(address indexed kernel);

    // --- Storage ---

    /// Per-account passkey record. One passkey per validator-install. Users
    /// who want multiple passkeys install this module multiple times under
    /// different validator IDs.
    struct Passkey {
        uint256 x;
        uint256 y;
        bytes32 credentialIdHash;
        bool requireUserVerification;
    }

    mapping(address smartAccount => Passkey) public passkeyOf;

    // --- IModule / IValidator install lifecycle ---

    /// `_data` packing (caller responsibility):
    ///   bytes32 credentialIdHash | uint256 x | uint256 y | uint8 requireUserVerification
    /// Total: 32 + 32 + 32 + 1 = 97 bytes.
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length != 97) revert InvalidInstallData();
        if (_isInitialized(msg.sender)) revert AlreadyInstalled(msg.sender);

        bytes32 credentialIdHash = bytes32(_data[0:32]);
        uint256 x = uint256(bytes32(_data[32:64]));
        uint256 y = uint256(bytes32(_data[64:96]));
        bool requireUv = uint8(_data[96]) != 0;

        if (x == 0 || y == 0) revert InvalidInstallData();

        passkeyOf[msg.sender] = Passkey({
            x: x,
            y: y,
            credentialIdHash: credentialIdHash,
            requireUserVerification: requireUv
        });

        emit PasskeyRegistered(msg.sender, credentialIdHash, x, y, requireUv);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete passkeyOf[msg.sender];
        emit PasskeyUninstalled(msg.sender);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return passkeyOf[smartAccount].x != 0 && passkeyOf[smartAccount].y != 0;
    }

    // --- IValidator: validate a UserOp ---

    /// Verifies a WebAuthn assertion over `userOpHash`. The signature blob
    /// is laid out as ABI-encoded:
    ///   `abi.encode(bytes authenticatorData, string clientDataJSON,
    ///               uint256 challengeLocation, uint256 responseTypeLocation,
    ///               uint256 r, uint256 s)`.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        Passkey memory pk = passkeyOf[msg.sender];
        if (pk.x == 0) return SIG_VALIDATION_FAILED_UINT;

        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeLocation,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(userOp.signature, (bytes, string, uint256, uint256, uint256, uint256));

        bool ok = WebAuthn.verifySignature(
            abi.encodePacked(userOpHash),
            authenticatorData,
            pk.requireUserVerification,
            clientDataJSON,
            challengeLocation,
            responseTypeLocation,
            r,
            s,
            pk.x,
            pk.y
        );

        return ok ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }

    // --- IValidator: EIP-1271 isValidSignature ---

    /// EIP-1271 path. The signature blob shape matches `validateUserOp`.
    /// `hash` is treated as the WebAuthn challenge.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        Passkey memory pk = passkeyOf[msg.sender];
        if (pk.x == 0) return ERC1271_INVALID;

        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeLocation,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(sig, (bytes, string, uint256, uint256, uint256, uint256));

        bool ok = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            pk.requireUserVerification,
            clientDataJSON,
            challengeLocation,
            responseTypeLocation,
            r,
            s,
            pk.x,
            pk.y
        );

        return ok ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    // --- IHook: preCheck / postCheck ---

    /// The WebAuthn validator does not impose execution-level restrictions
    /// beyond validating signatures. preCheck accepts any sender and returns
    /// empty hookData; postCheck is a no-op.
    function preCheck(address, /*msgSender*/ uint256, /*value*/ bytes calldata /*data*/ )
        external
        payable
        override
        returns (bytes memory)
    {
        return hex"";
    }

    function postCheck(bytes calldata /*hookData*/ ) external payable override {}
}
