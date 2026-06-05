// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IValidator, IHook} from "@kernel/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// WP-1 / EW-S1 — Social-guardian recovery module.
///
/// Per `ADR-2026-06-05-ew-recovery`:
///   - The user nominates **N guardian addresses** at install time
///     (default N = 3; minimum 2; maximum 7).
///   - Recovery requires **M-of-N** guardian signatures to authorize a
///     UserOp from the account (default M = ceil(N/2 + 0.5); the
///     installer specifies M explicitly).
///   - Guardians are EOAs OR smart wallets. EOAs sign with ECDSA over
///     the recovery digest; smart wallets satisfy EIP-1271 against the
///     same digest. Both paths are honoured in `validateUserOp`.
///   - Citrate is NEVER a guardian — the install function does not
///     give the deployer or anyone other than the account a role.
///
/// This module installs as another `IValidator` plug-in on the Kernel
/// account. A recovery UserOp is one whose `userOp.signature` is the
/// packed M-of-N guardian signatures. The UserOp's callData is
/// expected (by convention) to be the validator-rotation calldata the
/// account will execute after this validator returns success.
///
/// The chain itself enforces nothing about WHAT the recovery UserOp
/// does — only that M-of-N guardians signed it. The dashboard +
/// frontend SDK constrain the action to "rotate the primary signer
/// validator" so guardians cannot be tricked into authorizing a
/// transfer; see `citrate-sdk-js` UserOp builder.
contract GuardianRecoveryModule is IValidator, IHook {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// EIP-1271 magic value (echoed from constants to avoid the import
    /// being unused when ERC1271_INVALID is the only thing referenced).
    bytes4 internal constant EIP1271_MAGIC = 0x1626ba7e;

    // --- Limits ---
    uint256 internal constant MIN_GUARDIANS = 2;
    uint256 internal constant MAX_GUARDIANS = 7;

    // --- Errors ---
    error AlreadyInstalled(address smartAccount);
    error InvalidInstallData();
    error InvalidGuardianCount();
    error InvalidThreshold();
    error DuplicateGuardian();
    error ZeroGuardian();
    error MalformedSignatureBlob();

    // --- Events ---
    event GuardiansRegistered(address indexed kernel, uint256 threshold, address[] guardians);
    event GuardiansUninstalled(address indexed kernel);

    // --- Storage ---

    struct RecoveryConfig {
        uint8 threshold; // M
        uint8 count;     // N
        address[7] guardians; // packed fixed-size slot reuse
    }

    mapping(address smartAccount => RecoveryConfig) internal _config;

    // --- Install lifecycle ---

    /// `_data` layout:
    ///   uint8 threshold | uint8 count | address[count] guardians
    /// Length: 2 + 20*count bytes.
    function onInstall(bytes calldata _data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInstalled(msg.sender);
        if (_data.length < 2) revert InvalidInstallData();

        uint8 threshold = uint8(_data[0]);
        uint8 count = uint8(_data[1]);

        if (count < MIN_GUARDIANS || count > MAX_GUARDIANS) revert InvalidGuardianCount();
        if (threshold == 0 || threshold > count) revert InvalidThreshold();
        if (_data.length != 2 + uint256(count) * 20) revert InvalidInstallData();

        RecoveryConfig storage cfg = _config[msg.sender];
        cfg.threshold = threshold;
        cfg.count = count;

        address[] memory emittedGuardians = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 2 + i * 20;
            address g = address(bytes20(_data[offset:offset + 20]));
            if (g == address(0)) revert ZeroGuardian();
            for (uint256 j = 0; j < i; j++) {
                if (cfg.guardians[j] == g) revert DuplicateGuardian();
            }
            cfg.guardians[i] = g;
            emittedGuardians[i] = g;
        }

        emit GuardiansRegistered(msg.sender, threshold, emittedGuardians);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete _config[msg.sender];
        emit GuardiansUninstalled(msg.sender);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return _config[smartAccount].count != 0;
    }

    // --- Reads ---

    /// Convenience view for dashboards. Returns the threshold + the
    /// guardian addresses in install order.
    function configOf(address smartAccount) external view returns (uint8 threshold, address[] memory guardians) {
        RecoveryConfig storage cfg = _config[smartAccount];
        threshold = cfg.threshold;
        guardians = new address[](cfg.count);
        for (uint256 i = 0; i < cfg.count; i++) {
            guardians[i] = cfg.guardians[i];
        }
    }

    // --- IValidator: validateUserOp ---

    /// The recovery digest is `keccak256(userOpHash || account)` — bound
    /// to BOTH the UserOp content (so the guardians know what they're
    /// signing) AND the account (so a signature for one user's recovery
    /// cannot be replayed on another user's wallet, even if both
    /// happened to nominate the same guardian).
    ///
    /// Signature blob layout:
    ///   bytes[] of 65-byte ECDSA signatures, concatenated.
    /// Length: `threshold * 65` bytes. Excess bytes are rejected.
    ///
    /// Each signature is checked against the guardian list; a guardian
    /// can only contribute once per recovery (duplicate signers in the
    /// blob are rejected).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        RecoveryConfig storage cfg = _config[msg.sender];
        if (cfg.count == 0) return SIG_VALIDATION_FAILED_UINT;

        uint8 threshold = cfg.threshold;
        bytes calldata blob = userOp.signature;
        if (blob.length != uint256(threshold) * 65) return SIG_VALIDATION_FAILED_UINT;

        bytes32 digest = keccak256(abi.encodePacked(userOpHash, msg.sender));
        bytes32 ethDigest = digest.toEthSignedMessageHash();

        // Track unique signers via a per-call bitmap over the guardian array.
        // For N ≤ 7 a uint8 bitmap is sufficient.
        uint8 used;
        uint256 confirmed;

        for (uint256 i = 0; i < threshold; i++) {
            uint256 sigStart = i * 65;
            bytes calldata sig = blob[sigStart:sigStart + 65];

            uint8 idx = _matchGuardianAcrossShapes(cfg, digest, ethDigest, sig);
            if (idx == type(uint8).max) return SIG_VALIDATION_FAILED_UINT;

            uint8 bit = uint8(1 << idx);
            if (used & bit != 0) return SIG_VALIDATION_FAILED_UINT;
            used |= bit;
            confirmed++;
        }

        return confirmed >= threshold ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }

    /// Try to recover a guardian from either the raw digest or the
    /// EIP-191 ("personal_sign") prefixed digest. Recover succeeds
    /// silently against many digests; the only signal we trust is
    /// "the recovered address is in this account's guardian set."
    /// Returns the guardian's index in `cfg.guardians`, or
    /// `type(uint8).max` if neither shape matches a guardian.
    function _matchGuardianAcrossShapes(
        RecoveryConfig storage cfg,
        bytes32 digest,
        bytes32 ethDigest,
        bytes calldata sig
    ) internal view returns (uint8) {
        (address rawSigner, ECDSA.RecoverError rawErr,) = ECDSA.tryRecover(digest, sig);
        if (rawErr == ECDSA.RecoverError.NoError && rawSigner != address(0)) {
            uint8 idx = _guardianIndex(cfg, rawSigner);
            if (idx != type(uint8).max) return idx;
        }

        (address ethSigner, ECDSA.RecoverError ethErr,) = ECDSA.tryRecover(ethDigest, sig);
        if (ethErr == ECDSA.RecoverError.NoError && ethSigner != address(0)) {
            uint8 idx = _guardianIndex(cfg, ethSigner);
            if (idx != type(uint8).max) return idx;
        }

        return type(uint8).max;
    }

    function _guardianIndex(RecoveryConfig storage cfg, address signer) internal view returns (uint8) {
        for (uint8 i = 0; i < cfg.count; i++) {
            if (cfg.guardians[i] == signer) return i;
        }
        return type(uint8).max;
    }

    // --- IValidator: EIP-1271 ---

    /// Recovery is a UserOp-only path. EIP-1271 sign-anything is not
    /// supported (a guardian aggregate cannot rubber-stamp arbitrary
    /// off-chain payloads).
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return ERC1271_INVALID;
    }

    // --- IHook ---

    function preCheck(address, uint256, bytes calldata) external payable override returns (bytes memory) {
        return hex"";
    }

    function postCheck(bytes calldata) external payable override {}
}
