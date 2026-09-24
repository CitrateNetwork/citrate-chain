// SPDX-License-Identifier: Apache-2.0
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
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

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

    // --- CHAIN-B-C032: recovery-action allowlist ---
    /// Kernel `execute(bytes32 execMode, bytes executionData)` selector — the
    /// only outer call a recovery UserOp may carry.
    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(bytes32,bytes)"));
    /// Kernel `changeRootValidator(bytes21,address,bytes,bytes)` selector — the
    /// only inner action guardians may authorize (rotate the primary signer).
    bytes4 internal constant CHANGE_ROOT_SELECTOR =
        bytes4(keccak256("changeRootValidator(bytes21,address,bytes,bytes)"));

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
    ///
    /// @dev FWA-C3-06 hardening: EOA guardian signatures are recovered ONLY
    ///      against the EIP-191 ("\x19Ethereum Signed Message") prefixed
    ///      digest. The previously-accepted raw `keccak256(userOpHash,account)`
    ///      shape is no longer honored — a guardian EOA signature produced
    ///      for some unrelated protocol that happened to sign a 32-byte blob
    ///      can no longer be replayed into a recovery.
    /// @dev FWA-C3-07 hardening: contract (smart-wallet) guardians are
    ///      authenticated via EIP-1271 `isValidSignature` against the same
    ///      domain-separated digest, so an M-of-N set that includes a Safe /
    ///      smart wallet is no longer unsatisfiable (recovery un-bricked).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        RecoveryConfig storage cfg = _config[msg.sender];
        if (cfg.count == 0) return SIG_VALIDATION_FAILED_UINT;

        // CHAIN-B-C032 (audit 2026-09-02): constrain WHAT a guardian quorum may
        // authorize. Previously the module returned success for ANY userOpHash
        // M guardians signed and never inspected `userOp.callData`, so a
        // colluding / phished 2-of-3 could sign a recovery op whose callData
        // drains the wallet (arbitrary `execute` target) or delegatecalls
        // attacker code — the "rotate the primary signer" constraint lived only
        // in the frontend. The chain now enforces it: the op must be a single,
        // non-delegatecall `execute` to the account ITSELF, zero value, whose
        // inner call is `changeRootValidator`. Anything else fails closed.
        // (A per-account recovery timelock with an owner-cancel window is a
        // separate OWNER/reroll follow-up; this closes the drain surface.)
        if (!_isAllowedRecoveryAction(userOp.callData, msg.sender)) {
            return SIG_VALIDATION_FAILED_UINT;
        }

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

    /// Match a single 65-byte guardian signature slot to a guardian.
    ///
    /// FWA-C3-06: EOA guardians are recovered ONLY against the EIP-191
    /// prefixed `ethDigest`. The raw-digest acceptance path is removed,
    /// closing the cross-protocol replay surface.
    ///
    /// FWA-C3-07: if the EOA path does not match, each guardian that is a
    /// deployed contract is offered the signature via EIP-1271
    /// `isValidSignature(digest, sig)`. The application digest (the
    /// un-prefixed `keccak256(userOpHash, account)`) is what a smart-wallet
    /// guardian's own validator binds, mirroring how Kernel/7579 wallets
    /// receive a domain-separated hash. A contract guardian returning the
    /// 0x1626ba7e magic value is accepted.
    ///
    /// Returns the guardian's index in `cfg.guardians`, or
    /// `type(uint8).max` if no guardian matches.
    function _matchGuardianAcrossShapes(
        RecoveryConfig storage cfg,
        bytes32 digest,
        bytes32 ethDigest,
        bytes calldata sig
    ) internal view returns (uint8) {
        // EOA path — EIP-191 prefixed digest ONLY (FWA-C3-06).
        (address ethSigner, ECDSA.RecoverError ethErr,) = ECDSA.tryRecover(ethDigest, sig);
        if (ethErr == ECDSA.RecoverError.NoError && ethSigner != address(0)) {
            uint8 idx = _guardianIndex(cfg, ethSigner);
            if (idx != type(uint8).max) return idx;
        }

        // EIP-1271 contract-guardian path (FWA-C3-07). Only reachable for
        // guardians with deployed code; EOAs short-circuit above.
        uint8 n = cfg.count;
        for (uint8 i = 0; i < n; i++) {
            address g = cfg.guardians[i];
            if (g.code.length == 0) continue; // not a contract
            // staticcall via the interface; any revert / non-magic answer
            // simply means "this guardian did not sign", fail closed.
            try IERC1271(g).isValidSignature(digest, sig) returns (bytes4 magic) {
                if (magic == EIP1271_MAGIC) return i;
            } catch {
                // ignore — fall through, this guardian did not validate.
            }
        }

        return type(uint8).max;
    }

    function _guardianIndex(RecoveryConfig storage cfg, address signer) internal view returns (uint8) {
        for (uint8 i = 0; i < cfg.count; i++) {
            if (cfg.guardians[i] == signer) return i;
        }
        return type(uint8).max;
    }

    /// CHAIN-B-C032: true iff `cd` is a single, non-delegatecall Kernel
    /// `execute` to `account` itself, with zero value, whose inner call is
    /// `changeRootValidator`. Fails closed (returns false) on any malformed or
    /// non-conforming callData. `executionData` for a single call is
    /// `abi.encodePacked(target(20), value(32), innerCallData)`.
    function _isAllowedRecoveryAction(bytes calldata cd, address account) internal pure returns (bool) {
        // selector(4) + mode(32) + offset(32) + length(32) minimum.
        if (cd.length < 100) return false;
        if (bytes4(cd[0:4]) != EXECUTE_SELECTOR) return false;

        // ERC-7579 ModeCode: the most-significant byte is the CallType.
        // 0x00 = single (revert-default); reject batch (0x01) and
        // delegatecall (0xff).
        if (cd[4] != bytes1(0x00)) return false;

        // Offset to the `executionData` dynamic argument, relative to the
        // start of the args region (immediately after the 4-byte selector).
        uint256 offset = uint256(bytes32(cd[36:68]));
        uint256 lenPos = 4 + offset;
        if (lenPos + 32 < lenPos) return false; // overflow guard
        if (cd.length < lenPos + 32) return false;

        uint256 execLen = uint256(bytes32(cd[lenPos:lenPos + 32]));
        uint256 dataStart = lenPos + 32;
        if (dataStart + execLen < dataStart) return false; // overflow guard
        if (cd.length < dataStart + execLen) return false;

        // Need target(20) + value(32) + inner selector(4) at minimum.
        if (execLen < 56) return false;

        address target = address(bytes20(cd[dataStart:dataStart + 20]));
        uint256 value = uint256(bytes32(cd[dataStart + 20:dataStart + 52]));
        bytes4 innerSelector = bytes4(cd[dataStart + 52:dataStart + 56]);

        if (target != account) return false; // must be a self-call
        if (value != 0) return false; // no value transfer
        if (innerSelector != CHANGE_ROOT_SELECTOR) return false; // rotate only

        return true;
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
