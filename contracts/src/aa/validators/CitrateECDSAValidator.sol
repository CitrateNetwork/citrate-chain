// SPDX-License-Identifier: MIT
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

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// WP-1 / EW-S1 — Citrate ECDSA (secp256k1) validator plug-in.
///
/// This is the "Validator B" path from `ADR-2026-06-05-ew-surface-interop`:
/// the gui-native or wallet-extension enrolls its existing local EOA as
/// an authorized signer on the user's Kernel smart wallet, **without
/// importing the EOA's private key** — the EOA simply signs UserOp
/// hashes for the smart wallet's address. The EOA continues to operate
/// as a standalone wallet for direct sends; this validator only grants
/// it authority over the smart wallet's UserOps.
///
/// Architectural parity with `lib/kernel/src/validator/ECDSAValidator.sol`
/// is intentional. The Citrate variant ADDS:
///   - a label (`source`) so the dashboard can distinguish
///     "gui-native" vs "wallet-extension" vs other future surfaces;
///   - an `enabledAt` timestamp for audit / dashboard freshness display;
///   - explicit named errors for the surface-interop UX.
///
/// Each install of this validator binds ONE owner EOA. Users with both a
/// gui-native and a wallet-extension install this validator twice under
/// different validator IDs on the same Kernel account.
contract CitrateECDSAValidator is IValidator, IHook {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// Source identifier — short label written at install time so the
    /// dashboard can show users which device authored each registration.
    /// Pure metadata; never consulted in `validateUserOp`.
    enum Source {
        Unknown, // 0
        GuiNative, // 1
        WalletExtension, // 2
        Other // 3 — for future surfaces
    }

    struct OwnerRecord {
        address owner;
        Source source;
        uint64 enabledAt;
    }

    // --- Errors ---
    error AlreadyInstalled(address smartAccount);
    error InvalidInstallData();
    error InvalidOwner();

    // --- Events ---
    event OwnerRegistered(
        address indexed kernel,
        address indexed owner,
        Source source,
        uint64 enabledAt
    );
    event OwnerUninstalled(address indexed kernel, address indexed owner);

    // --- Storage ---

    mapping(address smartAccount => OwnerRecord) public ownerOf;

    // --- Install lifecycle ---

    /// `_data` packing:
    ///   address owner | uint8 source
    /// Total: 20 + 1 = 21 bytes.
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length != 21) revert InvalidInstallData();
        if (_isInitialized(msg.sender)) revert AlreadyInstalled(msg.sender);

        address owner = address(bytes20(_data[0:20]));
        if (owner == address(0)) revert InvalidOwner();

        uint8 sourceByte = uint8(_data[20]);
        Source source = sourceByte > uint8(Source.Other) ? Source.Unknown : Source(sourceByte);
        uint64 enabledAt = uint64(block.timestamp);

        ownerOf[msg.sender] = OwnerRecord({owner: owner, source: source, enabledAt: enabledAt});
        emit OwnerRegistered(msg.sender, owner, source, enabledAt);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address owner = ownerOf[msg.sender].owner;
        delete ownerOf[msg.sender];
        emit OwnerUninstalled(msg.sender, owner);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ownerOf[smartAccount].owner != address(0);
    }

    // --- IValidator: validateUserOp ---

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        address owner = ownerOf[msg.sender].owner;
        if (owner == address(0)) return SIG_VALIDATION_FAILED_UINT;

        bytes calldata sig = userOp.signature;

        // Accept either a raw 65-byte ECDSA signature over userOpHash
        // OR an EIP-191 ("\x19Ethereum Signed Message:\n32"-prefixed)
        // signature over userOpHash. The latter is what most browser
        // wallets emit by default via personal_sign; the former is
        // what wallets that call eth_sign or our own SDK produce.
        (address recovered, ECDSA.RecoverError err1,) = ECDSA.tryRecover(userOpHash, sig);
        if (err1 == ECDSA.RecoverError.NoError && recovered == owner) {
            return SIG_VALIDATION_SUCCESS_UINT;
        }

        bytes32 ethHash = userOpHash.toEthSignedMessageHash();
        (recovered,,) = ECDSA.tryRecover(ethHash, sig);
        return recovered == owner ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }

    // --- IValidator: EIP-1271 ---

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = ownerOf[msg.sender].owner;
        if (owner == address(0)) return ERC1271_INVALID;

        (address recovered, ECDSA.RecoverError err1,) = ECDSA.tryRecover(hash, sig);
        if (err1 == ECDSA.RecoverError.NoError && recovered == owner) {
            return ERC1271_MAGICVALUE;
        }

        bytes32 ethHash = hash.toEthSignedMessageHash();
        (recovered,,) = ECDSA.tryRecover(ethHash, sig);
        return recovered == owner ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    // --- IHook ---

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
