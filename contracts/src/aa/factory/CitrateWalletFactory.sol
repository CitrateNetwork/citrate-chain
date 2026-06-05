// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {LibClone} from "../../../lib/kernel/lib/solady/src/utils/LibClone.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// WP-1 / EW-S1 — Identity-keyed Kernel wallet factory.
///
/// Per `ADR-2026-06-05-ew-surface-interop`, the smart-wallet address
/// must be **stable across signer changes** so users see one address on
/// every Citrate surface. To honour that, this factory derives the
/// CREATE2 salt from the Citrate `userId` ALONE:
///
///   `salt = keccak256(abi.encodePacked(userId))`
///
/// and **does not mix the init data into the salt** the way Kernel's
/// stock factory does. The trade-off is that anyone calling the factory
/// could potentially deploy a Kernel for someone else's `userId` with
/// attacker-controlled init data, locking the legitimate owner out of
/// their address.
///
/// To prevent that we require every deploy to carry an EIP-191 signature
/// from a configured `identitySigner` (the operator key managed by
/// `auth.citrate.ai`). The signature commits to the exact `userId +
/// initData + expiresAt + chainId` tuple, so a leaked signature for one
/// user's deploy cannot be reused for another's.
///
/// The deploy itself is idempotent: once an account exists at the
/// userId-derived address, subsequent calls are no-ops that return the
/// existing address without re-initializing.
contract CitrateWalletFactory {
    using MessageHashUtils for bytes32;

    // --- Errors ---
    error ImplementationNotDeployed();
    error PermitExpired();
    error InvalidSigner();
    error InitializeFailed();
    error ZeroAddress();
    error NotOwner();

    // --- Events ---
    event AccountDeployed(bytes32 indexed userId, address indexed account, address initialValidator);
    event IdentitySignerRotated(address indexed oldSigner, address indexed newSigner);
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);

    // --- Immutable ---

    /// The Kernel v3 implementation behind every minimal-proxy clone.
    address public immutable implementation;

    // --- State ---

    /// The address whose ECDSA signature authorizes a deploy permit.
    /// Managed by `auth.citrate.ai`; rotatable by `owner`.
    address public identitySigner;

    /// Owner can rotate `identitySigner` (e.g. on key compromise).
    /// In production this should be a multisig.
    address public owner;

    constructor(address _implementation, address _identitySigner, address _owner) {
        if (_implementation == address(0) || _identitySigner == address(0) || _owner == address(0)) {
            revert ZeroAddress();
        }
        if (_implementation.code.length == 0) revert ImplementationNotDeployed();
        implementation = _implementation;
        identitySigner = _identitySigner;
        owner = _owner;
    }

    // --- Address derivation (deterministic + offline-computable) ---

    /// Returns the deterministic smart-wallet address for a Citrate user id.
    /// View — no state change. Callable by anyone, anywhere, including
    /// off-chain clients (the SDK uses this for offline address display in
    /// gui-native and the wallet-extension).
    function predictAddress(bytes32 userId) public view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(implementation, _salt(userId), address(this));
    }

    function _salt(bytes32 userId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(userId));
    }

    // --- Deploy (permit-gated) ---

    /// Deploys (or returns) the Kernel proxy for `userId`.
    ///
    /// Idempotent: a second call with the same parameters returns the
    /// existing address without re-running `initData` (the underlying
    /// Solady factory function reports `alreadyDeployed`).
    ///
    /// `signature` is `identitySigner`'s ECDSA over:
    ///   `permitDigest(userId, initData, expiresAt)`
    /// where `permitDigest` binds the call to this factory + chain so
    /// signatures cannot be replayed across deploys or networks.
    ///
    /// `initialValidator` is an informational parameter — the actual
    /// validator is whatever `initData` instructs the Kernel to install
    /// at construction. We accept it separately so the
    /// `AccountDeployed` event is queryable by-validator for dashboards
    /// without re-decoding the init blob.
    function deployFor(
        bytes32 userId,
        address initialValidator,
        bytes calldata initData,
        uint256 expiresAt,
        bytes calldata signature
    ) external payable returns (address account) {
        if (block.timestamp > expiresAt) revert PermitExpired();

        // Bind permit to (this contract, chainId, userId, initData, expiresAt).
        bytes32 digest = permitDigest(userId, initData, expiresAt);
        bytes32 ethDigest = digest.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethDigest, signature);
        if (err != ECDSA.RecoverError.NoError || recovered != identitySigner) {
            revert InvalidSigner();
        }

        bool alreadyDeployed;
        (alreadyDeployed, account) = LibClone.createDeterministicERC1967(msg.value, implementation, _salt(userId));
        if (!alreadyDeployed) {
            (bool ok,) = account.call(initData);
            if (!ok) revert InitializeFailed();
            emit AccountDeployed(userId, account, initialValidator);
        }
    }

    /// The digest the identity signer signs (off-chain, in
    /// auth.citrate.ai). Public so the SDK can reconstruct it locally
    /// when building a deploy permit.
    function permitDigest(bytes32 userId, bytes calldata initData, uint256 expiresAt)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                address(this),
                block.chainid,
                userId,
                keccak256(initData),
                expiresAt
            )
        );
    }

    // --- Admin (owner) ---

    function setIdentitySigner(address newSigner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newSigner == address(0)) revert ZeroAddress();
        emit IdentitySignerRotated(identitySigner, newSigner);
        identitySigner = newSigner;
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }
}
