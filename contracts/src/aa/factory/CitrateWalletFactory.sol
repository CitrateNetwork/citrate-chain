// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {LibClone} from "../../../lib/kernel/lib/solady/src/utils/LibClone.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// E-8: the registrar surface of CitratePaymaster this factory drives.
/// Minimal interface (not the full paymaster) so the factory carries no
/// compile-time dependency on paymaster internals.
interface ICitratePaymasterRegistry {
    function registerWallet(address account) external;
    function unregisterWallet(address account) external;
}

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
    /// E-8: deploys are refused until the paymaster registry is wired —
    /// a deploy that silently mints a sponsorship-ineligible wallet is
    /// the registrar gap reappearing as a configuration error.
    error PaymasterNotSet();
    /// E-8: `registerDeployedWallet` backfill only accepts addresses
    /// that actually hold code.
    error AccountNotDeployed(address account);

    // --- Events ---
    event AccountDeployed(bytes32 indexed userId, address indexed account, address initialValidator);
    event IdentitySignerRotated(address indexed oldSigner, address indexed newSigner);
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);
    /// E-8: paymaster registry wiring changed.
    event PaymasterSet(address indexed oldPaymaster, address indexed newPaymaster);

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

    /// FWA-C3-11: per-userId monotonic deploy nonce. Bound into the
    /// permit digest and consumed on a successful (non-idempotent) deploy
    /// so a captured permit cannot be replayed/front-run to grief the
    /// sender's forwarded `msg.value`.
    mapping(bytes32 userId => uint256) public deployNonce;

    /// E-8: the CitratePaymaster whose registry this factory feeds. The
    /// paymaster names this factory as its `registrar`; every successful
    /// deploy registers the new wallet atomically (see
    /// ADR-2026-07-11-e8-atomic-factory-registration). Set post-deploy by
    /// `owner` — a constructor argument is impossible because the CREATE2
    /// ceremony makes the factory and paymaster addresses mutually
    /// dependent (the paymaster's constructor takes this factory as
    /// registrar).
    address public paymaster;

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
        // Idempotent short-circuit (FWA-C3-11): the account address is
        // derived from `userId` alone, so once it exists the deploy is a
        // no-op that returns the existing address. We resolve that BEFORE
        // permit validation because the consumed nonce has already moved
        // past the permit that originally deployed the account — requiring
        // a fresh signature here would break the documented idempotency.
        // No state change and no `initData` execution happen on this path.
        account = predictAddress(userId);
        if (account.code.length != 0) {
            return account;
        }

        if (block.timestamp > expiresAt) revert PermitExpired();

        // Bind permit to (this contract, chainId, userId, initData,
        // expiresAt, nonce). FWA-C3-11: the nonce makes each permit
        // single-use so an observed permit cannot be front-run/replayed.
        bytes32 digest = permitDigest(userId, initData, expiresAt);
        bytes32 ethDigest = digest.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethDigest, signature);
        if (err != ECDSA.RecoverError.NoError || recovered != identitySigner) {
            revert InvalidSigner();
        }

        // E-8: refuse to mint a wallet that cannot be sponsored. Checked
        // before the CREATE2 so a mis-wired ceremony fails loudly instead
        // of silently reintroducing the registrar gap.
        address paymaster_ = paymaster;
        if (paymaster_ == address(0)) revert PaymasterNotSet();

        bool alreadyDeployed;
        (alreadyDeployed, account) = LibClone.createDeterministicERC1967(msg.value, implementation, _salt(userId));
        if (!alreadyDeployed) {
            // Consume the permit nonce ONLY on the deploy that actually
            // initializes the account (effects before the init call — CEI).
            deployNonce[userId] += 1;
            (bool ok,) = account.call(initData);
            if (!ok) revert InitializeFailed();
            // E-8: register atomically with the deploy. EntryPoint v0.7
            // runs initCode (this call) BEFORE paymaster validation
            // (_validatePrepayment: _createSenderIfNeeded at L480, then
            // _validatePaymasterPrepayment), so the counterfactual
            // wallet's FIRST sponsored UserOp already sees
            // isRegistered == true. The registry write stays behind the
            // identity-signer permit verified above — anti-griefing is
            // unchanged. A registration revert bubbles up (fail-closed).
            ICitratePaymasterRegistry(paymaster_).registerWallet(account);
            emit AccountDeployed(userId, account, initialValidator);
        }
        // NB: the idempotent path above returns early and NEVER
        // registers — a wallet unregistered for compromise cannot be
        // re-registered through this permit-less short-circuit.
    }

    /// The digest the identity signer signs (off-chain, in
    /// auth.citrate.ai). Public so the SDK can reconstruct it locally
    /// when building a deploy permit.
    /// @dev FWA-C3-11: includes the current per-userId `deployNonce` so
    ///      each permit is single-use. The SDK reads `deployNonce(userId)`
    ///      when building the permit; once a deploy lands the nonce
    ///      increments and the old permit no longer validates.
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
                expiresAt,
                deployNonce[userId]
            )
        );
    }

    // --- Admin (owner) ---

    /// E-8: wire (or rotate) the paymaster whose registry deploys feed.
    /// Zero is rejected — unwiring would re-open the registrar gap; to
    /// halt sponsorship use the paymaster's own `setPaused`.
    function setPaymaster(address newPaymaster) external {
        if (msg.sender != owner) revert NotOwner();
        if (newPaymaster == address(0)) revert ZeroAddress();
        emit PaymasterSet(paymaster, newPaymaster);
        paymaster = newPaymaster;
    }

    /// E-8: owner passthrough — backfill registration for a wallet this
    /// factory deployed BEFORE atomic registration existed (the paymaster
    /// only accepts `registerWallet` from its registrar, i.e. this
    /// factory, so the call must route through here). Restricted to
    /// addresses that hold code: counterfactual/arbitrary addresses
    /// cannot be pre-registered.
    function registerDeployedWallet(address account) external {
        if (msg.sender != owner) revert NotOwner();
        if (account.code.length == 0) revert AccountNotDeployed(account);
        ICitratePaymasterRegistry(paymaster).registerWallet(account);
    }

    /// E-8: owner passthrough — incident-response unregistration (e.g.
    /// known compromise; see the paymaster's KYC_OPERATOR.md flow). The
    /// permit-less idempotent `deployFor` path never re-registers, so
    /// this is sticky until an explicit `registerDeployedWallet`.
    function unregisterWallet(address account) external {
        if (msg.sender != owner) revert NotOwner();
        ICitratePaymasterRegistry(paymaster).unregisterWallet(account);
    }

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
