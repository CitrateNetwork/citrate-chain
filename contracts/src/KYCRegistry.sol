// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "./lib/InitialAdmin.sol";

import "./lib/AccessControl.sol";

/**
 * @title KYCRegistry
 * @notice Minimal on-chain stand-in for the off-chain identity authority's KYC
 *         claim. The IDP (panva authority) issues a revocable `kyc` claim over
 *         /userinfo (no PII on chain — see IDP-KYC); an authorized updater (the
 *         identity authority's on-chain key, or a KYC oracle relay) mirrors that
 *         claim here by flipping a single boolean per address.
 *
 * @dev This is deliberately tiny. It exists so that `IPFSIncentives` can gate
 *      `registerPinner()` on a verifiable, revocable KYC status — the anti-Sybil
 *      decision for PIN (one identity = one reward/replica). The financial state
 *      machine lives entirely in `IPFSIncentives`; this contract holds no value.
 *
 *      Roles:
 *        - DEFAULT_ADMIN_ROLE: deployer; manages updaters.
 *        - KYC_UPDATER_ROLE:   the identity authority key / KYC oracle that
 *                              sets/revokes verification.
 */
contract KYCRegistry is AccessControl {
    /// @notice Role permitted to set/revoke KYC verification status.
    bytes32 public constant KYC_UPDATER_ROLE = keccak256("KYC_UPDATER_ROLE");

    /// @notice Whether an address currently holds a valid (un-revoked) KYC claim.
    mapping(address => bool) private _verified;

    /// @notice PIN-S4: the IDP IDENTITY (`subHash` = `keccak256(IDP `sub` claim)`)
    ///         an address resolves to — the stable per-person id behind the OIDC
    ///         token. Lane C's IDP-S3 wallet-linking maps many addresses to one
    ///         `sub`; PIN's Sybil binding (`IPFSIncentivesV3`) uses it to require
    ///         a replication quorum be N DISTINCT identities, not N addresses of
    ///         one person. 0 = no identity bound.
    ///
    ///         **Provisional claim shape (until IDP-S3 lands):** `setVerified`
    ///         binds each address to its OWN identity (`keccak("PIN-self", addr)`),
    ///         so per-address KYC is unchanged and the Sybil binding is a no-op
    ///         (every address is a distinct identity). When the IDP issues real
    ///         `sub`/`wallet_address` claims, the authority calls
    ///         `setVerifiedWithIdentity(addr, subHash)` to link addresses and the
    ///         binding becomes meaningful. Matches `citrate-explorer-auth-seam`'s
    ///         provisional `sub`/`wallet_address` claims.
    mapping(address => bytes32) private _identity;

    event KYCVerified(address indexed account, address indexed updater);
    event KYCRevoked(address indexed account, address indexed updater);
    event IdentityBound(address indexed account, bytes32 indexed subHash, address indexed updater);

    /// @param admin Explicit DEFAULT_ADMIN (PBA-L2-002: never msg.sender, which is
    ///        the CREATE2 factory under a salted ceremony deploy).
    constructor(address updater, address admin) {
        InitialAdmin.check(admin);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        // The admin is also an updater so a single key can bootstrap; in
        // production the off-chain authority key is granted KYC_UPDATER_ROLE and
        // the admin's updater grant is revoked at the ceremony.
        _grantRole(KYC_UPDATER_ROLE, admin);
        if (updater != address(0) && updater != admin) {
            _grantRole(KYC_UPDATER_ROLE, updater);
        }
    }

    /**
     * @notice Mark `account` as KYC-verified (mirrors the off-chain IDP claim).
     * @dev Idempotent: re-verifying an already-verified account is a no-op flip.
     */
    function setVerified(address account) external onlyRole(KYC_UPDATER_ROLE) {
        require(account != address(0), "KYC: zero address");
        if (!_verified[account]) {
            _verified[account] = true;
            emit KYCVerified(account, msg.sender);
        }
        // Provisional binding: each address is its own identity until the IDP
        // links it to a real `sub` via setVerifiedWithIdentity. Never overwrite
        // a real (already-linked) identity with the self-default.
        if (_identity[account] == bytes32(0)) {
            bytes32 self = keccak256(abi.encode("PIN-self", account));
            _identity[account] = self;
            emit IdentityBound(account, self, msg.sender);
        }
    }

    /**
     * @notice PIN-S4: verify `account` AND bind it to a real IDP identity
     *         (`subHash = keccak256(sub)`) — Lane C's IDP-S3 wallet-linking. Two
     *         addresses bound to the SAME `subHash` are the same person, so PIN's
     *         Sybil binding will reject both filling one replication slot.
     * @dev    `subHash` must be non-zero (0 is the "unbound" sentinel).
     */
    function setVerifiedWithIdentity(address account, bytes32 subHash)
        external
        onlyRole(KYC_UPDATER_ROLE)
    {
        require(account != address(0), "KYC: zero address");
        require(subHash != bytes32(0), "KYC: zero identity");
        if (!_verified[account]) {
            _verified[account] = true;
            emit KYCVerified(account, msg.sender);
        }
        if (_identity[account] != subHash) {
            _identity[account] = subHash;
            emit IdentityBound(account, subHash, msg.sender);
        }
    }

    /**
     * @notice Revoke `account`'s KYC verification (mirrors an IDP claim
     *         revocation; the revocation bus drives this on-chain write). The
     *         identity binding is left intact (revocation is about the live KYC
     *         claim, not the person↔wallet link); re-verification keeps the same
     *         identity.
     */
    function revoke(address account) external onlyRole(KYC_UPDATER_ROLE) {
        if (_verified[account]) {
            _verified[account] = false;
            emit KYCRevoked(account, msg.sender);
        }
    }

    /// @notice View: is `account` currently KYC-verified?
    function isVerified(address account) external view returns (bool) {
        return _verified[account];
    }

    /// @notice PIN-S4: the IDP identity (`subHash`) `account` resolves to, or 0
    ///         if unverified/unbound. Two addresses returning the same non-zero
    ///         value are the same person.
    function identityOf(address account) external view returns (bytes32) {
        return _identity[account];
    }
}
