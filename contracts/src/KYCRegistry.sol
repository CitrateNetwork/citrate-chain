// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

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

    event KYCVerified(address indexed account, address indexed updater);
    event KYCRevoked(address indexed account, address indexed updater);

    constructor(address updater) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // The deployer is also an updater so a single key can bootstrap; in
        // production the off-chain authority key is granted KYC_UPDATER_ROLE and
        // the deployer's updater grant is revoked at the ceremony.
        _grantRole(KYC_UPDATER_ROLE, msg.sender);
        if (updater != address(0) && updater != msg.sender) {
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
    }

    /**
     * @notice Revoke `account`'s KYC verification (mirrors an IDP claim
     *         revocation; the revocation bus drives this on-chain write).
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
}
