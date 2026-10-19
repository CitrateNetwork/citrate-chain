// ── VENDORED: DO NOT EDIT. Change upstream, then re-vendor with a new header. ─────
// Source:    CitrateNetwork/citrate-coop contracts/src/lib/Auth.sol
// Upstream:  github.com/CitrateNetwork/citrate-coop @ b8a884f01d84a4605e5752e052ef092e1922ba0b
//            (branch fix/explicit-initial-admin; re-vendor from main after it merges), vendored 2026-10-18.
// Includes:  PBA R2 remediation (citrate-coop #3), Apache-2.0 relicense, explicit initial admin/registrar, role-holder validation.
// Integrity: every line after this 10-line header is byte-identical to upstream:
//            `tail -n +11 <this file> | sha256sum` == b1ec51d8ac4b94f438429c10c8d07e530f28cd5545473c91026d38205232313f
// Why:       C2 D9 / C4: deployed dormant at betanet genesis by the citrate-chain
//            ceremony (script/DeployDormantLedgers.s.sol).
// ───────────────────────────────────────────────────────────────────────────────────
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title Auth — minimal role-based access control (RFC-CIT-COOP-0001)
/// @notice Tiny, dependency-free AccessControl. The initial DEFAULT_ADMIN_ROLE holder is passed
///         EXPLICITLY to the constructor — it is never inferred from `msg.sender`.
/// @dev The initial admin is an explicit, audited deploy input rather than the deploying
///      account, so the role holder is whatever the deploy names. The canonical CREATE2
///      deployer is rejected as a holder because it is a permissionless relay.
abstract contract Auth {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    mapping(bytes32 => mapping(address => bool)) private _roles;
    /// PBA-L2-040 B-025: number of DEFAULT_ADMIN holders; the last one can never be revoked.
    /// @dev Counts only USABLE holders: every grant path funnels through `_grantAs`, which rejects
    ///      the zero address and the CREATE2 relay, so an unusable holder can never be recorded
    ///      and can never inflate this counter past the number of real administrators.
    uint256 private _adminCount;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /// Canonical (Arachnid) CREATE2 deployer — a permissionless relay; never a valid role holder.
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    error Unauthorized(bytes32 role, address account);
    error LastAdmin();
    error ZeroRoleHolder();
    error Create2DeployerAsHolder();

    /// @param initialAdmin the sole initial DEFAULT_ADMIN_ROLE holder (non-zero, not the CREATE2 relay)
    constructor(address initialAdmin) {
        _grantAs(DEFAULT_ADMIN_ROLE, initialAdmin, address(0)); // validates via _requireHolder
    }

    /// @dev Reject the zero address and the CREATE2 relay as a role holder. Enforced on EVERY
    ///      grant path (constructor, `grantRole`, `_grant`, `_grantAs`).
    function _requireHolder(address account) internal pure {
        if (account == address(0)) revert ZeroRoleHolder();
        if (account == CREATE2_DEPLOYER) revert Create2DeployerAsHolder();
    }

    /// @dev True iff `account` can act as a role holder (not zero, not the CREATE2 relay).
    function _isUsableHolder(address account) internal pure returns (bool) {
        return account != address(0) && account != CREATE2_DEPLOYER;
    }

    modifier onlyRole(bytes32 role) {
        if (!_roles[role][msg.sender]) revert Unauthorized(role, msg.sender);
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grant(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_roles[role][account]) {
            // B-025: never strand administration. Only usable holders are counted, so removing an
            // unusable entry neither trips nor decrements the guard.
            if (role == DEFAULT_ADMIN_ROLE && _isUsableHolder(account)) {
                if (_adminCount == 1) revert LastAdmin();
                _adminCount -= 1;
            }
            _roles[role][account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }

    function _grant(bytes32 role, address account) internal {
        _grantAs(role, account, msg.sender);
    }

    /// @dev Grant with an explicit `sender` for the event. Constructors use this with
    ///      `sender = address(0)` (a construction-time grant from an explicit argument), so no
    ///      code path reachable from a constructor reads `msg.sender`.
    ///      Every role recipient is validated here, so no grant path can bypass `_requireHolder`.
    function _grantAs(bytes32 role, address account, address sender) internal {
        _requireHolder(account);
        if (!_roles[role][account]) {
            if (role == DEFAULT_ADMIN_ROLE) _adminCount += 1; // account is usable (checked above)
            _roles[role][account] = true;
            emit RoleGranted(role, account, sender);
        }
    }
}

/// @notice Minimal reentrancy guard.
abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    error Reentrancy();

    modifier nonReentrant() {
        if (_status == 2) revert Reentrancy();
        _status = 2;
        _;
        _status = 1;
    }
}
