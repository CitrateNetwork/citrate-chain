// ── VENDORED: DO NOT EDIT. Change upstream, then re-vendor with a new header. ─────
// Source:    CitrateNetwork/citrate-coop contracts/src/lib/Auth.sol
// Upstream:  github.com/CitrateNetwork/citrate-coop @ 99b2d0d29d38e0576c0118e083c5de48747cc3ba
//            (fetched from GitHub main, not from a local copy), vendored 2026-10-19.
// Includes:  PBA R2 remediation (citrate-coop #3, 3d4aaae6) and the Apache-2.0 relicense.
// Integrity: every line after this 10-line header is byte-identical to upstream:
//            `tail -n +11 <this file> | sha256sum` == f2196a0bab6786f83d917c959114cc9f03f029a5e2266d9acfd58429d9b0458c
// Why:       C2 D9 / C4: deployed dormant at betanet genesis by the citrate-chain
//            ceremony (script/DeployDormantLedgers.s.sol).
// ───────────────────────────────────────────────────────────────────────────────────
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title Auth — minimal role-based access control (RFC-CIT-COOP-0001)
/// @notice Tiny, dependency-free AccessControl. Deployer gets DEFAULT_ADMIN_ROLE.
abstract contract Auth {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    mapping(bytes32 => mapping(address => bool)) private _roles;
    /// PBA-L2-040 B-025: number of DEFAULT_ADMIN holders; the last one can never be revoked.
    uint256 private _adminCount;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    error Unauthorized(bytes32 role, address account);
    error LastAdmin();

    constructor() {
        _grant(DEFAULT_ADMIN_ROLE, msg.sender);
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
            if (role == DEFAULT_ADMIN_ROLE) {
                if (_adminCount == 1) revert LastAdmin(); // B-025: never strand administration
                _adminCount -= 1;
            }
            _roles[role][account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }

    function _grant(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            if (role == DEFAULT_ADMIN_ROLE) _adminCount += 1;
            _roles[role][account] = true;
            emit RoleGranted(role, account, msg.sender);
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
