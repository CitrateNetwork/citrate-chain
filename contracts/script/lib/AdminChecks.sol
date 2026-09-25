// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title AdminChecks — post-deploy admin/owner/governance assertions (PBA-L2-002)
/// @notice The 2026-09-24 pre-bounty audit found that `new X{salt:}()` in a forge
///         script runs the constructor with `msg.sender == 0x4e59…956C` (the
///         Arachnid CREATE2 deployer). 21 live contracts on 40204 recorded that
///         factory as their governance / owner / DEFAULT_ADMIN, which nobody can
///         ever act as. Every ceremony script now calls these helpers after
///         deploying, so a regression fails the dry-run instead of shipping.
///
///         All reads are low-level `staticcall`s: a contract that does not
///         implement a given getter is simply not checked for that slot, and a
///         codeless target is an error in its own right.
abstract contract AdminChecks {
    address internal constant ARACHNID_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;

    function _readAddress(address target, bytes memory cd) internal view returns (bool ok, address value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, address(0));
        return (true, abi.decode(ret, (address)));
    }

    function _readBool(address target, bytes memory cd) internal view returns (bool ok, bool value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, false);
        return (true, abi.decode(ret, (bool)));
    }

    /// @notice Returns an empty string when `target` is clean, otherwise the
    ///         first problem found. Never reverts, so a sweep can collect all.
    function _factoryAdminProblem(address target) internal view returns (string memory) {
        if (target.code.length == 0) return "no code at address";
        (bool ok, address a) = _readAddress(target, abi.encodeWithSignature("governance()"));
        if (ok && a == ARACHNID_FACTORY) return "governance() is the CREATE2 factory";
        (ok, a) = _readAddress(target, abi.encodeWithSignature("pendingGovernance()"));
        if (ok && a == ARACHNID_FACTORY) return "pendingGovernance() is the CREATE2 factory";
        (ok, a) = _readAddress(target, abi.encodeWithSignature("owner()"));
        if (ok && a == ARACHNID_FACTORY) return "owner() is the CREATE2 factory";
        (ok, a) = _readAddress(target, abi.encodeWithSignature("provider()"));
        if (ok && a == ARACHNID_FACTORY) return "provider() is the CREATE2 factory";
        bool has;
        (ok, has) = _readBool(
            target, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, ARACHNID_FACTORY)
        );
        if (ok && has) return "CREATE2 factory holds DEFAULT_ADMIN_ROLE";
        return "";
    }

    /// @notice Revert if `target` names the CREATE2 factory in any admin slot.
    function _assertNoFactoryAdmin(string memory name, address target) internal view {
        string memory problem = _factoryAdminProblem(target);
        require(bytes(problem).length == 0, string.concat(name, ": ", problem));
    }

    /// @notice Revert unless `governance()` is exactly `expected`.
    function _assertGovernance(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, address g) = _readAddress(target, abi.encodeWithSignature("governance()"));
        require(ok && g == expected, string.concat(name, ": governance() is not the intended key"));
    }

    /// @notice Revert unless `expected` holds DEFAULT_ADMIN_ROLE.
    function _assertAdminRole(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, bool has) = _readBool(
            target, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, expected)
        );
        require(ok && has, string.concat(name, ": intended key lacks DEFAULT_ADMIN_ROLE"));
    }

    /// @notice Revert unless `owner()` is exactly `expected`.
    function _assertOwner(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, address o) = _readAddress(target, abi.encodeWithSignature("owner()"));
        require(ok && o == expected, string.concat(name, ": owner() is not the intended key"));
    }
}
