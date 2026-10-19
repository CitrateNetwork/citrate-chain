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
    /// OZ TimelockController role ids (keccak256 of the role name, as OZ defines them).
    bytes32 internal constant TIMELOCK_PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 internal constant TIMELOCK_EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 internal constant TIMELOCK_CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

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
        return _governingSeatProblem(target, ARACHNID_FACTORY, "CREATE2 factory");
    }

    /// @notice Like `_factoryAdminProblem` but for an arbitrary EOA holder — the
    ///         deployer EOA must not retain governance/owner/DEFAULT_ADMIN on any
    ///         deployed book contract after the governance hand-off (PBA follow-up).
    function _deployerAdminProblem(address target, address deployer) internal view returns (string memory) {
        if (target.code.length == 0) return "no code at address";
        (bool ok, address a) = _readAddress(target, abi.encodeWithSignature("governance()"));
        if (ok && a == deployer) return "governance() is the deployer EOA";
        (ok, a) = _readAddress(target, abi.encodeWithSignature("pendingGovernance()"));
        if (ok && a == deployer) return "pendingGovernance() is the deployer EOA";
        (ok, a) = _readAddress(target, abi.encodeWithSignature("owner()"));
        if (ok && a == deployer) return "owner() is the deployer EOA";
        (ok, a) = _readAddress(target, abi.encodeWithSignature("provider()"));
        if (ok && a == deployer) return "provider() is the deployer EOA";
        bool has;
        (ok, has) = _readBool(
            target, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, deployer)
        );
        if (ok && has) return "deployer EOA holds DEFAULT_ADMIN_ROLE";
        return _governingSeatProblem(target, deployer, "deployer EOA");
    }

    /// @notice C4 genesis governance: the seats that govern without being an "admin" slot.
    ///         OZ `TimelockController` PROPOSER / EXECUTOR / CANCELLER (whoever holds them
    ///         runs the timelock, and through it everything it administers), and an owner
    ///         seat on an m-of-n (`isOwner(address)`: MultisigProposer, MultisigTimelock2of3).
    ///         Empty string when `holder` sits in none of them.
    function _governingSeatProblem(address target, address holder, string memory who)
        internal
        view
        returns (string memory)
    {
        bytes32[3] memory roles = [TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE, TIMELOCK_CANCELLER_ROLE];
        string[3] memory names = ["PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"];
        for (uint256 i = 0; i < 3; i++) {
            (bool ok, bool has) =
                _readBool(target, abi.encodeWithSignature("hasRole(bytes32,address)", roles[i], holder));
            if (ok && has) return string.concat(who, " holds timelock ", names[i]);
        }
        (bool okOwner, bool owner) = _readBool(target, abi.encodeWithSignature("isOwner(address)", holder));
        if (okOwner && owner) return string.concat(who, " is a multisig owner");
        return "";
    }

    /// @notice Revert unless OZ TimelockController `timelock` has been handed over to
    ///         `multisig`: the multisig holds PROPOSER, EXECUTOR and CANCELLER, execution is
    ///         not open to everyone, the timelock administers itself, its delay is
    ///         `minDelay`, and `deployer` (and the CREATE2 factory) hold no seat on it.
    function _assertTimelockHandover(
        string memory name,
        address timelock,
        address multisig,
        address deployer,
        uint256 minDelay
    ) internal view {
        _assertNoFactoryAdmin(name, timelock);
        _assertNoDeployerAdmin(name, timelock, deployer);
        bytes32[3] memory roles = [TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE, TIMELOCK_CANCELLER_ROLE];
        for (uint256 i = 0; i < 3; i++) {
            (bool ok, bool has) =
                _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", roles[i], multisig));
            require(ok && has, string.concat(name, ": multisig lacks a timelock role"));
        }
        (bool okOpen, bool open) =
            _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", TIMELOCK_EXECUTOR_ROLE, address(0)));
        require(okOpen && !open, string.concat(name, ": timelock execution is open to anyone"));
        (bool okSelf, bool self) =
            _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, timelock));
        require(okSelf && self, string.concat(name, ": timelock does not administer itself"));
        (bool okDelay, bytes memory ret) = timelock.staticcall(abi.encodeWithSignature("getMinDelay()"));
        require(
            okDelay && ret.length == 32 && abi.decode(ret, (uint256)) == minDelay,
            string.concat(name, ": timelock minDelay is not the intended value")
        );
    }

    /// @notice Revert if `deployer` holds any admin slot or governing seat on `target`.
    function _assertNoDeployerAdmin(string memory name, address target, address deployer) internal view {
        string memory problem = _deployerAdminProblem(target, deployer);
        require(bytes(problem).length == 0, string.concat(name, ": ", problem));
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

    /// @notice Revert unless `expected` holds DEFAULT_ADMIN_ROLE on `target` and NO address in
    ///         `others` does. For contracts whose initial admin is a constructor argument: checks
    ///         the actual accounts that took part in the deploy (configured deployer, the real
    ///         broadcaster, the CREATE2 factory), not only the one the script was told about.
    function _assertSoleAdminAmong(string memory name, address target, address expected, address[] memory others)
        internal
        view
    {
        _assertAdminRole(name, target, expected);
        for (uint256 i = 0; i < others.length; i++) {
            require(others[i] != expected, string.concat(name, ": intended admin is also a deploy account"));
            (bool ok, bool has) =
                _readBool(target, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, others[i]));
            require(ok && !has, string.concat(name, ": a deploy account holds DEFAULT_ADMIN_ROLE"));
        }
    }

    /// @notice Revert unless `owner()` is exactly `expected`.
    function _assertOwner(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, address o) = _readAddress(target, abi.encodeWithSignature("owner()"));
        require(ok && o == expected, string.concat(name, ": owner() is not the intended key"));
    }
}
