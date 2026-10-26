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

    /// @dev A set/role getter is "true" only for a 32-byte 1; any other word
    ///      (not a bool encoding) means "not this kind of getter", never a revert.
    function _readBool(address target, bytes memory cd) internal view returns (bool ok, bool value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, false);
        uint256 w = abi.decode(ret, (uint256));
        if (w > 1) return (false, false);
        return (true, w == 1);
    }

    /// @notice Every address-valued privileged getter the sweep reads: admin
    ///         and governance slots, fee recipients, bound callers, operators,
    ///         oracles, signers and wired dependencies. A contract without a
    ///         getter is simply not checked for it.
    /// @dev scripts/ci/privileged_slots_tripwire.sh requires every address slot
    ///      of a DeployAll contract to be read here or exempt with a reason
    ///      (contracts/script/lib/privileged_slots.json).
    function _addressSlotGetters() internal pure returns (string[40] memory) {
        return [
            "governance()", "pendingGovernance()", "owner()", "pendingOwner()",
            "admin()", "pendingAdmin()", "guardian()", "provider()",
            "treasury()", "treasuryAddress()", "pendingTreasury()", "feeRecipient()",
            "marketplace()", "verifier()", "operator()", "minter()",
            "oracle()", "pricingOracle()", "signer()", "verifyingSigner()",
            "relayer()", "slasher()", "facilitator()", "burner()",
            "slashingContract()", "bulkGateway()", "jobRegistry()", "modelRegistry()",
            "marketMaker()", "contributionAccounting()", "contributions()", "stakingPool()",
            "distributionStablecoin()", "wSALT()", "registry()", "recorder()",
            "keeper()", "manager()", "controller()", "beneficiary()"
        ];
    }

    /// @notice Every `mapping(address => bool)` membership the sweep reads.
    function _addressSetGetters() internal pure returns (string[12] memory) {
        return [
            "authorizedRecorders(address)", "authorizedDisputers(address)", "authorizedSpenders(address)",
            "authorizedActivityRecorders(address)", "authorizedMatcher(address)", "teeOracles(address)",
            "isOracle(address)", "isOracleMember(address)", "isRecorder(address)",
            "eligibleParticipant(address)", "isOperator(address)", "isMinter(address)"
        ];
    }

    /// @notice Every role the sweep reads through `hasRole(bytes32,address)`.
    function _probedRoleNames() internal pure returns (string[12] memory) {
        return [
            "DEFAULT_ADMIN_ROLE", "OPERATOR_ROLE", "VALIDATOR_ROLE", "REPORTER_ROLE",
            "FACILITATOR_ROLE", "MINTER_ROLE", "PAUSER_ROLE", "UPGRADER_ROLE",
            "PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE", "TIMELOCK_ADMIN_ROLE"
        ];
    }

    function _roleId(string memory name) internal pure returns (bytes32) {
        return keccak256(bytes(name)) == keccak256("DEFAULT_ADMIN_ROLE") ? DEFAULT_ADMIN_ROLE : keccak256(bytes(name));
    }

    /// An address no genuine set or role contains: a getter that also answers
    /// "true" for it answers for everyone (a fallback), so its answer is ignored.
    address private constant UNHELD = address(uint160(uint256(keccak256("AdminChecks.unheld-probe"))));

    function _holds(address target, bytes memory cdWho, bytes memory cdUnheld) private view returns (bool) {
        (bool ok, bool v) = _readBool(target, cdWho);
        if (!ok || !v) return false;
        (bool ok2, bool v2) = _readBool(target, cdUnheld);
        return !(ok2 && v2);
    }

    /// @notice The first privileged slot of `target` that names `who`, as
    ///         "<getter> is <noun>", "<subject> is in <set>" or "<subject> holds
    ///         <ROLE>"; empty when there is none. Never reverts.
    function _holderProblem(address target, address who, string memory noun, string memory subject)
        internal
        view
        returns (string memory)
    {
        if (target.code.length == 0) return "no code at address";
        string[40] memory getters = _addressSlotGetters();
        for (uint256 i = 0; i < getters.length; i++) {
            (bool ok, address a) = _readAddress(target, abi.encodeWithSignature(getters[i]));
            if (ok && a == who) return string.concat(getters[i], " is ", noun);
        }
        string[12] memory sets = _addressSetGetters();
        for (uint256 i = 0; i < sets.length; i++) {
            if (_holds(target, abi.encodeWithSignature(sets[i], who), abi.encodeWithSignature(sets[i], UNHELD))) {
                return string.concat(subject, " is in ", sets[i]);
            }
        }
        string[12] memory roles = _probedRoleNames();
        for (uint256 i = 0; i < roles.length; i++) {
            bytes32 r = _roleId(roles[i]);
            if (
                _holds(
                    target,
                    abi.encodeWithSignature("hasRole(bytes32,address)", r, who),
                    abi.encodeWithSignature("hasRole(bytes32,address)", r, UNHELD)
                )
            ) return string.concat(subject, " holds ", roles[i]);
        }
        return "";
    }

    /// @notice Returns an empty string when `target` is clean, otherwise the
    ///         first problem found. Never reverts, so a sweep can collect all.
    function _factoryAdminProblem(address target) internal view returns (string memory) {
        return _holderProblem(target, ARACHNID_FACTORY, "the CREATE2 factory", "CREATE2 factory");
    }

    /// @notice Like `_factoryAdminProblem` but for the deployer EOA: after the
    ///         hand-off it must hold no privileged slot on any deployed book
    ///         contract (governance/owner/admin, fee recipient, bound caller,
    ///         operator, oracle, signer, set membership or role).
    function _deployerAdminProblem(address target, address deployer) internal view returns (string memory) {
        return _holderProblem(target, deployer, "the deployer EOA", "deployer EOA");
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
