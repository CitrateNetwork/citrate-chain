// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

interface IGovernanceTimelock {
    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        external
        pure
        returns (bytes32);

    function hashOperationBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external pure returns (bytes32);

    function cancel(bytes32 id) external;
}

/// @title GuardianCanceller: the GUARDIAN council's veto over GOVERNANCE, minus self-protection
/// @notice C2 D5, owner decision 2026-10-19 (fed#331). This contract, not the guardian itself,
///         holds CANCELLER_ROLE on the GOVERNANCE TimelockController. The guardian (the GUARDIAN
///         timelock, behind its m-of-n) cancels a queued GOVERNANCE operation by handing this
///         contract the operation's full preimage; the id is recomputed from it with the
///         timelock's own hash, so the inspected calls are exactly the calls that would run.
///
///         The veto covers every GOVERNANCE operation EXCEPT one that only removes or replaces
///         the guardian, so governance can always retire a compromised guardian after its
///         delay. Such an operation (single or batch) consists solely of calls of these forms,
///         each with value 0 and canonical ABI encoding, and contains at least one removal:
///           removal      GovernanceTimelock.revokeRole(CANCELLER_ROLE, this)
///           removal      GovernanceTimelock.renounceRole(CANCELLER_ROLE, this)
///           removal      this.setGuardian(newGuardian)          (newGuardian != the current guardian)
///           replacement  GovernanceTimelock.grantRole(CANCELLER_ROLE, anyone but this)
///                                                                (only alongside a removal)
///         A call that leaves the guardian path as it is (setGuardian(current guardian),
///         grantRole(CANCELLER_ROLE, this)) is not of these forms, so an operation that contains
///         one, including a batch that removes the guardian and restores it, stays cancellable.
///         An operation that mixes any other call with a removal stays cancellable, so a
///         removal cannot be used to carry an unrelated action past the veto.
///
///         Holds no value and no other role; nothing here can schedule or execute.
contract GuardianCanceller {
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
    bytes4 internal constant GRANT_ROLE = bytes4(keccak256("grantRole(bytes32,address)"));
    bytes4 internal constant REVOKE_ROLE = bytes4(keccak256("revokeRole(bytes32,address)"));
    bytes4 internal constant RENOUNCE_ROLE = bytes4(keccak256("renounceRole(bytes32,address)"));

    /// @notice The GOVERNANCE TimelockController this contract cancels on.
    address public immutable governanceTimelock;
    /// @notice The only caller of `cancel` / `cancelBatch` (the GUARDIAN timelock).
    address public guardian;

    event GuardianSet(address indexed previous, address indexed guardian);
    event GuardianCancelled(bytes32 indexed id);

    error NotGuardian();
    error NotGovernance();
    error TimelockHasNoCode();
    error GuardianIsTimelock();
    error LengthMismatch();
    error EmptyOperation();
    /// The operation only removes or replaces the guardian: outside the veto by owner decision.
    error GuardianRemovalNotCancellable(bytes32 id);

    constructor(address governanceTimelock_, address guardian_) {
        if (governanceTimelock_.code.length == 0) revert TimelockHasNoCode();
        governanceTimelock = governanceTimelock_;
        _setGuardian(guardian_);
    }

    /// @notice Replace the guardian. Only the GOVERNANCE timelock (a timelocked operation, and
    ///         one the guardian cannot cancel).
    function setGuardian(address guardian_) external {
        if (msg.sender != governanceTimelock) revert NotGovernance();
        _setGuardian(guardian_);
    }

    /// @notice Cancel the pending GOVERNANCE operation with this preimage (`schedule`).
    function cancel(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt) external {
        if (msg.sender != guardian) revert NotGuardian();
        bytes32 id = IGovernanceTimelock(governanceTimelock).hashOperation(target, value, data, predecessor, salt);
        (bool management, bool removal) = _classify(target, value, data);
        if (management && removal) revert GuardianRemovalNotCancellable(id);
        _cancel(id);
    }

    /// @notice Cancel the pending GOVERNANCE batch operation with this preimage (`scheduleBatch`).
    function cancelBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external {
        if (msg.sender != guardian) revert NotGuardian();
        bytes32 id =
            IGovernanceTimelock(governanceTimelock).hashOperationBatch(targets, values, payloads, predecessor, salt);
        if (isGuardianRemoval(targets, values, payloads)) revert GuardianRemovalNotCancellable(id);
        _cancel(id);
    }

    /// @notice True when the calls only remove or replace the guardian (see the contract notes).
    function isGuardianRemoval(address[] calldata targets, uint256[] calldata values, bytes[] calldata payloads)
        public
        view
        returns (bool)
    {
        uint256 n = targets.length;
        if (n != values.length || n != payloads.length) revert LengthMismatch();
        if (n == 0) revert EmptyOperation();
        bool anyRemoval = false;
        for (uint256 i = 0; i < n; i++) {
            (bool management, bool removal) = _classify(targets[i], values[i], payloads[i]);
            if (!management) return false;
            anyRemoval = anyRemoval || removal;
        }
        return anyRemoval;
    }

    function _cancel(bytes32 id) internal {
        IGovernanceTimelock(governanceTimelock).cancel(id);
        emit GuardianCancelled(id);
    }

    function _setGuardian(address guardian_) internal {
        InitialAdmin.check(guardian_); // nonzero, never the CREATE2 factory
        if (guardian_ == governanceTimelock) revert GuardianIsTimelock();
        emit GuardianSet(guardian, guardian_);
        guardian = guardian_;
    }

    /// @return management the call is one of the guardian-removal / -replacement forms
    /// @return removal    the call removes the current guardian path (revoke / renounce / setGuardian)
    function _classify(address target, uint256 value, bytes calldata data)
        internal
        view
        returns (bool management, bool removal)
    {
        if (value != 0 || data.length < 4) return (false, false);
        bytes4 sel = bytes4(data[:4]);
        if (target == governanceTimelock) {
            if (data.length != 68) return (false, false);
            if (sel != GRANT_ROLE && sel != REVOKE_ROLE && sel != RENOUNCE_ROLE) return (false, false);
            (bytes32 role, uint256 account) = abi.decode(data[4:], (bytes32, uint256));
            if (role != CANCELLER_ROLE || account > type(uint160).max) return (false, false);
            // Re-granting this canceller restores the guardian path: never part of a removal.
            if (sel == GRANT_ROLE) {
                return account == uint256(uint160(address(this))) ? (false, false) : (true, false);
            }
            return account == uint256(uint160(address(this))) ? (true, true) : (false, false);
        }
        if (target == address(this) && sel == this.setGuardian.selector && data.length == 36) {
            uint256 account = abi.decode(data[4:], (uint256));
            // setGuardian(current guardian) changes nothing, so it is not a removal; a batch
            // that sets another guardian and then the current one back contains this call and
            // so stays cancellable too.
            if (account > type(uint160).max || account == uint256(uint160(guardian))) return (false, false);
            return (true, true);
        }
        return (false, false);
    }
}
