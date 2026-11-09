// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

interface IGovernanceTimelockV2 {
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

/// @notice The ProviderRegistry read this canceller needs (contracts/src/amc/ProviderRegistry.sol).
interface IProviderRegistryGuardianSeat {
    function guardian() external view returns (address);
}

/// @title GuardianCancellerV2: GuardianCanceller for the 0.6.0 ceremony genesis, which also keeps
///        the guardian out of the ProviderRegistry guardian-seat rotation
/// @notice Owner decision 2026-11-09 (V60-GEN-Q21, option 1). For the 0.6.0 ceremony genesis
///         ONLY; r1006 and r1007 keep GuardianCanceller (v1) unchanged at its own salt. v2 is v1
///         plus one extra non-cancellable form, because under V60-GEN-Q9 the GUARDIAN council
///         is both ProviderRegistry's block-0 guardian and this canceller's guardian, and could
///         otherwise cancel governance's rotation of the registry seat away from itself:
///           rotation     providerRegistry.setGuardian(next)      (next != the registry's current guardian)
///         An operation is outside the veto when it is a v1 guardian removal (unchanged, below),
///         or when it is the rotation alone, or the rotation together only with v1 removal forms
///         of this canceller's own path. A CANCELLER_ROLE grant counts as a replacement only
///         alongside a removal of this canceller's path (revoke, renounce or this.setGuardian),
///         exactly as in v1; next to a rotation alone it is an ordinary call. So the rotation
///         mixed with any other call (an unrelated call, or a grant without a canceller-path
///         removal) stays cancellable, and a rotation to the registry's current guardian changes
///         nothing and stays cancellable.
///
/// v1 notes:
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
contract GuardianCancellerV2 {
    /// How a single call relates to the guardian paths.
    enum CallKind {
        Other, // anything else: keeps the operation cancellable
        Replacement, // grantRole(CANCELLER_ROLE, anyone but this): counts only beside a CancellerRemoval
        CancellerRemoval, // revoke / renounce CANCELLER_ROLE of this, or this.setGuardian(new guardian)
        RegistryRotation // providerRegistry.setGuardian(new guardian)
    }

    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
    bytes4 internal constant GRANT_ROLE = bytes4(keccak256("grantRole(bytes32,address)"));
    bytes4 internal constant REVOKE_ROLE = bytes4(keccak256("revokeRole(bytes32,address)"));
    bytes4 internal constant RENOUNCE_ROLE = bytes4(keccak256("renounceRole(bytes32,address)"));

    /// @notice The GOVERNANCE TimelockController this contract cancels on.
    address public immutable governanceTimelock;
    /// @notice The block-0 ProviderRegistry whose guardian-seat rotation is outside the veto.
    address public immutable providerRegistry;
    /// @notice The only caller of `cancel` / `cancelBatch` (the GUARDIAN timelock).
    address public guardian;

    event GuardianSet(address indexed previous, address indexed guardian);
    event GuardianCancelled(bytes32 indexed id);

    error NotGuardian();
    error NotGovernance();
    error TimelockHasNoCode();
    error RegistryHasNoCode();
    error GuardianIsTimelock();
    error LengthMismatch();
    error EmptyOperation();
    /// The operation only removes or replaces the guardian: outside the veto by owner decision.
    error GuardianRemovalNotCancellable(bytes32 id);

    /// @param governanceTimelock_ the GOVERNANCE TimelockController
    /// @param guardian_           the GUARDIAN timelock (the only caller of cancel / cancelBatch)
    /// @param providerRegistry_   the block-0 ProviderRegistry (deployed before this contract)
    constructor(address governanceTimelock_, address guardian_, address providerRegistry_) {
        if (governanceTimelock_.code.length == 0) revert TimelockHasNoCode();
        if (providerRegistry_.code.length == 0) revert RegistryHasNoCode();
        governanceTimelock = governanceTimelock_;
        providerRegistry = providerRegistry_;
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
        bytes32 id = IGovernanceTimelockV2(governanceTimelock).hashOperation(target, value, data, predecessor, salt);
        CallKind k = _classify(target, value, data);
        if (k == CallKind.CancellerRemoval || k == CallKind.RegistryRotation) {
            revert GuardianRemovalNotCancellable(id);
        }
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
            IGovernanceTimelockV2(governanceTimelock).hashOperationBatch(targets, values, payloads, predecessor, salt);
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
        bool cancellerRemoval = false;
        bool rotation = false;
        bool replacement = false;
        for (uint256 i = 0; i < n; i++) {
            CallKind k = _classify(targets[i], values[i], payloads[i]);
            if (k == CallKind.Other) return false;
            if (k == CallKind.CancellerRemoval) cancellerRemoval = true;
            else if (k == CallKind.RegistryRotation) rotation = true;
            else replacement = true;
        }
        // v1: a replacement grant is part of a removal only beside a canceller-path removal.
        if (replacement && !cancellerRemoval) return false;
        return cancellerRemoval || rotation;
    }

    function _cancel(bytes32 id) internal {
        IGovernanceTimelockV2(governanceTimelock).cancel(id);
        emit GuardianCancelled(id);
    }

    function _setGuardian(address guardian_) internal {
        // check() reverts on zero or the CREATE2 factory; its return value is its input.
        // slither-disable-next-line unused-return
        InitialAdmin.check(guardian_); // nonzero, never the CREATE2 factory
        if (guardian_ == governanceTimelock) revert GuardianIsTimelock();
        emit GuardianSet(guardian, guardian_);
        guardian = guardian_;
    }

    /// @return the kind of guardian-path change the call is (see `CallKind`)
    function _classify(address target, uint256 value, bytes calldata data) internal view returns (CallKind) {
        if (value != 0 || data.length < 4) return CallKind.Other;
        bytes4 sel = bytes4(data[:4]);
        if (target == governanceTimelock) {
            if (data.length != 68) return CallKind.Other;
            if (sel != GRANT_ROLE && sel != REVOKE_ROLE && sel != RENOUNCE_ROLE) return CallKind.Other;
            (bytes32 role, uint256 account) = abi.decode(data[4:], (bytes32, uint256));
            if (role != CANCELLER_ROLE || account > type(uint160).max) return CallKind.Other;
            // Re-granting this canceller restores the guardian path: never part of a removal.
            if (sel == GRANT_ROLE) {
                return account == uint256(uint160(address(this))) ? CallKind.Other : CallKind.Replacement;
            }
            return account == uint256(uint160(address(this))) ? CallKind.CancellerRemoval : CallKind.Other;
        }
        if (target == providerRegistry && sel == this.setGuardian.selector && data.length == 36) {
            // ProviderRegistry.setGuardian(address) has the same selector as this.setGuardian.
            uint256 next = abi.decode(data[4:], (uint256));
            // A rotation to the registry's current guardian changes nothing: not a removal.
            if (next > type(uint160).max) return CallKind.Other;
            if (next == uint256(uint160(IProviderRegistryGuardianSeat(providerRegistry).guardian()))) {
                return CallKind.Other;
            }
            return CallKind.RegistryRotation;
        }
        if (target == address(this) && sel == this.setGuardian.selector && data.length == 36) {
            uint256 account = abi.decode(data[4:], (uint256));
            // setGuardian(current guardian) changes nothing, so it is not a removal; a batch
            // that sets another guardian and then the current one back contains this call and
            // so stays cancellable too.
            if (account > type(uint160).max || account == uint256(uint160(guardian))) return CallKind.Other;
            return CallKind.CancellerRemoval;
        }
        return CallKind.Other;
    }
}
