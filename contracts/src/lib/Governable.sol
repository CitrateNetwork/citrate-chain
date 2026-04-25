// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title Governable — two-step governance transfer mixin
/// @notice Standardized governance pattern for the Citrate L1 contracts.
///         Inherits OZ-style two-step ownership semantics: the current
///         governor proposes a successor, and the proposed account
///         must explicitly accept the role before it activates.
///
///         RM-B1 / WP-D1.1 (audit SOL-21).
///
///         Pre-fix: every governable contract carried its own
///         `transferGovernance(newGovernance)` that wrote the new
///         address atomically. A mistyped or revoked-key successor
///         silently locked governance forever — there was no way
///         to detect that the new key was unreachable until the
///         next governance call rejected.
///
///         Post-fix: `transferGovernance(newGovernance)` only
///         records the proposal; the new account must call
///         `acceptGovernance()` to take effect. The current
///         governor may cancel the proposal at any time before
///         acceptance.
///
/// @dev Inheriting contracts:
///        - call `_initGovernance(initialGovernor)` from their
///          constructor, OR pass the governor to the abstract
///          constructor `Governable(initialGovernor)`.
///        - use `onlyGovernance` instead of any custom modifier.
///        - read `governance()` (function) instead of any private
///          field.
abstract contract Governable {
    address private _governance;
    address private _pendingGovernance;

    event GovernanceTransferProposed(
        address indexed currentGovernance,
        address indexed pendingGovernance
    );
    event GovernanceTransferred(
        address indexed previousGovernance,
        address indexed newGovernance
    );
    event GovernanceTransferCancelled(address indexed pendingGovernance);

    error Governable_NotGovernance();
    error Governable_NotPendingGovernance();
    error Governable_ZeroAddress();
    error Governable_NoPendingTransfer();

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert Governable_ZeroAddress();
        _governance = initialGovernance;
        emit GovernanceTransferred(address(0), initialGovernance);
    }

    modifier onlyGovernance() {
        if (msg.sender != _governance) revert Governable_NotGovernance();
        _;
    }

    /// @notice The active governor.
    function governance() public view returns (address) {
        return _governance;
    }

    /// @notice The proposed-but-not-yet-accepted governor, or zero
    /// if no transfer is pending.
    function pendingGovernance() public view returns (address) {
        return _pendingGovernance;
    }

    /// @notice Propose `newGovernance` as the next governor. The
    /// current governor still holds power until `acceptGovernance`
    /// is called by the proposed account.
    function transferGovernance(address newGovernance)
        external
        virtual
        onlyGovernance
    {
        if (newGovernance == address(0)) revert Governable_ZeroAddress();
        _pendingGovernance = newGovernance;
        emit GovernanceTransferProposed(_governance, newGovernance);
    }

    /// @notice Accept a pending governance transfer. Only callable
    /// by the address recorded as `pendingGovernance`.
    function acceptGovernance() external virtual {
        if (msg.sender != _pendingGovernance) revert Governable_NotPendingGovernance();
        address previous = _governance;
        _governance = _pendingGovernance;
        _pendingGovernance = address(0);
        emit GovernanceTransferred(previous, _governance);
    }

    /// @notice Cancel a pending governance transfer. Callable only
    /// by the current governor.
    function cancelGovernanceTransfer() external virtual onlyGovernance {
        if (_pendingGovernance == address(0)) revert Governable_NoPendingTransfer();
        address cancelled = _pendingGovernance;
        _pendingGovernance = address(0);
        emit GovernanceTransferCancelled(cancelled);
    }
}
