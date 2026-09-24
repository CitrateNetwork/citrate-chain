// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title IBudgetAllocation
/// @notice Per-classroom SALT spending limits drawn from the InstitutionalVault.
/// @dev Invariant from Q-004: BudgetCannotExceedVaultBalance
interface IBudgetAllocation {
    // ── Events ──

    event BudgetAllocated(uint256 indexed classroomId, uint256 amount, uint256 monthlyLimit);
    event BudgetSpent(uint256 indexed classroomId, uint256 amount, uint256 remaining);
    event BudgetRefilled(uint256 indexed classroomId, uint256 amount);
    event BudgetExhausted(uint256 indexed classroomId);

    // ── Views ──

    /// @notice Get remaining budget for a classroom.
    function getRemaining(uint256 classroomId) external view returns (uint256);

    /// @notice Get total allocated budget for a classroom.
    function getAllocated(uint256 classroomId) external view returns (uint256);

    /// @notice Get total spent by a classroom.
    function getSpent(uint256 classroomId) external view returns (uint256);

    /// @notice Get monthly spending limit.
    function getMonthlyLimit(uint256 classroomId) external view returns (uint256);

    // ── Mutators ──

    /// @notice Allocate budget from vault to a classroom (Admin only).
    function allocateBudget(uint256 classroomId, uint256 amount, uint256 monthlyLimit) external;

    /// @notice Spend from a classroom's budget (Teacher of that classroom, via Forwarder).
    /// @dev Reverts if amount > remaining budget.
    function spendFromBudget(uint256 classroomId, uint256 amount) external;

    /// @notice Refill a classroom's budget from vault (Admin only).
    function refillBudget(uint256 classroomId, uint256 amount) external;
}
