// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IBudgetAllocation} from "./interfaces/IBudgetAllocation.sol";

/// @title BudgetAllocation
/// @notice Per-classroom SALT spending limits drawn from the InstitutionalVault.
/// @dev Invariant from Q-004: BudgetCannotExceedVaultBalance (enforced by caller/vault).
contract BudgetAllocation is IBudgetAllocation {
    address public governance;

    struct Budget {
        uint256 allocated;
        uint256 spent;
        uint256 monthlyLimit;
        bool active;
    }

    mapping(uint256 => Budget) private _budgets;

    error NotGovernance();
    error BudgetNotActive();
    error BudgetAlreadyActive();
    error InsufficientBudget();
    error ExceedsMonthlyLimit();
    error ZeroAmount();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(address _governance) {
        governance = _governance;
    }

    function getRemaining(uint256 classroomId) external view returns (uint256) {
        Budget storage b = _budgets[classroomId];
        if (!b.active) return 0;
        return b.allocated > b.spent ? b.allocated - b.spent : 0;
    }

    function getAllocated(uint256 classroomId) external view returns (uint256) {
        return _budgets[classroomId].allocated;
    }

    function getSpent(uint256 classroomId) external view returns (uint256) {
        return _budgets[classroomId].spent;
    }

    function getMonthlyLimit(uint256 classroomId) external view returns (uint256) {
        return _budgets[classroomId].monthlyLimit;
    }

    function allocateBudget(uint256 classroomId, uint256 amount, uint256 monthlyLimit) external onlyGovernance {
        if (amount == 0) revert ZeroAmount();
        Budget storage b = _budgets[classroomId];
        b.allocated += amount;
        b.monthlyLimit = monthlyLimit;
        b.active = true;
        emit BudgetAllocated(classroomId, amount, monthlyLimit);
    }

    /// @dev Reverts if spending would exceed allocated budget.
    function spendFromBudget(uint256 classroomId, uint256 amount) external {
        Budget storage b = _budgets[classroomId];
        if (!b.active) revert BudgetNotActive();
        if (amount == 0) revert ZeroAmount();
        uint256 remaining = b.allocated > b.spent ? b.allocated - b.spent : 0;
        if (amount > remaining) revert InsufficientBudget();

        b.spent += amount;
        emit BudgetSpent(classroomId, amount, b.allocated - b.spent);

        if (b.allocated == b.spent) {
            emit BudgetExhausted(classroomId);
        }
    }

    function refillBudget(uint256 classroomId, uint256 amount) external onlyGovernance {
        if (amount == 0) revert ZeroAmount();
        Budget storage b = _budgets[classroomId];
        if (!b.active) revert BudgetNotActive();
        b.allocated += amount;
        emit BudgetRefilled(classroomId, amount);
    }
}
