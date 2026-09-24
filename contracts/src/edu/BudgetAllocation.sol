// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IBudgetAllocation} from "./interfaces/IBudgetAllocation.sol";

/// @title BudgetAllocation
/// @notice Per-classroom SALT spending limits drawn from the InstitutionalVault.
/// @dev Invariant from Q-004: BudgetCannotExceedVaultBalance (enforced by caller/vault).
contract BudgetAllocation is IBudgetAllocation {
    address public governance;

    /// @notice Pending governance address awaiting acceptance.
    /// Closes RFI26-05: 2-step transfer prevents permanent lock if
    /// the new governance address is mistyped.
    address public pendingGovernance;

    struct Budget {
        uint256 allocated;
        uint256 spent;
        uint256 monthlyLimit;
        bool active;
    }

    mapping(uint256 => Budget) private _budgets;

    /// @notice Governance-managed spender allowlist. Only an authorized
    /// spender (or governance itself) may draw down a classroom budget.
    /// Closes CHAIN-B-C006: `spendFromBudget` was permissionless, letting
    /// any address exhaust any classroom's allocation.
    mapping(address => bool) public authorizedSpender;

    error NotGovernance();
    error NotPendingGovernance();
    error NotAuthorizedSpender();
    error ZeroGovernance();
    error ZeroSpender();
    error BudgetNotActive();
    error BudgetAlreadyActive();
    error InsufficientBudget();
    error ExceedsMonthlyLimit();
    error ZeroAmount();

    event GovernanceProposed(address indexed pending);
    event GovernanceAccepted(address indexed previous, address indexed current);
    event SpenderSet(address indexed spender, bool authorized);

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    /// @dev Governance always counts as an authorized spender.
    modifier onlySpender() {
        if (msg.sender != governance && !authorizedSpender[msg.sender]) {
            revert NotAuthorizedSpender();
        }
        _;
    }

    constructor(address _governance) {
        if (_governance == address(0)) revert ZeroGovernance();
        governance = _governance;
    }

    /// @notice Step 1 of governance transfer: current governance proposes
    /// a new address. Caller must be `governance`. To cancel, call again
    /// with the same address — this is a no-op except for the event.
    /// Closes RFI26-05.
    function proposeGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert ZeroGovernance();
        pendingGovernance = newGovernance;
        emit GovernanceProposed(newGovernance);
    }

    /// @notice Step 2 of governance transfer: the proposed new address
    /// accepts. This proves the address is reachable and signs.
    /// Closes RFI26-05.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        address previous = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceAccepted(previous, governance);
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

    /// @notice Authorize (or revoke) an address permitted to call
    /// `spendFromBudget`. Governance-only. Closes CHAIN-B-C006.
    function setSpender(address spender, bool authorized) external onlyGovernance {
        if (spender == address(0)) revert ZeroSpender();
        authorizedSpender[spender] = authorized;
        emit SpenderSet(spender, authorized);
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
    /// @dev Access-gated (CHAIN-B-C006): only governance or a
    ///      governance-authorized spender may draw a classroom budget.
    function spendFromBudget(uint256 classroomId, uint256 amount) external onlySpender {
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
