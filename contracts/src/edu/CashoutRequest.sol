// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {ICashoutRequest} from "./interfaces/ICashoutRequest.sol";

/// @title CashoutRequest
/// @notice Teacher-initiated SALT withdrawal with admin approval.
/// @dev Invariants: CashoutRequiresAdminApproval, SelfApprovalForbidden (Q-004).
contract CashoutRequest is ICashoutRequest {
    address public governance;

    /// @notice Pending governance address awaiting acceptance.
    /// Closes RFI26-05: 2-step transfer prevents permanent lock.
    address public pendingGovernance;

    struct Request {
        address teacher;
        uint256 classroomId;
        uint256 saltAmount;
        bytes32 reasonHash;
        RequestStatus status;
        address approvedBy;
    }

    mapping(uint256 => Request) private _requests;
    uint256 private _nextRequestId;
    uint256 private _saltUsdRate; // basis points (100 = $0.01 per SALT)

    error NotGovernance();
    error NotPendingGovernance();
    error ZeroGovernance();
    error NotTeacher();
    error RequestNotPending();
    error SelfApproval();
    error ZeroAmount();

    event GovernanceProposed(address indexed pending);
    event GovernanceAccepted(address indexed previous, address indexed current);

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(address _governance, uint256 initialRate) {
        if (_governance == address(0)) revert ZeroGovernance();
        governance = _governance;
        _saltUsdRate = initialRate;
    }

    /// @notice Step 1 of governance transfer (closes RFI26-05).
    function proposeGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert ZeroGovernance();
        pendingGovernance = newGovernance;
        emit GovernanceProposed(newGovernance);
    }

    /// @notice Step 2 of governance transfer (closes RFI26-05).
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        address previous = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceAccepted(previous, governance);
    }

    function getRequestStatus(uint256 requestId) external view returns (RequestStatus) {
        return _requests[requestId].status;
    }

    function getRequestTeacher(uint256 requestId) external view returns (address) {
        return _requests[requestId].teacher;
    }

    function getRequestAmount(uint256 requestId) external view returns (uint256) {
        return _requests[requestId].saltAmount;
    }

    function getSaltUsdRate() external view returns (uint256) {
        return _saltUsdRate;
    }

    function requestCashout(
        uint256 classroomId,
        uint256 saltAmount,
        bytes32 reasonHash
    ) external returns (uint256 requestId) {
        if (saltAmount == 0) revert ZeroAmount();

        requestId = _nextRequestId++;
        _requests[requestId] = Request({
            teacher: msg.sender,
            classroomId: classroomId,
            saltAmount: saltAmount,
            reasonHash: reasonHash,
            status: RequestStatus.Pending,
            approvedBy: address(0)
        });

        emit CashoutRequested(requestId, msg.sender, classroomId, saltAmount, reasonHash);
    }

    /// @dev Invariant: SelfApprovalForbidden — approver cannot be the requesting teacher
    function approveCashout(uint256 requestId) external onlyGovernance {
        Request storage req = _requests[requestId];
        if (req.status != RequestStatus.Pending) revert RequestNotPending();
        if (req.teacher == msg.sender) revert SelfApproval();

        req.status = RequestStatus.Approved;
        req.approvedBy = msg.sender;

        emit CashoutApprovedByAdmin(requestId, msg.sender);
    }

    function rejectCashout(uint256 requestId, bytes32 rejectionReasonHash) external onlyGovernance {
        Request storage req = _requests[requestId];
        if (req.status != RequestStatus.Pending) revert RequestNotPending();

        req.status = RequestStatus.Rejected;
        emit CashoutRejectedByAdmin(requestId, msg.sender, rejectionReasonHash);
    }

    function setSaltUsdRate(uint256 rateBasisPoints) external onlyGovernance {
        _saltUsdRate = rateBasisPoints;
    }
}
