// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {ICashoutRequest} from "./interfaces/ICashoutRequest.sol";

/// @title CashoutRequest
/// @notice Teacher-initiated SALT withdrawal with admin approval.
/// @dev Invariants: CashoutRequiresAdminApproval, SelfApprovalForbidden (Q-004).
contract CashoutRequest is ICashoutRequest {
    address public governance;

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
    error NotTeacher();
    error RequestNotPending();
    error SelfApproval();
    error ZeroAmount();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(address _governance, uint256 initialRate) {
        governance = _governance;
        _saltUsdRate = initialRate;
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
