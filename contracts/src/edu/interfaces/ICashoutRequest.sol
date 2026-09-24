// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title ICashoutRequest
/// @notice Teacher-initiated SALT withdrawal with admin approval.
/// @dev Invariants from Q-004:
///   - CashoutRequiresAdminApproval
///   - SelfApprovalForbidden
interface ICashoutRequest {
    // ── Enums ──

    enum RequestStatus { Pending, Approved, Rejected, Paid }

    // ── Events ──

    event CashoutRequested(
        uint256 indexed requestId,
        address indexed teacher,
        uint256 indexed classroomId,
        uint256 saltAmount,
        bytes32 reasonHash
    );
    event CashoutApprovedByAdmin(uint256 indexed requestId, address indexed approvedBy);
    event CashoutRejectedByAdmin(uint256 indexed requestId, address indexed rejectedBy, bytes32 rejectionReasonHash);
    event CashoutPaid(uint256 indexed requestId, uint256 saltAmount);

    // ── Views ──

    /// @notice Get cashout request status.
    function getRequestStatus(uint256 requestId) external view returns (RequestStatus);

    /// @notice Get the teacher who made the request.
    function getRequestTeacher(uint256 requestId) external view returns (address);

    /// @notice Get the SALT amount requested.
    function getRequestAmount(uint256 requestId) external view returns (uint256);

    /// @notice Get the current admin-set SALT/USD rate (in basis points, e.g., 100 = $0.01).
    function getSaltUsdRate() external view returns (uint256);

    // ── Mutators ──

    /// @notice Request a cashout (Teacher only, via Forwarder).
    /// @dev Invariant: SelfApprovalForbidden — the requesting teacher cannot approve this.
    function requestCashout(
        uint256 classroomId,
        uint256 saltAmount,
        bytes32 reasonHash
    ) external returns (uint256 requestId);

    /// @notice Approve a cashout request (Admin only, NOT the requesting teacher).
    function approveCashout(uint256 requestId) external;

    /// @notice Reject a cashout request with reason (Admin only).
    function rejectCashout(uint256 requestId, bytes32 rejectionReasonHash) external;

    /// @notice Set the SALT/USD conversion rate (Admin only).
    function setSaltUsdRate(uint256 rateBasisPoints) external;
}
