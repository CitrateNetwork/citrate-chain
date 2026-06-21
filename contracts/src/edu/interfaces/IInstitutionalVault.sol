// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title IInstitutionalVault
/// @notice Multi-sig treasury for school-controlled SALT funds.
/// @dev Implements invariants from Q-004 InstitutionalVaultSafety.tla:
///   1. NoWithdrawalWithoutQuorum
///   2. EmergencyPauseStopsOutflows
///   3. UnpauseRequiresQuorum
///   4. SignerAddRemoveRequiresQuorum
///   5. BudgetCannotExceedVaultBalance
///   6. CashoutRequiresAdminApproval
///   7. SelfApprovalForbidden
///   8. ThresholdBoundsValid
interface IInstitutionalVault {
    // ── Events ──

    event Deposited(address indexed from, uint256 amount);
    event CashoutProposed(uint256 indexed txId, address indexed to, uint256 amount, bytes32 reasonHash);
    event CashoutApproved(uint256 indexed txId, address indexed signer);
    event CashoutExecuted(uint256 indexed txId, address indexed to, uint256 amount);
    event CashoutRejected(uint256 indexed txId, address indexed rejectedBy);
    event EmergencyPaused(address indexed pausedBy);
    event Unpaused(uint256 approvalCount);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event SignerChangeProposed(uint256 indexed proposalId, address target, bool isAdd, address proposer);
    event SignerChangeApproved(uint256 indexed proposalId, address approver);
    event SignerChangeRejected(uint256 indexed proposalId, address rejector);

    // ── Views ──

    /// @notice Current vault SALT balance.
    function getBalance() external view returns (uint256);

    /// @notice Whether the vault is paused (all outflows halted).
    function isPaused() external view returns (bool);

    /// @notice Current signing threshold (k in k-of-n).
    function getThreshold() external view returns (uint256);

    /// @notice Total number of signers.
    function getSignerCount() external view returns (uint256);

    /// @notice Check if an address is a signer.
    function isSigner(address addr) external view returns (bool);

    /// @notice Get approval count for a pending cashout.
    function getApprovalCount(uint256 txId) external view returns (uint256);

    /// @notice Check if a signer has approved a specific cashout.
    function hasApproved(uint256 txId, address signer) external view returns (bool);

    // ── Mutators ──

    /// @notice Deposit SALT into the vault.
    function deposit() external payable;

    /// @notice Propose a cashout (admin or SuperAdmin only).
    /// @param to Recipient address
    /// @param amount SALT amount in wei
    /// @param reasonHash keccak256 of the reason string (bytes32, not string — gas efficient)
    /// @return txId Unique cashout transaction ID
    function proposeCashout(address to, uint256 amount, bytes32 reasonHash) external returns (uint256 txId);

    /// @notice Approve a pending cashout (signer only).
    /// @dev Invariant: SelfApprovalForbidden — proposer cannot approve their own cashout.
    function approveCashout(uint256 txId) external;

    /// @notice Execute a cashout after quorum is met.
    function executeCashout(uint256 txId) external;

    /// @notice Reject a pending cashout (admin only).
    function rejectCashout(uint256 txId) external;

    /// @notice Emergency pause — any signer can trigger (1-of-n).
    /// @dev Invariant: EmergencyPauseStopsOutflows
    function emergencyPause() external;

    /// @notice Unpause — requires k-of-n approval.
    /// @dev Invariant: UnpauseRequiresQuorum
    function unpause() external;

    /// @notice Propose adding or removing a signer (requires k-of-n quorum to execute).
    /// @dev Invariant: SignerAddRemoveRequiresQuorum
    function proposeSignerChange(address target, bool isAdd) external returns (uint256 proposalId);

    /// @notice Approve a pending signer change proposal.
    function approveSignerChange(uint256 proposalId) external;

    /// @notice Execute a signer change proposal after quorum is met.
    function executeSignerChange(uint256 proposalId) external;

    /// @notice Reject a signer change proposal.
    function rejectSignerChange(uint256 proposalId) external;

    /// @notice Change the signing threshold (requires k-of-n approval).
    /// @dev Invariant: ThresholdBoundsValid — k > 0 and k <= n.
    ///      FWA-C3-16: a bare single-signer `setThreshold` let one signer
    ///      unilaterally weaken the multisig; replaced with a quorum-gated
    ///      propose/approve/execute flow mirroring the signer-change flow.
    function proposeThresholdChange(uint256 newThreshold) external returns (uint256 proposalId);
    function approveThresholdChange(uint256 proposalId) external;
    function executeThresholdChange(uint256 proposalId) external;
    function rejectThresholdChange(uint256 proposalId) external;
}
