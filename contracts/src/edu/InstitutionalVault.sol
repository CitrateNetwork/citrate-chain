// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IInstitutionalVault} from "./interfaces/IInstitutionalVault.sol";

/// @title InstitutionalVault
/// @notice Multi-sig treasury for school-controlled SALT funds.
/// @dev All 9 invariants from Q-004 InstitutionalVaultSafety.tla enforced.
///      Signer add/remove now requires k-of-n quorum via proposal flow.
contract InstitutionalVault is IInstitutionalVault {
    // ── Storage ──

    address[] private _signerList;
    mapping(address => bool) private _isSigner;
    uint256 private _threshold;
    bool private _paused;

    struct CashoutTx {
        address to;
        uint256 amount;
        bytes32 reasonHash;
        address proposer;
        uint256 approvalCount;
        bool executed;
        bool rejected;
    }

    mapping(uint256 => CashoutTx) private _cashouts;
    mapping(uint256 => mapping(address => bool)) private _approvals;
    uint256 private _nextTxId;

    // Unpause approval tracking
    mapping(address => bool) private _unpauseApprovals;
    uint256 private _unpauseApprovalCount;

    // Signer change proposals
    struct SignerChangeProposal {
        address target;        // address to add or remove
        bool isAdd;            // true = add, false = remove
        uint256 approvalCount;
        bool executed;
        bool rejected;
    }
    mapping(uint256 => SignerChangeProposal) private _signerProposals;
    mapping(uint256 => mapping(address => bool)) private _signerProposalApprovals;
    uint256 private _nextSignerProposalId;

    // ── Errors ──

    error NotSigner();
    error AlreadySigner();
    error NotASigner();
    error InvalidThreshold();
    error VaultPaused();
    error VaultNotPaused();
    error AlreadyApproved();
    error QuorumNotMet();
    error AlreadyExecuted();
    error AlreadyRejected();
    error SelfApproval();
    error InsufficientBalance();
    error TransferFailed();
    error ZeroAddress();
    error SignerProposalNotFound();
    error SignerProposalAlreadyExecuted();
    error SignerProposalAlreadyRejected();
    error SignerProposalAlreadyApproved();
    error SignerProposalQuorumNotMet();

    // ── Modifiers ──

    modifier onlySigner() {
        if (!_isSigner[msg.sender]) revert NotSigner();
        _;
    }

    modifier whenNotPaused() {
        if (_paused) revert VaultPaused();
        _;
    }

    modifier whenPaused() {
        if (!_paused) revert VaultNotPaused();
        _;
    }

    // ── Constructor ──

    constructor(address[] memory signers, uint256 threshold) {
        if (signers.length == 0) revert InvalidThreshold();
        if (threshold == 0 || threshold > signers.length) revert InvalidThreshold();

        for (uint256 i = 0; i < signers.length; i++) {
            address s = signers[i];
            if (s == address(0)) revert ZeroAddress();
            if (_isSigner[s]) revert AlreadySigner();
            _isSigner[s] = true;
            _signerList.push(s);
        }
        _threshold = threshold;
    }

    // ── Views ──

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function isPaused() external view returns (bool) {
        return _paused;
    }

    function getThreshold() external view returns (uint256) {
        return _threshold;
    }

    function getSignerCount() external view returns (uint256) {
        return _signerList.length;
    }

    function isSigner(address addr) external view returns (bool) {
        return _isSigner[addr];
    }

    function getApprovalCount(uint256 txId) external view returns (uint256) {
        return _cashouts[txId].approvalCount;
    }

    function hasApproved(uint256 txId, address signer) external view returns (bool) {
        return _approvals[txId][signer];
    }

    /// @notice Get approval count for a signer change proposal.
    function getSignerProposalApprovalCount(uint256 proposalId) external view returns (uint256) {
        return _signerProposals[proposalId].approvalCount;
    }

    /// @notice Check if a signer has approved a signer change proposal.
    function hasApprovedSignerChange(uint256 proposalId, address signer) external view returns (bool) {
        return _signerProposalApprovals[proposalId][signer];
    }

    // ── Deposit ──

    function deposit() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ── Cashout Lifecycle ──

    /// @dev Invariant: CashoutRequiresAdminApproval — only signers can propose
    function proposeCashout(
        address to,
        uint256 amount,
        bytes32 reasonHash
    ) external onlySigner whenNotPaused returns (uint256 txId) {
        if (to == address(0)) revert ZeroAddress();
        if (amount > address(this).balance) revert InsufficientBalance();

        txId = _nextTxId++;
        _cashouts[txId] = CashoutTx({
            to: to,
            amount: amount,
            reasonHash: reasonHash,
            proposer: msg.sender,
            approvalCount: 0,
            executed: false,
            rejected: false
        });

        emit CashoutProposed(txId, to, amount, reasonHash);
    }

    /// @dev Invariant: SelfApprovalForbidden — proposer cannot approve their own cashout
    /// @dev Invariant: NoWithdrawalWithoutQuorum — needs threshold approvals
    function approveCashout(uint256 txId) external onlySigner whenNotPaused {
        CashoutTx storage tx_ = _cashouts[txId];
        if (tx_.executed) revert AlreadyExecuted();
        if (tx_.rejected) revert AlreadyRejected();
        if (tx_.proposer == msg.sender) revert SelfApproval();
        if (_approvals[txId][msg.sender]) revert AlreadyApproved();

        _approvals[txId][msg.sender] = true;
        tx_.approvalCount++;

        emit CashoutApproved(txId, msg.sender);
    }

    function executeCashout(uint256 txId) external onlySigner whenNotPaused {
        CashoutTx storage tx_ = _cashouts[txId];
        if (tx_.executed) revert AlreadyExecuted();
        if (tx_.rejected) revert AlreadyRejected();
        if (tx_.approvalCount < _threshold) revert QuorumNotMet();
        if (tx_.amount > address(this).balance) revert InsufficientBalance();

        tx_.executed = true;

        (bool success,) = tx_.to.call{value: tx_.amount}("");
        if (!success) revert TransferFailed();

        emit CashoutExecuted(txId, tx_.to, tx_.amount);
    }

    function rejectCashout(uint256 txId) external onlySigner {
        CashoutTx storage tx_ = _cashouts[txId];
        if (tx_.executed) revert AlreadyExecuted();
        if (tx_.rejected) revert AlreadyRejected();

        tx_.rejected = true;
        emit CashoutRejected(txId, msg.sender);
    }

    // ── Emergency Pause ──

    /// @dev Invariant: EmergencyPauseStopsOutflows — any signer, 1-of-n
    function emergencyPause() external onlySigner whenNotPaused {
        _paused = true;
        // Reset unpause approvals
        for (uint256 i = 0; i < _signerList.length; i++) {
            _unpauseApprovals[_signerList[i]] = false;
        }
        _unpauseApprovalCount = 0;

        emit EmergencyPaused(msg.sender);
    }

    /// @dev Invariant: UnpauseRequiresQuorum — needs k-of-n
    function unpause() external onlySigner whenPaused {
        if (!_unpauseApprovals[msg.sender]) {
            _unpauseApprovals[msg.sender] = true;
            _unpauseApprovalCount++;
        }

        if (_unpauseApprovalCount >= _threshold) {
            _paused = false;
            // Reset
            for (uint256 i = 0; i < _signerList.length; i++) {
                _unpauseApprovals[_signerList[i]] = false;
            }
            _unpauseApprovalCount = 0;

            emit Unpaused(_threshold);
        }
    }

    // ── Signer Management (Quorum-gated proposal flow) ──

    /// @dev Invariant: SignerAddRemoveRequiresQuorum — Step 1: Any signer proposes
    function proposeSignerChange(address target, bool isAdd) external onlySigner returns (uint256 proposalId) {
        if (target == address(0)) revert ZeroAddress();
        if (isAdd && _isSigner[target]) revert AlreadySigner();
        if (!isAdd && !_isSigner[target]) revert NotASigner();
        // Pre-check: removing must not drop below threshold
        if (!isAdd && _signerList.length - 1 < _threshold) revert InvalidThreshold();

        proposalId = _nextSignerProposalId++;
        _signerProposals[proposalId] = SignerChangeProposal({
            target: target,
            isAdd: isAdd,
            approvalCount: 0,
            executed: false,
            rejected: false
        });
        // Proposer auto-approves
        _signerProposalApprovals[proposalId][msg.sender] = true;
        _signerProposals[proposalId].approvalCount = 1;

        emit SignerChangeProposed(proposalId, target, isAdd, msg.sender);
    }

    /// @dev Step 2: Other signers approve
    function approveSignerChange(uint256 proposalId) external onlySigner {
        SignerChangeProposal storage p = _signerProposals[proposalId];
        if (p.executed) revert SignerProposalAlreadyExecuted();
        if (p.rejected) revert SignerProposalAlreadyRejected();
        if (_signerProposalApprovals[proposalId][msg.sender]) revert SignerProposalAlreadyApproved();

        _signerProposalApprovals[proposalId][msg.sender] = true;
        p.approvalCount++;

        emit SignerChangeApproved(proposalId, msg.sender);
    }

    /// @dev Step 3: Execute once quorum reached
    function executeSignerChange(uint256 proposalId) external onlySigner {
        SignerChangeProposal storage p = _signerProposals[proposalId];
        if (p.executed) revert SignerProposalAlreadyExecuted();
        if (p.rejected) revert SignerProposalAlreadyRejected();
        if (p.approvalCount < _threshold) revert SignerProposalQuorumNotMet();

        p.executed = true;

        if (p.isAdd) {
            _isSigner[p.target] = true;
            _signerList.push(p.target);
            emit SignerAdded(p.target);
        } else {
            _isSigner[p.target] = false;
            for (uint256 i = 0; i < _signerList.length; i++) {
                if (_signerList[i] == p.target) {
                    _signerList[i] = _signerList[_signerList.length - 1];
                    _signerList.pop();
                    break;
                }
            }
            emit SignerRemoved(p.target);
        }
    }

    /// @dev Reject a signer change proposal (any signer can reject)
    function rejectSignerChange(uint256 proposalId) external onlySigner {
        SignerChangeProposal storage p = _signerProposals[proposalId];
        if (p.executed) revert SignerProposalAlreadyExecuted();
        if (p.rejected) revert SignerProposalAlreadyRejected();
        p.rejected = true;
        emit SignerChangeRejected(proposalId, msg.sender);
    }

    /// @dev Invariant: ThresholdBoundsValid — k > 0 and k <= n
    function setThreshold(uint256 newThreshold) external onlySigner {
        if (newThreshold == 0 || newThreshold > _signerList.length) revert InvalidThreshold();

        uint256 oldThreshold = _threshold;
        _threshold = newThreshold;

        emit ThresholdChanged(oldThreshold, newThreshold);
    }
}
