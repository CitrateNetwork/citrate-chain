// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

/// @title MultisigTimelock2of3 — RFC-CIT-AGENT-0001 §3 + planset
///        06_ON_CHAIN_SURFACE.md "2-of-3 timelocked controller".
///
/// 3 fixed owners. Any owner may propose an operation; a second
/// distinct owner approves it; after `minDelay` elapses, any owner
/// may execute. Operations are arbitrary `(target, calldata)` pairs
/// — the timelock has no special knowledge of cit-agent contracts;
/// admins just `transferOwnership(timelock)` their contracts to
/// route admin calls through this control layer.
///
/// Replay protection: opId = keccak256(target, payload, nonce). The
/// proposer's monotonic nonce prevents collision on identical
/// proposals.
contract MultisigTimelock2of3 is IERC1155Receiver {
    /// 3 fixed owners. Index-stable for accessor ergonomics.
    address[3] public owners;
    /// Minimum delay between a proposal reaching 2 approvals and
    /// being executable. Set at construction; cannot be modified
    /// without redeploy.
    uint256 public immutable minDelay;

    enum OpState { None, Proposed, Approved, Executed, Cancelled }

    struct Operation {
        address target;
        bytes payload;
        OpState state;
        /// Block timestamp at which `execute` becomes allowed.
        /// Set when `approve` transitions the op to `Approved`.
        uint256 executableAt;
        uint8 approvalCount;
        address proposer;
    }

    mapping(bytes32 => Operation) private _ops;
    /// approvals[opId][owner] = true means that owner has signed.
    mapping(bytes32 => mapping(address => bool)) private _approvals;

    /// Per-proposer nonce used in opId derivation so two identical
    /// (target, payload) proposals don't collide.
    mapping(address => uint256) public proposerNonce;

    error NotOwner();
    error OperationNotFound();
    error OperationAlreadyExists();
    error AlreadyApprovedBySigner();
    error NotEnoughApprovals();
    error TimelockNotElapsed();
    error InvalidState();
    error ExecutionFailed(bytes returnData);

    event Proposed(bytes32 indexed opId, address indexed proposer, address target);
    event Approved(bytes32 indexed opId, address indexed approver, uint8 approvalCount);
    event ExecutableAt(bytes32 indexed opId, uint256 timestamp);
    event Executed(bytes32 indexed opId, address indexed executor);
    event Cancelled(bytes32 indexed opId, address indexed canceller);

    modifier onlyOwner() {
        if (!_isOwner(msg.sender)) revert NotOwner();
        _;
    }

    constructor(address[3] memory _owners, uint256 _minDelay) {
        owners = _owners;
        minDelay = _minDelay;
    }

    /// Propose a new operation. Caller becomes the first approver
    /// implicitly (count starts at 1). A second owner must call
    /// `approve` before the timelock starts.
    function propose(address target, bytes calldata payload)
        external
        onlyOwner
        returns (bytes32 opId)
    {
        uint256 nonce = proposerNonce[msg.sender]++;
        opId = keccak256(abi.encode(target, payload, msg.sender, nonce));
        if (_ops[opId].state != OpState.None) revert OperationAlreadyExists();
        _ops[opId] = Operation({
            target: target,
            payload: payload,
            state: OpState.Proposed,
            executableAt: 0,
            approvalCount: 1,
            proposer: msg.sender
        });
        _approvals[opId][msg.sender] = true;
        emit Proposed(opId, msg.sender, target);
    }

    /// Approve an existing operation. Same caller cannot approve
    /// twice. Reaching 2-of-3 approvals starts the timelock by
    /// setting `executableAt`.
    function approve(bytes32 opId) external onlyOwner {
        Operation storage op = _ops[opId];
        if (op.state == OpState.None) revert OperationNotFound();
        if (op.state != OpState.Proposed) revert InvalidState();
        if (_approvals[opId][msg.sender]) revert AlreadyApprovedBySigner();
        _approvals[opId][msg.sender] = true;
        op.approvalCount += 1;
        emit Approved(opId, msg.sender, op.approvalCount);
        if (op.approvalCount >= 2) {
            op.state = OpState.Approved;
            op.executableAt = block.timestamp + minDelay;
            emit ExecutableAt(opId, op.executableAt);
        }
    }

    /// Execute an approved operation after the timelock has elapsed.
    /// Any owner may execute. Reentrancy guard: the op is marked
    /// `Executed` before the external call (checks-effects-
    /// interactions).
    function execute(bytes32 opId) external onlyOwner returns (bytes memory) {
        Operation storage op = _ops[opId];
        if (op.state != OpState.Approved) revert InvalidState();
        if (block.timestamp < op.executableAt) revert TimelockNotElapsed();
        op.state = OpState.Executed;
        (bool ok, bytes memory ret) = op.target.call(op.payload);
        if (!ok) revert ExecutionFailed(ret);
        emit Executed(opId, msg.sender);
        return ret;
    }

    /// Cancel a Proposed or Approved operation. Any owner may
    /// cancel — the assumption is that any of the 3 detecting a
    /// compromise is sufficient grounds to halt.
    function cancel(bytes32 opId) external onlyOwner {
        Operation storage op = _ops[opId];
        if (op.state != OpState.Proposed && op.state != OpState.Approved) {
            revert InvalidState();
        }
        op.state = OpState.Cancelled;
        emit Cancelled(opId, msg.sender);
    }

    // ── View helpers ───────────────────────────────────────────────

    function getOperation(bytes32 opId)
        external
        view
        returns (
            address target,
            bytes memory payload,
            OpState state,
            uint256 executableAt,
            uint8 approvalCount,
            address proposer
        )
    {
        Operation storage op = _ops[opId];
        return (op.target, op.payload, op.state, op.executableAt, op.approvalCount, op.proposer);
    }

    function hasApproved(bytes32 opId, address owner) external view returns (bool) {
        return _approvals[opId][owner];
    }

    function isOwner(address candidate) external view returns (bool) {
        return _isOwner(candidate);
    }

    function _isOwner(address candidate) internal view returns (bool) {
        return candidate == owners[0] || candidate == owners[1] || candidate == owners[2];
    }

    // ── ERC-1155 receiver hook ─────────────────────────────────────
    // CapsuleRegistry mints install tokens to `msg.sender`, which
    // is this contract when the timelock executes a registerCapsule
    // proposal. Implementing the receiver hook lets the timelock
    // hold the supply on behalf of the org until governance
    // distributes capabilities via other mechanisms.

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}
