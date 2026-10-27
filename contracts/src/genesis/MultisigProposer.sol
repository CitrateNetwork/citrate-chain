// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title MultisigProposer: an m-of-n front for one OpenZeppelin TimelockController
/// @notice C2 D5 / G3. The delay, the operation queue, the predecessor ordering and the
///         cancel path all live in the audited OZ `TimelockController`. This contract only
///         decides WHO may call it: an action is a single call to `timelock`, and it runs
///         once `threshold` distinct owners have approved it. The timelock grants this
///         contract PROPOSER, EXECUTOR and CANCELLER, so `schedule`, `execute` and `cancel`
///         on the timelock are each one approved action here.
///
///         Generalised from `MultisigTimelock2of3` (constructor checks, owner-only calls,
///         execute-once), with the delay removed (the timelock owns it) and the target fixed.
///
///         Fixed at deploy: owners, threshold and timelock. To rotate owners, deploy a new
///         MultisigProposer and, through this one, schedule a timelock self-call that grants
///         the roles to the new contract and revokes them from this one.
///
///         Approvals are on-chain transactions (no off-chain signatures), so there is no
///         signature, nonce or EIP-712 surface. Holds no value.
///
///         Proposals expire `proposalTtl` seconds after they are proposed (fixed at deploy,
///         1..30 days): from then on they can no longer be approved, revoked or executed, so a
///         stale approval set cannot be used later. Re-proposing the same call yields a new id.
contract MultisigProposer {
    uint256 public constant MAX_OWNERS = 10;
    uint256 public constant MIN_PROPOSAL_TTL = 1 days;
    uint256 public constant MAX_PROPOSAL_TTL = 30 days;

    address public immutable timelock;
    uint256 public immutable threshold;
    /// @notice Seconds after `propose` during which a proposal may be approved and executed.
    uint256 public immutable proposalTtl;

    address[] private _owners;
    mapping(address => bool) public isOwner;

    struct Proposal {
        bytes data;
        uint32 approvals;
        bool exists;
        bool executed;
        uint64 expiresAt;
    }

    /// @notice Proposal ids are keccak256(chainid, this, sequence number, data); the sequence
    ///         number makes two identical proposals distinct and an id never repeats.
    uint256 public proposalCount;
    mapping(bytes32 => Proposal) private _proposals;
    mapping(bytes32 => mapping(address => bool)) public hasApproved;

    event Proposed(bytes32 indexed id, address indexed proposer, bytes data, uint256 expiresAt);
    event Approved(bytes32 indexed id, address indexed owner, uint256 approvals);
    event Revoked(bytes32 indexed id, address indexed owner, uint256 approvals);
    event Executed(bytes32 indexed id, address indexed executor);

    error NotOwner();
    error TimelockHasNoCode();
    error BadOwnerCount(uint256 count);
    error BadThreshold(uint256 threshold, uint256 owners);
    error BadProposalTtl(uint256 ttl);
    error DuplicateOwner(address owner);
    error OwnerIsTimelock();
    error EmptyCall();
    error UnknownProposal();
    error AlreadyExecuted();
    error ProposalExpired(uint256 expiresAt);
    error AlreadyApproved();
    error NotApproved();
    error BelowThreshold(uint256 approvals, uint256 threshold);
    error ExecutionFailed(bytes returnData);

    modifier onlyOwner() {
        if (!isOwner[msg.sender]) revert NotOwner();
        _;
    }

    constructor(address timelock_, address[] memory owners_, uint256 threshold_, uint256 proposalTtl_) {
        if (timelock_.code.length == 0) revert TimelockHasNoCode();
        uint256 n = owners_.length;
        if (n == 0 || n > MAX_OWNERS) revert BadOwnerCount(n);
        if (threshold_ == 0 || threshold_ > n) revert BadThreshold(threshold_, n);
        if (proposalTtl_ < MIN_PROPOSAL_TTL || proposalTtl_ > MAX_PROPOSAL_TTL) revert BadProposalTtl(proposalTtl_);
        for (uint256 i = 0; i < n; i++) {
            address o = InitialAdmin.check(owners_[i]); // nonzero, never the CREATE2 factory
            if (o == timelock_) revert OwnerIsTimelock();
            if (isOwner[o]) revert DuplicateOwner(o);
            isOwner[o] = true;
        }
        _owners = owners_;
        timelock = timelock_;
        threshold = threshold_;
        proposalTtl = proposalTtl_;
    }

    /// @notice Propose one call to the timelock. The proposer's approval is counted. The
    ///         proposal expires at `block.timestamp + proposalTtl`.
    function propose(bytes calldata data) external onlyOwner returns (bytes32 id) {
        if (data.length < 4) revert EmptyCall();
        id = keccak256(abi.encode(block.chainid, address(this), proposalCount++, data));
        Proposal storage p = _proposals[id];
        p.data = data;
        p.exists = true;
        p.expiresAt = uint64(block.timestamp + proposalTtl);
        emit Proposed(id, msg.sender, data, p.expiresAt);
        _approve(id, p);
    }

    function approve(bytes32 id) external onlyOwner {
        _approve(id, _pending(id));
    }

    /// @notice Withdraw an approval before the action runs.
    function revoke(bytes32 id) external onlyOwner {
        Proposal storage p = _pending(id);
        if (!hasApproved[id][msg.sender]) revert NotApproved();
        hasApproved[id][msg.sender] = false;
        p.approvals -= 1;
        emit Revoked(id, msg.sender, p.approvals);
    }

    /// @notice Run an approved, unexpired action. Marked executed before the call; a call that
    ///         reverts reverts this too, so the action stays pending and may be retried until
    ///         it expires (for example a timelock `execute` sent before the delay has elapsed).
    function execute(bytes32 id) external onlyOwner returns (bytes memory ret) {
        Proposal storage p = _pending(id);
        if (p.approvals < threshold) revert BelowThreshold(p.approvals, threshold);
        p.executed = true;
        bool ok;
        (ok, ret) = timelock.call(p.data);
        if (!ok) revert ExecutionFailed(ret);
        emit Executed(id, msg.sender);
    }

    function owners() external view returns (address[] memory) {
        return _owners;
    }

    function getProposal(bytes32 id)
        external
        view
        returns (bytes memory data, uint256 approvals, bool exists, bool executed, uint256 expiresAt)
    {
        Proposal storage p = _proposals[id];
        return (p.data, p.approvals, p.exists, p.executed, p.expiresAt);
    }

    function _pending(bytes32 id) internal view returns (Proposal storage p) {
        p = _proposals[id];
        if (!p.exists) revert UnknownProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp >= p.expiresAt) revert ProposalExpired(p.expiresAt);
    }

    function _approve(bytes32 id, Proposal storage p) internal {
        if (hasApproved[id][msg.sender]) revert AlreadyApproved();
        hasApproved[id][msg.sender] = true;
        p.approvals += 1;
        emit Approved(id, msg.sender, p.approvals);
    }
}
