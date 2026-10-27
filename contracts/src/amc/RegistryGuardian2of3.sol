// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @dev The three guardian actions on ProviderRegistry. Nothing else is reachable from here.
interface IProviderRegistryGuardianActions {
    function emergencyDelist(bytes32 providerId, uint16 reasonCode) external;
    function veto(bytes32 providerId, uint16 reasonCode) external;
    function pause(uint16 reasonCode) external;
}

/// @title RegistryGuardian2of3: the direct, no-delay guardian seat of one ProviderRegistry
/// @notice Owner decision Q-8(b), 2026-10-26: an emergency delist acts at once through a direct
///         2-of-3, not through the GUARDIAN timelock's 1 h delay. Spec:
///         docs/amc/PROVIDER_GOVERNANCE_CONTRACTS.md section 5.
///
///         Removal and pause only. The single target is fixed at deployment, and the only
///         actions are `emergencyDelist`, `veto` and `pause`. None of them can list, restore,
///         unpause, move a role or call anything else. The owners are fixed: to rotate them,
///         governance deploys a new instance and calls `ProviderRegistry.setGuardian`, which this
///         contract cannot block (it holds no timelock role, RT-15).
///
///         Flow: an owner calls `propose`, which counts as its approval. A second owner calls
///         `approve`, which executes in the same transaction. A proposal expires after
///         PROPOSAL_TTL and runs at most once. No value is held.
contract RegistryGuardian2of3 {
    enum Action {
        EmergencyDelist,
        Veto,
        Pause
    }

    struct Proposal {
        Action action;
        bytes32 providerId; // unused for Pause
        uint16 reasonCode;
        uint64 expiresAt;
        uint8 approvals; // bitmap over owner index
        bool executed;
    }

    uint64 public constant PROPOSAL_TTL = 1 days;

    IProviderRegistryGuardianActions public immutable registry;
    address public immutable owner0;
    address public immutable owner1;
    address public immutable owner2;

    uint256 public nonce;
    mapping(bytes32 => Proposal) private _proposals;

    event Proposed(bytes32 indexed id, Action action, bytes32 indexed providerId, uint16 reasonCode, address by);
    event Approved(bytes32 indexed id, address indexed by);
    event Executed(bytes32 indexed id, Action action, bytes32 indexed providerId, uint16 reasonCode);

    error NotOwner();
    error DuplicateOwner();
    error RegistryHasNoCode();
    error UnknownProposal();
    error Expired();
    error AlreadyApproved();
    error AlreadyExecuted();

    constructor(IProviderRegistryGuardianActions registry_, address a, address b, address c) {
        if (address(registry_).code.length == 0) revert RegistryHasNoCode();
        InitialAdmin.check(a);
        InitialAdmin.check(b);
        InitialAdmin.check(c);
        if (a == b || a == c || b == c) revert DuplicateOwner();
        registry = registry_;
        owner0 = a;
        owner1 = b;
        owner2 = c;
    }

    function propose(Action action, bytes32 providerId, uint16 reasonCode) external returns (bytes32 id) {
        uint8 bit = _ownerBit(msg.sender);
        id = keccak256(abi.encode(address(this), nonce, action, providerId, reasonCode));
        nonce += 1;
        _proposals[id] = Proposal({
            action: action,
            providerId: providerId,
            reasonCode: reasonCode,
            expiresAt: uint64(block.timestamp) + PROPOSAL_TTL,
            approvals: bit,
            executed: false
        });
        emit Proposed(id, action, providerId, reasonCode, msg.sender);
        emit Approved(id, msg.sender);
    }

    /// @notice The second approval executes the action on the registry, with no delay.
    function approve(bytes32 id) external {
        uint8 bit = _ownerBit(msg.sender);
        Proposal storage p = _proposals[id];
        if (p.expiresAt == 0) revert UnknownProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp >= p.expiresAt) revert Expired();
        if (p.approvals & bit != 0) revert AlreadyApproved();
        p.approvals |= bit;
        p.executed = true;
        emit Approved(id, msg.sender);
        emit Executed(id, p.action, p.providerId, p.reasonCode);
        if (p.action == Action.EmergencyDelist) {
            registry.emergencyDelist(p.providerId, p.reasonCode);
        } else if (p.action == Action.Veto) {
            registry.veto(p.providerId, p.reasonCode);
        } else {
            registry.pause(p.reasonCode);
        }
    }

    function getProposal(bytes32 id) external view returns (Proposal memory) {
        return _proposals[id];
    }

    function isOwner(address who) public view returns (bool) {
        return who == owner0 || who == owner1 || who == owner2;
    }

    function _ownerBit(address who) internal view returns (uint8) {
        if (who == owner0) return 1;
        if (who == owner1) return 2;
        if (who == owner2) return 4;
        revert NotOwner();
    }
}
