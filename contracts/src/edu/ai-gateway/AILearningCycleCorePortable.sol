// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IAILearningCycleCore} from "./IAILearningCycleCore.sol";

/// @title AILearningCycleCorePortable
/// @notice Portable implementation of IAILearningCycleCore.
///         Implements invariants from Q-007 CycleTransitions.tla:
///           1. StateTransitionsAcyclic — forward-only state machine
///           2. JoinOnlyWhenOpen — join during Open or Collecting
///           3. CommitOnlyWhenCollecting — commitments only during Collecting
///           4. AdapterOnlyWhenAggregating — adapters only during Aggregating
///           5. FinalizeOnlyOnce — cannot re-finalize
///           6. ParticipantCountMonotonic — no removal during active cycle
///           7. NoCommitWithoutJoin — must be participant to commit
contract AILearningCycleCorePortable is IAILearningCycleCore {
    struct Cycle {
        CycleState state;
        uint256 checkpointHeight;
        address coordinator;
        uint256 participantCount;
        uint256 commitmentCount;
        bool exists;
    }

    mapping(uint256 => Cycle) private cycles;
    mapping(uint256 => mapping(address => bool)) private participants;
    mapping(uint256 => mapping(address => bool)) private committed;
    uint256 public cycleCount;

    address public governance;

    error NotGovernance();
    error CycleNotFound(uint256 cycleId);
    error InvalidStateTransition(CycleState current, CycleState required);
    error AlreadyJoined(uint256 cycleId, address participant);
    error NotParticipant(uint256 cycleId, address caller);
    error AlreadyCommitted(uint256 cycleId, address participant);
    error ZeroHash();
    error NotCoordinator(uint256 cycleId, address caller);

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(address _governance) {
        governance = _governance;
    }

    /// @inheritdoc IAILearningCycleCore
    function openCycle(uint256 checkpointHeight) external returns (uint256 cycleId) {
        cycleId = cycleCount;
        cycleCount++;

        cycles[cycleId] = Cycle({
            state: CycleState.Open,
            checkpointHeight: checkpointHeight,
            coordinator: msg.sender,
            participantCount: 0,
            commitmentCount: 0,
            exists: true
        });

        emit CycleOpened(cycleId, checkpointHeight);
    }

    /// @inheritdoc IAILearningCycleCore
    function joinCycle(uint256 cycleId) external {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);

        // Invariant 2: JoinOnlyWhenOpen — allow during Open or Collecting
        if (c.state != CycleState.Open && c.state != CycleState.Collecting) {
            revert InvalidStateTransition(c.state, CycleState.Open);
        }

        if (participants[cycleId][msg.sender]) revert AlreadyJoined(cycleId, msg.sender);

        participants[cycleId][msg.sender] = true;
        c.participantCount++;

        emit ParticipantJoined(cycleId, msg.sender);
    }

    /// @notice Transition from Open to Collecting. Coordinator only.
    function startCollecting(uint256 cycleId) external {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);
        if (c.coordinator != msg.sender) revert NotCoordinator(cycleId, msg.sender);

        // Invariant 1: forward-only
        if (c.state != CycleState.Open) {
            revert InvalidStateTransition(c.state, CycleState.Open);
        }

        c.state = CycleState.Collecting;
    }

    /// @inheritdoc IAILearningCycleCore
    function submitCommitment(uint256 cycleId, bytes32 commitment) external {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);

        // Invariant 3: CommitOnlyWhenCollecting
        if (c.state != CycleState.Collecting) {
            revert InvalidStateTransition(c.state, CycleState.Collecting);
        }

        // Invariant 7: NoCommitWithoutJoin
        if (!participants[cycleId][msg.sender]) revert NotParticipant(cycleId, msg.sender);

        if (committed[cycleId][msg.sender]) revert AlreadyCommitted(cycleId, msg.sender);
        if (commitment == bytes32(0)) revert ZeroHash();

        committed[cycleId][msg.sender] = true;
        c.commitmentCount++;

        emit CommitmentSubmitted(cycleId, msg.sender, commitment);
    }

    /// @notice Transition from Collecting to Aggregating. Coordinator only.
    function startAggregating(uint256 cycleId) external {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);
        if (c.coordinator != msg.sender) revert NotCoordinator(cycleId, msg.sender);

        if (c.state != CycleState.Collecting) {
            revert InvalidStateTransition(c.state, CycleState.Collecting);
        }

        c.state = CycleState.Aggregating;
    }

    /// @inheritdoc IAILearningCycleCore
    function recordAdapter(uint256 cycleId, bytes32 adapterHash, bytes32 evalManifestHash) external {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);

        // Invariant 4: AdapterOnlyWhenAggregating
        if (c.state != CycleState.Aggregating) {
            revert InvalidStateTransition(c.state, CycleState.Aggregating);
        }

        if (c.coordinator != msg.sender) revert NotCoordinator(cycleId, msg.sender);
        if (adapterHash == bytes32(0) || evalManifestHash == bytes32(0)) revert ZeroHash();

        emit AdapterRecorded(cycleId, adapterHash, evalManifestHash);
    }

    /// @inheritdoc IAILearningCycleCore
    function finalizeCycle(uint256 cycleId) external {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);

        // Invariant 5: FinalizeOnlyOnce
        if (c.state != CycleState.Aggregating) {
            revert InvalidStateTransition(c.state, CycleState.Aggregating);
        }

        if (c.coordinator != msg.sender) revert NotCoordinator(cycleId, msg.sender);

        c.state = CycleState.Finalized;

        emit CycleFinalized(cycleId);
    }

    /// @inheritdoc IAILearningCycleCore
    function getCycleState(uint256 cycleId) external view returns (CycleState) {
        if (!cycles[cycleId].exists) revert CycleNotFound(cycleId);
        return cycles[cycleId].state;
    }

    /// @notice Get cycle metadata.
    function getCycleInfo(uint256 cycleId) external view returns (
        CycleState state,
        uint256 checkpointHeight,
        address coordinator,
        uint256 participantCount,
        uint256 commitmentCount
    ) {
        Cycle storage c = cycles[cycleId];
        if (!c.exists) revert CycleNotFound(cycleId);
        return (c.state, c.checkpointHeight, c.coordinator, c.participantCount, c.commitmentCount);
    }

    /// @notice Check if an address is a participant in a cycle.
    function isParticipant(uint256 cycleId, address addr) external view returns (bool) {
        return participants[cycleId][addr];
    }
}
