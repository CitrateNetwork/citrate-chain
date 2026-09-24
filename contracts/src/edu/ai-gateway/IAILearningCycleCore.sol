// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title IAILearningCycleCore
/// @notice EIP-XXXX Level 3 (optional): Minimal federated learning cycle coordination.
/// @dev Implements invariants from Q-007 CycleTransitions.tla:
///   1. StateTransitionsAcyclic — only forward: Open → Collecting → Aggregating → Finalized
///   2. JoinOnlyWhenOpen — participants join during Open or Collecting
///   3. CommitOnlyWhenCollecting — commitments only during Collecting
///   4. AdapterOnlyWhenAggregating — adapters only during Aggregating
///   5. FinalizeOnlyOnce — cannot re-finalize
///   6. ParticipantCountMonotonic — no removal during active cycle
///
/// This is the MINIMAL core. Mentorship, incentives, and governance are
/// optional extension interfaces, not part of this standard.
interface IAILearningCycleCore {
    enum CycleState { Open, Collecting, Aggregating, Finalized }

    event CycleOpened(uint256 indexed cycleId, uint256 checkpointHeight);
    event ParticipantJoined(uint256 indexed cycleId, address indexed participant);
    event CommitmentSubmitted(uint256 indexed cycleId, address indexed participant, bytes32 commitment);
    event AdapterRecorded(uint256 indexed cycleId, bytes32 adapterHash, bytes32 evalManifestHash);
    event CycleFinalized(uint256 indexed cycleId);

    /// @notice Open a new learning cycle.
    function openCycle(uint256 checkpointHeight) external returns (uint256 cycleId);

    /// @notice Register as a cycle participant.
    function joinCycle(uint256 cycleId) external;

    /// @notice Submit a training-data or embedding commitment.
    function submitCommitment(uint256 cycleId, bytes32 commitment) external;

    /// @notice Record an adapter artifact produced by training.
    /// @param adapterHash keccak256 of adapter weights
    /// @param evalManifestHash keccak256 of AILearningCycleEvalManifestV1 JSON
    function recordAdapter(uint256 cycleId, bytes32 adapterHash, bytes32 evalManifestHash) external;

    /// @notice Finalize cycle.
    function finalizeCycle(uint256 cycleId) external;

    /// @notice Get current cycle state.
    function getCycleState(uint256 cycleId) external view returns (CycleState);
}
