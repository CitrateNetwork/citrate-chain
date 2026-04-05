// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title IForwarder
/// @notice EIP-2771 meta-transaction forwarder for sponsored student actions.
/// @dev Implements invariants from Q-006 ForwarderReplaySafety.tla:
///   1. NonceMonotonic
///   2. NoReplayAccepted
///   3. DeviceBindingEnforced
///   4. SessionExpiryEnforced
///   5. RevocationBarrierDouble
///   6. RelayerCannotCallVault
///   7. OfflineQueueFlushSafe
///
/// The relayer (institutional node) signs outer transactions and pays gas.
/// The Forwarder extracts the inner meta-tx payload and verifies:
///   - Nonce is monotonically increasing per (orgPrincipalId, classroomId)
///   - The orgPrincipalId is not revoked in ClassroomCluster
///   - The device certificate is not revoked
///   - The session has not expired
interface IForwarder {
    // ── Structs ──

    struct ForwardRequest {
        bytes32 orgPrincipalId;     // HMAC-derived pseudonymous identity
        uint256 classroomId;        // Target classroom
        uint256 nonce;              // Monotonic per (orgPrincipalId, classroomId)
        uint256 sessionExpiry;      // Block timestamp when session expires
        bytes32 deviceCertHash;     // Bound to the originating device
        address target;             // Target contract to call
        bytes data;                 // Calldata for the target contract
    }

    // ── Events ──

    event MetaTxExecuted(
        bytes32 indexed orgPrincipalId,
        uint256 indexed classroomId,
        uint256 nonce,
        address indexed target,
        bool success
    );
    event MetaTxRejected(
        bytes32 indexed orgPrincipalId,
        uint256 indexed classroomId,
        uint256 nonce,
        string reason
    );

    // ── Views ──

    /// @notice Get current nonce for a (orgPrincipalId, classroomId) pair.
    function getNonce(bytes32 orgPrincipalId, uint256 classroomId) external view returns (uint256);

    /// @notice Check if a relayer address is authorized.
    function isAuthorizedRelayer(address relayer) external view returns (bool);

    // ── Mutators ──

    /// @notice Execute a meta-transaction on behalf of a pseudonymous user.
    /// @dev Only callable by authorized relayers.
    ///      Checks: nonce monotonic, not revoked, session not expired, device active.
    ///      Invariant: RelayerCannotCallVault — target must not be the vault contract.
    function execute(ForwardRequest calldata request, bytes calldata relayerSignature) external returns (bool success);

    /// @notice Add an authorized relayer address (governance only).
    function addRelayer(address relayer) external;

    /// @notice Remove an authorized relayer address (governance only).
    function removeRelayer(address relayer) external;

    /// @notice Set the ClassroomCluster contract address for revocation checks.
    function setClusterContract(address cluster) external;

    /// @notice Set the vault address (for RelayerCannotCallVault invariant enforcement).
    function setVaultAddress(address vault) external;
}
