// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title IAIModelRegistry
/// @notice EIP-XXXX Level 1: AI model registration, verification, and provenance.
/// @dev Cross-chain model identity uses modelHash (keccak256 of weight bytes).
///      modelId is a chain-local registry handle, NOT cross-chain stable.
///      Full metadata lives off-chain in AIModelManifestV1 JSON, referenced by manifestHash.
interface IAIModelRegistry {
    event ModelRegistered(
        bytes32 indexed modelId,
        bytes32 indexed modelHash,
        address indexed owner,
        bytes32 manifestHash
    );
    event ModelTransferred(
        bytes32 indexed modelId,
        address indexed from,
        address indexed to
    );

    /// @notice Register a new AI model.
    /// @param modelHash keccak256 of the model weight bytes (cross-chain canonical identity)
    /// @param manifestHash keccak256 of the AIModelManifestV1 JSON (off-chain metadata)
    /// @return modelId Chain-local registry handle
    function registerModel(bytes32 modelHash, bytes32 manifestHash) external returns (bytes32 modelId);

    /// @notice Verify a model's registered hash matches expected content hash.
    function verifyModel(bytes32 modelId, bytes32 expectedModelHash) external view returns (bool);

    /// @notice Get the canonical content hash for a local registry handle.
    function getModelHash(bytes32 modelId) external view returns (bytes32);

    /// @notice Get the manifest hash for off-chain metadata retrieval.
    function getManifestHash(bytes32 modelId) external view returns (bytes32);

    /// @notice Get the owner of a registered model.
    function getModelOwner(bytes32 modelId) external view returns (address);

    /// @notice Transfer model ownership.
    function transferOwnership(bytes32 modelId, address newOwner) external;
}
