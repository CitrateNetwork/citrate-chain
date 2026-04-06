// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IAIModelRegistry} from "./IAIModelRegistry.sol";
import {IAIBackendCapabilities} from "./IAIBackendCapabilities.sol";

/// @title AIModelRegistryPortable
/// @notice Portable (non-precompile) implementation of IAIModelRegistry.
///         Deployable on any EVM chain. Part of the citrate ai-evm portable library.
/// @dev Storage layout:
///   - models: modelId => ModelRecord (owner, modelHash, manifestHash, exists)
///   - modelCount: sequential counter for generating modelIds
///   - modelHashToId: reverse lookup modelHash => modelId (cross-chain resolution)
contract AIModelRegistryPortable is IAIModelRegistry, IAIBackendCapabilities {
    struct ModelRecord {
        address owner;
        bytes32 modelHash;
        bytes32 manifestHash;
        bool exists;
    }

    mapping(bytes32 => ModelRecord) private models;
    mapping(bytes32 => bytes32) private modelHashToId;
    uint256 public modelCount;

    bytes32 private constant VERSION = keccak256("ai-evm-portable-v1");

    error ModelNotFound(bytes32 modelId);
    error ModelHashAlreadyRegistered(bytes32 modelHash);
    error NotModelOwner(bytes32 modelId, address caller);
    error ZeroHash();
    error ZeroAddress();

    /// @inheritdoc IAIModelRegistry
    function registerModel(bytes32 modelHash, bytes32 manifestHash) external returns (bytes32 modelId) {
        if (modelHash == bytes32(0)) revert ZeroHash();
        if (modelHashToId[modelHash] != bytes32(0)) revert ModelHashAlreadyRegistered(modelHash);

        modelId = keccak256(abi.encodePacked(block.chainid, address(this), modelCount));
        modelCount++;

        models[modelId] = ModelRecord({
            owner: msg.sender,
            modelHash: modelHash,
            manifestHash: manifestHash,
            exists: true
        });
        modelHashToId[modelHash] = modelId;

        emit ModelRegistered(modelId, modelHash, msg.sender, manifestHash);
    }

    /// @inheritdoc IAIModelRegistry
    function verifyModel(bytes32 modelId, bytes32 expectedModelHash) external view returns (bool) {
        if (!models[modelId].exists) revert ModelNotFound(modelId);
        return models[modelId].modelHash == expectedModelHash;
    }

    /// @inheritdoc IAIModelRegistry
    function getModelHash(bytes32 modelId) external view returns (bytes32) {
        if (!models[modelId].exists) revert ModelNotFound(modelId);
        return models[modelId].modelHash;
    }

    /// @inheritdoc IAIModelRegistry
    function getManifestHash(bytes32 modelId) external view returns (bytes32) {
        if (!models[modelId].exists) revert ModelNotFound(modelId);
        return models[modelId].manifestHash;
    }

    /// @inheritdoc IAIModelRegistry
    function getModelOwner(bytes32 modelId) external view returns (address) {
        if (!models[modelId].exists) revert ModelNotFound(modelId);
        return models[modelId].owner;
    }

    /// @inheritdoc IAIModelRegistry
    function transferOwnership(bytes32 modelId, address newOwner) external {
        if (!models[modelId].exists) revert ModelNotFound(modelId);
        if (models[modelId].owner != msg.sender) revert NotModelOwner(modelId, msg.sender);
        if (newOwner == address(0)) revert ZeroAddress();

        address oldOwner = models[modelId].owner;
        models[modelId].owner = newOwner;

        emit ModelTransferred(modelId, oldOwner, newOwner);
    }

    /// @notice Resolve a cross-chain modelHash to the local modelId.
    function resolveModelHash(bytes32 modelHash) external view returns (bytes32) {
        return modelHashToId[modelHash];
    }

    // --- IAIBackendCapabilities ---

    /// @inheritdoc IAIBackendCapabilities
    function getExecutionProfile() external pure returns (AIExecutionProfile) {
        return AIExecutionProfile.PortableWasm;
    }

    /// @inheritdoc IAIBackendCapabilities
    function getBackendVersion() external pure returns (bytes32) {
        return VERSION;
    }

    /// @inheritdoc IAIBackendCapabilities
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IAIModelRegistry).interfaceId
            || interfaceId == type(IAIBackendCapabilities).interfaceId
            || interfaceId == 0x01ffc9a7; // ERC-165
    }
}
