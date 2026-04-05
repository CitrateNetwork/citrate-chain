// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IAIBackendCapabilities
/// @notice EIP-XXXX Level 0: Profile detection and capability discovery.
/// @dev Every AI Gateway compliant contract MUST implement this interface.
///      Uses ERC-165 for interface detection.
interface IAIBackendCapabilities {
    enum AIExecutionProfile {
        PortableWasm,      // 0 — Solidity contracts + off-chain WASM workers
        NativePrecompile   // 1 — Chain-native precompiled contracts
    }

    /// @notice Returns the execution profile of this backend.
    function getExecutionProfile() external view returns (AIExecutionProfile);

    /// @notice Returns the backend version hash.
    function getBackendVersion() external view returns (bytes32);

    /// @notice ERC-165 interface detection.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
