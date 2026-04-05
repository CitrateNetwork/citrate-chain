// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IAIInferenceRouter
/// @notice EIP-XXXX Level 2: Async inference request/fulfill with typed receipts.
/// @dev Canonical portable API. Direct synchronous inference is native-profile only.
///      Receipt verification uses EIP-712 typed data signatures.
///      Replay protection: (chainId, router, requestId) tuple consumed on fulfillment.
interface IAIInferenceRouter {
    event InferenceRequested(
        uint256 indexed requestId,
        bytes32 indexed modelId,
        address indexed requester
    );
    event InferenceFulfilled(
        uint256 indexed requestId,
        bytes32 outputCommitment,
        address worker
    );

    /// @notice Request an inference. Returns a requestId.
    /// @param modelId Registry handle for the model
    /// @param inputCommitment keccak256 of input data
    /// @param maxPrice Maximum payment willing to offer
    /// @return requestId Unique request identifier
    function requestInference(
        bytes32 modelId,
        bytes32 inputCommitment,
        uint256 maxPrice
    ) external payable returns (uint256 requestId);

    /// @notice Submit a completed inference with a signed receipt.
    /// @param requestId The request being fulfilled
    /// @param outputCommitment keccak256 of the inference output
    /// @param evidence EIP-712 signed receipt (see AIExecutionReceiptV1 schema)
    function fulfillInference(
        uint256 requestId,
        bytes32 outputCommitment,
        bytes calldata evidence
    ) external;

    /// @notice Verify an inference receipt's EIP-712 signature.
    /// @return valid True if signature verifies and signer is authorized
    /// @return signer Recovered signer address
    function verifyReceipt(
        uint256 requestId,
        bytes32 outputCommitment,
        bytes calldata evidence
    ) external view returns (bool valid, address signer);
}
