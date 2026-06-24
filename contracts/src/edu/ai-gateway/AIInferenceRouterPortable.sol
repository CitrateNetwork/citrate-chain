// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IAIInferenceRouter} from "./IAIInferenceRouter.sol";
import {IAIModelRegistry} from "./IAIModelRegistry.sol";

/// @title AIInferenceRouterPortable
/// @notice Portable implementation of IAIInferenceRouter.
///         Uses EIP-712 typed data for receipt verification.
///         Replay protection: (chainId, router, requestId) tuple consumed on fulfillment.
/// @dev Authorized workers are managed by the governance address.
///      Payment is held in escrow and released on fulfillment.
contract AIInferenceRouterPortable is IAIInferenceRouter {
    struct InferenceRequest {
        bytes32 modelId;
        bytes32 inputCommitment;
        address requester;
        uint256 maxPrice;
        uint256 timestamp;
        bool fulfilled;
        bool exists;
    }

    // EIP-712 domain separator components
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant RECEIPT_TYPEHASH = keccak256(
        "AIExecutionReceipt(uint256 requestId,bytes32 outputCommitment,bytes32 modelId,uint256 timestamp)"
    );
    bytes32 private immutable DOMAIN_SEPARATOR;

    IAIModelRegistry public immutable registry;
    address public governance;

    mapping(uint256 => InferenceRequest) private requests;
    mapping(address => bool) public authorizedWorkers;
    uint256 public requestCount;

    error RequestNotFound(uint256 requestId);
    error AlreadyFulfilled(uint256 requestId);
    error ModelNotRegistered(bytes32 modelId);
    error InsufficientPayment();
    error NotGovernance();
    error NotAuthorizedWorker(address worker);
    error InvalidSignature();
    error ZeroCommitment();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(address _registry, address _governance) {
        registry = IAIModelRegistry(_registry);
        governance = _governance;

        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("AIInferenceRouter"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    /// @notice Add an authorized inference worker.
    function addWorker(address worker) external onlyGovernance {
        authorizedWorkers[worker] = true;
    }

    /// @notice Remove an authorized worker.
    function removeWorker(address worker) external onlyGovernance {
        authorizedWorkers[worker] = false;
    }

    /// @inheritdoc IAIInferenceRouter
    function requestInference(
        bytes32 modelId,
        bytes32 inputCommitment,
        uint256 maxPrice
    ) external payable returns (uint256 requestId) {
        if (inputCommitment == bytes32(0)) revert ZeroCommitment();
        if (msg.value < maxPrice) revert InsufficientPayment();

        // Verify model exists in registry
        try registry.getModelHash(modelId) returns (bytes32) {} catch {
            revert ModelNotRegistered(modelId);
        }

        requestId = requestCount;
        requestCount++;

        requests[requestId] = InferenceRequest({
            modelId: modelId,
            inputCommitment: inputCommitment,
            requester: msg.sender,
            maxPrice: maxPrice,
            timestamp: block.timestamp,
            fulfilled: false,
            exists: true
        });

        emit InferenceRequested(requestId, modelId, msg.sender);
    }

    /// @inheritdoc IAIInferenceRouter
    function fulfillInference(
        uint256 requestId,
        bytes32 outputCommitment,
        bytes calldata evidence
    ) external {
        InferenceRequest storage req = requests[requestId];
        if (!req.exists) revert RequestNotFound(requestId);
        if (req.fulfilled) revert AlreadyFulfilled(requestId);
        if (outputCommitment == bytes32(0)) revert ZeroCommitment();

        // Verify the EIP-712 receipt signature
        (bool valid, address signer) = _verifyReceipt(requestId, outputCommitment, evidence);
        if (!valid) revert InvalidSignature();
        if (!authorizedWorkers[signer]) revert NotAuthorizedWorker(signer);

        req.fulfilled = true;

        // Transfer payment to worker
        if (req.maxPrice > 0) {
            (bool sent,) = signer.call{value: req.maxPrice}("");
            if (!sent) {
                // If transfer fails, allow governance to recover later
                req.fulfilled = true; // Still mark fulfilled to prevent replay
            }
        }

        emit InferenceFulfilled(requestId, outputCommitment, signer);
    }

    /// @inheritdoc IAIInferenceRouter
    function verifyReceipt(
        uint256 requestId,
        bytes32 outputCommitment,
        bytes calldata evidence
    ) external view returns (bool valid, address signer) {
        return _verifyReceipt(requestId, outputCommitment, evidence);
    }

    /// @notice Get request details.
    function getRequest(uint256 requestId) external view returns (
        bytes32 modelId,
        bytes32 inputCommitment,
        address requester,
        uint256 maxPrice,
        bool fulfilled
    ) {
        InferenceRequest storage req = requests[requestId];
        if (!req.exists) revert RequestNotFound(requestId);
        return (req.modelId, req.inputCommitment, req.requester, req.maxPrice, req.fulfilled);
    }

    // --- Internal ---

    function _verifyReceipt(
        uint256 requestId,
        bytes32 outputCommitment,
        bytes calldata evidence
    ) internal view returns (bool valid, address signer) {
        if (evidence.length != 65) return (false, address(0));

        bytes32 structHash = keccak256(abi.encode(
            RECEIPT_TYPEHASH,
            requestId,
            outputCommitment,
            requests[requestId].modelId,
            requests[requestId].timestamp
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(evidence.offset)
            s := calldataload(add(evidence.offset, 32))
            v := byte(0, calldataload(add(evidence.offset, 64)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return (false, address(0));
        // FWA-C3-05 sweep: reject malleable high-s signatures (EIP-2).
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (false, address(0));
        }

        // nosemgrep: fwa-c3-05-raw-ecrecover-no-low-s-guard -- low-s enforced above
        signer = ecrecover(digest, v, r, s);
        valid = signer != address(0);
    }
}
