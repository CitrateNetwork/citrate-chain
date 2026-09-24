// SPDX-License-Identifier: Apache-2.0
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

    /// @notice C041: pull-payment credits. Excess over `maxPrice`, refunds from
    ///         cancelled requests, and payouts whose push transfer failed all
    ///         accrue here and are claimed via `withdraw` — nothing is stranded.
    mapping(address => uint256) public pendingWithdrawals;

    /// @notice How long a requester must wait before reclaiming an unfulfilled
    ///         request's escrow. Compared against `block.timestamp` (seconds).
    uint256 public constant REQUEST_TIMEOUT = 1 hours;

    error RequestNotFound(uint256 requestId);
    error AlreadyFulfilled(uint256 requestId);
    error ModelNotRegistered(bytes32 modelId);
    error InsufficientPayment();
    error NotGovernance();
    error NotAuthorizedWorker(address worker);
    error InvalidSignature();
    error ZeroCommitment();
    error NotRequester(uint256 requestId, address caller);
    error TimeoutNotElapsed(uint256 requestId);
    error NothingToWithdraw();
    error WithdrawFailed();

    event WithdrawalCredited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);
    event RequestCancelled(uint256 indexed requestId, address indexed requester, uint256 refund);

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

        // C041: refund any overpayment above `maxPrice` immediately (as a
        // pull credit) — the escrow the router needs to hold is exactly
        // `maxPrice`, and the surplus was previously locked forever.
        uint256 excess = msg.value - maxPrice;
        if (excess > 0) {
            pendingWithdrawals[msg.sender] += excess;
            emit WithdrawalCredited(msg.sender, excess);
        }

        emit InferenceRequested(requestId, modelId, msg.sender);
    }

    /// @notice C041: reclaim the escrow of a request that was never fulfilled,
    ///         once `REQUEST_TIMEOUT` has elapsed. Marks the request terminal so
    ///         it can never later pay a worker, then credits the requester.
    function cancelRequest(uint256 requestId) external {
        InferenceRequest storage req = requests[requestId];
        if (!req.exists) revert RequestNotFound(requestId);
        if (req.fulfilled) revert AlreadyFulfilled(requestId);
        if (msg.sender != req.requester) revert NotRequester(requestId, msg.sender);
        if (block.timestamp < req.timestamp + REQUEST_TIMEOUT) revert TimeoutNotElapsed(requestId);

        req.fulfilled = true; // terminal: no replay, no double-refund
        uint256 refund = req.maxPrice;
        if (refund > 0) {
            pendingWithdrawals[req.requester] += refund;
            emit WithdrawalCredited(req.requester, refund);
        }
        emit RequestCancelled(requestId, req.requester, refund);
    }

    /// @notice C041: claim accrued credits (excess refunds, cancelled escrows,
    ///         and payouts whose push transfer failed).
    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
        emit Withdrawn(msg.sender, amount);
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
                // C041: credit the worker's pull-payment balance instead of
                // silently swallowing the funds under a governance-recovery
                // comment that was never implemented. The request stays
                // fulfilled (replay-safe) and the worker claims via `withdraw`.
                pendingWithdrawals[signer] += req.maxPrice;
                emit WithdrawalCredited(signer, req.maxPrice);
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
