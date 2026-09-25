// SPDX-License-Identifier: Apache-2.0

// citrate-v3/contracts/src/LoRAFactory.sol
pragma solidity ^0.8.26;

import {InitialAdmin} from "./lib/InitialAdmin.sol";

import "./interfaces/IModelRegistry.sol";
import "./lib/AccessControl.sol";

/**
 * @title LoRAFactory
 * @notice Factory for creating and managing LoRA (Low-Rank Adaptation) fine-tunes
 * @dev Integrates with Citrate LoRA precompile for efficient adaptation
 */
contract LoRAFactory is AccessControl {
    // Citrate precompile address
    address constant LORA_PRECOMPILE = 0x0000000000000000000000000000000000001001;

    /// 0x0108 — INFERENCE_PROOF_VERIFY (Halo2-KZG verifier).
    /// RM-FL-4 / WP-4.7: adapter quality is cryptographically backed
    /// by submitting a Halo2 proof attesting to a (input_commitment,
    /// model_commitment, output_commitment) tuple. The precompile
    /// returns 32 bytes — 1 iff the proof verifies.
    address constant INFERENCE_PROOF_VERIFY = 0x0000000000000000000000000000000000000108;

    /// Circuit version v1 for InferenceCircuit. Encoded as 4-byte BE
    /// in the precompile input. RM-M1b WP-M1b.4.
    uint32 internal constant INFERENCE_CIRCUIT_V1 = 1;
    
    // Structs
    struct LoRAAdapter {
        bytes32 loraHash;
        bytes32 baseModelHash;
        address creator;
        string name;
        string description;
        string ipfsCID;
        uint256 rank;
        uint256 alpha;
        uint256 dropout;
        uint256 createdAt;
        uint256 trainingCost;
        bool isPublic;
        TrainingConfig config;
    }
    
    struct TrainingConfig {
        uint256 epochs;
        uint256 batchSize;
        uint256 learningRate; // Fixed point (1e18 = 1.0)
        string datasetCID;
        uint256 datasetSize;
        uint256 validationSplit; // Percentage in basis points
    }
    
    struct MergeRequest {
        bytes32 requestHash;
        bytes32[] loraHashes;
        uint256[] weights; // Fixed point weights for each LoRA
        address requester;
        bytes32 resultHash;
        string resultCID;
        uint256 mergeType; // 0: Linear, 1: SVD, 2: Task-Arithmetic
        bool completed;
    }
    
    // State variables
    IModelRegistry public modelRegistry;
    
    mapping(bytes32 => LoRAAdapter) public adapters;
    mapping(bytes32 => MergeRequest) public mergeRequests;
    mapping(address => bytes32[]) public userAdapters;
    mapping(bytes32 => bytes32[]) public modelAdapters; // baseModel => LoRAs
    mapping(bytes32 => mapping(address => bool)) public adapterPermissions;
    
    bytes32[] public allAdapterHashes;
    uint256 public totalAdapters;
    uint256 public trainingFeePerEpoch = 0.01 ether; // 0.01 LATT per epoch
    uint256 public mergeFee = 0.05 ether; // 0.05 LATT per merge

    /// RM-FL-4 / WP-4.7 — adapter verification flow.
    /// Maps adapter → its in-circuit Poseidon model commitment. The
    /// operator sets this when training completes (via
    /// `setAdapterModelCommitment`). Without it, `verifyAdapterAt`
    /// reverts; an adapter cannot be verified before its weights have
    /// a chain-known commitment to verify against.
    mapping(bytes32 => bytes32) public adapterModelCommitment;

    /// Set true on first successful proof verification. Once flipped,
    /// stays true — the adapter is permanently "proof-backed."
    mapping(bytes32 => bool) public adapterProofVerified;
    
    // Events
    event LoRACreated(
        bytes32 indexed loraHash,
        bytes32 indexed baseModelHash,
        address indexed creator,
        string name
    );
    
    event LoRAMerged(
        bytes32 indexed requestHash,
        bytes32[] loraHashes,
        bytes32 resultHash
    );
    
    event TrainingStarted(
        bytes32 indexed loraHash,
        uint256 epochs,
        uint256 cost
    );
    
    event TrainingCompleted(
        bytes32 indexed loraHash,
        string ipfsCID
    );
    
    event PermissionGranted(
        bytes32 indexed loraHash,
        address indexed user
    );

    event TrainingFeeUpdated(
        uint256 oldFee,
        uint256 newFee
    );

    event MergeFeeUpdated(
        uint256 oldFee,
        uint256 newFee
    );

    /// RM-FL-4 / WP-4.7 events + errors.

    event AdapterModelCommitmentSet(
        bytes32 indexed loraHash,
        bytes32 commitment
    );

    event AdapterVerified(
        bytes32 indexed loraHash,
        address indexed verifier,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        uint256 blockNumber
    );

    /// Reverts the verifyAdapterAt call when the precompile rejects
    /// the proof. The contract returns `false` for ill-formed input
    /// (truncated proof), reverts here for proofs the verifier
    /// actively rejected.
    error AdapterProofRejected(bytes32 loraHash);

    /// The adapter has no in-circuit model commitment recorded; the
    /// operator must call setAdapterModelCommitment before any
    /// verification can happen.
    error AdapterModelCommitmentNotSet(bytes32 loraHash);

    /// The adapter doesn't exist in the registry.
    error AdapterNotFound(bytes32 loraHash);

    /// @param admin Explicit DEFAULT_ADMIN (PBA-L2-002: never msg.sender, which is
    ///        the CREATE2 factory under a salted ceremony deploy).
    constructor(address _modelRegistry, address admin) {
        InitialAdmin.check(admin);
        modelRegistry = IModelRegistry(_modelRegistry);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
    }
    
    /**
     * @notice Create a new LoRA adapter
     * @param baseModelHash Hash of the base model
     * @param name Name of the LoRA
     * @param description Description of the adaptation
     * @param rank LoRA rank parameter
     * @param alpha LoRA alpha parameter
     * @param dropout Dropout rate (basis points)
     * @param config Training configuration
     */
    function createLoRA(
        bytes32 baseModelHash,
        string memory name,
        string memory description,
        uint256 rank,
        uint256 alpha,
        uint256 dropout,
        TrainingConfig memory config
    ) external payable returns (bytes32) {
        // Verify base model exists
        (address modelOwner,,,,,,,) = modelRegistry.getModel(baseModelHash);
        require(modelOwner != address(0), "Base model not found");
        
        // Check permissions for private models
        require(
            modelRegistry.hasPermission(baseModelHash, msg.sender),
            "No permission for base model"
        );
        
        // Calculate training cost
        uint256 trainingCost = config.epochs * trainingFeePerEpoch;
        require(msg.value >= trainingCost, "Insufficient training fee");
        
        // Generate LoRA hash
        bytes32 loraHash = keccak256(
            abi.encodePacked(
                msg.sender,
                baseModelHash,
                name,
                block.timestamp,
                totalAdapters
            )
        );
        
        // Store LoRA adapter
        LoRAAdapter storage adapter = adapters[loraHash];
        adapter.loraHash = loraHash;
        adapter.baseModelHash = baseModelHash;
        adapter.creator = msg.sender;
        adapter.name = name;
        adapter.description = description;
        adapter.rank = rank;
        adapter.alpha = alpha;
        adapter.dropout = dropout;
        adapter.createdAt = block.timestamp;
        adapter.trainingCost = trainingCost;
        adapter.isPublic = false;
        adapter.config = config;
        
        // Update mappings
        userAdapters[msg.sender].push(loraHash);
        modelAdapters[baseModelHash].push(loraHash);
        allAdapterHashes.push(loraHash);
        totalAdapters++;
        
        // Start training via precompile
        _startTraining(loraHash, config);
        
        emit LoRACreated(loraHash, baseModelHash, msg.sender, name);
        emit TrainingStarted(loraHash, config.epochs, trainingCost);
        
        return loraHash;
    }
    
    /**
     * @notice Complete LoRA training (called by operator after training)
     * @param loraHash Hash of the LoRA
     * @param ipfsCID IPFS CID of trained weights
     */
    function completeTraining(
        bytes32 loraHash,
        string memory ipfsCID
    ) external onlyRole(OPERATOR_ROLE) {
        LoRAAdapter storage adapter = adapters[loraHash];
        require(adapter.creator != address(0), "LoRA not found");
        require(bytes(adapter.ipfsCID).length == 0, "Already completed");

        adapter.ipfsCID = ipfsCID;

        emit TrainingCompleted(loraHash, ipfsCID);
    }

    // ── RM-FL-4 / WP-4.7 — Adapter verification via 0x0108 ──────────

    /**
     * @notice Operator records the in-circuit Poseidon commitment of
     *         the adapter's weights so future verifyAdapterAt calls
     *         can pass it to the precompile. One-shot: cannot be
     *         changed once set, to prevent rugging the verification
     *         contract by swapping the model out from under proofs.
     * @param loraHash Adapter identifier.
     * @param commitment 32-byte big-endian Poseidon Fr commitment.
     */
    function setAdapterModelCommitment(
        bytes32 loraHash,
        bytes32 commitment
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapters[loraHash].creator == address(0)) {
            revert AdapterNotFound(loraHash);
        }
        require(
            adapterModelCommitment[loraHash] == bytes32(0),
            "Commitment already set"
        );
        require(commitment != bytes32(0), "Zero commitment");

        adapterModelCommitment[loraHash] = commitment;
        emit AdapterModelCommitmentSet(loraHash, commitment);
    }

    /**
     * @notice Verify an adapter against a benchmark IO + Halo2 proof.
     *         Calls 0x0108 INFERENCE_PROOF_VERIFY with the
     *         (input_commitment, model_commitment, output_commitment,
     *          version, chain_id, proof_bytes) wire format.
     *
     *         On verifier success: marks the adapter as proof-backed
     *         and emits AdapterVerified. On verifier rejection:
     *         reverts with AdapterProofRejected. On structural error
     *         (precompile call itself failed): reverts with the
     *         precompile's error message.
     *
     * @param loraHash         Adapter identifier.
     * @param inputCommitment  Caller-supplied benchmark input
     *                         commitment (Poseidon Fr, 32B BE).
     * @param outputCommitment Caller-supplied expected output
     *                         commitment (Poseidon Fr, 32B BE).
     * @param proofBytes       Halo2-KZG proof transcript.
     */
    function verifyAdapterAt(
        bytes32 loraHash,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes calldata proofBytes
    ) external {
        if (adapters[loraHash].creator == address(0)) {
            revert AdapterNotFound(loraHash);
        }
        bytes32 modelCommitment = adapterModelCommitment[loraHash];
        if (modelCommitment == bytes32(0)) {
            revert AdapterModelCommitmentNotSet(loraHash);
        }

        // Build the precompile input per verify.rs::inference_proof_verify:
        //   32B input_commitment + 32B model_commitment +
        //   32B output_commitment + 4B circuit_version (BE) +
        //   4B chain_id (BE) + proof_bytes
        bytes memory input = abi.encodePacked(
            inputCommitment,
            modelCommitment,
            outputCommitment,
            INFERENCE_CIRCUIT_V1,
            uint32(block.chainid),
            proofBytes
        );

        (bool ok, bytes memory ret) = INFERENCE_PROOF_VERIFY.staticcall(input);
        require(ok, "INFERENCE_PROOF_VERIFY precompile call failed");
        require(ret.length == 32, "INFERENCE_PROOF_VERIFY: bad output length");

        // The precompile returns 32 bytes BE; value 1 means verified.
        // Decode as uint256 and check the lowest byte (the BE-encoded
        // boolean lives there).
        uint256 verdict = abi.decode(ret, (uint256));
        if (verdict != 1) {
            revert AdapterProofRejected(loraHash);
        }

        // First-success flip; subsequent verifications are no-ops at
        // the storage level but still emit (for indexer / dashboard
        // consumption).
        if (!adapterProofVerified[loraHash]) {
            adapterProofVerified[loraHash] = true;
        }

        emit AdapterVerified(
            loraHash,
            msg.sender,
            inputCommitment,
            outputCommitment,
            block.number
        );
    }

    /**
     * @notice Convenience view: is the adapter proof-backed?
     */
    function isAdapterVerified(bytes32 loraHash) external view returns (bool) {
        return adapterProofVerified[loraHash];
    }
    
    /**
     * @notice Merge multiple LoRA adapters
     * @param loraHashes Array of LoRA hashes to merge
     * @param weights Weights for each LoRA (must sum to 1e18)
     * @param mergeType Type of merge (0: Linear, 1: SVD, 2: Task-Arithmetic)
     */
    function mergeLoRAs(
        bytes32[] memory loraHashes,
        uint256[] memory weights,
        uint256 mergeType
    ) external payable returns (bytes32) {
        require(loraHashes.length >= 2, "Need at least 2 LoRAs");
        require(loraHashes.length == weights.length, "Length mismatch");
        require(msg.value >= mergeFee, "Insufficient merge fee");
        require(mergeType <= 2, "Invalid merge type");
        
        // Verify all LoRAs have same base model
        bytes32 baseModel = adapters[loraHashes[0]].baseModelHash;
        uint256 totalWeight = 0;
        
        for (uint i = 0; i < loraHashes.length; i++) {
            LoRAAdapter storage adapter = adapters[loraHashes[i]];
            require(adapter.baseModelHash == baseModel, "Different base models");
            require(
                adapter.isPublic || adapter.creator == msg.sender || 
                adapterPermissions[loraHashes[i]][msg.sender],
                "No permission"
            );
            totalWeight += weights[i];
        }
        
        require(totalWeight == 1e18, "Weights must sum to 1");

        // Create merge request
        // Use abi.encode instead of abi.encodePacked to prevent hash collisions
        // with dynamic arrays (loraHashes, weights)
        bytes32 requestHash = keccak256(
            abi.encode(
                msg.sender,
                loraHashes,
                weights,
                block.timestamp
            )
        );
        
        MergeRequest storage request = mergeRequests[requestHash];
        request.requestHash = requestHash;
        request.loraHashes = loraHashes;
        request.weights = weights;
        request.requester = msg.sender;
        request.mergeType = mergeType;
        request.completed = false;
        
        // Execute merge via precompile
        _executeMerge(requestHash, loraHashes, weights, mergeType);
        
        return requestHash;
    }
    
    /**
     * @notice Complete merge request (called by operator)
     * @param requestHash Hash of the merge request
     * @param resultCID IPFS CID of merged LoRA
     */
    function completeMerge(
        bytes32 requestHash,
        string memory resultCID
    ) external onlyRole(OPERATOR_ROLE) {
        MergeRequest storage request = mergeRequests[requestHash];
        require(request.requester != address(0), "Request not found");
        require(!request.completed, "Already completed");
        
        // Generate result hash
        bytes32 resultHash = keccak256(abi.encodePacked(requestHash, resultCID));
        
        request.resultHash = resultHash;
        request.resultCID = resultCID;
        request.completed = true;
        
        // Create new LoRA entry for merged result
        LoRAAdapter storage merged = adapters[resultHash];
        merged.loraHash = resultHash;
        merged.baseModelHash = adapters[request.loraHashes[0]].baseModelHash;
        merged.creator = request.requester;
        merged.name = "Merged LoRA";
        merged.description = "Merged from multiple LoRAs";
        merged.ipfsCID = resultCID;
        merged.createdAt = block.timestamp;
        merged.isPublic = false;
        
        userAdapters[request.requester].push(resultHash);
        modelAdapters[merged.baseModelHash].push(resultHash);
        allAdapterHashes.push(resultHash);
        totalAdapters++;
        
        emit LoRAMerged(requestHash, request.loraHashes, resultHash);
    }
    
    /**
     * @notice Apply LoRA to base model for inference
     * @param baseModelHash Hash of base model
     * @param loraHash Hash of LoRA adapter
     * @param inputData Input data for inference
     */
    function inferWithLoRA(
        bytes32 baseModelHash,
        bytes32 loraHash,
        bytes calldata inputData
    ) external payable returns (bytes memory) {
        LoRAAdapter storage adapter = adapters[loraHash];
        require(adapter.baseModelHash == baseModelHash, "LoRA not for this model");
        require(
            adapter.isPublic || adapter.creator == msg.sender || 
            adapterPermissions[loraHash][msg.sender],
            "No permission"
        );
        
        // Get inference price from base model
        (,,,,,uint256 inferencePrice,,) = modelRegistry.getModel(baseModelHash);
        require(msg.value >= inferencePrice, "Insufficient payment");
        
        // Apply LoRA and execute inference via precompile
        bytes memory result = _applyLoRAAndInfer(baseModelHash, loraHash, inputData);
        
        // Distribute payment (80% to base model owner, 20% to LoRA creator)
        if (inferencePrice > 0) {
            uint256 loraShare = (inferencePrice * 20) / 100;
            uint256 modelShare = inferencePrice - loraShare;
            
            (bool success1, ) = adapter.creator.call{value: loraShare}("");
            require(success1, "LoRA payment failed");
            
            // Remaining goes through model registry
            modelRegistry.requestInference{value: modelShare}(baseModelHash, inputData);
        }
        
        return result;
    }
    
    /**
     * @notice Set LoRA as public/private
     * @param loraHash Hash of the LoRA
     * @param isPublic Whether LoRA should be public
     */
    function setPublicStatus(bytes32 loraHash, bool isPublic) external {
        LoRAAdapter storage adapter = adapters[loraHash];
        require(adapter.creator == msg.sender, "Not creator");
        
        adapter.isPublic = isPublic;
    }
    
    /**
     * @notice Grant permission to use LoRA
     * @param loraHash Hash of the LoRA
     * @param user Address to grant permission
     */
    function grantPermission(bytes32 loraHash, address user) external {
        LoRAAdapter storage adapter = adapters[loraHash];
        require(adapter.creator == msg.sender, "Not creator");
        
        adapterPermissions[loraHash][user] = true;
        emit PermissionGranted(loraHash, user);
    }
    
    /**
     * @notice Revoke permission to use LoRA
     * @param loraHash Hash of the LoRA
     * @param user Address to revoke permission
     */
    function revokePermission(bytes32 loraHash, address user) external {
        LoRAAdapter storage adapter = adapters[loraHash];
        require(adapter.creator == msg.sender, "Not creator");
        
        adapterPermissions[loraHash][user] = false;
    }
    
    // View functions
    
    function getLoRA(bytes32 loraHash) external view returns (
        bytes32 baseModelHash,
        address creator,
        string memory name,
        string memory ipfsCID,
        uint256 rank,
        bool isPublic
    ) {
        LoRAAdapter storage adapter = adapters[loraHash];
        return (
            adapter.baseModelHash,
            adapter.creator,
            adapter.name,
            adapter.ipfsCID,
            adapter.rank,
            adapter.isPublic
        );
    }
    
    function getUserLoRAs(address user) external view returns (bytes32[] memory) {
        return userAdapters[user];
    }
    
    function getModelLoRAs(bytes32 modelHash) external view returns (bytes32[] memory) {
        return modelAdapters[modelHash];
    }
    
    function getMergeRequest(bytes32 requestHash) external view returns (
        bytes32[] memory loraHashes,
        uint256[] memory weights,
        address requester,
        bool completed,
        string memory resultCID
    ) {
        MergeRequest storage request = mergeRequests[requestHash];
        return (
            request.loraHashes,
            request.weights,
            request.requester,
            request.completed,
            request.resultCID
        );
    }
    
    // Internal precompile interactions
    
    function _startTraining(bytes32 loraHash, TrainingConfig memory config) internal {
        (bool success, ) = LORA_PRECOMPILE.call(
            abi.encodeWithSignature(
                "startTraining(bytes32,uint256,uint256,uint256,string)",
                loraHash,
                config.epochs,
                config.batchSize,
                config.learningRate,
                config.datasetCID
            )
        );
        require(success, "Training start failed");
    }
    
    function _executeMerge(
        bytes32 requestHash,
        bytes32[] memory loraHashes,
        uint256[] memory weights,
        uint256 mergeType
    ) internal {
        (bool success, ) = LORA_PRECOMPILE.call(
            abi.encodeWithSignature(
                "mergeLoras(bytes32,bytes32[],uint256[],uint256)",
                requestHash,
                loraHashes,
                weights,
                mergeType
            )
        );
        require(success, "Merge execution failed");
    }
    
    function _applyLoRAAndInfer(
        bytes32 baseModelHash,
        bytes32 loraHash,
        bytes calldata inputData
    ) internal returns (bytes memory) {
        (bool success, bytes memory result) = LORA_PRECOMPILE.call(
            abi.encodeWithSignature(
                "applyAndInfer(bytes32,bytes32,bytes)",
                baseModelHash,
                loraHash,
                inputData
            )
        );
        require(success, "LoRA inference failed");
        return result;
    }
    
    // Admin functions
    
    function setTrainingFee(uint256 newFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldFee = trainingFeePerEpoch;
        trainingFeePerEpoch = newFee;
        emit TrainingFeeUpdated(oldFee, newFee);
    }

    function setMergeFee(uint256 newFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldFee = mergeFee;
        mergeFee = newFee;
        emit MergeFeeUpdated(oldFee, newFee);
    }
    
    function withdrawFees() external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees");
        
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Withdrawal failed");
    }
}