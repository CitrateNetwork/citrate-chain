// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title TensorCommitDemo
/// @notice Reference contract demonstrating use of the 0x0107
///         TENSOR_COMMIT precompile (RM-M1, WP-M1.2).
///
/// 0x0107 takes the canonical-format bytes of a tensor and returns
/// a 32-byte Poseidon commitment. This contract:
///
///   1. Lets a caller submit raw tensor bytes.
///   2. Computes the commitment via the precompile.
///   3. Stores the commitment indexed by the caller's address.
///   4. Lets a verifier confirm a tensor matches a stored commitment
///      by re-committing the bytes and comparing.
///
/// Use case: a model author publishes a tensor commitment on-chain;
/// later disputes about "what was actually committed" are settled by
/// re-running the precompile.
///
/// Production note: this is a reference / demo contract, not a
/// shipped product. Real consumers will combine TENSOR_COMMIT with
/// 0x0108 INFERENCE_PROOF_VERIFY (RM-M1b) and 0x0109
/// MERKLE_VERIFY_TENSOR (RM-M1, WP-M1.4) for richer flows.
contract TensorCommitDemo {
    /// Address of the TENSOR_COMMIT precompile.
    address public constant TENSOR_COMMIT = address(0x0107);

    /// Each address can publish one commitment per `name`.
    mapping(address => mapping(bytes32 => bytes32)) public commitments;

    event TensorCommitted(
        address indexed publisher,
        bytes32 indexed name,
        bytes32 commitment,
        uint256 inputBytes
    );

    /// Publish a commitment over `tensor` under `name`. Reverts if
    /// the tensor bytes are malformed (e.g. unknown dtype, oversize
    /// shape) — the precompile rejects via revert with a stable
    /// "TENSOR_FORMAT_ERROR:" prefix.
    function publish(bytes32 name, bytes calldata tensor) external returns (bytes32 commitment) {
        commitment = _commit(tensor);
        commitments[msg.sender][name] = commitment;
        emit TensorCommitted(msg.sender, name, commitment, tensor.length);
    }

    /// Verify that the supplied `tensor` bytes still hash to the
    /// commitment previously published by `publisher` under `name`.
    /// Returns true on match, false otherwise. Does NOT revert on
    /// mismatch — caller decides what mismatches mean.
    function verify(
        address publisher,
        bytes32 name,
        bytes calldata tensor
    ) external view returns (bool) {
        bytes32 stored = commitments[publisher][name];
        if (stored == bytes32(0)) {
            return false; // Nothing published; nothing to verify against.
        }
        bytes32 fresh = _commit(tensor);
        return fresh == stored;
    }

    /// Internal: invoke the 0x0107 precompile.
    /// Uses STATICCALL — the precompile is pure and stateless.
    function _commit(bytes memory tensor) internal view returns (bytes32) {
        (bool ok, bytes memory ret) = TENSOR_COMMIT.staticcall(tensor);
        require(ok, "TENSOR_COMMIT precompile reverted");
        require(ret.length == 32, "TENSOR_COMMIT returned wrong length");
        return abi.decode(ret, (bytes32));
    }
}
