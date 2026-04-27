// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title LargeTensorRegistry
/// @notice Reference contract demonstrating use of the 0x0109
///         MERKLE_VERIFY_TENSOR precompile (RM-M1, WP-M1.4).
///
/// 0x0109 verifies inclusion of a `(leaf_index, leaf_value)` pair in
/// a Poseidon-Merkle tree given the root and a sibling path.
///
/// Use case: a publisher has a large tensor that's too big to ship
/// in a single transaction's calldata. They build a Merkle tree over
/// the tensor's elements off-chain, anchor the root on-chain, and
/// later let consumers prove individual elements without uploading
/// the whole tensor.
///
/// Workflow:
///   1. Publisher calls `register(name, root, count)` to anchor a
///      Merkle root for a named tensor.
///   2. Consumer calls `proveElement(publisher, name, index, value,
///      siblings)` to assert that element `index` of that tensor has
///      value `value`. The contract calls 0x0109 to verify.
///
/// This is a generic Merkle anchor — the structure of the tree
/// (binary, Poseidon-hashed leaves where leaf_i =
/// Poseidon(i, value_i)) is implicit in 0x0109's contract; callers
/// must build their off-chain trees the same way.
contract LargeTensorRegistry {
    address public constant MERKLE_VERIFY_TENSOR = address(0x0109);

    struct Tensor {
        bytes32 root;
        uint64 leafCount;
        uint64 registeredAt;
    }

    /// publisher → tensor name → metadata
    mapping(address => mapping(bytes32 => Tensor)) public tensors;

    event TensorRegistered(
        address indexed publisher,
        bytes32 indexed name,
        bytes32 root,
        uint64 leafCount
    );

    event ElementProven(
        address indexed publisher,
        bytes32 indexed name,
        uint32 leafIndex,
        bytes32 leafValue,
        bool valid
    );

    /// Anchor a Merkle root for a tensor of `leafCount` leaves under
    /// `name`. Caller is the publisher. Re-registering under the same
    /// (publisher, name) overwrites the prior root — by design;
    /// publishers can revise their commitments. Consumers should pin
    /// to the `registeredAt` timestamp to detect rebases.
    function register(bytes32 name, bytes32 root, uint64 leafCount) external {
        require(root != bytes32(0), "root must be nonzero");
        require(leafCount > 0, "leafCount must be > 0");
        tensors[msg.sender][name] = Tensor({
            root: root,
            leafCount: leafCount,
            registeredAt: uint64(block.timestamp)
        });
        emit TensorRegistered(msg.sender, name, root, leafCount);
    }

    /// Prove that element `leafIndex` of `(publisher, name)` has the
    /// claimed `leafValue`, given a Merkle sibling path. Returns true
    /// on valid proof, false otherwise. Emits an event either way for
    /// auditability.
    ///
    /// `siblings` is bottom-up: siblings[0] is the sibling at the leaf
    /// level. Length must equal the tree depth (= ceil(log2(leafCount))).
    function proveElement(
        address publisher,
        bytes32 name,
        uint32 leafIndex,
        bytes32 leafValue,
        bytes32[] calldata siblings
    ) external returns (bool valid) {
        Tensor memory t = tensors[publisher][name];
        require(t.root != bytes32(0), "no tensor registered under (publisher, name)");
        require(uint64(leafIndex) < t.leafCount, "leafIndex out of range");
        require(siblings.length <= 32, "proof depth exceeds precompile cap");

        // Build wire format for 0x0109:
        //   [32B root][32B leaf_index BE][32B leaf_value]
        //   [1B proof_depth][proof_depth × 32B siblings]
        // The leaf_index field is 32 bytes BE — we left-pad a uint32
        // by encoding as uint256 (Solidity always BE-encodes uints).
        bytes memory input = abi.encodePacked(
            t.root,
            uint256(leafIndex),
            leafValue,
            uint8(siblings.length)
        );
        for (uint256 i = 0; i < siblings.length; ++i) {
            input = abi.encodePacked(input, siblings[i]);
        }

        (bool ok, bytes memory ret) = MERKLE_VERIFY_TENSOR.staticcall(input);
        require(ok, "MERKLE_VERIFY_TENSOR precompile reverted");
        require(ret.length == 32, "precompile returned wrong length");

        bytes32 result = abi.decode(ret, (bytes32));
        valid = (result == bytes32(uint256(1)));
        emit ElementProven(publisher, name, leafIndex, leafValue, valid);
    }
}
