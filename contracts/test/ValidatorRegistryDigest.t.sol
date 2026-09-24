// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/ValidatorRegistry.sol";

/// @notice Emits the exact registration + equivocation digests the contract verifies,
///         for fixed vectors. The node's Rust `crypto.rs::registration_digest` /
///         `equivocation_vote_digest` MUST reproduce these byte-for-byte (asserted in
///         core/consensus/src/crypto.rs tests). This is the cross-layer equivalence gate.
contract ValidatorRegistryDigestTest is Test {
    // Fixed vectors (kept in sync with the Rust test).
    uint256 constant CHAIN_ID = 40204;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;
    address constant STAKER = 0x2222222222222222222222222222222222222222;
    bytes32 constant PUBKEY = bytes32(uint256(0xABCDEF));
    uint256 constant NONCE = 7;
    uint64 constant HEIGHT = 12345;
    bytes32 constant BLOCKHASH_ = bytes32(uint256(0x99));

    function test_emit_registration_digest() public pure {
        bytes32 d = keccak256(
            abi.encode(
                keccak256("Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)"),
                CHAIN_ID, REGISTRY, STAKER, PUBKEY, NONCE
            )
        );
        console.logBytes32(d);
    }

    function test_emit_equivocation_digest() public pure {
        bytes32 d = keccak256(
            abi.encode(
                keccak256("EquivocationVote(uint256 chainId,address registry,uint64 height,bytes32 blockHash)"),
                CHAIN_ID, REGISTRY, HEIGHT, BLOCKHASH_
            )
        );
        console.logBytes32(d);
    }

    // Sanity: the type strings hashed above equal the contract's public TYPEHASH constants.
    function test_typehashes_match_contract() public {
        ValidatorRegistry r = new ValidatorRegistry(
            address(0x1), address(0x2), address(0x3), 32_000 ether, 1 ether, 5000, 10_000 ether
        );
        assertEq(
            r.REGISTER_TYPEHASH(),
            keccak256("Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)")
        );
        assertEq(
            r.EQUIVOCATION_TYPEHASH(),
            keccak256("EquivocationVote(uint256 chainId,address registry,uint64 height,bytes32 blockHash)")
        );
    }
}
