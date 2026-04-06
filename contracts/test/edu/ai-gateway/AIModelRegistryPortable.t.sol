// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AIModelRegistryPortable} from "../../../src/edu/ai-gateway/AIModelRegistryPortable.sol";
import {IAIModelRegistry} from "../../../src/edu/ai-gateway/IAIModelRegistry.sol";
import {IAIBackendCapabilities} from "../../../src/edu/ai-gateway/IAIBackendCapabilities.sol";

contract AIModelRegistryPortableTest is Test {
    AIModelRegistryPortable registry;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    bytes32 modelHash1 = keccak256("qwen2.5-0.5b-weights");
    bytes32 manifestHash1 = keccak256("manifest-v1-json");
    bytes32 modelHash2 = keccak256("llama-3.2-1b-weights");
    bytes32 manifestHash2 = keccak256("manifest-v1-llama-json");

    function setUp() public {
        registry = new AIModelRegistryPortable();
    }

    // ===================================================================
    // REGISTRATION
    // ===================================================================

    function test_register_model() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        assertEq(registry.getModelHash(modelId), modelHash1);
        assertEq(registry.getManifestHash(modelId), manifestHash1);
        assertEq(registry.getModelOwner(modelId), alice);
        assertEq(registry.modelCount(), 1);
    }

    function test_register_emits_event() public {
        vm.prank(alice);
        vm.expectEmit(false, true, true, true);
        emit IAIModelRegistry.ModelRegistered(bytes32(0), modelHash1, alice, manifestHash1);
        registry.registerModel(modelHash1, manifestHash1);
    }

    function test_register_two_models() public {
        vm.prank(alice);
        bytes32 id1 = registry.registerModel(modelHash1, manifestHash1);

        vm.prank(bob);
        bytes32 id2 = registry.registerModel(modelHash2, manifestHash2);

        assertTrue(id1 != id2);
        assertEq(registry.modelCount(), 2);
        assertEq(registry.getModelOwner(id1), alice);
        assertEq(registry.getModelOwner(id2), bob);
    }

    function test_register_zero_hash_reverts() public {
        vm.prank(alice);
        vm.expectRevert(); // ZeroHash
        registry.registerModel(bytes32(0), manifestHash1);
    }

    function test_register_duplicate_model_hash_reverts() public {
        vm.prank(alice);
        registry.registerModel(modelHash1, manifestHash1);

        vm.prank(bob);
        vm.expectRevert(); // ModelHashAlreadyRegistered
        registry.registerModel(modelHash1, manifestHash2);
    }

    // ===================================================================
    // VERIFICATION
    // ===================================================================

    function test_verify_model_correct_hash() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        assertTrue(registry.verifyModel(modelId, modelHash1));
    }

    function test_verify_model_wrong_hash() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        assertFalse(registry.verifyModel(modelId, modelHash2));
    }

    function test_verify_nonexistent_model_reverts() public {
        vm.expectRevert(); // ModelNotFound
        registry.verifyModel(bytes32(uint256(999)), modelHash1);
    }

    // ===================================================================
    // CROSS-CHAIN RESOLUTION
    // ===================================================================

    function test_resolve_model_hash() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        assertEq(registry.resolveModelHash(modelHash1), modelId);
    }

    function test_resolve_unknown_hash_returns_zero() public view {
        assertEq(registry.resolveModelHash(modelHash1), bytes32(0));
    }

    // ===================================================================
    // OWNERSHIP TRANSFER
    // ===================================================================

    function test_transfer_ownership() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        vm.prank(alice);
        registry.transferOwnership(modelId, bob);

        assertEq(registry.getModelOwner(modelId), bob);
    }

    function test_transfer_emits_event() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IAIModelRegistry.ModelTransferred(modelId, alice, bob);
        registry.transferOwnership(modelId, bob);
    }

    function test_non_owner_cannot_transfer() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        vm.prank(bob);
        vm.expectRevert(); // NotModelOwner
        registry.transferOwnership(modelId, bob);
    }

    function test_transfer_to_zero_reverts() public {
        vm.prank(alice);
        bytes32 modelId = registry.registerModel(modelHash1, manifestHash1);

        vm.prank(alice);
        vm.expectRevert(); // ZeroAddress
        registry.transferOwnership(modelId, address(0));
    }

    // ===================================================================
    // BACKEND CAPABILITIES (L0)
    // ===================================================================

    function test_execution_profile_is_portable() public view {
        assertEq(
            uint256(registry.getExecutionProfile()),
            uint256(IAIBackendCapabilities.AIExecutionProfile.PortableWasm)
        );
    }

    function test_backend_version() public view {
        assertEq(registry.getBackendVersion(), keccak256("ai-evm-portable-v1"));
    }

    function test_supports_interface_erc165() public view {
        assertTrue(registry.supportsInterface(0x01ffc9a7));
    }

    function test_supports_interface_model_registry() public view {
        assertTrue(registry.supportsInterface(type(IAIModelRegistry).interfaceId));
    }

    function test_supports_interface_backend_capabilities() public view {
        assertTrue(registry.supportsInterface(type(IAIBackendCapabilities).interfaceId));
    }

    function test_does_not_support_random_interface() public view {
        assertFalse(registry.supportsInterface(0xdeadbeef));
    }

    // ===================================================================
    // FUZZ TESTS
    // ===================================================================

    function testFuzz_register_any_hash(bytes32 mHash, bytes32 manHash) public {
        vm.assume(mHash != bytes32(0));

        vm.prank(alice);
        bytes32 modelId = registry.registerModel(mHash, manHash);
        assertEq(registry.getModelHash(modelId), mHash);
        assertEq(registry.getManifestHash(modelId), manHash);
    }

    function testFuzz_ids_are_unique(uint8 count) public {
        count = uint8(bound(count, 2, 50));
        bytes32[] memory ids = new bytes32[](count);

        for (uint8 i = 0; i < count; i++) {
            bytes32 h = keccak256(abi.encodePacked("model-", i));
            vm.prank(alice);
            ids[i] = registry.registerModel(h, manifestHash1);
        }

        // All IDs should be unique
        for (uint8 i = 0; i < count; i++) {
            for (uint8 j = i + 1; j < count; j++) {
                assertTrue(ids[i] != ids[j]);
            }
        }
    }
}
