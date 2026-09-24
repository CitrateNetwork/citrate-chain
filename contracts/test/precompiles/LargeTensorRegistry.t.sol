// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../examples/precompiles/LargeTensorRegistry.sol";

/// @notice Compile + ABI-shape tests for LargeTensorRegistry. The
/// 0x0109 MERKLE_VERIFY_TENSOR precompile is not in stock anvil, so
/// the full proveElement round-trip is exercised against a Citrate
/// node. We test:
///
///   1. Registration emits the expected event.
///   2. `register` rejects zero root + zero leafCount.
///   3. `proveElement` rejects out-of-range leafIndex.
///   4. `proveElement` rejects oversized proof depth (>32).
contract LargeTensorRegistryTest is Test {
    LargeTensorRegistry reg;
    address publisher = address(0xBEEF);

    function setUp() public {
        reg = new LargeTensorRegistry();
    }

    function test_RegisterEmitsEvent() public {
        vm.prank(publisher);
        vm.expectEmit(true, true, false, true);
        emit LargeTensorRegistry.TensorRegistered(
            publisher,
            bytes32("model-weights-v1"),
            bytes32(uint256(0xCAFEBABE)),
            1024
        );
        reg.register(bytes32("model-weights-v1"), bytes32(uint256(0xCAFEBABE)), 1024);
    }

    function test_RegisterRejectsZeroRoot() public {
        vm.expectRevert("root must be nonzero");
        reg.register(bytes32("x"), bytes32(0), 16);
    }

    function test_RegisterRejectsZeroLeafCount() public {
        vm.expectRevert("leafCount must be > 0");
        reg.register(bytes32("x"), bytes32(uint256(1)), 0);
    }

    function test_ProveElementRejectsUnregistered() public {
        bytes32[] memory siblings = new bytes32[](0);
        vm.expectRevert("no tensor registered under (publisher, name)");
        reg.proveElement(publisher, bytes32("never"), 0, bytes32(0), siblings);
    }

    function test_ProveElementRejectsOutOfRangeIndex() public {
        vm.prank(publisher);
        reg.register(bytes32("t"), bytes32(uint256(1)), 4);

        bytes32[] memory siblings = new bytes32[](2);
        vm.expectRevert("leafIndex out of range");
        reg.proveElement(publisher, bytes32("t"), 4, bytes32(0), siblings); // index 4 of 4-leaf tree
    }

    function test_ProveElementRejectsOversizedProof() public {
        vm.prank(publisher);
        reg.register(bytes32("t"), bytes32(uint256(1)), 4);

        bytes32[] memory siblings = new bytes32[](33); // > 32 cap
        vm.expectRevert("proof depth exceeds precompile cap");
        reg.proveElement(publisher, bytes32("t"), 0, bytes32(0), siblings);
    }

    function test_PrecompileAddressIsCorrect() public view {
        assertEq(reg.MERKLE_VERIFY_TENSOR(), address(0x0109));
    }
}
