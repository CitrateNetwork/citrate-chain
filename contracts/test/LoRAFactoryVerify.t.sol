// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {LoRAFactory} from "../src/LoRAFactory.sol";
import {IModelRegistry} from "../src/interfaces/IModelRegistry.sol";

/// Minimal mock of IModelRegistry to satisfy LoRAFactory's
/// constructor + permission checks. Returns msg.sender as owner
/// for any model and grants permission to any caller.
contract MockModelRegistry is IModelRegistry {
    function registerModel(
        string memory,
        string memory,
        string memory,
        string memory,
        uint256,
        uint256,
        ModelMetadata memory
    ) external payable returns (bytes32) {
        return bytes32(uint256(0xBEEF));
    }

    function requestInference(bytes32, bytes calldata)
        external
        payable
        returns (bytes memory)
    {
        return "";
    }

    function getModel(bytes32 modelHash)
        external
        pure
        returns (
            address owner,
            string memory,
            string memory,
            string memory,
            string memory,
            uint256,
            uint256,
            bool
        )
    {
        // Synthesize a non-zero owner deterministically from the hash
        // so LoRAFactory.createLoRA's "Base model not found" check passes.
        owner = address(uint160(uint256(modelHash) | 0xCAFE));
        return (owner, "", "", "", "", 0, 0, true);
    }

    function hasPermission(bytes32, address) external pure returns (bool) {
        return true;
    }
}

/// @title LoRAFactoryVerifyTest — RM-FL-4 / WP-4.7
/// @notice Maps Gherkin scenarios 6 + 7 (adapter verification
///         success / failure paths) to Forge tests. The 0x0108
///         precompile is stubbed via vm.etch with a deterministic
///         "stub verifier" that returns 1 or 0 based on the input's
///         last byte — sufficient to exercise the contract's
///         success/failure branches.
contract LoRAFactoryVerifyTest is Test {
    LoRAFactory public factory;
    MockModelRegistry public registry;

    address public operator;
    address public mentor;
    address public mentee;

    bytes32 public constant BASE_MODEL = bytes32(uint256(0xBEEF));
    bytes32 public constant ADAPTER_COMMITMENT = bytes32(uint256(0xC0FFEE));

    address constant INFERENCE_PROOF_VERIFY = address(0x108);

    function setUp() public {
        registry = new MockModelRegistry();
        factory = new LoRAFactory(address(registry));

        operator = address(this);
        mentor = address(0xA11CE);
        mentee = address(0xB055);

        vm.deal(operator, 100 ether);
        vm.deal(mentor, 100 ether);
        vm.deal(mentee, 100 ether);

        // Install a deterministic stub at 0x0108 — returns 32 bytes
        // BE; verdict = 1 if input's LAST byte == 0xAA, else 0.
        // This lets the test toggle proof success by varying the
        // last byte of the proof transcript.
        vm.etch(INFERENCE_PROOF_VERIFY, type(StubVerifier).runtimeCode);
    }

    function _createAdapter() internal returns (bytes32) {
        LoRAFactory.TrainingConfig memory cfg = LoRAFactory.TrainingConfig({
            epochs: 1,
            batchSize: 1,
            learningRate: 1e16,
            datasetCID: "ipfs://stub",
            datasetSize: 1,
            validationSplit: 1000
        });
        vm.prank(mentor);
        bytes32 loraHash = factory.createLoRA{value: 0.01 ether}(
            BASE_MODEL,
            "test-adapter",
            "test",
            8,
            16,
            500,
            cfg
        );
        // Operator finishes training so adapter has IPFS weights.
        factory.completeTraining(loraHash, "ipfs://weights-cid");
        return loraHash;
    }

    // ====================================================================
    // Scenario 6 — Adapter verification: success path
    // ====================================================================

    function test_scenario6_verify_adapter_success() public {
        bytes32 loraHash = _createAdapter();
        factory.setAdapterModelCommitment(loraHash, ADAPTER_COMMITMENT);

        // Proof transcript ending in 0xAA → stub returns 1.
        bytes memory proof = hex"01020304AA";

        bytes32 inputC = bytes32(uint256(0x1111));
        bytes32 outputC = bytes32(uint256(0x2222));

        vm.expectEmit(true, true, false, true);
        emit LoRAFactory.AdapterVerified(
            loraHash,
            mentee,
            inputC,
            outputC,
            block.number
        );

        vm.prank(mentee);
        factory.verifyAdapterAt(loraHash, inputC, outputC, proof);

        assertTrue(factory.isAdapterVerified(loraHash));
        assertTrue(factory.adapterProofVerified(loraHash));
    }

    // ====================================================================
    // Scenario 7 — Adapter verification: failure path
    // ====================================================================

    function test_scenario7_verify_adapter_rejected() public {
        bytes32 loraHash = _createAdapter();
        factory.setAdapterModelCommitment(loraHash, ADAPTER_COMMITMENT);

        // Proof ending in 0xBB → stub returns 0 → revert.
        bytes memory badProof = hex"01020304BB";

        vm.expectRevert(
            abi.encodeWithSelector(
                LoRAFactory.AdapterProofRejected.selector,
                loraHash
            )
        );
        vm.prank(mentee);
        factory.verifyAdapterAt(
            loraHash,
            bytes32(uint256(0x1111)),
            bytes32(uint256(0x2222)),
            badProof
        );

        assertFalse(factory.isAdapterVerified(loraHash));
    }

    // ====================================================================
    // Pre-conditions
    // ====================================================================

    function test_verify_reverts_when_adapter_not_found() public {
        bytes32 nonexistent = bytes32(uint256(0xDEAD));
        vm.expectRevert(
            abi.encodeWithSelector(
                LoRAFactory.AdapterNotFound.selector,
                nonexistent
            )
        );
        vm.prank(mentee);
        factory.verifyAdapterAt(
            nonexistent,
            bytes32(0),
            bytes32(0),
            hex"AA"
        );
    }

    function test_verify_reverts_when_commitment_not_set() public {
        bytes32 loraHash = _createAdapter();
        // Skip setAdapterModelCommitment.
        vm.expectRevert(
            abi.encodeWithSelector(
                LoRAFactory.AdapterModelCommitmentNotSet.selector,
                loraHash
            )
        );
        vm.prank(mentee);
        factory.verifyAdapterAt(
            loraHash,
            bytes32(uint256(0x1111)),
            bytes32(uint256(0x2222)),
            hex"AA"
        );
    }

    // ====================================================================
    // Operator hooks
    // ====================================================================

    function test_set_commitment_one_shot() public {
        bytes32 loraHash = _createAdapter();
        factory.setAdapterModelCommitment(loraHash, ADAPTER_COMMITMENT);

        // Second attempt reverts.
        vm.expectRevert("Commitment already set");
        factory.setAdapterModelCommitment(loraHash, bytes32(uint256(0x9999)));
    }

    function test_set_commitment_rejects_zero() public {
        bytes32 loraHash = _createAdapter();
        vm.expectRevert("Zero commitment");
        factory.setAdapterModelCommitment(loraHash, bytes32(0));
    }

    function test_set_commitment_unauthorized_reverts() public {
        bytes32 loraHash = _createAdapter();
        vm.prank(address(0xBADD));
        // AccessControl revert message format varies; just check it
        // reverts with non-empty data.
        vm.expectRevert();
        factory.setAdapterModelCommitment(loraHash, ADAPTER_COMMITMENT);
    }

    function test_idempotent_repeat_verification_no_state_change() public {
        bytes32 loraHash = _createAdapter();
        factory.setAdapterModelCommitment(loraHash, ADAPTER_COMMITMENT);
        bytes memory proof = hex"AA";

        vm.prank(mentee);
        factory.verifyAdapterAt(loraHash, bytes32(0), bytes32(0), proof);
        assertTrue(factory.adapterProofVerified(loraHash));

        // Second verify: still emits an event but flag is unchanged.
        vm.prank(mentee);
        factory.verifyAdapterAt(loraHash, bytes32(0), bytes32(0), proof);
        assertTrue(factory.adapterProofVerified(loraHash));
    }
}

/// Stub verifier installed at 0x0108 via vm.etch. Reads the input's
/// LAST byte and returns 32 bytes BE: 1 if last byte == 0xAA, else 0.
/// Pure deterministic; lets the test toggle success by choosing the
/// trailing byte of the proof transcript.
contract StubVerifier {
    fallback(bytes calldata input) external returns (bytes memory) {
        uint256 verdict = 0;
        if (input.length > 0 && uint8(input[input.length - 1]) == 0xAA) {
            verdict = 1;
        }
        return abi.encode(verdict);
    }
}
