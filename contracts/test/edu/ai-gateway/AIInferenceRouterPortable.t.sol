// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AIInferenceRouterPortable} from "../../../src/edu/ai-gateway/AIInferenceRouterPortable.sol";
import {AIModelRegistryPortable} from "../../../src/edu/ai-gateway/AIModelRegistryPortable.sol";
import {IAIInferenceRouter} from "../../../src/edu/ai-gateway/IAIInferenceRouter.sol";

contract AIInferenceRouterPortableTest is Test {
    AIModelRegistryPortable registry;
    AIInferenceRouterPortable router;

    address governance = address(0x1000);
    address requester = address(0xA11CE);
    uint256 workerPk = 0xBEEF;
    address worker;
    address nobody = address(0xDEAD);

    bytes32 modelHash = keccak256("qwen2.5-0.5b-weights");
    bytes32 manifestHash = keccak256("manifest-v1");
    bytes32 modelId;

    function setUp() public {
        worker = vm.addr(workerPk);
        vm.deal(requester, 100 ether);
        vm.deal(worker, 1 ether);

        registry = new AIModelRegistryPortable();
        router = new AIInferenceRouterPortable(address(registry), governance);

        // Register a model
        vm.prank(requester);
        modelId = registry.registerModel(modelHash, manifestHash);

        // Authorize the worker
        vm.prank(governance);
        router.addWorker(worker);
    }

    // ===================================================================
    // REQUEST
    // ===================================================================

    function test_request_inference() public {
        bytes32 inputCommitment = keccak256("what is photosynthesis");

        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, inputCommitment, 1 ether
        );

        assertEq(requestId, 0);
        assertEq(router.requestCount(), 1);

        (bytes32 mId, bytes32 ic, address req, uint256 mp, bool fulfilled) = router.getRequest(0);
        assertEq(mId, modelId);
        assertEq(ic, inputCommitment);
        assertEq(req, requester);
        assertEq(mp, 1 ether);
        assertFalse(fulfilled);
    }

    function test_request_emits_event() public {
        bytes32 inputCommitment = keccak256("test");

        vm.prank(requester);
        vm.expectEmit(true, true, true, true);
        emit IAIInferenceRouter.InferenceRequested(0, modelId, requester);
        router.requestInference{value: 1 ether}(modelId, inputCommitment, 1 ether);
    }

    function test_request_zero_commitment_reverts() public {
        vm.prank(requester);
        vm.expectRevert(); // ZeroCommitment
        router.requestInference{value: 1 ether}(modelId, bytes32(0), 1 ether);
    }

    function test_request_insufficient_payment_reverts() public {
        vm.prank(requester);
        vm.expectRevert(); // InsufficientPayment
        router.requestInference{value: 0.5 ether}(
            modelId, keccak256("test"), 1 ether
        );
    }

    function test_request_unregistered_model_reverts() public {
        vm.prank(requester);
        vm.expectRevert(); // ModelNotRegistered
        router.requestInference{value: 1 ether}(
            bytes32(uint256(999)), keccak256("test"), 1 ether
        );
    }

    function test_request_free_inference() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference(modelId, keccak256("test"), 0);
        assertEq(requestId, 0);
    }

    // ===================================================================
    // FULFILLMENT
    // ===================================================================

    function test_fulfill_inference() public {
        bytes32 inputCommitment = keccak256("what is photosynthesis");
        bytes32 outputCommitment = keccak256("photosynthesis is the process");

        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, inputCommitment, 1 ether
        );

        // Sign the receipt with EIP-712
        bytes memory signature = _signReceipt(requestId, outputCommitment, workerPk);

        uint256 workerBalBefore = worker.balance;

        vm.prank(worker);
        router.fulfillInference(requestId, outputCommitment, signature);

        // Request is now fulfilled
        (,,,, bool fulfilled) = router.getRequest(requestId);
        assertTrue(fulfilled);

        // Worker received payment
        assertEq(worker.balance, workerBalBefore + 1 ether);
    }

    function test_fulfill_emits_event() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, keccak256("test"), 1 ether
        );

        bytes32 outputCommitment = keccak256("response");
        bytes memory sig = _signReceipt(requestId, outputCommitment, workerPk);

        vm.prank(worker);
        vm.expectEmit(true, true, true, true);
        emit IAIInferenceRouter.InferenceFulfilled(requestId, outputCommitment, worker);
        router.fulfillInference(requestId, outputCommitment, sig);
    }

    function test_fulfill_already_fulfilled_reverts() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, keccak256("test"), 1 ether
        );

        bytes32 out = keccak256("response");
        bytes memory sig = _signReceipt(requestId, out, workerPk);

        vm.prank(worker);
        router.fulfillInference(requestId, out, sig);

        vm.prank(worker);
        vm.expectRevert(); // AlreadyFulfilled
        router.fulfillInference(requestId, out, sig);
    }

    function test_fulfill_nonexistent_request_reverts() public {
        bytes32 out = keccak256("response");
        // Use a dummy 65-byte signature since we can't build a valid one for a non-existent request
        bytes memory sig = new bytes(65);

        vm.prank(worker);
        vm.expectRevert(); // RequestNotFound
        router.fulfillInference(999, out, sig);
    }

    function test_fulfill_unauthorized_worker_reverts() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, keccak256("test"), 1 ether
        );

        // Sign with a different key (not authorized)
        uint256 fakePk = 0xCAFE;
        bytes32 out = keccak256("response");
        bytes memory sig = _signReceipt(requestId, out, fakePk);

        vm.prank(vm.addr(fakePk));
        vm.expectRevert(); // NotAuthorizedWorker
        router.fulfillInference(requestId, out, sig);
    }

    function test_fulfill_zero_output_reverts() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, keccak256("test"), 1 ether
        );

        bytes memory sig = _signReceipt(requestId, bytes32(0), workerPk);

        vm.prank(worker);
        vm.expectRevert(); // ZeroCommitment
        router.fulfillInference(requestId, bytes32(0), sig);
    }

    // ===================================================================
    // RECEIPT VERIFICATION
    // ===================================================================

    function test_verify_receipt() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, keccak256("test"), 1 ether
        );

        bytes32 out = keccak256("response");
        bytes memory sig = _signReceipt(requestId, out, workerPk);

        (bool valid, address signer) = router.verifyReceipt(requestId, out, sig);
        assertTrue(valid);
        assertEq(signer, worker);
    }

    function test_verify_invalid_signature() public {
        vm.prank(requester);
        uint256 requestId = router.requestInference{value: 1 ether}(
            modelId, keccak256("test"), 1 ether
        );

        // Invalid signature (wrong length)
        (bool valid,) = router.verifyReceipt(requestId, keccak256("out"), hex"deadbeef");
        assertFalse(valid);
    }

    // ===================================================================
    // WORKER MANAGEMENT
    // ===================================================================

    function test_add_worker() public {
        vm.prank(governance);
        router.addWorker(nobody);
        assertTrue(router.authorizedWorkers(nobody));
    }

    function test_remove_worker() public {
        vm.prank(governance);
        router.addWorker(nobody);

        vm.prank(governance);
        router.removeWorker(nobody);
        assertFalse(router.authorizedWorkers(nobody));
    }

    function test_non_governance_cannot_add_worker() public {
        vm.prank(nobody);
        vm.expectRevert(); // NotGovernance
        router.addWorker(nobody);
    }

    // ===================================================================
    // HELPERS
    // ===================================================================

    function _signReceipt(uint256 requestId, bytes32 outputCommitment, uint256 pk) internal view returns (bytes memory) {
        bytes32 RECEIPT_TYPEHASH = keccak256(
            "AIExecutionReceipt(uint256 requestId,bytes32 outputCommitment,bytes32 modelId,uint256 timestamp)"
        );
        bytes32 DOMAIN_TYPEHASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

        bytes32 domainSeparator = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("AIInferenceRouter"),
            keccak256("1"),
            block.chainid,
            address(router)
        ));

        // Get the request's modelId and timestamp
        (bytes32 mId,,, , ) = router.getRequest(requestId);

        bytes32 structHash = keccak256(abi.encode(
            RECEIPT_TYPEHASH,
            requestId,
            outputCommitment,
            mId,
            block.timestamp // timestamp from setUp
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
