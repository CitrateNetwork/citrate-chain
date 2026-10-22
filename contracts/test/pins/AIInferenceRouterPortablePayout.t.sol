// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AIInferenceRouterPortable} from "../../src/edu/ai-gateway/AIInferenceRouterPortable.sol";
import {AIModelRegistryPortable} from "../../src/edu/ai-gateway/AIModelRegistryPortable.sol";

/// When the push payout to a worker fails, the fulfilled request's escrow is
/// credited to that worker's pull balance instead of staying in the router.
contract AIInferenceRouterPortablePayoutTest is Test {
    AIModelRegistryPortable internal registry;
    AIInferenceRouterPortable internal router;
    address internal constant GOVERNANCE = address(0x1000);
    address internal constant REQUESTER = address(0xA11CE);
    uint256 internal constant WORKER_PK = 0xBEEF;
    address internal worker;
    bytes32 internal modelId;

    function setUp() public {
        worker = vm.addr(WORKER_PK);
        vm.deal(REQUESTER, 100 ether);
        registry = new AIModelRegistryPortable();
        router = new AIInferenceRouterPortable(address(registry), GOVERNANCE);
        vm.prank(REQUESTER);
        modelId = registry.registerModel(keccak256("weights"), keccak256("manifest"));
        vm.prank(GOVERNANCE);
        router.addWorker(worker);
    }

    function _signReceipt(uint256 requestId, bytes32 outputCommitment) internal view returns (bytes memory) {
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("AIInferenceRouter"),
            keccak256("1"),
            block.chainid,
            address(router)
        ));
        (bytes32 mId,,,,) = router.getRequest(requestId);
        bytes32 structHash = keccak256(abi.encode(
            keccak256("AIExecutionReceipt(uint256 requestId,bytes32 outputCommitment,bytes32 modelId,uint256 timestamp)"),
            requestId,
            outputCommitment,
            mId,
            block.timestamp
        ));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(WORKER_PK, keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)));
        return abi.encodePacked(r, s, v);
    }

    function test_failedWorkerPushIsCreditedAndClaimable() public {
        vm.prank(REQUESTER);
        uint256 id = router.requestInference{value: 1 ether}(modelId, keccak256("q"), 1 ether);

        // The worker address refuses plain value transfers (PUSH0 PUSH0 REVERT).
        vm.etch(worker, hex"5f5ffd");
        router.fulfillInference(id, keccak256("out"), _signReceipt(id, keccak256("out")));
        assertEq(router.pendingWithdrawals(worker), 1 ether, "failed payout credited to the worker");

        vm.etch(worker, "");
        uint256 bal = worker.balance;
        vm.prank(worker);
        router.withdraw();
        assertEq(worker.balance, bal + 1 ether, "worker claims the credited payout");
        assertEq(address(router).balance, 0, "nothing stranded in the router");
    }

    function test_successfulPushLeavesNoCredit() public {
        vm.prank(REQUESTER);
        uint256 id = router.requestInference{value: 1 ether}(modelId, keccak256("q"), 1 ether);
        uint256 bal = worker.balance;
        router.fulfillInference(id, keccak256("out"), _signReceipt(id, keccak256("out")));
        assertEq(worker.balance, bal + 1 ether);
        assertEq(router.pendingWithdrawals(worker), 0);
    }
}
