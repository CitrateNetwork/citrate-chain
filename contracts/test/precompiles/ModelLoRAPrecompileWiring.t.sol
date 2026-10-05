// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ModelRegistry} from "../../src/ModelRegistry.sol";
import {LoRAFactory} from "../../src/LoRAFactory.sol";
import {ModelAccessControl} from "../../src/ModelAccessControl.sol";
import {IModelRegistry} from "../../src/interfaces/IModelRegistry.sol";
import {CitratePrecompiles} from "../../src/lib/CitratePrecompiles.sol";

/// Stand-in for a node that serves 0x0101 to contract code: echoes the input
/// after the 52-byte (model_id || caller) header, prefixed with "out:".
contract InferenceStandIn {
    fallback(bytes calldata input) external returns (bytes memory) {
        require(input.length >= 52, "native layout");
        return bytes.concat(bytes("out:"), input[52:]);
    }
}

/// HUP-S7.2: the model and LoRA contracts integrate with precompiles through
/// `CitratePrecompiles` (native layouts, fail closed). Registration, training
/// and merge requests are records plus events and make no precompile call;
/// inference goes to 0x0101 and, on a chain without it (forge's EVM here, like
/// anvil and like a Citrate node that does not serve inference to contracts),
/// reverts with `PrecompileUnavailable` and moves no value.
contract ModelLoRAPrecompileWiringTest is Test {
    address internal constant UNASSIGNED_1000 = address(0x1000);
    address internal constant UNASSIGNED_1001 = address(0x1001);
    address internal constant UNASSIGNED_1002 = address(0x1002);

    ModelRegistry internal registry;
    LoRAFactory internal factory;
    address internal owner = makeAddr("modelOwner");
    address internal creator = makeAddr("loraCreator");
    address internal user = makeAddr("user");

    function setUp() public {
        registry = new ModelRegistry(address(this));
        factory = new LoRAFactory(address(registry), address(this));
        vm.deal(owner, 100 ether);
        vm.deal(creator, 100 ether);
        vm.deal(user, 100 ether);
    }

    function _meta() internal pure returns (IModelRegistry.ModelMetadata memory m) {
        m = IModelRegistry.ModelMetadata({
            description: "d",
            inputShape: new string[](0),
            outputShape: new string[](0),
            parameters: 1,
            license: "Apache-2.0",
            tags: new string[](0)
        });
    }

    function _register(uint256 price) internal returns (bytes32 h) {
        vm.prank(owner);
        h = registry.registerModel{value: 0.1 ether}("M", "F", "1", "cid", 1, price, _meta());
    }

    function _cfg() internal pure returns (LoRAFactory.TrainingConfig memory) {
        return LoRAFactory.TrainingConfig({
            epochs: 1, batchSize: 1, learningRate: 1e16, datasetCID: "ipfs://d", datasetSize: 1, validationSplit: 1000
        });
    }

    function _lora(bytes32 base) internal returns (bytes32 lora) {
        vm.prank(owner);
        registry.grantPermission(base, creator);
        vm.prank(creator);
        lora = factory.createLoRA{value: 0.01 ether}(base, "a", "d", 8, 16, 0, _cfg());
        factory.completeTraining(lora, "ipfs://w");
        vm.prank(creator);
        factory.setPublicStatus(lora, true);
    }

    // ── Registration / training / merge: no phantom precompile calls ──

    function test_registerAndUpdateModel_makeNoPrecompileCall() public {
        vm.expectCall(UNASSIGNED_1000, "", 0);
        vm.expectCall(UNASSIGNED_1002, "", 0);
        bytes32 h = _register(0);
        vm.prank(owner);
        registry.updateModel(h, "2", "cid2");
    }

    function test_createLoRA_andMerge_makeNoPrecompileCall() public {
        bytes32 base = _register(0);
        vm.expectCall(UNASSIGNED_1001, "", 0);
        bytes32 a = _lora(base);
        bytes32 b = _lora(base);
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = a;
        hashes[1] = b;
        uint256[] memory weights = new uint256[](2);
        weights[0] = 0.5e18;
        weights[1] = 0.5e18;
        vm.prank(creator);
        vm.expectEmit(false, false, false, false);
        emit LoRAFactory.MergeRequested(bytes32(0), hashes, weights, 0, creator);
        bytes32 req = factory.mergeLoRAs{value: 0.05 ether}(hashes, weights, 0);
        // The merge is done off chain and recorded by the operator, as before.
        factory.completeMerge(req, "ipfs://merged");
        (,,, bool completed, string memory cid) = factory.getMergeRequest(req);
        assertTrue(completed);
        assertEq(cid, "ipfs://merged");
    }

    // ── Inference: fail closed, no value moves ──

    function test_requestInference_failsClosedWithoutInferencePrecompile() public {
        bytes32 h = _register(0);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileUnavailable.selector, address(0x0101)));
        registry.requestInference(h, hex"00");
    }

    function test_pricedRequestInference_movesNoMoneyWhenItFails() public {
        bytes32 h = _register(1 ether);
        vm.prank(owner);
        registry.grantPermission(h, user);
        uint256 ownerBefore = owner.balance;
        uint256 userBefore = user.balance;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileUnavailable.selector, address(0x0101)));
        registry.requestInference{value: 1 ether}(h, hex"00");
        assertEq(owner.balance, ownerBefore);
        assertEq(user.balance, userBefore);
    }

    function test_inferWithLoRA_failsClosedAndMovesNoValue() public {
        bytes32 base = _register(1 ether);
        bytes32 lora = _lora(base);
        vm.prank(owner);
        registry.grantPermission(base, user);
        uint256 ownerBefore = owner.balance;
        uint256 creatorBefore = creator.balance;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileUnavailable.selector, address(0x0101)));
        factory.inferWithLoRA{value: 1 ether}(base, lora, hex"00");
        assertEq(owner.balance, ownerBefore, "base-model owner unpaid");
        assertEq(creator.balance, creatorBefore, "adapter creator unpaid");
    }

    function test_modelAccessControl_inferenceFailsClosed() public {
        ModelAccessControl mac = new ModelAccessControl(address(this));
        bytes32 mid = keccak256("m");
        vm.prank(owner);
        mac.registerModel(mid, "cid", false, 0);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileUnavailable.selector, address(0x0101)));
        mac.executeInference(mid, hex"00");
    }

    function test_modelAccessControl_encryptedInferenceFailsClosed() public {
        ModelAccessControl mac = new ModelAccessControl(address(this));
        bytes32 mid = keccak256("enc");
        vm.prank(owner);
        mac.registerModel(mid, "cid", true, 0);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileUnavailable.selector, address(0x0106)));
        mac.executeEncryptedInference(mid, hex"00", bytes32(0));
    }

    // ── Where a node does serve 0x0101, the native layout reaches it ──

    function test_servedInference_receivesNativeLayoutAndReturnsRawOutput() public {
        vm.etch(address(0x0101), type(InferenceStandIn).runtimeCode);
        bytes32 h = _register(0);
        vm.expectCall(address(0x0101), abi.encodePacked(h, user, hex"AABB"));
        vm.prank(user);
        bytes memory out = registry.requestInference(h, hex"AABB");
        assertEq(out, bytes.concat(bytes("out:"), hex"AABB"));
    }

    function test_servedLoRAInference_addressesTheAdapter() public {
        vm.etch(address(0x0101), type(InferenceStandIn).runtimeCode);
        bytes32 base = _register(0);
        bytes32 lora = _lora(base);
        vm.expectCall(address(0x0101), abi.encodePacked(lora, user, hex"01"));
        vm.prank(user);
        bytes memory out = factory.inferWithLoRA(base, lora, hex"01");
        assertEq(out, bytes.concat(bytes("out:"), hex"01"));
    }
}
