// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LoRAFactory} from "../../src/LoRAFactory.sol";
import {IModelRegistry} from "../../src/interfaces/IModelRegistry.sol";
import {PricedRegistry, LoraPrecompileStub} from "./PBA_L2_046_LoRA.t.sol";

/// Mutation hardening (PBA-L2-046): the CALLER's base-model permission gates a
/// priced inference (the factory's own permission no longer matters).
contract PBA_L2_046_Permission is Test {
    function test_L2_046_callerWithoutBasePermissionRefused() public {
        PricedRegistry reg = new PricedRegistry();
        LoRAFactory f = new LoRAFactory(address(reg), address(this));
        vm.etch(address(0x1001), type(LoraPrecompileStub).runtimeCode);
        address creator = makeAddr("creator");
        vm.deal(creator, 10 ether);
        reg.setPerm(creator);
        LoRAFactory.TrainingConfig memory cfg = LoRAFactory.TrainingConfig({
            epochs: 1, batchSize: 1, learningRate: 1e16, datasetCID: "ipfs://stub", datasetSize: 1, validationSplit: 1000
        });
        vm.prank(creator);
        bytes32 lora = f.createLoRA{value: 0.01 ether}(bytes32(uint256(0xBEEF)), "a", "d", 8, 16, 500, cfg);
        f.completeTraining(lora, "ipfs://w");
        vm.prank(creator);
        f.setPublicStatus(lora, true);
        address user = makeAddr("user"); // public adapter, but no base-model permission
        vm.deal(user, 2 ether);
        vm.prank(user);
        vm.expectRevert("No base model permission");
        f.inferWithLoRA{value: 1 ether}(bytes32(uint256(0xBEEF)), lora, hex"00");
    }
}
