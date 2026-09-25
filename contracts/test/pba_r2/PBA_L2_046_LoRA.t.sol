// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {LoRAFactory} from "../../src/LoRAFactory.sol";
import {IModelRegistry} from "../../src/interfaces/IModelRegistry.sol";

/// Priced base model: `requestInference` enforces the FULL price and a
/// per-caller permission, exactly like ModelRegistry.
contract PricedRegistry is IModelRegistry {
    address public owner_ = address(0x0DE1);
    uint256 public price = 1 ether;
    mapping(address => bool) public perm;

    function setPerm(address u) external {
        perm[u] = true;
    }

    function registerModel(string memory, string memory, string memory, string memory, uint256, uint256, ModelMetadata memory)
        external
        payable
        returns (bytes32)
    {
        return bytes32(uint256(0xBEEF));
    }

    function requestInference(bytes32, bytes calldata) external payable returns (bytes memory) {
        require(msg.value >= price, "Insufficient payment");
        require(perm[msg.sender] || msg.sender == owner_, "No permission");
        return "";
    }

    function hasPermission(bytes32, address u) external view returns (bool) {
        return perm[u] || u == owner_;
    }

    function getModel(bytes32)
        external
        view
        returns (address, string memory, string memory, string memory, string memory, uint256, uint256, bool)
    {
        return (owner_, "", "", "", "", price, 0, true);
    }
}

contract LoraPrecompileStub {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

/// Regression for PBA-L2-046 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_046_Regression is Test {
    function _create(bytes memory initCode) internal returns (address a) {
        assembly {
            a := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(a != address(0), "create failed");
    }

    function test_L2_046_inferWithLoRA_worksForPricedModel_andSplitsPayment() public {
        PricedRegistry reg = new PricedRegistry();
        LoRAFactory f = LoRAFactory(
            payable(_create(abi.encodePacked(type(LoRAFactory).creationCode, abi.encode(address(reg), address(this)))))
        );
        vm.etch(address(0x1001), type(LoraPrecompileStub).runtimeCode);
        address creator = makeAddr("creator");
        vm.deal(creator, 10 ether);
        LoRAFactory.TrainingConfig memory cfg = LoRAFactory.TrainingConfig({
            epochs: 1, batchSize: 1, learningRate: 1e16, datasetCID: "ipfs://stub", datasetSize: 1, validationSplit: 1000
        });
        reg.setPerm(creator);
        vm.prank(creator);
        bytes32 lora = f.createLoRA{value: 0.01 ether}(bytes32(uint256(0xBEEF)), "a", "d", 8, 16, 500, cfg);
        f.completeTraining(lora, "ipfs://w");

        uint256 ownerBefore = reg.owner_().balance;
        uint256 creatorBefore = creator.balance;
        vm.prank(creator);
        try f.inferWithLoRA{value: 1.5 ether}(bytes32(uint256(0xBEEF)), lora, hex"00") {} catch {}
        assertEq(reg.owner_().balance - ownerBefore, 0.8 ether, "base-model owner paid 80%");
        // creator paid 1.5, received 0.2 (LoRA share) + 0.5 refund
        assertEq(creatorBefore - creator.balance, 0.8 ether, "creator net cost = model share only");
        assertEq(address(f).balance, 0.01 ether, "only the training fee stays in the factory");
    }
}
