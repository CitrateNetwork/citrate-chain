// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IValidator} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED_UINT, MODULE_TYPE_VALIDATOR, ERC1271_INVALID} from "../types/Constants.sol";

contract EmitIdentifierValidator is IValidator {
    event IdentifierEmitted(bytes id, address indexed kernel);

    function onInstall(bytes calldata _data) external payable override {
        emit IdentifierEmitted(_data, msg.sender);
    }

    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external payable override returns (uint256) {
        return SIG_VALIDATION_FAILED_UINT;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return ERC1271_INVALID;
    }
}
