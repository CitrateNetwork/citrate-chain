pragma solidity ^0.8.0;

import "../../src/core/ValidationManager.sol";
import "forge-std/Test.sol";

contract MockValidatorLib {
    function encodeFlag(bool skipUserOp, bool skipSignature) external pure returns (PassFlag flag) {
        return ValidatorLib.encodeFlag(skipUserOp, skipSignature);
    }

    function encodeAsNonce(
        bytes1 mode,
        bytes1 vType,
        bytes20 validatorIdentifierWithoutType,
        uint16 nonceKey,
        uint64 nonce
    ) external pure returns (uint256 res) {
        return ValidatorLib.encodeAsNonce(mode, vType, validatorIdentifierWithoutType, nonceKey, nonce);
    }

    function encodeAsNonceKey(bytes1 mode, bytes1 vType, bytes20 validatorIdentifierWithoutType, uint16 nonceKey)
        external
        pure
        returns (uint192 res)
    {
        return ValidatorLib.encodeAsNonceKey(mode, vType, validatorIdentifierWithoutType, nonceKey);
    }

    function decodeNonce(uint256 nonce)
        external
        pure
        returns (ValidationMode mode, ValidationType vType, ValidationId identifier)
    {
        return ValidatorLib.decodeNonce(nonce);
    }

    function validatorToIdentifier(IValidator validator) external pure returns (ValidationId vId) {
        return ValidatorLib.validatorToIdentifier(validator);
    }

    function getType(ValidationId validator) external pure returns (ValidationType vType) {
        return ValidatorLib.getType(validator);
    }

    function getValidator(ValidationId validator) external pure returns (IValidator v) {
        return ValidatorLib.getValidator(validator);
    }

    function getPolicy(PolicyData data) external pure returns (IPolicy vId) {
        return ValidatorLib.getPolicy(data);
    }

    function getPermissionId(ValidationId validation) external pure returns (PermissionId vId) {
        return ValidatorLib.getPermissionId(validation);
    }
}
