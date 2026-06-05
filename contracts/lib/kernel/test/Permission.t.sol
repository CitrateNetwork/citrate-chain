// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../src/core/ValidationManager.sol";
import "./mock/MockValidatorLib.sol";
import "forge-std/Test.sol";

contract PermissionTest is Test {
    MockValidatorLib validatorLib;

    function setUp() external {
        validatorLib = new MockValidatorLib();
    }

    function testFlagEncode() external {
        PassFlag flag = validatorLib.encodeFlag(true, true);
        assertEq(PassFlag.unwrap(flag), bytes2(0x0003));
        flag = validatorLib.encodeFlag(true, false);
        assertEq(PassFlag.unwrap(flag), bytes2(0x0001));
        flag = validatorLib.encodeFlag(false, true);
        assertEq(PassFlag.unwrap(flag), bytes2(0x0002));
        flag = validatorLib.encodeFlag(false, false);
        assertEq(PassFlag.unwrap(flag), bytes2(0x0000));
    }

    function testDecode() external {
        uint256 nonce = uint256(bytes32(0));
        (ValidationMode vMode, ValidationType vType,) = validatorLib.decodeNonce(nonce);
        assertTrue(vMode == VALIDATION_MODE_DEFAULT, "vMode != MODE_DEFAULT");
        assertTrue(vType == VALIDATION_TYPE_ROOT, "vType != TYPE_VALIDATOR");
    }

    function testDecode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) external {
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, sequencialNonce)));
        (ValidationMode vMode, ValidationType vType, ValidationId vId) = validatorLib.decodeNonce(nonce);
        assertTrue(vMode == ValidationMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidationType.wrap(vtype), "vType != type");
        if (ValidationType.wrap(vtype) == VALIDATION_TYPE_PERMISSION) {
            vIdWithoutType = (vIdWithoutType >> 128) << 128;
        }
        assertTrue(vId == ValidationId.wrap(bytes21(abi.encodePacked(vtype, vIdWithoutType))), "vId != vIdWithoutType");
    }

    function testEncode(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, uint16 nonceKey, uint64 seqNonce) external {
        uint256 encoded = validatorLib.encodeAsNonce(mode, vtype, vIdWithoutType, nonceKey, seqNonce);
        uint256 nonce = uint256(bytes32(abi.encodePacked(mode, vtype, vIdWithoutType, nonceKey, seqNonce)));
        assertEq(bytes32(nonce), bytes32(encoded));

        uint192 encodedAsNonceKey = validatorLib.encodeAsNonceKey(mode, vtype, vIdWithoutType, nonceKey);
        assertEq(nonce >> 64, encodedAsNonceKey);
    }

    function testValidatorLibPermission() public {
        testValidatorLib(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(makeAddr("random")),
            bytes10(0)
        );
    }

    function testValidatorLib(bytes1 mode, bytes1 vtype, bytes20 vIdWithoutType, bytes10 sequencialNonce) public {
        bytes20 expected = vIdWithoutType;
        if (ValidationType.wrap(vtype) == VALIDATION_TYPE_PERMISSION) {
            expected = (expected >> 128) << 128;
        }
        uint16 nonceKey = uint16(bytes2(sequencialNonce));
        uint64 seqNonce = uint64(bytes8(sequencialNonce << 16));
        uint256 encoded = validatorLib.encodeAsNonce(mode, vtype, vIdWithoutType, nonceKey, seqNonce);

        (ValidationMode vMode, ValidationType vType, ValidationId vId) = validatorLib.decodeNonce(encoded);
        assertTrue(vMode == ValidationMode.wrap(mode), "vMode != mode");
        assertTrue(vType == ValidationType.wrap(vtype), "vType != type");
        assertTrue(vId == ValidationId.wrap(bytes21(abi.encodePacked(vtype, expected))), "vId != vIdWithoutType");

        if (ValidationType.wrap(vtype) == VALIDATION_TYPE_VALIDATOR) {
            IValidator v = validatorLib.getValidator(vId);
            assertEq(address(v), address(vIdWithoutType), "v != vIdWithoutType");
            ValidationId vid = validatorLib.validatorToIdentifier(v);
            assertTrue(
                vid == ValidationId.wrap(bytes21(abi.encodePacked(VALIDATION_TYPE_VALIDATOR, vIdWithoutType))),
                "vid != vIdWithoutType"
            );
        } else if (ValidationType.wrap(vtype) == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = validatorLib.getPermissionId(vId);
            assertEq(bytes20(abi.encodePacked(PermissionId.unwrap(pId), bytes16(0))), expected);
        }

        ValidationType vt = validatorLib.getType(vId);
        assertTrue(vt == ValidationType.wrap(vtype), "vt != vtype");
    }
}
