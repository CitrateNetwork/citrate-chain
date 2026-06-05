// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, Vm} from "forge-std/Test.sol";

import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// Tests for the secp256k1 ECDSA validator (WP-1 of EW-S1 — the
/// "Validator B" path for gui-native + wallet-extension enrollment).
///
/// vm.sign produces real ECDSA signatures, so every happy path here is
/// a genuine signature-verifies test, not a contrivance.
contract CitrateECDSAValidatorTest is Test {
    using MessageHashUtils for bytes32;

    CitrateECDSAValidator internal validator;
    address internal kernel;
    uint256 internal ownerPk;
    address internal ownerAddr;

    function setUp() public {
        validator = new CitrateECDSAValidator();
        kernel = address(0xACC1);
        ownerPk = 0xA11CE; // deterministic test key
        ownerAddr = vm.addr(ownerPk);
        _install(kernel, ownerAddr, CitrateECDSAValidator.Source.GuiNative);
    }

    // --- Install lifecycle ---

    function test_install_storesOwnerAndEmitsRegistered() public {
        address k2 = address(0xACC2);
        uint64 enabledAt;
        bytes memory data = abi.encodePacked(ownerAddr, uint8(uint256(CitrateECDSAValidator.Source.WalletExtension)));
        vm.recordLogs();
        vm.prank(k2);
        validator.onInstall(data);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertGt(logs.length, 0);

        assertTrue(validator.isInitialized(k2));
        (address owner, CitrateECDSAValidator.Source source, uint64 ts) = validator.ownerOf(k2);
        assertEq(owner, ownerAddr);
        assertEq(uint8(source), uint8(CitrateECDSAValidator.Source.WalletExtension));
        enabledAt = ts;
        assertGt(enabledAt, 0);
    }

    function test_install_rejectsZeroOwner() public {
        address k2 = address(0xACC3);
        bytes memory data = abi.encodePacked(address(0), uint8(0));
        vm.prank(k2);
        vm.expectRevert(CitrateECDSAValidator.InvalidOwner.selector);
        validator.onInstall(data);
    }

    function test_install_rejectsWrongLength() public {
        address k2 = address(0xACC4);
        bytes memory data = abi.encodePacked(ownerAddr); // missing source byte
        vm.prank(k2);
        vm.expectRevert(CitrateECDSAValidator.InvalidInstallData.selector);
        validator.onInstall(data);
    }

    function test_install_rejectsDoubleInstall() public {
        bytes memory data = abi.encodePacked(ownerAddr, uint8(0));
        vm.prank(kernel);
        vm.expectRevert(abi.encodeWithSelector(CitrateECDSAValidator.AlreadyInstalled.selector, kernel));
        validator.onInstall(data);
    }

    function test_install_unknownSourceFallsBackToUnknown() public {
        address k2 = address(0xACC5);
        bytes memory data = abi.encodePacked(ownerAddr, uint8(99));
        vm.prank(k2);
        validator.onInstall(data);
        (, CitrateECDSAValidator.Source source,) = validator.ownerOf(k2);
        assertEq(uint8(source), uint8(CitrateECDSAValidator.Source.Unknown));
    }

    function test_uninstall_clearsState() public {
        vm.prank(kernel);
        validator.onUninstall("");
        assertFalse(validator.isInitialized(kernel));
    }

    function test_uninstall_revertsIfNotInstalled() public {
        address k2 = address(0xACC6);
        vm.prank(k2);
        vm.expectRevert();
        validator.onUninstall("");
    }

    function test_moduleType_advertisesValidatorAndHook() public {
        assertTrue(validator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(validator.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(validator.isModuleType(999));
    }

    // --- validateUserOp ---

    function test_validateUserOp_rawSig_succeeds() public {
        bytes32 userOpHash = keccak256("eth_signed_op");
        bytes memory sig = _sign(ownerPk, userOpHash);
        PackedUserOperation memory op = _opWithSig(sig);

        vm.prank(kernel);
        uint256 result = validator.validateUserOp(op, userOpHash);
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_validateUserOp_ethPrefixedSig_succeeds() public {
        bytes32 userOpHash = keccak256("personal_signed_op");
        bytes32 ethHash = userOpHash.toEthSignedMessageHash();
        bytes memory sig = _sign(ownerPk, ethHash);
        PackedUserOperation memory op = _opWithSig(sig);

        vm.prank(kernel);
        uint256 result = validator.validateUserOp(op, userOpHash);
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_validateUserOp_wrongSigner_fails() public {
        bytes32 userOpHash = keccak256("not_mine");
        uint256 attackerPk = 0xBADBAD;
        bytes memory sig = _sign(attackerPk, userOpHash);
        PackedUserOperation memory op = _opWithSig(sig);

        vm.prank(kernel);
        uint256 result = validator.validateUserOp(op, userOpHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    function test_validateUserOp_tamperedHash_fails() public {
        bytes32 userOpHash = keccak256("legitimate");
        bytes memory sig = _sign(ownerPk, userOpHash);
        PackedUserOperation memory op = _opWithSig(sig);

        bytes32 wrongHash = keccak256("tampered");
        vm.prank(kernel);
        uint256 result = validator.validateUserOp(op, wrongHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    function test_validateUserOp_notInstalled_fails() public {
        address k2 = address(0xACC9);
        bytes32 userOpHash = keccak256("anything");
        bytes memory sig = _sign(ownerPk, userOpHash);
        PackedUserOperation memory op = _opWithSig(sig);

        vm.prank(k2);
        uint256 result = validator.validateUserOp(op, userOpHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    // --- EIP-1271 ---

    function test_isValidSignatureWithSender_rawSig_ok() public {
        bytes32 hash = keccak256("user_payload");
        bytes memory sig = _sign(ownerPk, hash);

        vm.prank(kernel);
        bytes4 res = validator.isValidSignatureWithSender(address(0), hash, sig);
        assertEq(res, ERC1271_MAGICVALUE);
    }

    function test_isValidSignatureWithSender_ethPrefixed_ok() public {
        bytes32 hash = keccak256("user_payload_prefixed");
        bytes32 ethHash = hash.toEthSignedMessageHash();
        bytes memory sig = _sign(ownerPk, ethHash);

        vm.prank(kernel);
        bytes4 res = validator.isValidSignatureWithSender(address(0), hash, sig);
        assertEq(res, ERC1271_MAGICVALUE);
    }

    function test_isValidSignatureWithSender_wrongSigner_invalid() public {
        bytes32 hash = keccak256("payload");
        bytes memory sig = _sign(0xBADBAD, hash);

        vm.prank(kernel);
        bytes4 res = validator.isValidSignatureWithSender(address(0), hash, sig);
        assertEq(res, ERC1271_INVALID);
    }

    function test_isValidSignatureWithSender_notInstalled_invalid() public {
        address k2 = address(0xACC0);
        bytes32 hash = keccak256("payload");
        bytes memory sig = _sign(ownerPk, hash);

        vm.prank(k2);
        bytes4 res = validator.isValidSignatureWithSender(address(0), hash, sig);
        assertEq(res, ERC1271_INVALID);
    }

    // --- Hook trivia ---

    function test_preCheck_returnsEmpty() public {
        bytes memory ret = validator.preCheck(address(0xDEAD), 1 ether, "");
        assertEq(ret.length, 0);
    }

    function test_postCheck_doesNotRevert() public {
        validator.postCheck("");
    }

    // ── Helpers ──

    function _install(address k, address owner, CitrateECDSAValidator.Source src) internal {
        bytes memory data = abi.encodePacked(owner, uint8(uint256(src)));
        vm.prank(k);
        validator.onInstall(data);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _opWithSig(bytes memory sig) internal pure returns (PackedUserOperation memory op) {
        op.signature = sig;
    }
}
