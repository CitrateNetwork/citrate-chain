// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation as AaPackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";

import {GuardianRecoveryModuleV2, IGuardianRecoveryModuleV1} from "../../src/aa/recovery/GuardianRecoveryModuleV2.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";

/// An EIP-1271 guardian (smart wallet) that accepts an ECDSA signature by its owner over the raw digest.
contract V2SmartWalletGuardian {
    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        if (sig.length != 65) return 0xffffffff;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(hash, v, r, s) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// Shared helpers: guardian keys, install bytes, rotation callData, signing.
abstract contract GuardianV2Base is Test {
    using MessageHashUtils for bytes32;

    uint256 internal constant PK_A = 0xA;
    uint256 internal constant PK_B = 0xB;
    uint256 internal constant PK_C = 0xC;
    uint256 internal constant PK_OTHER = 0xDEAD;

    uint48 internal constant DELAY = 72 hours;

    GuardianRecoveryModuleV2 internal module;

    function _threeGuardians() internal pure returns (address[] memory g) {
        g = new address[](3);
        g[0] = vm.addr(PK_A);
        g[1] = vm.addr(PK_B);
        g[2] = vm.addr(PK_C);
    }

    function _installBytes(uint8 threshold, address[] memory g) internal pure returns (bytes memory packed) {
        packed = abi.encodePacked(threshold, uint8(g.length));
        for (uint256 i = 0; i < g.length; i++) {
            packed = abi.encodePacked(packed, g[i]);
        }
    }

    function _rotateCallData(address account, bytes32 salt) internal pure returns (bytes memory) {
        bytes memory inner = abi.encodeWithSignature(
            "changeRootValidator(bytes21,address,bytes,bytes)",
            bytes21(0),
            address(0),
            abi.encodePacked(salt),
            bytes("")
        );
        return
            abi.encodeWithSignature("execute(bytes32,bytes)", bytes32(0), abi.encodePacked(account, uint256(0), inner));
    }

    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    /// EOA guardian signature over the module's initiation digest (EIP-191 form).
    function _initSig(uint256 pk, address account, bytes memory callData, uint64 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 d = module.recoveryDigest(account, keccak256(callData), nonce);
        return _sign(pk, d.toEthSignedMessageHash());
    }

    function _quorum(address account, bytes memory callData) internal view returns (bytes memory) {
        uint64 n = module.recoveryNonce(account);
        return bytes.concat(_initSig(PK_A, account, callData, n), _initSig(PK_B, account, callData, n));
    }

    /// The execution-phase guardian signature: keccak256(userOpHash ‖ account), EIP-191.
    function _execSig(uint256 pk, bytes32 userOpHash, address account) internal pure returns (bytes memory) {
        return _sign(pk, keccak256(abi.encodePacked(userOpHash, account)).toEthSignedMessageHash());
    }
}

/// Unit tests against a stand-in account address (the module is called with msg.sender = account).
contract GuardianRecoveryModuleV2Test is GuardianV2Base {
    address internal kernel = address(0xCAFEBABE);
    bytes32 internal constant OP_HASH = keccak256("v2-op");

    event RecoveryInitiated(
        address indexed account, uint64 indexed nonce, bytes32 callDataHash, uint48 executeAfter, bytes callData
    );
    event RecoverySuperseded(address indexed account, uint64 indexed nonce, bytes32 callDataHash);
    event RecoveryCancelled(address indexed account, uint64 indexed nonce, bytes32 callDataHash);
    event RecoveryExecuted(address indexed account, uint64 indexed nonce, bytes32 callDataHash);

    function setUp() public {
        module = new GuardianRecoveryModuleV2(IGuardianRecoveryModuleV1(address(new GuardianRecoveryModule())));
        vm.warp(1_700_000_000);
    }

    function _install(address k) internal {
        vm.prank(k);
        module.onInstall(_installBytes(2, _threeGuardians()));
    }

    function _initiate(address k, bytes memory cd) internal returns (uint48) {
        return module.initiateRecovery(k, cd, _quorum(k, cd));
    }

    function _op(bytes memory cd, bytes memory sig) internal pure returns (PackedUserOperation memory op) {
        op.callData = cd;
        op.signature = sig;
    }

    function _validate(address k, bytes memory cd) internal returns (uint256) {
        vm.prank(k);
        return module.validateUserOp(_op(cd, _execSig(PK_C, OP_HASH, k)), OP_HASH);
    }

    // ── constants and module surface ────────────────────────────────

    function test_delay_is_72_hours_constant() public view {
        assertEq(uint256(module.RECOVERY_DELAY()), 72 hours);
    }

    function test_moduleType_validatorAndHook() public view {
        assertTrue(module.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(module.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(module.isModuleType(123));
    }

    function test_isValidSignatureWithSender_alwaysInvalid() public view {
        assertEq(module.isValidSignatureWithSender(kernel, bytes32(0), ""), ERC1271_INVALID);
    }

    // ── install lifecycle (V1 parity) ───────────────────────────────

    function test_install_storesConfig() public {
        _install(kernel);
        assertTrue(module.isInitialized(kernel));
        (uint8 t, address[] memory g) = module.configOf(kernel);
        assertEq(t, 2);
        assertEq(g.length, 3);
        assertEq(g[2], vm.addr(PK_C));
    }

    function test_install_rejectsBadShapes() public {
        address[] memory one = new address[](1);
        one[0] = vm.addr(PK_A);
        vm.startPrank(kernel);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianCount.selector);
        module.onInstall(_installBytes(1, one));
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidThreshold.selector);
        module.onInstall(_installBytes(0, _threeGuardians()));
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidThreshold.selector);
        module.onInstall(_installBytes(4, _threeGuardians()));
        address[] memory dup = _threeGuardians();
        dup[2] = dup[0];
        vm.expectRevert(GuardianRecoveryModuleV2.DuplicateGuardian.selector);
        module.onInstall(_installBytes(2, dup));
        address[] memory zero = _threeGuardians();
        zero[1] = address(0);
        vm.expectRevert(GuardianRecoveryModuleV2.ZeroGuardian.selector);
        module.onInstall(_installBytes(2, zero));
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidInstallData.selector);
        module.onInstall(abi.encodePacked(uint8(2), uint8(3), vm.addr(PK_A), vm.addr(PK_B)));
        vm.stopPrank();
    }

    function test_install_rejectsDoubleInstall() public {
        _install(kernel);
        vm.prank(kernel);
        vm.expectRevert(abi.encodeWithSelector(GuardianRecoveryModuleV2.AlreadyInstalled.selector, kernel));
        module.onInstall(_installBytes(2, _threeGuardians()));
    }

    // ── phase 1: initiate ───────────────────────────────────────────

    function test_initiate_recordsPendingWith72hDelay() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        vm.expectEmit(true, true, false, true, address(module));
        emit RecoveryInitiated(kernel, 0, keccak256(cd), uint48(block.timestamp) + DELAY, cd);
        uint48 ea = _initiate(kernel, cd);
        assertEq(ea, uint48(block.timestamp) + DELAY);
        (bytes32 h, uint48 got, uint64 n) = module.pendingRecovery(kernel);
        assertEq(h, keccak256(cd));
        assertEq(got, ea);
        assertEq(n, 0);
        assertEq(module.recoveryNonce(kernel), 1);
    }

    function test_initiate_isPermissionlessSubmission() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        vm.prank(address(0xB0B)); // anyone may relay the guardians' signatures
        module.initiateRecovery(kernel, cd, sigs);
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertGt(ea, 0);
    }

    function test_initiate_rejectsNotInstalled() public {
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        vm.expectRevert(abi.encodeWithSignature("NotInitialized(address)", kernel));
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsBelowThreshold() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory one = _initSig(PK_A, kernel, cd, 0);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, one);
    }

    function test_initiate_rejectsDuplicateGuardianSig() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory a = _initSig(PK_A, kernel, cd, 0);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, bytes.concat(a, a));
    }

    function test_initiate_rejectsNonGuardian() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = bytes.concat(_initSig(PK_A, kernel, cd, 0), _initSig(PK_OTHER, kernel, cd, 0));
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsRawDigestEoaSignature() public {
        // FWA-C3-06 parity: an EOA signature over the un-prefixed digest is not accepted.
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes32 d = module.recoveryDigest(kernel, keccak256(cd), 0);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, bytes.concat(_sign(PK_A, d), _sign(PK_B, d)));
    }

    function test_initiate_rejectsSignaturesForAnotherAccount() public {
        address other = address(0xD15EA5E);
        _install(kernel);
        _install(other);
        bytes memory cd = _rotateCallData(kernel, "k1");
        // Guardians signed for `other` (same callData bytes); replay onto `kernel` must fail.
        bytes memory sigs = bytes.concat(_initSig(PK_A, other, cd, 0), _initSig(PK_B, other, cd, 0));
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsWrongChain() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        vm.chainId(1);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsSignaturesForDifferentCallData() public {
        _install(kernel);
        bytes memory signedFor = _rotateCallData(kernel, "k1");
        bytes memory submitted = _rotateCallData(kernel, "attacker-key");
        bytes memory sigs = _quorum(kernel, signedFor);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, submitted, sigs);
    }

    function test_initiate_rejectsNonAllowlistedCallData_transfer() public {
        _install(kernel);
        bytes memory cd = abi.encodeWithSignature(
            "execute(bytes32,bytes)", bytes32(0), abi.encodePacked(address(0xBAD), uint256(1 ether), bytes(""))
        );
        bytes memory sigs = _quorum(kernel, cd);
        vm.expectRevert(GuardianRecoveryModuleV2.RecoveryActionNotAllowed.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsNonAllowlistedCallData_delegatecall() public {
        _install(kernel);
        bytes memory inner = abi.encodeWithSignature(
            "changeRootValidator(bytes21,address,bytes,bytes)", bytes21(0), address(0), bytes(""), bytes("")
        );
        bytes memory cd = abi.encodeWithSignature(
            "execute(bytes32,bytes)", bytes32(uint256(0xff) << 248), abi.encodePacked(kernel, uint256(0), inner)
        );
        bytes memory sigs = _quorum(kernel, cd);
        vm.expectRevert(GuardianRecoveryModuleV2.RecoveryActionNotAllowed.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsNonAllowlistedCallData_otherTarget() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(address(0xD15EA5E), "k1"); // rotation of someone else
        bytes memory sigs = _quorum(kernel, cd);
        vm.expectRevert(GuardianRecoveryModuleV2.RecoveryActionNotAllowed.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_rejectsMalformedOffset() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        assembly {
            mstore(add(cd, 68), not(0)) // offset word = 2^256-1
        }
        bytes memory sigs = _quorum(kernel, cd);
        vm.expectRevert(GuardianRecoveryModuleV2.RecoveryActionNotAllowed.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_replayAfterCancel_fails() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        module.initiateRecovery(kernel, cd, sigs);
        vm.prank(kernel);
        module.cancelRecovery();
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_replayAfterExecute_fails() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        module.initiateRecovery(kernel, cd, sigs);
        assertEq(_validate(kernel, cd) & 1, 0);
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_replayAfterReinstall_fails() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        module.initiateRecovery(kernel, cd, sigs);
        vm.prank(kernel);
        module.onUninstall("");
        _install(kernel);
        assertEq(module.recoveryNonce(kernel), 1, "nonce survives uninstall");
        vm.expectRevert(GuardianRecoveryModuleV2.InvalidGuardianSignatures.selector);
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_initiate_supersedesPendingAndRestartsClock() public {
        _install(kernel);
        bytes memory cd1 = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd1);
        vm.warp(block.timestamp + 70 hours);
        bytes memory cd2 = _rotateCallData(kernel, "k2");
        vm.expectEmit(true, true, false, true, address(module));
        emit RecoverySuperseded(kernel, 0, keccak256(cd1));
        uint48 ea2 = _initiate(kernel, cd2);
        assertEq(ea2, uint48(block.timestamp) + DELAY);
        (bytes32 h, uint48 ea, uint64 n) = module.pendingRecovery(kernel);
        assertEq(h, keccak256(cd2));
        assertEq(ea, ea2);
        assertEq(n, 1);
        // the superseded rotation no longer validates
        assertEq(_validate(kernel, cd1), SIG_VALIDATION_FAILED_UINT);
    }

    function test_initiate_by1271Guardian() public {
        V2SmartWalletGuardian sw = new V2SmartWalletGuardian(vm.addr(PK_OTHER));
        address[] memory g = new address[](3);
        g[0] = vm.addr(PK_A);
        g[1] = address(sw);
        g[2] = vm.addr(PK_C);
        vm.prank(kernel);
        module.onInstall(_installBytes(2, g));
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes32 d = module.recoveryDigest(kernel, keccak256(cd), 0);
        // contract guardian signs the RAW digest (its owner key), EOA signs the EIP-191 form
        bytes memory sigs = bytes.concat(_initSig(PK_A, kernel, cd, 0), _sign(PK_OTHER, d));
        module.initiateRecovery(kernel, cd, sigs);
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertEq(ea, uint48(block.timestamp) + DELAY);
    }

    // ── owner Q19 (2026-11-09): V2 never works alongside V1 ─────────

    function _installV1(address k) internal {
        vm.prank(k);
        GuardianRecoveryModule(address(module.v1())).onInstall(_installBytes(2, _threeGuardians()));
    }

    function test_constructor_rejectsV1WithoutCode() public {
        vm.expectRevert(GuardianRecoveryModuleV2.V1HasNoCode.selector);
        new GuardianRecoveryModuleV2(IGuardianRecoveryModuleV1(address(0xBEEF)));
    }

    function test_install_refusedWhileV1Installed() public {
        _installV1(kernel);
        vm.prank(kernel);
        vm.expectRevert(abi.encodeWithSelector(GuardianRecoveryModuleV2.V1StillInstalled.selector, kernel));
        module.onInstall(_installBytes(2, _threeGuardians()));
    }

    function test_install_allowedAfterV1Uninstalled() public {
        _installV1(kernel);
        vm.prank(kernel);
        GuardianRecoveryModule(address(module.v1())).onUninstall("");
        _install(kernel);
        assertTrue(module.isInitialized(kernel));
    }

    /// Reverse order: V1 installed after V2. V2 cannot block V1's install, so it refuses to act.
    function test_initiate_refusedWhileV1InstalledAfterV2() public {
        _install(kernel);
        _installV1(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        bytes memory sigs = _quorum(kernel, cd);
        vm.expectRevert(abi.encodeWithSelector(GuardianRecoveryModuleV2.V1StillInstalled.selector, kernel));
        module.initiateRecovery(kernel, cd, sigs);
    }

    function test_validate_failsWhileV1InstalledAfterV2() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        _installV1(kernel);
        assertEq(_validate(kernel, cd), SIG_VALIDATION_FAILED_UINT);
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertGt(ea, 0, "not consumed while refused");
    }

    // ── owner Q20 (2026-11-09): the execution-op signer is an EOA guardian ──

    function test_validate_rejects1271ExecutionSigner() public {
        V2SmartWalletGuardian sw = new V2SmartWalletGuardian(vm.addr(PK_OTHER));
        address[] memory g = new address[](3);
        g[0] = vm.addr(PK_A);
        g[1] = vm.addr(PK_B);
        g[2] = address(sw);
        vm.prank(kernel);
        module.onInstall(_installBytes(2, g));
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        // the smart-wallet guardian's owner signs the raw execution digest (the 1271 convention)
        bytes memory raw = _sign(PK_OTHER, keccak256(abi.encodePacked(OP_HASH, kernel)));
        vm.prank(kernel);
        assertEq(module.validateUserOp(_op(cd, raw), OP_HASH), SIG_VALIDATION_FAILED_UINT, "1271 signer refused");
        // an EOA guardian still executes
        vm.prank(kernel);
        uint256 vd = module.validateUserOp(_op(cd, _execSig(PK_A, OP_HASH, kernel)), OP_HASH);
        assertEq(vd & 1, 0);
    }

    // ── phase 2: validate ───────────────────────────────────────────

    function test_validate_returnsValidAfterEqualToExecuteAfter() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        uint48 ea = _initiate(kernel, cd);
        vm.expectEmit(true, true, false, true, address(module));
        emit RecoveryExecuted(kernel, 0, keccak256(cd));
        uint256 vd = _validate(kernel, cd);
        assertEq(vd & 1, 0, "sig ok");
        assertEq(uint48(vd >> 160), 0, "no validUntil");
        assertEq(uint48(vd >> 208), ea, "validAfter = executeAfter");
        (, uint48 left,) = module.pendingRecovery(kernel);
        assertEq(left, 0, "consumed");
    }

    function test_validate_failsWithoutPending() public {
        _install(kernel);
        assertEq(_validate(kernel, _rotateCallData(kernel, "k1")), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_failsWhenNotInstalled() public {
        assertEq(_validate(kernel, _rotateCallData(kernel, "k1")), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_failsOnCallDataMismatch() public {
        _install(kernel);
        _initiate(kernel, _rotateCallData(kernel, "k1"));
        assertEq(_validate(kernel, _rotateCallData(kernel, "k2")), SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_requiresAGuardianExecutionSignature() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        vm.startPrank(kernel);
        assertEq(module.validateUserOp(_op(cd, ""), OP_HASH), SIG_VALIDATION_FAILED_UINT, "no signature");
        assertEq(
            module.validateUserOp(_op(cd, _execSig(PK_OTHER, OP_HASH, kernel)), OP_HASH),
            SIG_VALIDATION_FAILED_UINT,
            "non-guardian"
        );
        assertEq(
            module.validateUserOp(_op(cd, _execSig(PK_A, keccak256("other-op"), kernel)), OP_HASH),
            SIG_VALIDATION_FAILED_UINT,
            "signature over another op"
        );
        vm.stopPrank();
    }

    function test_validate_isPerAccount() public {
        address other = address(0xD15EA5E);
        _install(kernel);
        _install(other);
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        // `other` has nothing pending; kernel's pending cannot be consumed through other.
        assertEq(_validate(other, cd), SIG_VALIDATION_FAILED_UINT);
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertGt(ea, 0);
    }

    function test_validate_consumesPending() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        assertEq(_validate(kernel, cd) & 1, 0);
        assertEq(_validate(kernel, cd), SIG_VALIDATION_FAILED_UINT, "second use fails");
    }

    // ── cancel ──────────────────────────────────────────────────────

    function test_owner_cancels() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        vm.expectEmit(true, true, false, true, address(module));
        emit RecoveryCancelled(kernel, 0, keccak256(cd));
        vm.prank(kernel);
        module.cancelRecovery();
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertEq(ea, 0);
        vm.warp(block.timestamp + DELAY + 1);
        assertEq(_validate(kernel, cd), SIG_VALIDATION_FAILED_UINT, "cancelled recovery never validates");
    }

    function test_cancel_onlyByTheAccountItself() public {
        _install(kernel);
        _initiate(kernel, _rotateCallData(kernel, "k1"));
        vm.prank(vm.addr(PK_A)); // a guardian cannot cancel on the account's behalf
        vm.expectRevert(GuardianRecoveryModuleV2.NoPendingRecovery.selector);
        module.cancelRecovery();
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertGt(ea, 0);
    }

    function test_cancel_revertsWithoutPending() public {
        _install(kernel);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModuleV2.NoPendingRecovery.selector);
        module.cancelRecovery();
    }

    function test_uninstall_clearsPending() public {
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        _initiate(kernel, cd);
        vm.prank(kernel);
        module.onUninstall("");
        assertFalse(module.isInitialized(kernel));
        (, uint48 ea,) = module.pendingRecovery(kernel);
        assertEq(ea, 0);
        _install(kernel);
        assertEq(_validate(kernel, cd), SIG_VALIDATION_FAILED_UINT);
    }

    // ── fuzz ────────────────────────────────────────────────────────

    function testFuzz_executeAfterIsInitiationPlus72h(uint32 start) public {
        vm.warp(uint256(start) + 1);
        _install(kernel);
        bytes memory cd = _rotateCallData(kernel, "k1");
        uint48 ea = _initiate(kernel, cd);
        assertEq(ea, uint48(block.timestamp) + DELAY);
        assertEq(uint48(_validate(kernel, cd) >> 208), ea);
    }

    function testFuzz_initiate_rejectsArbitraryCallData(bytes calldata cd) public {
        _install(kernel);
        vm.assume(keccak256(cd) != keccak256(_rotateCallData(kernel, "k1")));
        // Anything that is not a self-rotation either fails the allowlist or the signature check.
        bytes memory sigs = _quorum(kernel, _rotateCallData(kernel, "k1"));
        vm.expectRevert();
        module.initiateRecovery(kernel, cd, sigs);
    }
}

/// End to end through the real EntryPoint v0.7 and a factory-deployed CitrateWallet (Kernel v3),
/// the same fixture as GuardianRecoveryE2E.t.sol with V2 installed instead of V1.
contract GuardianRecoveryModuleV2E2ETest is GuardianV2Base {
    using MessageHashUtils for bytes32;

    uint256 internal constant IDENTITY_PK = 0x59E7;
    uint256 internal constant OLD_OWNER_PK = 0xA11A;
    uint256 internal constant NEW_OWNER_PK = 0xB22B;
    bytes32 internal constant USER_ID = keccak256("recovery-v2-e2e-user");

    EntryPoint internal entryPoint;
    CitrateWalletFactory internal factory;
    CitrateECDSAValidator internal ecdsaValidator;
    CitrateECDSAValidator internal newValidator;
    address payable internal wallet;
    address payable internal beneficiary = payable(address(0xFEE));

    function setUp() public {
        vm.warp(1_700_000_000);
        entryPoint = new EntryPoint();
        CitrateWallet impl = new CitrateWallet(IKernelEntryPoint(address(entryPoint)));
        ecdsaValidator = new CitrateECDSAValidator();
        newValidator = new CitrateECDSAValidator();
        module = new GuardianRecoveryModuleV2(IGuardianRecoveryModuleV1(address(new GuardianRecoveryModule())));
        factory = new CitrateWalletFactory(address(impl), vm.addr(IDENTITY_PK), address(0xA11CE));
        CitratePaymaster pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)),
            address(0xA11CE),
            address(factory),
            vm.addr(IDENTITY_PK),
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(address(0xA11CE));
        factory.setPaymaster(address(pm));
        wallet = payable(_deploy());
        entryPoint.depositTo{value: 10 ether}(wallet);
    }

    function _deploy() internal returns (address account) {
        bytes memory guardianData = _installBytes(2, _threeGuardians());
        bytes memory installRecovery = abi.encodeWithSignature(
            "installModule(uint256,address,bytes)",
            uint256(1),
            address(module),
            abi.encodePacked(
                address(0),
                abi.encode(guardianData, bytes(""), abi.encodePacked(bytes4(keccak256("execute(bytes32,bytes)"))))
            )
        );
        bytes[] memory initConfig = new bytes[](1);
        initConfig[0] = installRecovery;
        bytes memory initData = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            bytes21(abi.encodePacked(bytes1(0x01), address(ecdsaValidator))),
            address(0),
            abi.encodePacked(vm.addr(OLD_OWNER_PK), uint8(1)),
            bytes(""),
            initConfig
        );
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 digest = factory.permitDigest(USER_ID, initData, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(IDENTITY_PK, digest.toEthSignedMessageHash());
        account = factory.deployFor(USER_ID, address(ecdsaValidator), initData, expiresAt, abi.encodePacked(r, s, v));
        assertTrue(module.isInitialized(account));
    }

    function _packedOp(uint256 nonce, bytes memory callData) internal view returns (AaPackedUserOperation memory op) {
        op = AaPackedUserOperation({
            sender: wallet,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(2 gwei))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _moduleNonceKey() internal view returns (uint192) {
        return uint192(bytes24(abi.encodePacked(bytes1(0x00), bytes1(0x01), address(module), bytes2(0))));
    }

    /// Rotate the root to a fresh ECDSA validator instance holding a NEW owner key.
    function _rotationCallData() internal view returns (bytes memory) {
        bytes memory rotate = abi.encodeWithSignature(
            "changeRootValidator(bytes21,address,bytes,bytes)",
            bytes21(abi.encodePacked(bytes1(0x01), address(newValidator))),
            address(0),
            abi.encodePacked(vm.addr(NEW_OWNER_PK), uint8(1)),
            bytes("")
        );
        return
            abi.encodeWithSignature("execute(bytes32,bytes)", bytes32(0), abi.encodePacked(wallet, uint256(0), rotate));
    }

    function _handle(AaPackedUserOperation memory op) internal {
        AaPackedUserOperation[] memory ops = new AaPackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function _recoveryOp() internal view returns (AaPackedUserOperation memory op) {
        op = _packedOp(entryPoint.getNonce(wallet, _moduleNonceKey()), _rotationCallData());
        op.signature = _execSig(PK_C, entryPoint.getUserOpHash(op), wallet);
    }

    function _ownerOp(uint256 pk, bytes memory callData) internal view returns (AaPackedUserOperation memory op) {
        op = _packedOp(entryPoint.getNonce(wallet, 0), callData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, entryPoint.getUserOpHash(op));
        op.signature = abi.encodePacked(r, s, v);
    }

    /// The owner key of the account's current root validator.
    function _rootOwner() internal view returns (address owner) {
        (, bytes memory raw) = wallet.staticcall(abi.encodeWithSignature("rootValidator()"));
        address root = address(uint160(bytes20(bytes21(raw) << 8)));
        (bool ok, bytes memory rec) = root.staticcall(abi.encodeWithSignature("ownerOf(address)", wallet));
        require(ok, "ownerOf");
        owner = abi.decode(rec, (address));
    }

    function _expectNotDue(AaPackedUserOperation memory op) internal {
        AaPackedUserOperation[] memory ops = new AaPackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_recovery_executes_only_after_72h() public {
        bytes memory cd = _rotationCallData();
        uint48 ea = module.initiateRecovery(wallet, cd, _quorum(wallet, cd));
        assertEq(ea, uint48(block.timestamp) + DELAY);

        // Immediately, and one second before the delay ends: the EntryPoint refuses the op.
        _expectNotDue(_recoveryOp());
        vm.warp(uint256(ea) - 1);
        _expectNotDue(_recoveryOp());
        assertEq(_rootOwner(), vm.addr(OLD_OWNER_PK), "root unchanged before 72 h");

        // At 72 h it executes and the root signer is the new key.
        vm.warp(ea);
        _handle(_recoveryOp());
        assertEq(_rootOwner(), vm.addr(NEW_OWNER_PK), "rotated after 72 h");
        (, uint48 left,) = module.pendingRecovery(wallet);
        assertEq(left, 0);
    }

    function test_owner_cancels() public {
        bytes memory cd = _rotationCallData();
        module.initiateRecovery(wallet, cd, _quorum(wallet, cd));

        // The owner (current root signer) cancels through an ordinary UserOp.
        bytes memory cancel = abi.encodeWithSignature(
            "execute(bytes32,bytes)",
            bytes32(0),
            abi.encodePacked(address(module), uint256(0), abi.encodeWithSignature("cancelRecovery()"))
        );
        _handle(_ownerOp(OLD_OWNER_PK, cancel));
        (, uint48 ea,) = module.pendingRecovery(wallet);
        assertEq(ea, 0, "cancelled");

        // After the delay the guardian op fails validation (AA24) and the root is unchanged.
        vm.warp(block.timestamp + DELAY + 1);
        AaPackedUserOperation[] memory ops = new AaPackedUserOperation[](1);
        ops[0] = _recoveryOp();
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, beneficiary);
        assertEq(_rootOwner(), vm.addr(OLD_OWNER_PK));
    }

    function test_recovery_rejectsInflatedGasNotSignedByAGuardian() public {
        bytes memory cd = _rotationCallData();
        uint48 ea = module.initiateRecovery(wallet, cd, _quorum(wallet, cd));
        vm.warp(ea);
        AaPackedUserOperation memory op = _recoveryOp();
        // A third party bumps the fee after the guardian signed: the signature no longer matches.
        op.gasFees = bytes32(abi.encodePacked(uint128(1000 gwei), uint128(1000 gwei)));
        AaPackedUserOperation[] memory ops = new AaPackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, beneficiary);
    }

    function testFuzz_delayBoundary(uint32 dt) public {
        bytes memory cd = _rotationCallData();
        uint48 start = uint48(block.timestamp);
        module.initiateRecovery(wallet, cd, _quorum(wallet, cd));
        vm.warp(uint256(start) + dt);
        if (dt < DELAY) {
            _expectNotDue(_recoveryOp());
            assertEq(_rootOwner(), vm.addr(OLD_OWNER_PK));
        } else {
            _handle(_recoveryOp());
            assertEq(_rootOwner(), vm.addr(NEW_OWNER_PK));
        }
    }
}

/// Drives initiate / cancel / supersede / uninstall / reinstall / validate / time in random order.
contract GuardianV2Handler is GuardianV2Base {
    address public constant ACCOUNT = address(0xACC0);

    uint256 public earlyExecutions; // executable validation before initiation + 72 h
    uint256 public cancelledExecutions; // a cancelled / superseded / uninstalled hash executed
    uint256 public replayedInitiations; // a used signature set accepted again
    uint256 public executions;

    uint48 public pendingStart;
    mapping(bytes32 => bool) internal dead;
    bytes internal lastSigs;
    bytes internal lastCd;
    uint256 internal salt;

    constructor(GuardianRecoveryModuleV2 m) {
        module = m;
        vm.prank(ACCOUNT);
        module.onInstall(_installBytes(2, _threeGuardians()));
    }

    function _kill() internal {
        (bytes32 h, uint48 ea,) = module.pendingRecovery(ACCOUNT);
        if (ea != 0) dead[h] = true;
    }

    function initiate() external {
        if (!module.isInitialized(ACCOUNT)) return;
        bytes memory cd = _rotateCallData(ACCOUNT, bytes32(++salt));
        bytes memory sigs = _quorum(ACCOUNT, cd);
        _kill();
        module.initiateRecovery(ACCOUNT, cd, sigs);
        pendingStart = uint48(block.timestamp);
        lastSigs = sigs;
        lastCd = cd;
    }

    function replay() external {
        if (lastSigs.length == 0 || !module.isInitialized(ACCOUNT)) return;
        try module.initiateRecovery(ACCOUNT, lastCd, lastSigs) {
            replayedInitiations++;
        } catch {}
    }

    function cancel() external {
        _kill();
        vm.prank(ACCOUNT);
        try module.cancelRecovery() {} catch {}
    }

    function uninstall() external {
        if (!module.isInitialized(ACCOUNT)) return;
        _kill();
        vm.prank(ACCOUNT);
        module.onUninstall("");
    }

    function reinstall() external {
        if (module.isInitialized(ACCOUNT)) return;
        vm.prank(ACCOUNT);
        module.onInstall(_installBytes(2, _threeGuardians()));
    }

    function warp(uint32 dt) external {
        vm.warp(block.timestamp + (dt % (100 hours)));
    }

    /// Emulates the EntryPoint: an op is executable only when sigFailed == 0 and now >= validAfter;
    /// otherwise the whole op reverts and the module's state change is rolled back.
    function execute(bool useDead, uint256 pick) external {
        bytes memory cd = useDead ? _rotateCallData(ACCOUNT, bytes32(pick % (salt + 1))) : lastCd;
        if (cd.length == 0) return;
        bytes32 opHash = keccak256(abi.encode("op", pick));
        PackedUserOperation memory op;
        op.callData = cd;
        op.signature = _execSig(PK_C, opHash, ACCOUNT);
        vm.prank(ACCOUNT);
        uint256 vd = module.validateUserOp(op, opHash);
        if (vd & 1 == 1 || block.timestamp < uint48(vd >> 208)) revert("not executable");
        executions++;
        if (block.timestamp < uint256(pendingStart) + DELAY) earlyExecutions++;
        if (dead[keccak256(cd)]) cancelledExecutions++;
    }
}

contract GuardianRecoveryModuleV2InvariantTest is Test {
    GuardianRecoveryModuleV2 internal module;
    GuardianV2Handler internal handler;

    function setUp() public {
        vm.warp(1_700_000_000);
        module = new GuardianRecoveryModuleV2(IGuardianRecoveryModuleV1(address(new GuardianRecoveryModule())));
        handler = new GuardianV2Handler(module);
        targetContract(address(handler));
    }

    function invariant_noExecutionBefore72h() public view {
        assertEq(handler.earlyExecutions(), 0);
    }

    function invariant_cancelledOrSupersededRecoveryNeverExecutes() public view {
        assertEq(handler.cancelledExecutions(), 0);
    }

    function invariant_signatureSetsAreSingleUse() public view {
        assertEq(handler.replayedInitiations(), 0);
    }

    function invariant_pendingNeverDueEarlierThanDelay() public view {
        (, uint48 ea,) = module.pendingRecovery(handler.ACCOUNT());
        // a pending entry is always due exactly 72 h after the initiation that created it
        if (ea != 0) assertEq(uint256(ea), uint256(handler.pendingStart()) + 72 hours);
    }
}
