// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// FWA-C3-07: a smart-wallet (contract) guardian that authenticates via
/// EIP-1271. It validates an ECDSA signature from a single owner key over
/// the EXACT digest the module passes (the un-prefixed application digest).
contract MockSmartWalletGuardian {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        require(sig.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        address recovered = ecrecover(hash, v, r, s);
        return recovered == owner ? MAGIC : bytes4(0xffffffff);
    }
}

/// Tests for the M-of-N social-guardian recovery module.
contract GuardianRecoveryModuleTest is Test {
    using MessageHashUtils for bytes32;

    GuardianRecoveryModule internal module;
    address internal kernel;

    // Deterministic guardian keys + addresses.
    uint256 internal constant PK_A = 0xA;
    uint256 internal constant PK_B = 0xB;
    uint256 internal constant PK_C = 0xC;
    uint256 internal constant PK_OTHER = 0xDEAD;

    function setUp() public {
        module = new GuardianRecoveryModule();
        kernel = address(0xCAFEBABE);
    }

    // ── Install lifecycle ──

    function test_install_storesAndEmits() public {
        address[] memory guardians = _threeGuardians();
        bytes memory data = _installBytes(2, guardians);
        vm.prank(kernel);
        module.onInstall(data);

        assertTrue(module.isInitialized(kernel));
        (uint8 threshold, address[] memory got) = module.configOf(kernel);
        assertEq(threshold, 2);
        assertEq(got.length, 3);
        assertEq(got[0], guardians[0]);
        assertEq(got[1], guardians[1]);
        assertEq(got[2], guardians[2]);
    }

    function test_install_rejectsCountBelowMin() public {
        address[] memory g = new address[](1);
        g[0] = vm.addr(PK_A);
        bytes memory data = _installBytes(1, g);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.InvalidGuardianCount.selector);
        module.onInstall(data);
    }

    function test_install_rejectsCountAboveMax() public {
        address[] memory g = new address[](8);
        for (uint256 i = 0; i < 8; i++) {
            g[i] = vm.addr(uint256(0x1000 + i));
        }
        bytes memory data = _installBytes(5, g);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.InvalidGuardianCount.selector);
        module.onInstall(data);
    }

    function test_install_rejectsThresholdZero() public {
        address[] memory g = _threeGuardians();
        bytes memory data = _installBytes(0, g);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.InvalidThreshold.selector);
        module.onInstall(data);
    }

    function test_install_rejectsThresholdAboveCount() public {
        address[] memory g = _threeGuardians();
        bytes memory data = _installBytes(4, g);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.InvalidThreshold.selector);
        module.onInstall(data);
    }

    function test_install_rejectsZeroGuardian() public {
        address[] memory g = new address[](2);
        g[0] = vm.addr(PK_A);
        g[1] = address(0);
        bytes memory data = _installBytes(2, g);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.ZeroGuardian.selector);
        module.onInstall(data);
    }

    function test_install_rejectsDuplicateGuardian() public {
        address[] memory g = new address[](3);
        g[0] = vm.addr(PK_A);
        g[1] = vm.addr(PK_B);
        g[2] = vm.addr(PK_A); // duplicate
        bytes memory data = _installBytes(2, g);
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.DuplicateGuardian.selector);
        module.onInstall(data);
    }

    function test_install_rejectsTruncatedData() public {
        // header says 3 guardians, but blob has only 2 addresses worth of bytes
        bytes memory data = abi.encodePacked(uint8(2), uint8(3), vm.addr(PK_A), vm.addr(PK_B));
        vm.prank(kernel);
        vm.expectRevert(GuardianRecoveryModule.InvalidInstallData.selector);
        module.onInstall(data);
    }

    function test_install_rejectsDoubleInstall() public {
        bytes memory data = _installBytes(2, _threeGuardians());
        vm.prank(kernel);
        module.onInstall(data);

        vm.prank(kernel);
        vm.expectRevert(abi.encodeWithSelector(GuardianRecoveryModule.AlreadyInstalled.selector, kernel));
        module.onInstall(data);
    }

    function test_uninstall_clearsState() public {
        _installFresh(kernel, 2, _threeGuardians());
        vm.prank(kernel);
        module.onUninstall("");
        assertFalse(module.isInitialized(kernel));
    }

    function test_uninstall_revertsIfNotInstalled() public {
        vm.prank(kernel);
        vm.expectRevert();
        module.onUninstall("");
    }

    function test_moduleType_advertisesValidatorAndHook() public {
        assertTrue(module.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(module.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(module.isModuleType(123));
    }

    // ── Validation ──

    /// FWA-C3-06: EOA guardian signatures are now accepted ONLY over the
    /// EIP-191 prefixed digest. The previously-accepted RAW-digest shape is
    /// rejected (see RoleEscalation… no — see C3_06 red test below). This
    /// test, formerly "rawSigs_succeeds", now signs the prefixed digest —
    /// the canonical guardian signing scheme — and must still succeed.
    function test_validate_twoOfThree_ethPrefixed_succeeds_canonical() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("recover_to_new_passkey");
        bytes32 digest = _digest(userOpHash, kernel);
        bytes32 ethDigest = digest.toEthSignedMessageHash();

        bytes memory blob = bytes.concat(_sign(PK_A, ethDigest), _sign(PK_B, ethDigest));

        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_validate_twoOfThree_ethPrefixed_succeeds() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("recover");
        bytes32 digest = _digest(userOpHash, kernel);
        bytes32 ethDigest = digest.toEthSignedMessageHash();

        bytes memory blob = bytes.concat(_sign(PK_A, ethDigest), _sign(PK_C, ethDigest));
        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_validate_duplicateSigner_fails() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("op");
        bytes32 digest = _digest(userOpHash, kernel);

        // Same guardian twice — should fail.
        bytes memory blob = bytes.concat(_sign(PK_A, digest), _sign(PK_A, digest));
        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_unknownSigner_fails() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("op");
        bytes32 digest = _digest(userOpHash, kernel);

        bytes memory blob = bytes.concat(_sign(PK_A, digest), _sign(PK_OTHER, digest));
        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_wrongLength_fails() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("op");
        bytes32 digest = _digest(userOpHash, kernel);
        bytes memory blob = _sign(PK_A, digest); // only 1 signature, threshold is 2

        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_notInstalled_fails() public {
        bytes32 userOpHash = keccak256("op");
        bytes memory blob = _sign(PK_A, _digest(userOpHash, kernel));
        PackedUserOperation memory op = _op(bytes.concat(blob, blob));

        address fresh = address(0xFEED);
        vm.prank(fresh);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_FAILED_UINT);
    }

    function test_validate_replayAcrossAccounts_fails() public {
        address kernelA = address(0xA001);
        address kernelB = address(0xA002);
        address[] memory g = _threeGuardians();
        _installFresh(kernelA, 2, g);
        _installFresh(kernelB, 2, g);

        bytes32 userOpHash = keccak256("op");
        // FWA-C3-06: sign the EIP-191 prefixed digest (the only EOA shape
        // now accepted). Replay protection is unchanged: the digest binds
        // the account, so a signature for kernelA fails on kernelB.
        bytes32 digestForA = _digest(userOpHash, kernelA).toEthSignedMessageHash();
        bytes memory blob = bytes.concat(_sign(PK_A, digestForA), _sign(PK_B, digestForA));
        PackedUserOperation memory op = _op(blob);

        // The signatures were over a digest bound to kernelA; submitting
        // them to kernelB's validation must FAIL because the digest
        // recomputes against kernelB and the recovered addresses won't
        // match the guardian set's expectation.
        vm.prank(kernelB);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_FAILED_UINT);

        // Sanity: it works for kernelA where it was meant.
        vm.prank(kernelA);
        res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_SUCCESS_UINT);
    }

    // ── FWA-C3-06: raw (un-prefixed) digest signatures must be REJECTED ──

    /// Pre-fix: a guardian EOA signature over the RAW digest
    /// keccak256(userOpHash, account) was accepted, re-opening
    /// cross-protocol replay. Post-fix: only EIP-191 prefixed sigs match,
    /// so a raw-digest signature no longer validates.
    function test_C3_06_raw_digest_signature_rejected() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("op");
        bytes32 rawDigest = _digest(userOpHash, kernel); // NOT eth-prefixed

        bytes memory blob = bytes.concat(_sign(PK_A, rawDigest), _sign(PK_B, rawDigest));
        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_FAILED_UINT, "raw-digest guardian sig must be rejected");
    }

    // ── FWA-C3-07: contract (EIP-1271) guardians can complete recovery ──

    /// Pre-fix: the module advertised smart-wallet guardians but only ran
    /// ECDSA tryRecover, so a contract guardian could never satisfy
    /// recovery → an M-of-N set including one was BRICKED. Post-fix: a
    /// contract guardian is authenticated via isValidSignature.
    function test_C3_07_smart_wallet_guardian_completes_recovery() public {
        // Guardian set: one EOA (PK_A) + one smart-wallet guardian.
        uint256 swOwnerPk = 0x5A7E;
        address swOwner = vm.addr(swOwnerPk);
        MockSmartWalletGuardian sw = new MockSmartWalletGuardian(swOwner);

        address[] memory g = new address[](2);
        g[0] = vm.addr(PK_A);
        g[1] = address(sw);
        _installFresh(kernel, 2, g); // 2-of-2

        bytes32 userOpHash = keccak256("recover-with-sw");
        bytes32 digest = _digest(userOpHash, kernel);
        bytes32 ethDigest = digest.toEthSignedMessageHash();

        // EOA guardian signs the EIP-191 prefixed digest; the smart-wallet
        // guardian's owner signs the application digest (what isValidSignature
        // receives). Blob is two 65-byte slots.
        bytes memory eoaSig = _sign(PK_A, ethDigest);
        bytes memory swSig = _sign(swOwnerPk, digest);
        bytes memory blob = bytes.concat(eoaSig, swSig);

        PackedUserOperation memory op = _op(blob);
        vm.prank(kernel);
        uint256 res = module.validateUserOp(op, userOpHash);
        assertEq(res, SIG_VALIDATION_SUCCESS_UINT, "smart-wallet guardian must complete recovery");
    }

    // ── EIP-1271 ──

    function test_isValidSignatureWithSender_alwaysInvalid() public {
        _installFresh(kernel, 2, _threeGuardians());
        bytes32 userOpHash = keccak256("op");
        bytes memory blob = bytes.concat(
            _sign(PK_A, _digest(userOpHash, kernel)),
            _sign(PK_B, _digest(userOpHash, kernel))
        );
        vm.prank(kernel);
        bytes4 res = module.isValidSignatureWithSender(address(0), userOpHash, blob);
        assertEq(res, ERC1271_INVALID);
    }

    // ── Hook trivia ──

    function test_preCheck_returnsEmpty() public {
        bytes memory ret = module.preCheck(address(0xDEAD), 0, "");
        assertEq(ret.length, 0);
    }

    function test_postCheck_doesNotRevert() public {
        module.postCheck("");
    }

    // ── Helpers ──

    function _installFresh(address k, uint8 threshold, address[] memory g) internal {
        bytes memory data = _installBytes(threshold, g);
        vm.prank(k);
        module.onInstall(data);
    }

    function _threeGuardians() internal pure returns (address[] memory g) {
        g = new address[](3);
        g[0] = vm.addr(PK_A);
        g[1] = vm.addr(PK_B);
        g[2] = vm.addr(PK_C);
    }

    function _installBytes(uint8 threshold, address[] memory g) internal pure returns (bytes memory) {
        bytes memory packed = abi.encodePacked(threshold, uint8(g.length));
        for (uint256 i = 0; i < g.length; i++) {
            packed = abi.encodePacked(packed, g[i]);
        }
        return packed;
    }

    function _digest(bytes32 userOpHash, address account) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(userOpHash, account));
    }

    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    function _op(bytes memory sig) internal pure returns (PackedUserOperation memory op) {
        op.signature = sig;
    }
}
