// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {AgentSessionKeyValidator} from "../src/aa/validators/AgentSessionKeyValidator.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {Execution} from "@kernel/interfaces/IERC7579Account.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";

/// ADR-XA-1 D6 / handoff §4 W1 acceptance A3.
///
/// The criterion is precise: "Delegation cap enforced ON-CHAIN (N+1 rejected by the
/// validator, not the client)". So these tests call `validateUserOp` directly, the
/// way the EntryPoint does, with no client in the loop at all. A test that went
/// through an SDK would prove the SDK behaves — which is not the claim.
contract AgentSessionKeyValidatorTest is Test {
    AgentSessionKeyValidator internal v;

    /// The smart account under delegation (Kernel calls the validator as itself).
    address internal kernel = address(0xC0FFEE);
    uint256 internal sessionPk = 0xA11CE;
    address internal sessionKey;

    address internal allowed = address(0xBEEF);
    address internal notAllowed = address(0xBAD);

    uint48 internal validUntil;
    uint256 internal constant CAP = 10 ether;

    function setUp() public {
        v = new AgentSessionKeyValidator();
        sessionKey = vm.addr(sessionPk);
        validUntil = uint48(block.timestamp + 30 days);
    }

    // --- helpers -------------------------------------------------------------

    /// Single-recipient tree: the root IS the leaf, so the proof is empty.
    function _rootFor(address target) internal view returns (bytes32) {
        return v.recipientLeaf(target);
    }

    function _install(bytes32 root, uint256 cap, uint48 until) internal {
        bytes memory data = abi.encodePacked(sessionKey, bytes6(until), bytes32(cap), root);
        assertEq(data.length, 90, "install data must be exactly 90 bytes");
        vm.prank(kernel);
        v.onInstall(data);
    }

    function _installDefault() internal {
        _install(_rootFor(allowed), CAP, validUntil);
    }

    /// `execute(ExecMode, bytes)` for a single call — mode 0x00 = CALLTYPE_SINGLE.
    function _singleCallData(address target, uint256 value) internal pure returns (bytes memory) {
        bytes memory execData = abi.encodePacked(target, bytes32(value), bytes(""));
        return abi.encodeWithSignature("execute(bytes32,bytes)", bytes32(0), execData);
    }

    /// `execute(ExecMode, bytes)` for a batch — first mode byte 0x01 = CALLTYPE_BATCH.
    function _batchCallData(Execution[] memory execs) internal pure returns (bytes memory) {
        bytes32 mode = bytes32(uint256(0x01) << 248);
        return abi.encodeWithSignature("execute(bytes32,bytes)", mode, abi.encode(execs));
    }

    function _op(bytes memory callData, bytes32[][] memory proofs, uint256 pk)
        internal
        view
        returns (PackedUserOperation memory op, bytes32 opHash)
    {
        op.sender = kernel;
        op.callData = callData;
        opHash = keccak256(abi.encode(callData, op.sender, block.timestamp));
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, opHash);
        op.signature = abi.encode(abi.encodePacked(r, s, vv), proofs);
    }

    function _emptyProofs(uint256 n) internal pure returns (bytes32[][] memory p) {
        p = new bytes32[][](n);
        for (uint256 i; i < n; ++i) {
            p[i] = new bytes32[](0);
        }
    }

    function _validate(bytes memory callData, bytes32[][] memory proofs, uint256 pk)
        internal
        returns (uint256)
    {
        (PackedUserOperation memory op, bytes32 h) = _op(callData, proofs, pk);
        vm.prank(kernel);
        return v.validateUserOp(op, h);
    }

    /// Spend `value` once, expecting success.
    function _spendOk(uint256 value) internal {
        assertEq(
            _validate(_singleCallData(allowed, value), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_SUCCESS_UINT
        );
    }

    // --- the selector constant must actually be execute(bytes32,bytes) -------

    function test_executeSelectorMatchesKernel() public pure {
        // If Kernel's signature ever changes, the validator would silently refuse
        // every operation. Pin it.
        assertEq(bytes4(keccak256("execute(bytes32,bytes)")), bytes4(0xe9ae5c53));
    }

    // --- install ------------------------------------------------------------

    function test_installStoresTheBound() public {
        _installDefault();
        (address sk, uint48 until, uint256 cap, uint256 spent, bytes32 root) = v.sessionOf(kernel);
        assertEq(sk, sessionKey);
        assertEq(until, validUntil);
        assertEq(cap, CAP);
        assertEq(spent, 0);
        assertEq(root, _rootFor(allowed));
        assertTrue(v.isInitialized(kernel));
        assertEq(v.remaining(kernel), CAP);
    }

    // NOTE on sequencing: `_rootFor` makes an external call to the validator, so it
    // MUST be evaluated into a local before `vm.expectRevert`. Left inline as an
    // argument it becomes "the next call", and the cheatcode binds to it instead of
    // to `onInstall` — which reads as a contract bug when it is a test bug.
    function test_installRejectsZeroCap() public {
        bytes memory data =
            abi.encodePacked(sessionKey, bytes6(validUntil), bytes32(0), _rootFor(allowed));
        vm.prank(kernel);
        vm.expectRevert(AgentSessionKeyValidator.InvalidSpendCap.selector);
        v.onInstall(data);
    }

    function test_installRejectsZeroRoot() public {
        bytes memory data =
            abi.encodePacked(sessionKey, bytes6(validUntil), bytes32(CAP), bytes32(0));
        vm.prank(kernel);
        vm.expectRevert(AgentSessionKeyValidator.InvalidRecipientsRoot.selector);
        v.onInstall(data);
    }

    function test_installRejectsZeroSessionKey() public {
        bytes memory data =
            abi.encodePacked(address(0), bytes6(validUntil), bytes32(CAP), _rootFor(allowed));
        vm.prank(kernel);
        vm.expectRevert(AgentSessionKeyValidator.InvalidSessionKey.selector);
        v.onInstall(data);
    }

    function test_installRejectsPastExpiry() public {
        bytes memory data =
            abi.encodePacked(sessionKey, bytes6(uint48(999)), bytes32(CAP), _rootFor(allowed));
        vm.warp(1000);
        vm.prank(kernel);
        vm.expectRevert(AgentSessionKeyValidator.ExpiryInPast.selector);
        v.onInstall(data);
    }

    function test_installRejectsWrongLength() public {
        bytes memory data = abi.encodePacked(sessionKey, bytes6(validUntil));
        vm.prank(kernel);
        vm.expectRevert(AgentSessionKeyValidator.InvalidInstallData.selector);
        v.onInstall(data);
    }

    function test_doubleInstallReverts() public {
        _installDefault();
        bytes memory data =
            abi.encodePacked(sessionKey, bytes6(validUntil), bytes32(CAP), _rootFor(allowed));
        vm.prank(kernel);
        vm.expectRevert(
            abi.encodeWithSelector(AgentSessionKeyValidator.AlreadyInstalled.selector, kernel)
        );
        v.onInstall(data);
    }

    // --- A3: THE CAP, enforced by the validator -----------------------------

    function test_A3_spendUpToCapSucceedsAndNplus1IsRejected() public {
        _installDefault();
        // Ten 1-ether spends exactly exhaust a 10-ether cap.
        for (uint256 i; i < 10; ++i) {
            _spendOk(1 ether);
        }
        (,,, uint256 spent,) = v.sessionOf(kernel);
        assertEq(spent, CAP);
        assertEq(v.remaining(kernel), 0);

        // N+1. Rejected by the validator itself — no client involved anywhere in
        // this test. THIS is acceptance A3.
        assertEq(
            _validate(_singleCallData(allowed, 1), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );

        // And the rejection did not consume budget or corrupt accounting.
        (,,, uint256 spentAfter,) = v.sessionOf(kernel);
        assertEq(spentAfter, CAP);
    }

    function test_A3_singleSpendOverCapIsRejected() public {
        _installDefault();
        assertEq(
            _validate(_singleCallData(allowed, CAP + 1), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
        (,,, uint256 spent,) = v.sessionOf(kernel);
        assertEq(spent, 0, "a rejected op must not accrue spend");
    }

    function test_A3_batchTotalIsCapped() public {
        _installDefault();
        Execution[] memory execs = new Execution[](3);
        for (uint256 i; i < 3; ++i) {
            execs[i] = Execution({target: allowed, value: 4 ether, callData: ""});
        }
        // 12 ether across a batch exceeds the 10 ether cap — a batch must not be a
        // way to step around a per-call check.
        assertEq(
            _validate(_batchCallData(execs), _emptyProofs(3), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );

        // Under the cap, the same shape succeeds and accrues the TOTAL.
        for (uint256 i; i < 3; ++i) {
            execs[i] = Execution({target: allowed, value: 3 ether, callData: ""});
        }
        assertEq(
            _validate(_batchCallData(execs), _emptyProofs(3), sessionPk),
            SIG_VALIDATION_SUCCESS_UINT
        );
        (,,, uint256 spent,) = v.sessionOf(kernel);
        assertEq(spent, 9 ether);
    }

    function test_A3_capIsCumulativeAcrossOps() public {
        _installDefault();
        _spendOk(6 ether);
        _spendOk(4 ether);
        // Cumulative, not per-op: a second 6-ether op must fail even though 6 < cap.
        assertEq(
            _validate(_singleCallData(allowed, 6 ether), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    function testFuzz_A3_neverExceedsCap(uint96 a, uint96 b) public {
        _installDefault();
        // Whatever the pair, accrued spend can never pass the cap.
        _validate(_singleCallData(allowed, a), _emptyProofs(1), sessionPk);
        _validate(_singleCallData(allowed, b), _emptyProofs(1), sessionPk);
        (,,, uint256 spent,) = v.sessionOf(kernel);
        assertLe(spent, CAP);
    }

    // --- signer / expiry ----------------------------------------------------

    function test_wrongSignerRejected() public {
        _installDefault();
        assertEq(
            _validate(_singleCallData(allowed, 1 ether), _emptyProofs(1), 0xD00D),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    function test_expiredSessionRejected() public {
        _installDefault();
        vm.warp(uint256(validUntil) + 1);
        assertEq(
            _validate(_singleCallData(allowed, 1), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
        assertEq(v.remaining(kernel), 0);
    }

    function test_uninstalledSessionRejected() public {
        _installDefault();
        vm.prank(kernel);
        v.onUninstall("");
        assertFalse(v.isInitialized(kernel));
        // A7/A4: an on-chain revoke ends authority on-chain, not just in a database.
        assertEq(
            _validate(_singleCallData(allowed, 1), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    // --- X7: recipient allow-list ------------------------------------------

    function test_X7_nonAllowlistedRecipientRejected() public {
        _installDefault();
        assertEq(
            _validate(_singleCallData(notAllowed, 1 ether), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    function test_X7_twoLeafTreeAcceptsBothWithRealProofs() public {
        bytes32 leafA = v.recipientLeaf(allowed);
        bytes32 leafB = v.recipientLeaf(notAllowed);
        // OZ MerkleProof hashes pairs sorted, so build the root the same way.
        bytes32 root = leafA < leafB
            ? keccak256(abi.encodePacked(leafA, leafB))
            : keccak256(abi.encodePacked(leafB, leafA));
        _install(root, CAP, validUntil);

        bytes32[][] memory pA = new bytes32[][](1);
        pA[0] = new bytes32[](1);
        pA[0][0] = leafB;
        assertEq(
            _validate(_singleCallData(allowed, 1 ether), pA, sessionPk),
            SIG_VALIDATION_SUCCESS_UINT
        );

        bytes32[][] memory pB = new bytes32[][](1);
        pB[0] = new bytes32[](1);
        pB[0][0] = leafA;
        assertEq(
            _validate(_singleCallData(notAllowed, 1 ether), pB, sessionPk),
            SIG_VALIDATION_SUCCESS_UINT
        );
    }

    function test_X7_batchRejectedIfAnyRecipientIsNotAllowed() public {
        _installDefault();
        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({target: allowed, value: 1 ether, callData: ""});
        execs[1] = Execution({target: notAllowed, value: 1 ether, callData: ""});
        // One bad target poisons the batch — otherwise a batch launders a
        // disallowed recipient behind an allowed one.
        assertEq(
            _validate(_batchCallData(execs), _emptyProofs(2), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    function test_X7_proofCountMustMatchExecutionCount() public {
        _installDefault();
        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({target: allowed, value: 1, callData: ""});
        execs[1] = Execution({target: allowed, value: 1, callData: ""});
        assertEq(
            _validate(_batchCallData(execs), _emptyProofs(1), sessionPk),
            SIG_VALIDATION_FAILED_UINT
        );
    }

    // --- X8: unrecognized calldata shapes fail closed -----------------------

    function test_X8_delegatecallRefused() public {
        _installDefault();
        // CALLTYPE_DELEGATECALL (0xFF) is a total account takeover; no cap survives it.
        bytes32 mode = bytes32(uint256(0xFF) << 248);
        bytes memory cd = abi.encodeWithSignature(
            "execute(bytes32,bytes)", mode, abi.encodePacked(allowed, bytes32(0), bytes(""))
        );
        assertEq(_validate(cd, _emptyProofs(1), sessionPk), SIG_VALIDATION_FAILED_UINT);
    }

    function test_X8_unknownSelectorRefused() public {
        _installDefault();
        bytes memory cd = abi.encodeWithSignature("transfer(address,uint256)", allowed, 1 ether);
        assertEq(_validate(cd, _emptyProofs(1), sessionPk), SIG_VALIDATION_FAILED_UINT);
    }

    function test_X8_emptyCallDataRefused() public {
        _installDefault();
        assertEq(_validate("", _emptyProofs(1), sessionPk), SIG_VALIDATION_FAILED_UINT);
    }

    function test_X8_truncatedSignatureEnvelopeRefused() public {
        _installDefault();
        PackedUserOperation memory op;
        op.sender = kernel;
        op.callData = _singleCallData(allowed, 1);
        op.signature = hex"deadbeef";
        vm.prank(kernel);
        assertEq(v.validateUserOp(op, keccak256("h")), SIG_VALIDATION_FAILED_UINT);
    }

    // --- ERC-1271 is always refused ----------------------------------------

    function test_erc1271AlwaysInvalid() public {
        _installDefault();
        // A session key that could sign arbitrary payloads could authorize an
        // approval/permit that moves value without passing validateUserOp.
        vm.prank(kernel);
        assertEq(
            v.isValidSignatureWithSender(address(this), keccak256("anything"), hex"00"),
            ERC1271_INVALID
        );
    }

    // --- module type --------------------------------------------------------

    function test_moduleTypes() public view {
        assertTrue(v.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(v.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(v.isModuleType(99));
    }
}
