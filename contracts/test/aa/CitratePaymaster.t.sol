// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {IPaymaster} from "@account-abstraction/interfaces/IPaymaster.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// Minimal EntryPoint stub that:
///   - reports support for IEntryPoint (so BasePaymaster's constructor passes)
///   - lets us masquerade as the entry point when invoking the paymaster
contract StubEntryPoint {
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IEntryPoint).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// Required by BasePaymaster.deposit() — receive ETH.
    receive() external payable {}

    /// BasePaymaster.deposit() forwards to this. We accept it silently.
    function depositTo(address) external payable {}
}

contract CitratePaymasterTest is Test {
    CitratePaymaster internal pm;
    StubEntryPoint internal entryPoint;

    address internal ownerAddr = address(0xA11CE);
    address internal registrar = address(0xFAC7);
    address internal account = address(0xACC1);
    address internal otherAccount = address(0xACC2);

    uint256 internal constant DAILY = 100_000;
    uint256 internal constant RECOVERY = 200_000;
    uint256 internal constant FIRST_OP = 300_000;

    function setUp() public {
        entryPoint = new StubEntryPoint();
        pm = new CitratePaymaster(IEntryPoint(address(entryPoint)), ownerAddr, registrar, DAILY, RECOVERY, FIRST_OP);

        // Register one wallet.
        vm.prank(registrar);
        pm.registerWallet(account);
    }

    // ── Registrar ──

    function test_registerWallet_onlyByRegistrar() public {
        vm.expectRevert(CitratePaymaster.NotARegistrar.selector);
        pm.registerWallet(otherAccount);

        vm.prank(registrar);
        pm.registerWallet(otherAccount);
        assertTrue(pm.isRegistered(otherAccount));
    }

    function test_unregisterWallet_onlyByRegistrar() public {
        vm.expectRevert(CitratePaymaster.NotARegistrar.selector);
        pm.unregisterWallet(account);

        vm.prank(registrar);
        pm.unregisterWallet(account);
        assertFalse(pm.isRegistered(account));
    }

    function test_setRegistrar_onlyByOwner_rotatesAuthority() public {
        address newReg = address(0xBEEF);
        vm.expectRevert();
        pm.setRegistrar(newReg);

        vm.prank(ownerAddr);
        pm.setRegistrar(newReg);
        assertEq(pm.registrar(), newReg);

        // Old registrar no longer authorized
        vm.prank(registrar);
        vm.expectRevert(CitratePaymaster.NotARegistrar.selector);
        pm.registerWallet(otherAccount);

        // New one is
        vm.prank(newReg);
        pm.registerWallet(otherAccount);
        assertTrue(pm.isRegistered(otherAccount));
    }

    // ── Validation: standard category ──

    function test_validate_standard_within_cap_succeeds() public {
        uint256 maxCost = 30_000;
        bytes memory ctx = _validate(account, _userOpStandard(account), maxCost);
        // context should encode (account, CAT_STANDARD=0)
        (address a, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(a, account);
        assertEq(c, 0);
    }

    function test_validate_standard_aboveCap_reverts() public {
        uint256 maxCost = DAILY + 1;
        vm.expectRevert();
        _validate(account, _userOpStandard(account), maxCost);
    }

    function test_validate_standard_unregisteredAccount_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(CitratePaymaster.NotARegisteredCitrateWallet.selector, otherAccount));
        _validate(otherAccount, _userOpStandard(otherAccount), 1);
    }

    function test_validate_whenPaused_reverts() public {
        vm.prank(ownerAddr);
        pm.setPaused(true);
        vm.expectRevert(CitratePaymaster.Paused.selector);
        _validate(account, _userOpStandard(account), 1);
    }

    function test_validate_missingCategoryTag_reverts() public {
        PackedUserOperation memory op = _baseOp(account);
        // 52 bytes exactly — no tag suffix
        op.paymasterAndData = new bytes(52);
        vm.expectRevert(CitratePaymaster.MissingCategoryTag.selector);
        _validate(account, op, 1);
    }

    function test_validate_unknownCategory_reverts() public {
        PackedUserOperation memory op = _baseOp(account);
        op.paymasterAndData = _pmdWithTag(uint8(99));
        vm.expectRevert(abi.encodeWithSelector(CitratePaymaster.UnknownCategory.selector, uint8(99)));
        _validate(account, op, 1);
    }

    // ── Accounting on postOp ──

    function test_postOp_standardAccountsAgainstDaily() public {
        uint256 maxCost = 30_000;
        bytes memory ctx = _validate(account, _userOpStandard(account), maxCost);
        uint256 actual = 25_000;
        _postOp(ctx, actual);

        (uint128 used, uint64 dayKey) = pm.dailyUsage(account);
        assertEq(uint256(used), actual);
        assertEq(uint256(dayKey), uint256(pm.todayKey()));
        assertEq(pm.remainingStandard(account), DAILY - actual);
    }

    function test_postOp_standardAccumulatesAcrossOpsSameDay() public {
        uint256 a1 = 20_000;
        uint256 a2 = 30_000;

        bytes memory c1 = _validate(account, _userOpStandard(account), a1);
        _postOp(c1, a1);
        bytes memory c2 = _validate(account, _userOpStandard(account), a2);
        _postOp(c2, a2);

        (uint128 used,) = pm.dailyUsage(account);
        assertEq(uint256(used), a1 + a2);
    }

    function test_postOp_standardResetsAcrossDays() public {
        bytes memory c = _validate(account, _userOpStandard(account), 20_000);
        _postOp(c, 20_000);

        // jump forward one day + a bit
        vm.warp(block.timestamp + 86400 + 7200);

        c = _validate(account, _userOpStandard(account), 10_000);
        _postOp(c, 10_000);

        (uint128 used, uint64 dayKey) = pm.dailyUsage(account);
        assertEq(uint256(used), 10_000, "counter reset on new day");
        assertEq(uint256(dayKey), uint256(pm.todayKey()));
    }

    function test_validate_standard_secondOpWithRemainingBudget_passes() public {
        bytes memory c1 = _validate(account, _userOpStandard(account), 60_000);
        _postOp(c1, 60_000);

        // remaining = 40_000; this op cost 40_000 = exactly the cap.
        bytes memory c2 = _validate(account, _userOpStandard(account), 40_000);
        _postOp(c2, 40_000);

        (uint128 used,) = pm.dailyUsage(account);
        assertEq(uint256(used), DAILY);
        assertEq(pm.remainingStandard(account), 0);
    }

    function test_validate_standard_thirdOpExceedingRemaining_reverts() public {
        bytes memory c1 = _validate(account, _userOpStandard(account), 60_000);
        _postOp(c1, 60_000);

        // remaining = 40_000; ask for 50_000.
        vm.expectRevert();
        _validate(account, _userOpStandard(account), 50_000);
    }

    // ── Recovery category ──

    function test_validate_recovery_underCap_passes() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 1), 150_000);
        (, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(c, 1);
    }

    function test_validate_recovery_overCap_reverts() public {
        vm.expectRevert();
        _validate(account, _userOpCat(account, 1), RECOVERY + 1);
    }

    function test_recovery_doesNotConsumeDailyBudget() public {
        // exhaust ~ all of daily
        bytes memory c1 = _validate(account, _userOpStandard(account), 80_000);
        _postOp(c1, 80_000);

        // recovery should still work even close-to-cap
        bytes memory c2 = _validate(account, _userOpCat(account, 1), 150_000);
        _postOp(c2, 150_000);

        // daily counter unchanged
        (uint128 used,) = pm.dailyUsage(account);
        assertEq(uint256(used), 80_000);
    }

    // ── FWA-C3-04: recovery daily COUNT cap (deposit-drain bound) ──

    /// Pre-fix: a registered wallet could self-tag UNLIMITED recovery ops
    /// (each only checked the per-op cap, no cumulative counter) to drain
    /// the paymaster deposit. Post-fix: a per-account daily recovery-op
    /// COUNT cap (default 3) bounds it; the 4th op in a day reverts.
    function test_C3_04_recovery_daily_count_cap_blocks_drain() public {
        assertEq(pm.recoveryDailyCountCap(), 3);

        // 3 recovery ops in the same day, each under the per-op cap.
        for (uint256 i = 0; i < 3; i++) {
            bytes memory ctx = _validate(account, _userOpCat(account, 1), 150_000);
            _postOp(ctx, 150_000);
        }

        // 4th recovery op the same day is rejected at validation.
        vm.expectRevert(
            abi.encodeWithSelector(
                CitratePaymaster.RecoveryDailyCountExceeded.selector, account, uint256(3), uint256(3)
            )
        );
        _validate(account, _userOpCat(account, 1), 150_000);
    }

    function test_C3_04_recovery_count_resets_next_day() public {
        for (uint256 i = 0; i < 3; i++) {
            bytes memory ctx = _validate(account, _userOpCat(account, 1), 150_000);
            _postOp(ctx, 150_000);
        }
        // Advance one day; the counter resets and recovery works again.
        vm.warp(block.timestamp + 1 days);
        bytes memory ctx2 = _validate(account, _userOpCat(account, 1), 150_000);
        (, uint8 c) = abi.decode(ctx2, (address, uint8));
        assertEq(c, 1);
    }

    function test_C3_04_count_cap_zero_means_unlimited() public {
        vm.prank(ownerAddr);
        pm.setRecoveryDailyCountCap(0);
        // Many recovery ops now allowed (per-op cap still applies).
        for (uint256 i = 0; i < 10; i++) {
            bytes memory ctx = _validate(account, _userOpCat(account, 1), 150_000);
            _postOp(ctx, 150_000);
        }
    }

    // ── First-op category ──

    function test_validate_firstOp_passes() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 2), 250_000);
        (, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(c, 2);
    }

    function test_firstOp_flagsAccountAfterPostOp() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 2), 250_000);
        _postOp(ctx, 250_000);
        assertTrue(pm.hasUsedFirstOp(account));
    }

    function test_validate_secondFirstOp_reverts() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 2), 250_000);
        _postOp(ctx, 250_000);

        vm.expectRevert(abi.encodeWithSelector(CitratePaymaster.FirstOpAlreadyUsed.selector, account));
        _validate(account, _userOpCat(account, 2), 250_000);
    }

    function test_validate_firstOp_overCap_reverts() public {
        vm.expectRevert();
        _validate(account, _userOpCat(account, 2), FIRST_OP + 1);
    }

    // ── Caller restrictions ──

    function test_validatePaymasterUserOp_externalCallerMustBeEntryPoint() public {
        vm.expectRevert();
        pm.validatePaymasterUserOp(_userOpStandard(account), bytes32(0), 1);
    }

    function test_postOp_externalCallerMustBeEntryPoint() public {
        bytes memory ctx = abi.encode(account, uint8(0));
        vm.expectRevert();
        pm.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 1, 1);
    }

    // ── Admin caps ──

    function test_setDailyCap_onlyOwner() public {
        vm.expectRevert();
        pm.setDailyCap(50_000);

        vm.prank(ownerAddr);
        pm.setDailyCap(50_000);
        assertEq(pm.dailyCap(), 50_000);
    }

    function test_setRecoveryEventCap_onlyOwner() public {
        vm.expectRevert();
        pm.setRecoveryEventCap(0);

        vm.prank(ownerAddr);
        pm.setRecoveryEventCap(0);
        assertEq(pm.recoveryEventCap(), 0);

        // and now recovery is disabled
        vm.expectRevert();
        _validate(account, _userOpCat(account, 1), 1);
    }

    function test_setFirstOpCap_onlyOwner() public {
        vm.expectRevert();
        pm.setFirstOpCap(0);

        vm.prank(ownerAddr);
        pm.setFirstOpCap(0);
        assertEq(pm.firstOpCap(), 0);

        vm.expectRevert();
        _validate(account, _userOpCat(account, 2), 1);
    }

    // ── Helpers ──

    function _validate(address sender, PackedUserOperation memory op, uint256 maxCost)
        internal
        returns (bytes memory ctx)
    {
        op.sender = sender;
        vm.prank(address(entryPoint));
        (ctx,) = pm.validatePaymasterUserOp(op, bytes32(0), maxCost);
    }

    function _postOp(bytes memory ctx, uint256 actualGasCost) internal {
        vm.prank(address(entryPoint));
        pm.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, actualGasCost, 1);
    }

    function _baseOp(address sender) internal pure returns (PackedUserOperation memory op) {
        op.sender = sender;
    }

    function _userOpStandard(address sender) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory op = _baseOp(sender);
        op.paymasterAndData = _pmdWithTag(uint8(0));
        return op;
    }

    function _userOpCat(address sender, uint8 cat) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory op = _baseOp(sender);
        op.paymasterAndData = _pmdWithTag(cat);
        return op;
    }

    /// Compose a paymasterAndData blob: 52 bytes of zero-prefix followed
    /// by one category-tag byte. We don't need to write a real paymaster
    /// address — `_validatePaymasterUserOp` only reads the tag.
    function _pmdWithTag(uint8 tag) internal view returns (bytes memory) {
        bytes memory out = new bytes(53);
        // Optional: write the actual paymaster address to mirror what the
        // bundler emits. Not required by our paymaster's validation but
        // keeps the layout realistic.
        for (uint256 i = 0; i < 20; i++) {
            out[i] = bytes20(address(pm))[i];
        }
        out[52] = bytes1(tag);
        return out;
    }
}
