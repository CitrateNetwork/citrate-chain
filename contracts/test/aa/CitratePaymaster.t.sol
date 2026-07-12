// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {IPaymaster} from "@account-abstraction/interfaces/IPaymaster.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

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
    using MessageHashUtils for bytes32;

    CitratePaymaster internal pm;
    StubEntryPoint internal entryPoint;

    address internal ownerAddr = address(0xA11CE);
    address internal registrar = address(0xFAC7);
    address internal account = address(0xACC1);
    address internal otherAccount = address(0xACC2);

    uint256 internal constant SPONSOR_PK = 0x59E7;
    address internal sponsorSigner;

    // E8-2: caps are now WEI. Round wei values keep the arithmetic
    // readable; maxCost inputs below are sub-cap WEI amounts.
    uint256 internal constant DAILY = 0.01 ether;
    uint256 internal constant RECOVERY = 0.01 ether;
    uint256 internal constant FIRST_OP = 0.02 ether;
    // The shared paymaster disables the maxFeePerGas ceiling and the
    // global cap (0 == disabled) so the category/cap unit tests below are
    // not perturbed by them; dedicated tests construct enabled paymasters.
    uint256 internal constant MAX_FEE_CEIL = 0;
    uint256 internal constant GLOBAL_CAP = 0;

    function setUp() public {
        sponsorSigner = vm.addr(SPONSOR_PK);
        entryPoint = new StubEntryPoint();
        pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)),
            ownerAddr,
            registrar,
            sponsorSigner,
            DAILY,
            RECOVERY,
            FIRST_OP,
            MAX_FEE_CEIL,
            GLOBAL_CAP
        );

        // Register one wallet (standard/recovery require registration).
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

    // ── E8-1: sponsor-signature gating ──

    function test_setSponsorSigner_onlyByOwner_rotatesAuthority() public {
        address newSigner = address(0xD00D);
        vm.expectRevert();
        pm.setSponsorSigner(newSigner);

        vm.prank(ownerAddr);
        vm.expectRevert(CitratePaymaster.ZeroAddress.selector);
        pm.setSponsorSigner(address(0));

        vm.prank(ownerAddr);
        pm.setSponsorSigner(newSigner);
        assertEq(pm.sponsorSigner(), newSigner);
    }

    /// A valid category tag with NO / a WRONG signature must be refused —
    /// the signature is now the authorization, not a self-asserted tag.
    function test_validate_firstOp_wrongSigner_reverts() public {
        PackedUserOperation memory op = _baseOp(account);
        // Sign with a NON-sponsor key.
        op.paymasterAndData = _signedPmd(account, 2, _until(), _after(), 0xBADBAD);
        vm.expectRevert(CitratePaymaster.InvalidSponsorSignature.selector);
        _validate(account, op, _wei(1));
    }

    /// A signature for account X must not authorize account Y (cross-wallet
    /// replay). The digest binds the sender.
    function test_validate_signatureBoundToSender() public {
        PackedUserOperation memory op = _baseOp(otherAccount);
        // Signature is for `account`, but the op sender is `otherAccount`.
        op.paymasterAndData = _signedPmd(account, 2, _until(), _after(), SPONSOR_PK);
        vm.expectRevert(CitratePaymaster.InvalidSponsorSignature.selector);
        _validate(otherAccount, op, _wei(1));
    }

    /// A signature for category standard(0) must not be spendable as
    /// first-op(2) — the digest binds the category.
    function test_validate_signatureBoundToCategory() public {
        PackedUserOperation memory op = _baseOp(account);
        // Sign category 0, but place tag byte 2 in the blob.
        bytes memory sig = _sponsorSig(account, 0, _until(), _after(), SPONSOR_PK);
        op.paymasterAndData = _pmdWithSig(2, _until(), _after(), sig);
        vm.expectRevert(CitratePaymaster.InvalidSponsorSignature.selector);
        _validate(account, op, _wei(1));
    }

    /// A signed op past its validUntil must revert (window enforced in the
    /// paymaster too, defense-in-depth over EntryPoint's validationData).
    function test_validate_expiredWindow_reverts() public {
        uint48 until = uint48(block.timestamp + 100);
        PackedUserOperation memory op = _baseOp(account);
        op.paymasterAndData = _signedPmd(account, 2, until, 0, SPONSOR_PK);
        vm.warp(block.timestamp + 101);
        vm.expectRevert(CitratePaymaster.SponsorshipExpired.selector);
        _validate(account, op, _wei(1));
    }

    /// The returned validationData packs [validAfter, validUntil] so the
    /// EntryPoint enforces the same window.
    function test_validate_returnsPackedTimeRange() public {
        uint48 until = uint48(block.timestamp + 1000);
        uint48 aft = uint48(block.timestamp);
        PackedUserOperation memory op = _baseOp(account);
        op.paymasterAndData = _signedPmd(account, 2, until, aft, SPONSOR_PK);
        vm.prank(address(entryPoint));
        (, uint256 validationData) = pm.validatePaymasterUserOp(op, bytes32(0), _wei(1));
        // Layout: [0:20] aggregator | [160:208] validUntil | [208:256] validAfter
        assertEq(uint160(validationData), 0, "sigFailed/aggregator must be 0 (success)");
        uint48 gotUntil = uint48(validationData >> 160);
        uint48 gotAfter = uint48(validationData >> (160 + 48));
        assertEq(gotUntil, until, "packed validUntil");
        assertEq(gotAfter, aft, "packed validAfter");
    }

    // ── Validation: standard category ──

    function test_validate_standard_within_cap_succeeds() public {
        uint256 maxCost = 0.003 ether;
        bytes memory ctx = _validate(account, _userOpStandard(account), maxCost);
        (address a, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(a, account);
        assertEq(c, 0);
    }

    function test_validate_standard_aboveCap_reverts() public {
        uint256 maxCost = DAILY + 1;
        PackedUserOperation memory op = _userOpStandard(account);
        vm.expectRevert();
        _validate(account, op, maxCost);
    }

    function test_validate_standard_unregisteredAccount_reverts() public {
        PackedUserOperation memory op = _userOpStandard(otherAccount);
        vm.expectRevert(abi.encodeWithSelector(CitratePaymaster.NotARegisteredCitrateWallet.selector, otherAccount));
        _validate(otherAccount, op, _wei(1));
    }

    function test_validate_whenPaused_reverts() public {
        vm.prank(ownerAddr);
        pm.setPaused(true);
        PackedUserOperation memory op = _userOpStandard(account);
        vm.expectRevert(CitratePaymaster.Paused.selector);
        _validate(account, op, _wei(1));
    }

    function test_validate_missingCategoryTag_reverts() public {
        PackedUserOperation memory op = _baseOp(account);
        // Shorter than the signed suffix — no full blob.
        op.paymasterAndData = new bytes(52);
        vm.expectRevert(CitratePaymaster.MissingCategoryTag.selector);
        _validate(account, op, _wei(1));
    }

    function test_validate_unknownCategory_reverts() public {
        // A validly-signed category 99 gets past the signature check, then
        // trips UnknownCategory.
        PackedUserOperation memory op = _baseOp(account);
        op.paymasterAndData = _signedPmd(account, 99, _until(), _after(), SPONSOR_PK);
        vm.expectRevert(abi.encodeWithSelector(CitratePaymaster.UnknownCategory.selector, uint8(99)));
        _validate(account, op, _wei(1));
    }

    // ── Accounting on postOp ──

    function test_postOp_standardAccountsAgainstDaily() public {
        uint256 maxCost = 0.003 ether;
        bytes memory ctx = _validate(account, _userOpStandard(account), maxCost);
        uint256 actual = 0.0025 ether;
        _postOp(ctx, actual);

        (uint128 usedWei, uint64 dayKey) = pm.dailyUsage(account);
        assertEq(uint256(usedWei), actual);
        assertEq(uint256(dayKey), uint256(pm.todayKey()));
        assertEq(pm.remainingStandard(account), DAILY - actual);
    }

    function test_postOp_standardAccumulatesAcrossOpsSameDay() public {
        uint256 a1 = 0.002 ether;
        uint256 a2 = 0.003 ether;

        bytes memory c1 = _validate(account, _userOpStandard(account), a1);
        _postOp(c1, a1);
        bytes memory c2 = _validate(account, _userOpStandard(account), a2);
        _postOp(c2, a2);

        (uint128 usedWei,) = pm.dailyUsage(account);
        assertEq(uint256(usedWei), a1 + a2);
    }

    function test_postOp_standardResetsAcrossDays() public {
        bytes memory c = _validate(account, _userOpStandard(account), 0.002 ether);
        _postOp(c, 0.002 ether);

        vm.warp(block.timestamp + 86400 + 7200);

        c = _validate(account, _userOpStandard(account), 0.001 ether);
        _postOp(c, 0.001 ether);

        (uint128 usedWei, uint64 dayKey) = pm.dailyUsage(account);
        assertEq(uint256(usedWei), 0.001 ether, "counter reset on new day");
        assertEq(uint256(dayKey), uint256(pm.todayKey()));
    }

    function test_validate_standard_secondOpWithRemainingBudget_passes() public {
        bytes memory c1 = _validate(account, _userOpStandard(account), 0.006 ether);
        _postOp(c1, 0.006 ether);

        // remaining = 0.004 ether; this op costs exactly the remainder.
        bytes memory c2 = _validate(account, _userOpStandard(account), 0.004 ether);
        _postOp(c2, 0.004 ether);

        (uint128 usedWei,) = pm.dailyUsage(account);
        assertEq(uint256(usedWei), DAILY);
        assertEq(pm.remainingStandard(account), 0);
    }

    function test_validate_standard_thirdOpExceedingRemaining_reverts() public {
        bytes memory c1 = _validate(account, _userOpStandard(account), 0.006 ether);
        _postOp(c1, 0.006 ether);

        // remaining = 0.004 ether; ask for 0.005 ether.
        PackedUserOperation memory op = _userOpStandard(account);
        vm.expectRevert();
        _validate(account, op, 0.005 ether);
    }

    // ── Recovery category ──

    function test_validate_recovery_underCap_passes() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 1), 0.008 ether);
        (, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(c, 1);
    }

    function test_validate_recovery_overCap_reverts() public {
        PackedUserOperation memory op = _userOpCat(account, 1);
        vm.expectRevert();
        _validate(account, op, RECOVERY + 1);
    }

    function test_recovery_doesNotConsumeDailyBudget() public {
        bytes memory c1 = _validate(account, _userOpStandard(account), 0.008 ether);
        _postOp(c1, 0.008 ether);

        bytes memory c2 = _validate(account, _userOpCat(account, 1), 0.008 ether);
        _postOp(c2, 0.008 ether);

        (uint128 usedWei,) = pm.dailyUsage(account);
        assertEq(uint256(usedWei), 0.008 ether);
    }

    // ── FWA-C3-04: recovery daily COUNT cap (deposit-drain bound) ──

    function test_C3_04_recovery_daily_count_cap_blocks_drain() public {
        assertEq(pm.recoveryDailyCountCap(), 3);

        for (uint256 i = 0; i < 3; i++) {
            bytes memory ctx = _validate(account, _userOpCat(account, 1), 0.008 ether);
            _postOp(ctx, 0.008 ether);
        }

        PackedUserOperation memory op = _userOpCat(account, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                CitratePaymaster.RecoveryDailyCountExceeded.selector, account, uint256(3), uint256(3)
            )
        );
        _validate(account, op, 0.008 ether);
    }

    function test_C3_04_recovery_count_resets_next_day() public {
        for (uint256 i = 0; i < 3; i++) {
            bytes memory ctx = _validate(account, _userOpCat(account, 1), 0.008 ether);
            _postOp(ctx, 0.008 ether);
        }
        vm.warp(block.timestamp + 1 days);
        bytes memory ctx2 = _validate(account, _userOpCat(account, 1), 0.008 ether);
        (, uint8 c) = abi.decode(ctx2, (address, uint8));
        assertEq(c, 1);
    }

    function test_C3_04_count_cap_zero_means_unlimited() public {
        vm.prank(ownerAddr);
        pm.setRecoveryDailyCountCap(0);
        for (uint256 i = 0; i < 10; i++) {
            bytes memory ctx = _validate(account, _userOpCat(account, 1), 0.008 ether);
            _postOp(ctx, 0.008 ether);
        }
    }

    // ── First-op category ──

    /// E8-1: first-op does NOT require registration — the signature alone
    /// authorizes it. An UNREGISTERED (counterfactual) account must be
    /// sponsorable on its first op.
    function test_validate_firstOp_unregisteredAccount_passes() public {
        assertFalse(pm.isRegistered(otherAccount), "counterfactual: not registered");
        bytes memory ctx = _validate(otherAccount, _userOpCat(otherAccount, 2), 0.015 ether);
        (, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(c, 2);
    }

    function test_validate_firstOp_passes() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 2), 0.015 ether);
        (, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(c, 2);
    }

    function test_firstOp_flagsAccountAfterPostOp() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 2), 0.015 ether);
        _postOp(ctx, 0.015 ether);
        assertTrue(pm.hasUsedFirstOp(account));
    }

    function test_validate_secondFirstOp_reverts() public {
        bytes memory ctx = _validate(account, _userOpCat(account, 2), 0.015 ether);
        _postOp(ctx, 0.015 ether);

        PackedUserOperation memory op2 = _userOpCat(account, 2);
        vm.expectRevert(abi.encodeWithSelector(CitratePaymaster.FirstOpAlreadyUsed.selector, account));
        _validate(account, op2, 0.015 ether);
    }

    function test_validate_firstOp_overCap_reverts() public {
        PackedUserOperation memory op = _userOpCat(account, 2);
        vm.expectRevert();
        _validate(account, op, FIRST_OP + 1);
    }

    // ── E8-2: maxFeePerGas ceiling (over-sponsor drain guard) ──

    /// An op whose maxFeePerGas exceeds the ceiling is refused even though
    /// its maxCost is under the wei cap — this is the fee-inflation drain
    /// vector the reviewer flagged.
    function test_E82_maxFeePerGasCeiling_blocksInflatedFee() public {
        CitratePaymaster capped = _cappedPm(20 gwei, 0);
        vm.prank(registrar);
        capped.registerWallet(account);

        // maxFeePerGas = 21 gwei > 20 gwei ceiling → revert.
        PackedUserOperation memory op = _baseOp(account);
        op.gasFees = _packGasFees(1 gwei, 21 gwei);
        op.paymasterAndData = _signedPmdFor(capped, account, 2, _until(), _after(), SPONSOR_PK);
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(CitratePaymaster.MaxFeePerGasCeilingExceeded.selector, uint256(21 gwei), uint256(20 gwei))
        );
        capped.validatePaymasterUserOp(op, bytes32(0), 0.015 ether);
    }

    function test_E82_maxFeePerGasCeiling_atOrBelow_passes() public {
        CitratePaymaster capped = _cappedPm(20 gwei, 0);
        vm.prank(registrar);
        capped.registerWallet(account);

        PackedUserOperation memory op = _baseOp(account);
        op.gasFees = _packGasFees(1 gwei, 20 gwei); // == ceiling, allowed
        op.paymasterAndData = _signedPmdFor(capped, account, 2, _until(), _after(), SPONSOR_PK);
        vm.prank(address(entryPoint));
        (bytes memory ctx,) = capped.validatePaymasterUserOp(op, bytes32(0), 0.015 ether);
        (, uint8 c) = abi.decode(ctx, (address, uint8));
        assertEq(c, 2);
    }

    // ── E8-2: global daily deposit-spend backstop ──

    /// Even with per-account caps and the fee ceiling satisfied, aggregate
    /// spend across all accounts cannot exceed the global daily cap.
    function test_E82_globalDailyCap_backstopsAggregateDrain() public {
        // Global cap 0.03 ether; first-op cap 0.02 ether.
        CitratePaymaster capped = _cappedPm(0, 0.03 ether);
        vm.prank(registrar);
        capped.registerWallet(account);
        vm.prank(registrar);
        capped.registerWallet(otherAccount);

        // Op 1: account first-op 0.02 ether — under global.
        _validateGlobal(capped, account, 2, 0.02 ether);
        _postOpOn(capped, abi.encode(account, uint8(2)), 0.02 ether);

        // Op 2: otherAccount first-op 0.02 ether — would push aggregate to
        // 0.04 ether > 0.03 ether global cap → revert.
        PackedUserOperation memory op = _baseOp(otherAccount);
        op.paymasterAndData = _signedPmdFor(capped, otherAccount, 2, _until(), _after(), SPONSOR_PK);
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                CitratePaymaster.GlobalDailyCapExceeded.selector,
                uint256(0.02 ether),
                uint256(0.03 ether),
                uint256(0.04 ether)
            )
        );
        capped.validatePaymasterUserOp(op, bytes32(0), 0.02 ether);
    }

    function test_E82_globalDailyCap_resetsNextDay() public {
        CitratePaymaster capped = _cappedPm(0, 0.03 ether);
        vm.prank(registrar);
        capped.registerWallet(account);

        _validateGlobal(capped, account, 2, 0.02 ether);
        _postOpOn(capped, abi.encode(account, uint8(2)), 0.02 ether);
        (uint128 spent,) = capped.globalUsage();
        assertEq(uint256(spent), 0.02 ether);

        vm.warp(block.timestamp + 1 days);
        // New day: aggregate resets; a fresh account first-op passes.
        vm.prank(registrar);
        capped.registerWallet(otherAccount);
        _validateGlobal(capped, otherAccount, 2, 0.02 ether);
    }

    // ── Caller restrictions ──

    function test_validatePaymasterUserOp_externalCallerMustBeEntryPoint() public {
        PackedUserOperation memory op = _userOpStandard(account);
        vm.expectRevert();
        pm.validatePaymasterUserOp(op, bytes32(0), _wei(1));
    }

    function test_postOp_externalCallerMustBeEntryPoint() public {
        bytes memory ctx = abi.encode(account, uint8(0));
        vm.expectRevert();
        pm.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 1, 1);
    }

    // ── Admin caps ──

    function test_setDailyCap_onlyOwner() public {
        vm.expectRevert();
        pm.setDailyCap(0.005 ether);

        vm.prank(ownerAddr);
        pm.setDailyCap(0.005 ether);
        assertEq(pm.dailyCap(), 0.005 ether);
    }

    function test_setRecoveryEventCap_onlyOwner() public {
        vm.expectRevert();
        pm.setRecoveryEventCap(0);

        vm.prank(ownerAddr);
        pm.setRecoveryEventCap(0);
        assertEq(pm.recoveryEventCap(), 0);

        PackedUserOperation memory op = _userOpCat(account, 1);
        vm.expectRevert();
        _validate(account, op, _wei(1));
    }

    function test_setFirstOpCap_onlyOwner() public {
        vm.expectRevert();
        pm.setFirstOpCap(0);

        vm.prank(ownerAddr);
        pm.setFirstOpCap(0);
        assertEq(pm.firstOpCap(), 0);

        PackedUserOperation memory op = _userOpCat(account, 2);
        vm.expectRevert();
        _validate(account, op, _wei(1));
    }

    function test_setMaxFeePerGasCeiling_onlyOwner() public {
        vm.expectRevert();
        pm.setMaxFeePerGasCeiling(10 gwei);

        vm.prank(ownerAddr);
        pm.setMaxFeePerGasCeiling(10 gwei);
        assertEq(pm.maxFeePerGasCeiling(), 10 gwei);
    }

    function test_setGlobalDailyCap_onlyOwner() public {
        vm.expectRevert();
        pm.setGlobalDailyCap(1 ether);

        vm.prank(ownerAddr);
        pm.setGlobalDailyCap(1 ether);
        assertEq(pm.globalDailyCap(), 1 ether);
    }

    // ── Helpers ──

    function _wei(uint256 x) internal pure returns (uint256) {
        return x;
    }

    function _until() internal view returns (uint48) {
        return uint48(block.timestamp + 1 hours);
    }

    function _after() internal view returns (uint48) {
        return uint48(block.timestamp);
    }

    function _cappedPm(uint256 feeCeiling, uint256 globalCap) internal returns (CitratePaymaster) {
        return new CitratePaymaster(
            IEntryPoint(address(entryPoint)),
            ownerAddr,
            registrar,
            sponsorSigner,
            DAILY,
            RECOVERY,
            FIRST_OP,
            feeCeiling,
            globalCap
        );
    }

    function _validate(address sender, PackedUserOperation memory op, uint256 maxCost)
        internal
        returns (bytes memory ctx)
    {
        op.sender = sender;
        vm.prank(address(entryPoint));
        (ctx,) = pm.validatePaymasterUserOp(op, bytes32(0), maxCost);
    }

    function _validateGlobal(CitratePaymaster target, address sender, uint8 cat, uint256 maxCost)
        internal
        returns (bytes memory ctx)
    {
        PackedUserOperation memory op = _baseOp(sender);
        op.paymasterAndData = _signedPmdFor(target, sender, cat, _until(), _after(), SPONSOR_PK);
        vm.prank(address(entryPoint));
        (ctx,) = target.validatePaymasterUserOp(op, bytes32(0), maxCost);
    }

    function _postOp(bytes memory ctx, uint256 actualGasCost) internal {
        vm.prank(address(entryPoint));
        pm.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, actualGasCost, 1);
    }

    function _postOpOn(CitratePaymaster target, bytes memory ctx, uint256 actualGasCost) internal {
        vm.prank(address(entryPoint));
        target.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, actualGasCost, 1);
    }

    function _baseOp(address sender) internal pure returns (PackedUserOperation memory op) {
        op.sender = sender;
    }

    function _userOpStandard(address sender) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory op = _baseOp(sender);
        op.paymasterAndData = _signedPmd(sender, 0, _until(), _after(), SPONSOR_PK);
        return op;
    }

    function _userOpCat(address sender, uint8 cat) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory op = _baseOp(sender);
        op.paymasterAndData = _signedPmd(sender, cat, _until(), _after(), SPONSOR_PK);
        return op;
    }

    /// Build the full signed paymasterAndData blob against `pm`.
    function _signedPmd(address sender, uint8 cat, uint48 until, uint48 aft, uint256 signPk)
        internal
        view
        returns (bytes memory)
    {
        bytes memory sig = _sponsorSig(sender, cat, until, aft, signPk);
        return _pmdWithSig(cat, until, aft, sig);
    }

    /// Build the blob against an arbitrary paymaster `target` (its address
    /// is part of the signed digest for domain separation).
    function _signedPmdFor(CitratePaymaster target, address sender, uint8 cat, uint48 until, uint48 aft, uint256 signPk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = target.sponsorDigest(sender, cat, until, aft);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signPk, digest.toEthSignedMessageHash());
        bytes memory sig = abi.encodePacked(r, s, v);
        return _pmdWithSigFor(target, cat, until, aft, sig);
    }

    function _sponsorSig(address sender, uint8 cat, uint48 until, uint48 aft, uint256 signPk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = pm.sponsorDigest(sender, cat, until, aft);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signPk, digest.toEthSignedMessageHash());
        return abi.encodePacked(r, s, v);
    }

    /// Compose paymasterAndData: 52-byte prefix (pm addr + gas limits) then
    /// [tag(1) | validUntil(6) | validAfter(6) | signature(65)].
    function _pmdWithSig(uint8 tag, uint48 until, uint48 aft, bytes memory sig) internal view returns (bytes memory) {
        return _pmdWithSigFor(pm, tag, until, aft, sig);
    }

    function _pmdWithSigFor(CitratePaymaster target, uint8 tag, uint48 until, uint48 aft, bytes memory sig)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            address(target), // [0:20]
            uint128(0), // [20:36] verificationGasLimit
            uint128(0), // [36:52] postOpGasLimit
            bytes1(tag), // [52]
            uint48(until), // [53:59]
            uint48(aft), // [59:65]
            sig // [65:130]
        );
    }

    function _packGasFees(uint256 maxPriority, uint256 maxFee) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(uint128(maxPriority), uint128(maxFee)));
    }
}
