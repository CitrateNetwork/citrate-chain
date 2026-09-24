// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {BasePaymaster} from "@account-abstraction/core/BasePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {_packValidationData} from "@account-abstraction/core/Helpers.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// WP-1 / EW-S1 — Signature-gated, wei-budgeted verifying paymaster for
/// the Citrate embedded-wallet stack.
///
/// Per `ADR-2026-07-11-e8-signature-based-paymaster` (supersedes the E-8
/// atomic-factory-registration ADR for the first-op path):
///
///   - **Signature gating (E8-1).** Every sponsored UserOp carries, in
///     the suffix of `paymasterAndData`, an ECDSA signature from a
///     trusted `sponsorSigner` over a message that binds the chainId,
///     THIS paymaster's address, the sender, the sponsorship category,
///     and a `[validAfter, validUntil]` window. The paymaster verifies
///     that signature against a signer address stored in its OWN storage.
///     No entity writes another entity's storage during validation — the
///     factory no longer calls `registerWallet` from `deployFor`'s
///     validation path, so a strict ERC-7562 bundler tracer sees the
///     paymaster touch only its own storage + `ecrecover`. This closes
///     the E8-1 cross-entity-write violation and makes the counterfactual
///     first-op mempool-legal.
///
///   - **Standard budget**: a Citrate wallet gets a daily WEI allowance
///     (default `dailyCap`). Resets at the start of the next UTC day
///     after the first sponsored op of any given day. Standard/recovery
///     additionally require the account to be `isRegistered` (a read of
///     the paymaster's OWN storage — always legal under ERC-7562
///     STO-010). Registration happens OUTSIDE the validation phase (owner
///     passthrough on the factory).
///
///   - **Recovery budget**: a recovery-tagged op draws from a per-event
///     WEI budget (`recoveryEventCap`) that does NOT consume the standard
///     daily counter, bounded by a per-account daily recovery-op COUNT
///     cap. First-op does NOT require registration — the signature is the
///     authorization — so a counterfactual wallet's very first op is
///     sponsorable with zero cross-entity writes.
///
///   - **Cap units (E8-2).** ALL three caps are denominated in WEI
///     (requiredPreFund = requiredGas × maxFeePerGas, EntryPoint L412).
///     A `maxFeePerGasCeiling` bounds the fee an attacker can claim so a
///     generous wei cap cannot be drained by a single inflated-fee op.
///     A GLOBAL daily deposit-spend cap (`globalDailyCap`) aggregates
///     spend across ALL accounts as a drain backstop.
///
///   - **Fail-closed**: any op whose signature, budget, fee ceiling, or
///     global cap check fails reverts at `validatePaymasterUserOp`.
///
///   - **Admin pause** for incident response (operator multisig holds
///     `owner`).
///
/// The `paymasterAndData` layout (ERC-4337 v0.7):
///   [0:20]    address paymaster
///   [20:36]   uint128 paymasterVerificationGasLimit
///   [36:52]   uint128 paymasterPostOpGasLimit
///   [52]      uint8   category  (0 standard / 1 recovery / 2 first-op)
///   [53:59]   uint48  validUntil
///   [59:65]   uint48  validAfter
///   [65:130]  bytes65 sponsorSigner ECDSA signature (r||s||v)
contract CitratePaymaster is BasePaymaster {
    using MessageHashUtils for bytes32;

    // --- Categories ---
    uint8 internal constant CAT_STANDARD = 0;
    uint8 internal constant CAT_RECOVERY = 1;
    uint8 internal constant CAT_FIRST_OP = 2;

    /// ERC-4337 v0.7 reserves the first 52 bytes of `paymasterAndData`
    /// for `paymaster + gas limits`; our signed suffix starts at index 52.
    uint256 internal constant PMD_TAG_OFFSET = 52; // category byte
    uint256 internal constant PMD_VALID_UNTIL_OFFSET = 53; // uint48
    uint256 internal constant PMD_VALID_AFTER_OFFSET = 59; // uint48
    uint256 internal constant PMD_SIG_OFFSET = 65; // 65-byte ECDSA sig
    uint256 internal constant PMD_MIN_LEN = 130; // 65 + 65

    // --- Errors ---
    error Paused();
    error NotARegisteredCitrateWallet(address account);
    error NotARegistrar();
    error StandardCapExceeded(address account, uint256 usedWei, uint256 capWei, uint256 wouldUseWei);
    error RecoveryCapExceeded(address account, uint256 capWei, uint256 wouldUseWei);
    error FirstOpAlreadyUsed(address account);
    error FirstOpCapExceeded(uint256 capWei, uint256 wouldUseWei);
    error UnknownCategory(uint8 tag);
    error MissingCategoryTag();
    error ZeroAddress();
    /// FWA-C3-04: too many recovery-tagged ops for this account today.
    error RecoveryDailyCountExceeded(address account, uint256 usedToday, uint256 maxPerDay);
    /// E8-1: sponsorship signature invalid / not from `sponsorSigner`.
    error InvalidSponsorSignature();
    /// E8-1: signed sponsorship window does not cover `block.timestamp`.
    error SponsorshipExpired();
    /// E8-2: per-op fee exceeds the sponsorship fee ceiling (drain guard).
    error MaxFeePerGasCeilingExceeded(uint256 maxFeePerGas, uint256 ceiling);
    /// E8-2: aggregate deposit spend today would exceed the global backstop.
    error GlobalDailyCapExceeded(uint256 spentTodayWei, uint256 capWei, uint256 wouldSpendWei);

    // --- Events ---
    event WalletRegistered(address indexed account);
    event WalletUnregistered(address indexed account);
    event RegistrarSet(address indexed oldRegistrar, address indexed newRegistrar);
    event SponsorSignerSet(address indexed oldSigner, address indexed newSigner);
    event SponsorshipUsed(address indexed account, uint8 category, uint256 actualGasCostWei);
    event PausedSet(bool paused);
    event DailyCapSet(uint256 oldCapWei, uint256 newCapWei);
    event RecoveryEventCapSet(uint256 oldCapWei, uint256 newCapWei);
    event FirstOpCapSet(uint256 oldCapWei, uint256 newCapWei);
    event RecoveryDailyCountCapSet(uint256 oldCap, uint256 newCap);
    event MaxFeePerGasCeilingSet(uint256 oldCeiling, uint256 newCeiling);
    event GlobalDailyCapSet(uint256 oldCapWei, uint256 newCapWei);

    // --- Storage ---

    /// Per-account daily spend. `usedWei` accumulates the actual WEI gas
    /// cost charged to the deposit in `_postOp` (NOT gas units).
    struct DailyUsage {
        uint128 usedWei; // WEI of deposit spent by this account today
        uint64 dayKey; // unix day (block.timestamp / 86400) when `usedWei` last reset
    }

    /// FWA-C3-04: per-account daily recovery-op counter (bounds the
    /// NUMBER of recovery-sponsored ops per account per day).
    struct RecoveryUsage {
        uint64 count; // recovery ops sponsored today
        uint64 dayKey; // unix day when `count` last reset
    }

    /// E8-2: global aggregate deposit spend across ALL accounts, per day.
    /// Drain backstop — even if per-account caps and the fee ceiling are
    /// individually satisfied, aggregate spend cannot exceed the day cap.
    struct GlobalUsage {
        uint128 spentWei; // WEI of deposit spent by ALL accounts today
        uint64 dayKey; // unix day when `spentWei` last reset
    }

    mapping(address account => DailyUsage) public dailyUsage;
    mapping(address account => RecoveryUsage) public recoveryUsage;
    mapping(address account => bool) public isRegistered;
    mapping(address account => bool) public hasUsedFirstOp;

    /// E8-2: aggregate spend backstop.
    GlobalUsage public globalUsage;

    /// The single address authorized to register / unregister Citrate
    /// wallets (typically `CitrateWalletFactory`). Settable by owner.
    address public registrar;

    /// E8-1: the address whose ECDSA signature authorizes sponsorship.
    /// Managed by the sponsorship service; rotatable by `owner`. Held in
    /// the paymaster's OWN storage so verification reads no other entity.
    address public sponsorSigner;

    /// Operator pause for incident response.
    bool public paused;

    /// Per-user-per-day WEI cap. 0 disables the standard category.
    uint256 public dailyCap;

    /// Per-event recovery budget (WEI). 0 disables recovery sponsorship.
    uint256 public recoveryEventCap;

    /// Per-call first-op budget (WEI). Bounds deploy + first-action cost.
    uint256 public firstOpCap;

    /// FWA-C3-04: max recovery-tagged ops sponsored per account per day.
    uint256 public recoveryDailyCountCap;

    /// E8-2: max `maxFeePerGas` (wei/gas) a sponsored op may claim. Bounds
    /// the drain a single generous-wei-cap op can inflict. 0 disables the
    /// check (NOT recommended in production).
    uint256 public maxFeePerGasCeiling;

    /// E8-2: aggregate deposit-spend ceiling across all accounts per UTC
    /// day. 0 disables the global backstop (NOT recommended in prod).
    uint256 public globalDailyCap;

    constructor(
        IEntryPoint _entryPoint,
        address _owner,
        address _registrar,
        address _sponsorSigner,
        uint256 _dailyCap,
        uint256 _recoveryEventCap,
        uint256 _firstOpCap,
        uint256 _maxFeePerGasCeiling,
        uint256 _globalDailyCap
    ) BasePaymaster(_entryPoint) {
        if (_owner == address(0) || _registrar == address(0) || _sponsorSigner == address(0)) {
            revert ZeroAddress();
        }
        _transferOwnership(_owner);
        registrar = _registrar;
        sponsorSigner = _sponsorSigner;
        dailyCap = _dailyCap;
        recoveryEventCap = _recoveryEventCap;
        firstOpCap = _firstOpCap;
        maxFeePerGasCeiling = _maxFeePerGasCeiling;
        globalDailyCap = _globalDailyCap;
        // A wallet should never legitimately need many recovery ops in a
        // single day. Owner can re-tune via setter.
        recoveryDailyCountCap = 3;
    }

    // --- Admin ---

    function setRegistrar(address newRegistrar) external onlyOwner {
        if (newRegistrar == address(0)) revert ZeroAddress();
        emit RegistrarSet(registrar, newRegistrar);
        registrar = newRegistrar;
    }

    function setSponsorSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        emit SponsorSignerSet(sponsorSigner, newSigner);
        sponsorSigner = newSigner;
    }

    function setPaused(bool v) external onlyOwner {
        paused = v;
        emit PausedSet(v);
    }

    function setDailyCap(uint256 v) external onlyOwner {
        emit DailyCapSet(dailyCap, v);
        dailyCap = v;
    }

    function setRecoveryEventCap(uint256 v) external onlyOwner {
        emit RecoveryEventCapSet(recoveryEventCap, v);
        recoveryEventCap = v;
    }

    function setFirstOpCap(uint256 v) external onlyOwner {
        emit FirstOpCapSet(firstOpCap, v);
        firstOpCap = v;
    }

    function setRecoveryDailyCountCap(uint256 v) external onlyOwner {
        emit RecoveryDailyCountCapSet(recoveryDailyCountCap, v);
        recoveryDailyCountCap = v;
    }

    function setMaxFeePerGasCeiling(uint256 v) external onlyOwner {
        emit MaxFeePerGasCeilingSet(maxFeePerGasCeiling, v);
        maxFeePerGasCeiling = v;
    }

    function setGlobalDailyCap(uint256 v) external onlyOwner {
        emit GlobalDailyCapSet(globalDailyCap, v);
        globalDailyCap = v;
    }

    // --- Registrar ---

    /// Called OUTSIDE the validation phase (owner passthrough on the
    /// factory, or a permitted tx) to mark a wallet sponsorship-eligible
    /// for the standard/recovery categories. Never called during a
    /// UserOp's initCode/validation (that was the E8-1 violation).
    function registerWallet(address account) external {
        if (msg.sender != registrar) revert NotARegistrar();
        if (account == address(0)) revert ZeroAddress();
        isRegistered[account] = true;
        emit WalletRegistered(account);
    }

    function unregisterWallet(address account) external {
        if (msg.sender != registrar) revert NotARegistrar();
        isRegistered[account] = false;
        emit WalletUnregistered(account);
    }

    // --- Reads (dashboard / SDK) ---

    function todayKey() public view returns (uint64) {
        return uint64(block.timestamp / 86400);
    }

    /// Remaining standard WEI budget for `account` today.
    function remainingStandard(address account) external view returns (uint256) {
        DailyUsage memory u = dailyUsage[account];
        if (u.dayKey != todayKey()) return dailyCap;
        if (u.usedWei >= dailyCap) return 0;
        return dailyCap - u.usedWei;
    }

    /// E8-1: the message digest the `sponsorSigner` signs (off-chain).
    /// Public so the sponsorship service + SDK can reconstruct it. Binds
    /// chainId (cross-chain replay), THIS paymaster (cross-paymaster
    /// replay / domain separation), the sender (cross-wallet replay), the
    /// category (so a standard grant can't be spent as first-op), the
    /// [validAfter, validUntil] window, AND the UserOp nonce.
    ///
    /// CHAIN-B-C033 (audit 2026-09-02): the digest USED to omit any per-op
    /// value, so one signature was replayable for every op from the sender for
    /// the whole window (and `validUntil == 0` made the window infinite). Since
    /// `paymasterAndData` is public calldata, anyone who observed a sponsored
    /// op could reuse that account's signature indefinitely. Binding the
    /// UserOp `nonce` makes each signature single-use for exactly one op (the
    /// EntryPoint NonceManager forbids reusing a nonce), and `validUntil == 0`
    /// is now rejected in validation.
    function sponsorDigest(
        address account,
        uint8 category,
        uint48 validUntil,
        uint48 validAfter,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                account,
                category,
                validUntil,
                validAfter,
                nonce
            )
        );
    }

    // --- Paymaster hooks ---

    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32, /*userOpHash*/
        uint256 maxCost
    ) internal override returns (bytes memory context, uint256 validationData) {
        if (paused) revert Paused();

        address account = userOp.sender;
        bytes calldata pmd = userOp.paymasterAndData;
        if (pmd.length < PMD_MIN_LEN) revert MissingCategoryTag();

        uint8 category = uint8(pmd[PMD_TAG_OFFSET]);
        uint48 validUntil = _readUint48(pmd, PMD_VALID_UNTIL_OFFSET);
        uint48 validAfter = _readUint48(pmd, PMD_VALID_AFTER_OFFSET);
        bytes calldata signature = pmd[PMD_SIG_OFFSET:PMD_MIN_LEN];

        // E8-1: authorize this op by the sponsor's signature. The digest
        // binds chainId + this paymaster + sender + category + window +
        // userOp.nonce (CHAIN-B-C033), so a signature cannot be replayed
        // across wallets, chains, paymasters, categories, or OPS. ecrecover
        // touches no external storage — ERC-7562 clean.
        _verifySponsorSignature(account, category, validUntil, validAfter, userOp.nonce, signature);

        // E8-2: bound the fee an op may claim so a generous wei cap can't
        // be drained by inflating maxFeePerGas.
        if (maxFeePerGasCeiling != 0) {
            uint256 opMaxFee = _maxFeePerGas(userOp);
            if (opMaxFee > maxFeePerGasCeiling) {
                revert MaxFeePerGasCeilingExceeded(opMaxFee, maxFeePerGasCeiling);
            }
        }

        // CHAIN-B-C021 (audit 2026-09-02): RESERVE every budget in the
        // validation phase, not just in `_postOp`. EntryPoint v0.7 runs ALL
        // validations before ANY execution, so when the counters were advanced
        // only in `_postOp`, N UserOps for one sender in a single `handleOps`
        // bundle all validated against the same pre-bundle counters and every
        // cap was bypassed at once. Writing the paymaster's OWN storage during
        // validation is ERC-7562-legal; `_postOp` then trues the reservation
        // up from `maxCost` to the actual gas cost. The reserved `maxCost` is
        // carried in `context`.
        uint64 today = todayKey();

        // E8-2: aggregate deposit-spend backstop — reserve against maxCost.
        if (globalDailyCap != 0) {
            GlobalUsage memory g = globalUsage;
            uint256 spentToday = g.dayKey == today ? g.spentWei : 0;
            uint256 wouldSpend = spentToday + maxCost;
            if (wouldSpend > globalDailyCap) {
                revert GlobalDailyCapExceeded(spentToday, globalDailyCap, wouldSpend);
            }
            g.spentWei = wouldSpend > type(uint128).max ? type(uint128).max : uint128(wouldSpend);
            g.dayKey = today;
            globalUsage = g;
        }

        if (category == CAT_STANDARD) {
            // Standard/recovery require registration (own-storage read,
            // ERC-7562 STO-010 — always legal).
            if (!isRegistered[account]) revert NotARegisteredCitrateWallet(account);
            DailyUsage memory u = dailyUsage[account];
            uint256 usedToday = u.dayKey == today ? u.usedWei : 0;
            uint256 wouldUse = usedToday + maxCost;
            if (dailyCap == 0 || wouldUse > dailyCap) {
                revert StandardCapExceeded(account, usedToday, dailyCap, wouldUse);
            }
            // CHAIN-B-C021: persist the reservation so a same-bundle sibling
            // op sees it.
            u.usedWei = wouldUse > type(uint128).max ? type(uint128).max : uint128(wouldUse);
            u.dayKey = today;
            dailyUsage[account] = u;
        } else if (category == CAT_RECOVERY) {
            if (!isRegistered[account]) revert NotARegisteredCitrateWallet(account);
            if (recoveryEventCap == 0 || maxCost > recoveryEventCap) {
                revert RecoveryCapExceeded(account, recoveryEventCap, maxCost);
            }
            // FWA-C3-04: cumulative per-account daily recovery-op count.
            // CHAIN-B-C021: advance the counter HERE (was postOp-only) so a
            // bundle cannot slip N recovery ops past the daily count cap.
            if (recoveryDailyCountCap != 0) {
                RecoveryUsage memory ru = recoveryUsage[account];
                uint256 usedToday = ru.dayKey == today ? ru.count : 0;
                if (usedToday >= recoveryDailyCountCap) {
                    revert RecoveryDailyCountExceeded(account, usedToday, recoveryDailyCountCap);
                }
                ru.count = uint64(usedToday + 1);
                ru.dayKey = today;
                recoveryUsage[account] = ru;
            }
        } else if (category == CAT_FIRST_OP) {
            // E8-1: the first op is authorized by the sponsor signature
            // ALONE — NO registration read/write. This is what makes the
            // counterfactual first op mempool-legal: during it, this
            // paymaster touches only its own storage + ecrecover, and the
            // factory writes NO paymaster storage.
            // CHAIN-B-C021: consume the one-shot flag in validation so two
            // first-ops in one bundle cannot both be sponsored.
            if (hasUsedFirstOp[account]) revert FirstOpAlreadyUsed(account);
            if (firstOpCap == 0 || maxCost > firstOpCap) {
                revert FirstOpCapExceeded(firstOpCap, maxCost);
            }
            hasUsedFirstOp[account] = true;
        } else {
            revert UnknownCategory(category);
        }

        // CHAIN-B-C021: carry the reserved maxCost so _postOp can true up.
        context = abi.encode(account, category, maxCost);
        // E8-1: return the signed time window so the EntryPoint enforces
        // it (packed validationData, ERC-4337 v0.7). sigFailed=false — we
        // already reverted on a bad signature above.
        validationData = _packValidationData(false, validUntil, validAfter);
    }

    function _postOp(
        PostOpMode, /*mode*/
        bytes calldata context,
        uint256 actualGasCost,
        uint256 /*actualUserOpFeePerGas*/
    ) internal override {
        // CHAIN-B-C021: the counters were RESERVED against `reservedMaxCost`
        // during validation. Here we refund the over-reservation
        // (`reservedMaxCost - actualGasCost`) so each counter reflects the
        // actual gas cost. Validation and postOp run in the same transaction
        // (same `todayKey()`), so no day-boundary reset can intervene, and the
        // refund never underflows because the same amount was added.
        (address account, uint8 category, uint256 reservedMaxCost) =
            abi.decode(context, (address, uint8, uint256));

        uint256 refund = reservedMaxCost > actualGasCost ? reservedMaxCost - actualGasCost : 0;

        // E8-2: true up the global aggregate spend backstop (WEI).
        if (refund != 0) {
            GlobalUsage memory g = globalUsage;
            uint256 spent = uint256(g.spentWei);
            g.spentWei = uint128(spent > refund ? spent - refund : 0);
            globalUsage = g;
        }

        if (category == CAT_STANDARD && refund != 0) {
            DailyUsage memory u = dailyUsage[account];
            uint256 used = uint256(u.usedWei);
            u.usedWei = uint128(used > refund ? used - refund : 0);
            dailyUsage[account] = u;
        }
        // CAT_FIRST_OP and CAT_RECOVERY counters (boolean flag / op count)
        // were consumed in validation and need no true-up.

        emit SponsorshipUsed(account, category, actualGasCost);
    }

    // --- Internal helpers ---

    /// E8-1: recover the sponsor signature and enforce the signed window.
    function _verifySponsorSignature(
        address account,
        uint8 category,
        uint48 validUntil,
        uint48 validAfter,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        // CHAIN-B-C033: reject an infinite sponsorship window. `validUntil == 0`
        // previously meant "never expires", so a leaked signature was usable
        // forever.
        if (validUntil == 0) revert SponsorshipExpired();
        // Enforce the window here too (defense in depth); the EntryPoint
        // also enforces it via the returned packed validationData.
        if (block.timestamp < validAfter) revert SponsorshipExpired();
        if (block.timestamp > validUntil) revert SponsorshipExpired();

        bytes32 digest = sponsorDigest(account, category, validUntil, validAfter, nonce);
        bytes32 ethDigest = digest.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethDigest, signature);
        if (err != ECDSA.RecoverError.NoError || recovered != sponsorSigner) {
            revert InvalidSponsorSignature();
        }
    }

    /// Read a big-endian uint48 out of `paymasterAndData` at `offset`.
    function _readUint48(bytes calldata pmd, uint256 offset) internal pure returns (uint48 v) {
        // 6 bytes, big-endian.
        for (uint256 i = 0; i < 6; i++) {
            v = uint48((uint256(v) << 8) | uint8(pmd[offset + i]));
        }
    }

    /// The op's maxFeePerGas (wei/gas). `gasFees` packs
    /// [maxPriorityFeePerGas(16) | maxFeePerGas(16)] per UserOperationLib.
    function _maxFeePerGas(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return uint128(uint256(userOp.gasFees));
    }
}
