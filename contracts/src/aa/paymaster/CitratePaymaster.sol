// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BasePaymaster} from "@account-abstraction/core/BasePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";

/// WP-1 / EW-S1 — Per-user-per-day budgeted paymaster for the Citrate
/// embedded-wallet stack.
///
/// Per `ADR-2026-06-05-ew-paymaster-policy`:
///   - **Standard budget**: every Citrate wallet account gets a daily
///     gas-units allowance (default 100,000; settable by owner). Resets
///     at the start of the next UTC day after the first sponsored op
///     of any given day.
///   - **Recovery budget**: when the bundler tags a UserOp as recovery,
///     it draws from a per-event budget (default 200,000) that does NOT
///     consume the standard daily counter. Recovery flows must succeed
///     even when the user has exhausted their daily allowance.
///   - **First-op budget**: when the bundler tags a UserOp as the
///     account's first-ever transaction, sponsorship is unconditional
///     (subject to a per-op cap to bound the spend), and the first-op
///     flag flips so the same account cannot reuse it.
///   - **Fail-closed**: an account whose daily/recovery/first-op budget
///     is insufficient for the EntryPoint-reported `maxCost` reverts at
///     `validatePaymasterUserOp` so the user sees a clear refusal at
///     the bundler layer (per bundler's off-chain pre-check).
///   - **Admin pause** for incident response (operator multisig holds
///     `owner`).
///
/// Account-eligibility is enforced via a "Citrate registry" — a
/// trusted address (typically the wallet factory) calls
/// `registerWallet(account)` after a successful deploy. Only registered
/// accounts can be sponsored.
///
/// The bundler embeds a 1-byte **category tag** in the suffix of
/// `paymasterAndData` (after the standard 52-byte ERC-4337 v0.7 prefix
/// of `address paymaster | uint128 verificationGasLimit |
/// uint128 postOpGasLimit`):
///   0x00 = standard
///   0x01 = recovery
///   0x02 = first-op
contract CitratePaymaster is BasePaymaster {
    // --- Categories ---
    uint8 internal constant CAT_STANDARD = 0;
    uint8 internal constant CAT_RECOVERY = 1;
    uint8 internal constant CAT_FIRST_OP = 2;

    /// Constant offset of the category byte inside `paymasterAndData`.
    /// ERC-4337 v0.7 reserves the first 52 bytes for `paymaster + gas
    /// limits`; our suffix starts at index 52.
    uint256 internal constant PMD_TAG_OFFSET = 52;

    // --- Errors ---
    error Paused();
    error NotARegisteredCitrateWallet(address account);
    error NotARegistrar();
    error StandardCapExceeded(address account, uint256 used, uint256 cap, uint256 wouldUse);
    error RecoveryCapExceeded(address account, uint256 cap, uint256 wouldUse);
    error FirstOpAlreadyUsed(address account);
    error FirstOpCapExceeded(uint256 cap, uint256 wouldUse);
    error UnknownCategory(uint8 tag);
    error MissingCategoryTag();
    error ZeroAddress();

    // --- Events ---
    event WalletRegistered(address indexed account);
    event WalletUnregistered(address indexed account);
    event RegistrarSet(address indexed oldRegistrar, address indexed newRegistrar);
    event SponsorshipUsed(address indexed account, uint8 category, uint256 actualGasUsed);
    event PausedSet(bool paused);
    event DailyCapSet(uint256 oldCap, uint256 newCap);
    event RecoveryEventCapSet(uint256 oldCap, uint256 newCap);
    event FirstOpCapSet(uint256 oldCap, uint256 newCap);

    // --- Storage ---

    struct DailyUsage {
        uint128 used; // gas units consumed today
        uint64 dayKey; // unix day (block.timestamp / 86400) when `used` last reset
    }

    mapping(address account => DailyUsage) public dailyUsage;
    mapping(address account => bool) public isRegistered;
    mapping(address account => bool) public hasUsedFirstOp;

    /// The single address authorized to register / unregister Citrate
    /// wallets (typically `CitrateWalletFactory`). Settable by owner.
    address public registrar;

    /// Operator pause for incident response.
    bool public paused;

    /// Per-user-per-day gas-unit cap. 0 disables the standard category.
    uint256 public dailyCap;

    /// Per-event recovery budget. 0 disables recovery sponsorship.
    uint256 public recoveryEventCap;

    /// Per-call first-op budget. Bounds the deploy + first-action cost.
    uint256 public firstOpCap;

    constructor(
        IEntryPoint _entryPoint,
        address _owner,
        address _registrar,
        uint256 _dailyCap,
        uint256 _recoveryEventCap,
        uint256 _firstOpCap
    ) BasePaymaster(_entryPoint) {
        if (_owner == address(0) || _registrar == address(0)) revert ZeroAddress();
        _transferOwnership(_owner);
        registrar = _registrar;
        dailyCap = _dailyCap;
        recoveryEventCap = _recoveryEventCap;
        firstOpCap = _firstOpCap;
    }

    // --- Admin ---

    function setRegistrar(address newRegistrar) external onlyOwner {
        if (newRegistrar == address(0)) revert ZeroAddress();
        emit RegistrarSet(registrar, newRegistrar);
        registrar = newRegistrar;
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

    // --- Registrar ---

    /// Called by the wallet factory after a successful deploy.
    function registerWallet(address account) external {
        if (msg.sender != registrar) revert NotARegistrar();
        if (account == address(0)) revert ZeroAddress();
        isRegistered[account] = true;
        emit WalletRegistered(account);
    }

    /// Optional: factory may unregister a wallet (e.g. on a known
    /// compromise). Used sparingly; documented in KYC_OPERATOR.md.
    function unregisterWallet(address account) external {
        if (msg.sender != registrar) revert NotARegistrar();
        isRegistered[account] = false;
        emit WalletUnregistered(account);
    }

    // --- Reads (dashboard / SDK) ---

    function todayKey() public view returns (uint64) {
        return uint64(block.timestamp / 86400);
    }

    /// Remaining standard gas-unit budget for `account` today.
    function remainingStandard(address account) external view returns (uint256) {
        DailyUsage memory u = dailyUsage[account];
        if (u.dayKey != todayKey()) return dailyCap;
        if (u.used >= dailyCap) return 0;
        return dailyCap - u.used;
    }

    // --- Paymaster hooks ---

    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32, /*userOpHash*/
        uint256 maxCost
    ) internal override returns (bytes memory context, uint256 validationData) {
        if (paused) revert Paused();

        address account = userOp.sender;
        if (!isRegistered[account]) revert NotARegisteredCitrateWallet(account);

        if (userOp.paymasterAndData.length <= PMD_TAG_OFFSET) revert MissingCategoryTag();
        uint8 category = uint8(userOp.paymasterAndData[PMD_TAG_OFFSET]);

        if (category == CAT_STANDARD) {
            DailyUsage memory u = dailyUsage[account];
            uint64 today = todayKey();
            uint256 usedToday = u.dayKey == today ? u.used : 0;
            uint256 wouldUse = usedToday + maxCost;
            if (dailyCap == 0 || wouldUse > dailyCap) {
                revert StandardCapExceeded(account, usedToday, dailyCap, wouldUse);
            }
        } else if (category == CAT_RECOVERY) {
            if (recoveryEventCap == 0 || maxCost > recoveryEventCap) {
                revert RecoveryCapExceeded(account, recoveryEventCap, maxCost);
            }
        } else if (category == CAT_FIRST_OP) {
            if (hasUsedFirstOp[account]) revert FirstOpAlreadyUsed(account);
            if (firstOpCap == 0 || maxCost > firstOpCap) {
                revert FirstOpCapExceeded(firstOpCap, maxCost);
            }
        } else {
            revert UnknownCategory(category);
        }

        // The EntryPoint's `postOp` is required for STANDARD ops (we
        // need to record the actually-used gas against the daily
        // counter). The other categories don't need accounting, but we
        // unconditionally pass context so we can emit a SponsorshipUsed
        // event for observability.
        context = abi.encode(account, category);
        validationData = 0; // 0 == ok, no time bounds
    }

    function _postOp(
        PostOpMode, /*mode*/
        bytes calldata context,
        uint256 actualGasCost,
        uint256 /*actualUserOpFeePerGas*/
    ) internal override {
        (address account, uint8 category) = abi.decode(context, (address, uint8));

        if (category == CAT_STANDARD) {
            DailyUsage memory u = dailyUsage[account];
            uint64 today = todayKey();
            if (u.dayKey != today) {
                u.used = 0;
                u.dayKey = today;
            }
            // Saturating add — we never undercharge but a tx that exactly
            // hits the cap should still settle.
            uint256 next = uint256(u.used) + actualGasCost;
            u.used = next > type(uint128).max ? type(uint128).max : uint128(next);
            dailyUsage[account] = u;
        } else if (category == CAT_FIRST_OP) {
            hasUsedFirstOp[account] = true;
        }
        // CAT_RECOVERY: no counter; per-event budget already checked.

        emit SponsorshipUsed(account, category, actualGasCost);
    }
}
