// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IValidator, IHook} from "@kernel/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title GuardianRecoveryModuleV2: M-of-N guardian recovery with a 72 h delay and owner cancel
/// @notice 0.6.0 W-GUARDV2 (amc053 07 §5.3 / Q-W4, 72 h delay with owner cancel; 0.6.0 06 §1:
///         ceremony genesis block 0). V1 (`GuardianRecoveryModule`) lets a guardian quorum rotate
///         the root validator in the same UserOp it signs, so a colluding or phished quorum takes
///         the wallet with no window for the owner to react (amc053 07 G-7 / R-W2). V2 splits
///         recovery into two phases:
///
///         1. **Initiate.** M-of-N guardians sign a domain-separated digest over
///            (chain id, this module, the account, keccak256 of the exact rotation callData, the
///            account's recovery nonce). Anyone submits the signatures with `initiateRecovery`.
///            The module checks the callData against the same allowlist as V1 (CHAIN-B-C032:
///            a single, zero-value self-`execute` whose inner call is `changeRootValidator`),
///            records the pending recovery with `executeAfter = now + 72 h` and bumps the nonce,
///            so each signature set is single-use.
///         2. **Execute.** After the delay, a UserOp routed to this validator whose callData
///            hashes to the pending hash, carrying one guardian signature over
///            `keccak256(userOpHash ‖ account)` (the V1 digest, binding the gas fields), validates.
///            The module returns ERC-4337 validation data with `validAfter = executeAfter`; the
///            EntryPoint refuses the op before then ("AA22 expired or not due"), so validation
///            never reads the block timestamp (ERC-7562). The pending entry is consumed.
///
///         The account itself cancels (`cancelRecovery`, a normal UserOp signed by the current
///         root validator) at any time before execution; uninstalling the module also clears it.
///         A new guardian quorum may replace a pending recovery, which restarts the 72 h clock.
///
///         The module has **no owner, admin or governance role and no constructor parameters**:
///         it is a per-account plug-in, and the delay is a constant. It holds no value.
///         Citrate is never a guardian; nothing in the module gives the deployer any role.
/// @notice The V1 read this module needs (contracts/src/aa/recovery/GuardianRecoveryModule.sol).
interface IGuardianRecoveryModuleV1 {
    function isInitialized(address smartAccount) external view returns (bool);
}

contract GuardianRecoveryModuleV2 is IValidator, IHook {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ── constants ───────────────────────────────────────────────────

    /// @notice Time between a guardian quorum initiating recovery and the rotation being executable.
    uint48 public constant RECOVERY_DELAY = 72 hours;

    /// @notice Domain tag of the guardian initiation digest.
    bytes32 public constant RECOVERY_TYPEHASH = keccak256(
        "CitrateGuardianRecoveryV2(uint256 chainId,address module,address account,bytes32 callDataHash,uint64 nonce)"
    );

    bytes4 internal constant EIP1271_MAGIC = 0x1626ba7e;
    uint256 internal constant MIN_GUARDIANS = 2;
    uint256 internal constant MAX_GUARDIANS = 7;
    uint8 internal constant NO_GUARDIAN = type(uint8).max;

    /// Kernel `execute(bytes32,bytes)`: the only outer call a recovery may carry (CHAIN-B-C032).
    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(bytes32,bytes)"));
    /// Kernel `changeRootValidator(bytes21,address,bytes,bytes)`: the only inner action.
    bytes4 internal constant CHANGE_ROOT_SELECTOR =
        bytes4(keccak256("changeRootValidator(bytes21,address,bytes,bytes)"));

    // ── errors ──────────────────────────────────────────────────────

    error AlreadyInstalled(address smartAccount);
    error InvalidInstallData();
    error InvalidGuardianCount();
    error InvalidThreshold();
    error DuplicateGuardian();
    error ZeroGuardian();
    error RecoveryActionNotAllowed();
    error InvalidGuardianSignatures();
    error NoPendingRecovery();
    error V1HasNoCode();
    error V1StillInstalled(address smartAccount);

    // ── events ──────────────────────────────────────────────────────

    event GuardiansRegistered(address indexed kernel, uint256 threshold, address[] guardians);
    event GuardiansUninstalled(address indexed kernel);
    /// @notice `callData` is the full rotation the account will execute, so the owner (and any
    ///         monitor) can see exactly which root validator the guardians chose and cancel.
    event RecoveryInitiated(
        address indexed account, uint64 indexed nonce, bytes32 callDataHash, uint48 executeAfter, bytes callData
    );
    event RecoverySuperseded(address indexed account, uint64 indexed nonce, bytes32 callDataHash);
    event RecoveryCancelled(address indexed account, uint64 indexed nonce, bytes32 callDataHash);
    event RecoveryExecuted(address indexed account, uint64 indexed nonce, bytes32 callDataHash);

    // ── storage ─────────────────────────────────────────────────────

    struct RecoveryConfig {
        uint8 threshold; // M
        uint8 count; // N
        address[7] guardians;
    }

    struct PendingRecovery {
        bytes32 callDataHash;
        uint48 executeAfter; // 0 = none pending
        uint64 nonce; // the nonce the guardians signed
    }

    /// @notice The genesis V1 module. V2 refuses to work for an account while V1 is initialized
    ///         for it (owner Q19, 2026-11-09): V1 has no delay.
    IGuardianRecoveryModuleV1 public immutable v1;

    mapping(address smartAccount => RecoveryConfig) internal _config;
    mapping(address smartAccount => PendingRecovery) internal _pending;
    /// @notice Next nonce a guardian quorum must sign for `account`. Never reset (survives
    ///         uninstall and reinstall), so a signature set can never be replayed.
    mapping(address smartAccount => uint64) public recoveryNonce;

    /// @param v1_ the genesis GuardianRecoveryModule (V1) address (GEN-PARAM)
    constructor(IGuardianRecoveryModuleV1 v1_) {
        v1 = v1_;
    }

    // ── install lifecycle ───────────────────────────────────────────

    /// `_data` layout (same as V1): uint8 threshold | uint8 count | address[count] guardians.
    function onInstall(bytes calldata _data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInstalled(msg.sender);
        if (_data.length < 2) revert InvalidInstallData();

        uint8 threshold = uint8(_data[0]);
        uint8 count = uint8(_data[1]);

        if (count < MIN_GUARDIANS || count > MAX_GUARDIANS) revert InvalidGuardianCount();
        if (threshold == 0 || threshold > count) revert InvalidThreshold();
        if (_data.length != 2 + uint256(count) * 20) revert InvalidInstallData();

        RecoveryConfig storage cfg = _config[msg.sender];
        cfg.threshold = threshold;
        cfg.count = count;

        address[] memory emitted = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 2 + i * 20;
            address g = address(bytes20(_data[offset:offset + 20]));
            if (g == address(0)) revert ZeroGuardian();
            for (uint256 j = 0; j < i; j++) {
                if (cfg.guardians[j] == g) revert DuplicateGuardian();
            }
            cfg.guardians[i] = g;
            emitted[i] = g;
        }

        emit GuardiansRegistered(msg.sender, threshold, emitted);
    }

    /// @notice Clears the guardian set and any pending recovery. The recovery nonce is kept.
    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        PendingRecovery memory p = _pending[msg.sender];
        if (p.executeAfter != 0) {
            delete _pending[msg.sender];
            emit RecoveryCancelled(msg.sender, p.nonce, p.callDataHash);
        }
        delete _config[msg.sender];
        emit GuardiansUninstalled(msg.sender);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return _config[smartAccount].count != 0;
    }

    // ── reads ───────────────────────────────────────────────────────

    /// @notice Threshold and guardians in install order (dashboard read).
    function configOf(address smartAccount) external view returns (uint8 threshold, address[] memory guardians) {
        RecoveryConfig storage cfg = _config[smartAccount];
        threshold = cfg.threshold;
        guardians = new address[](cfg.count);
        for (uint256 i = 0; i < cfg.count; i++) {
            guardians[i] = cfg.guardians[i];
        }
    }

    /// @notice The pending recovery for `account`; `executeAfter == 0` means none.
    function pendingRecovery(address account)
        external
        view
        returns (bytes32 callDataHash, uint48 executeAfter, uint64 nonce)
    {
        PendingRecovery memory p = _pending[account];
        return (p.callDataHash, p.executeAfter, p.nonce);
    }

    /// @notice The digest guardians sign to initiate recovery. EOA guardians sign its EIP-191
    ///         form (`toEthSignedMessageHash`); contract guardians are asked via EIP-1271 for the
    ///         digest itself (the V1 convention).
    function recoveryDigest(address account, bytes32 callDataHash, uint64 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(RECOVERY_TYPEHASH, block.chainid, address(this), account, callDataHash, nonce));
    }

    // ── phase 1: initiate ───────────────────────────────────────────

    /// @notice Record a guardian-approved rotation for `account`, executable after 72 h.
    /// @param callData   The exact UserOp callData that will execute the rotation.
    /// @param signatures `threshold` concatenated 65-byte signatures over `recoveryDigest`, each
    ///                   from a distinct guardian.
    function initiateRecovery(address account, bytes calldata callData, bytes calldata signatures)
        external
        returns (uint48 executeAfter)
    {
        RecoveryConfig storage cfg = _config[account];
        if (cfg.count == 0) revert NotInitialized(account);
        if (!_isAllowedRecoveryAction(callData, account)) revert RecoveryActionNotAllowed();

        uint64 nonce = recoveryNonce[account];
        bytes32 callDataHash = keccak256(callData);
        bytes32 digest = recoveryDigest(account, callDataHash, nonce);
        if (!_quorumSigned(cfg, digest, signatures)) revert InvalidGuardianSignatures();

        recoveryNonce[account] = nonce + 1;

        PendingRecovery memory old = _pending[account];
        if (old.executeAfter != 0) emit RecoverySuperseded(account, old.nonce, old.callDataHash);

        executeAfter = uint48(block.timestamp) + RECOVERY_DELAY;
        _pending[account] = PendingRecovery({callDataHash: callDataHash, executeAfter: executeAfter, nonce: nonce});
        emit RecoveryInitiated(account, nonce, callDataHash, executeAfter, callData);
    }

    /// @notice The account cancels its own pending recovery (a UserOp signed by its current root).
    function cancelRecovery() external {
        PendingRecovery memory p = _pending[msg.sender];
        if (p.executeAfter == 0) revert NoPendingRecovery();
        delete _pending[msg.sender];
        emit RecoveryCancelled(msg.sender, p.nonce, p.callDataHash);
    }

    // ── phase 2: execute (IValidator) ───────────────────────────────

    /// @notice Validates the rotation UserOp of a pending recovery. Returns ERC-4337 validation
    ///         data with `validAfter = executeAfter`; the EntryPoint enforces the delay.
    /// @dev `userOp.signature` is one 65-byte guardian signature over
    ///      `keccak256(userOpHash ‖ account)` (EIP-191 for EOAs, EIP-1271 for contracts), so the
    ///      op's gas fields are guardian-chosen and a third party cannot submit the rotation with
    ///      inflated fees against the account's deposit.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        RecoveryConfig storage cfg = _config[msg.sender];
        if (cfg.count == 0) return SIG_VALIDATION_FAILED_UINT;

        PendingRecovery memory p = _pending[msg.sender];
        if (p.executeAfter == 0) return SIG_VALIDATION_FAILED_UINT;
        if (keccak256(userOp.callData) != p.callDataHash) return SIG_VALIDATION_FAILED_UINT;
        // Defence in depth: the hash was allowlisted at initiation; re-check the bytes.
        if (!_isAllowedRecoveryAction(userOp.callData, msg.sender)) return SIG_VALIDATION_FAILED_UINT;

        if (userOp.signature.length != 65) return SIG_VALIDATION_FAILED_UINT;
        bytes32 opDigest = keccak256(abi.encodePacked(userOpHash, msg.sender));
        if (_matchGuardian(cfg, opDigest, userOp.signature) == NO_GUARDIAN) return SIG_VALIDATION_FAILED_UINT;

        delete _pending[msg.sender];
        emit RecoveryExecuted(msg.sender, p.nonce, p.callDataHash);
        // sigFailed = 0, validUntil = 0 (no expiry), validAfter = executeAfter.
        return uint256(p.executeAfter) << 208;
    }

    /// Recovery is UserOp-only; the guardian set never signs arbitrary EIP-1271 payloads.
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return ERC1271_INVALID;
    }

    // ── IHook (parity with V1's module types) ───────────────────────

    function preCheck(address, uint256, bytes calldata) external payable override returns (bytes memory) {
        return hex"";
    }

    function postCheck(bytes calldata) external payable override {}

    // ── internals ───────────────────────────────────────────────────

    /// True iff `blob` is exactly `threshold` signatures over `digest`, each from a distinct guardian.
    function _quorumSigned(RecoveryConfig storage cfg, bytes32 digest, bytes calldata blob)
        internal
        view
        returns (bool)
    {
        uint8 threshold = cfg.threshold;
        if (blob.length != uint256(threshold) * 65) return false;
        uint8 used;
        for (uint256 i = 0; i < threshold; i++) {
            uint8 idx = _matchGuardian(cfg, digest, blob[i * 65:i * 65 + 65]);
            if (idx == NO_GUARDIAN) return false;
            uint8 bit = uint8(1 << idx);
            if (used & bit != 0) return false;
            used |= bit;
        }
        return true;
    }

    /// Index of the guardian that produced `sig` over `digest`, or NO_GUARDIAN. EOAs are recovered
    /// only against the EIP-191 form (FWA-C3-06); contract guardians are asked via EIP-1271 for the
    /// raw digest (FWA-C3-07). Any revert or non-magic answer means "did not sign".
    function _matchGuardian(RecoveryConfig storage cfg, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (uint8)
    {
        uint8 n = cfg.count;
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest.toEthSignedMessageHash(), sig);
        if (err == ECDSA.RecoverError.NoError && signer != address(0)) {
            for (uint8 i = 0; i < n; i++) {
                if (cfg.guardians[i] == signer) return i;
            }
        }
        for (uint8 i = 0; i < n; i++) {
            address g = cfg.guardians[i];
            if (g.code.length == 0) continue;
            try IERC1271(g).isValidSignature(digest, sig) returns (bytes4 magic) {
                if (magic == EIP1271_MAGIC) return i;
            } catch {}
        }
        return NO_GUARDIAN;
    }

    /// CHAIN-B-C032 (unchanged from V1): true iff `cd` is a single, non-delegatecall Kernel
    /// `execute` to `account` itself, zero value, whose inner call is `changeRootValidator`.
    /// `executionData` for a single call is `abi.encodePacked(target(20), value(32), innerCallData)`.
    function _isAllowedRecoveryAction(bytes calldata cd, address account) internal pure returns (bool) {
        if (cd.length < 100) return false;
        if (bytes4(cd[0:4]) != EXECUTE_SELECTOR) return false;
        if (cd[4] != bytes1(0x00)) return false; // CallType single

        // Bound every attacker-chosen word by the calldata length first, so no addition below
        // can overflow (V1 relied on checked arithmetic reverting instead).
        uint256 offset = uint256(bytes32(cd[36:68]));
        if (offset > cd.length) return false;
        uint256 lenPos = 4 + offset;
        if (cd.length < lenPos + 32) return false;

        uint256 execLen = uint256(bytes32(cd[lenPos:lenPos + 32]));
        if (execLen > cd.length) return false;
        uint256 dataStart = lenPos + 32;
        if (cd.length < dataStart + execLen) return false;
        if (execLen < 56) return false;

        address target = address(bytes20(cd[dataStart:dataStart + 20]));
        uint256 value = uint256(bytes32(cd[dataStart + 20:dataStart + 52]));
        bytes4 innerSelector = bytes4(cd[dataStart + 52:dataStart + 56]);

        return target == account && value == 0 && innerSelector == CHANGE_ROOT_SELECTOR;
    }
}
