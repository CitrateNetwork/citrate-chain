// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IValidator, IHook} from "@kernel/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";
import {Execution} from "@kernel/interfaces/IERC7579Account.sol";
import {ExecMode, CallType} from "@kernel/types/Types.sol";
import {CALLTYPE_SINGLE, CALLTYPE_BATCH} from "@kernel/types/Constants.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_INVALID
} from "@kernel/types/Constants.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// ADR-XA-1 D6 — bounded agent delegation, enforced ON-CHAIN.
///
/// `ADR-2026-06-04-agent-signing-and-key-custody` permits delegating a scoped key
/// to an agent only as a "pro opt-in (discouraged, heavily warned)", bounded by an
/// allowance cap, an expiry, and a revoke. This module is what makes those bounds
/// REAL rather than advisory.
///
/// The distinction matters more than it sounds. An authority-side cap is a
/// suggestion: it lives in a database the agent's own client could ignore, and a
/// patched client spends without limit. So the acceptance criterion in handoff §4
/// W1 is specifically that "the N+1th spend is rejected by the validator, not the
/// client" — the cap has to be enforced by code the agent cannot edit, at the
/// moment the EntryPoint asks whether the operation is valid.
///
/// Installs on the existing `CitrateWallet` (Kernel / ERC-7579) beside
/// `CitrateECDSAValidator`, so delegation needs no wallet change.
///
/// ## What is enforced
///   1. the signer IS the delegated session key;
///   2. `block.timestamp <= validUntil`;
///   3. every call target is in the owner's allow-list (merkle-proved);
///   4. cumulative native value never exceeds `spendCap`.
///
/// ## What is deliberately refused (fail closed)
///   - `CALLTYPE_DELEGATECALL` — a delegatecall under a delegated key is a total
///     account takeover; no cap is meaningful past it.
///   - any selector other than the wallet's `execute(bytes32,bytes)` — blind-signing
///     unrecognized calldata is exactly the hazard the ADR warns about.
///   - ERC-1271 (`isValidSignatureWithSender`) ALWAYS. A session key that can sign
///     arbitrary off-chain payloads could authorize a token approval or a Permit
///     that moves value without ever passing through `validateUserOp` — routing
///     around the cap entirely. Session keys validate UserOps and nothing else.
///
/// ## v1 boundaries (ADR-XA-1 §9)
///   - the cap is CUMULATIVE, not per-period: it makes "N+1 is rejected" a single
///     unambiguous assertion, and a weaker grant is the right default for a path
///     the policy calls discouraged.
///   - the cap covers NATIVE value only. An allow-listed ERC-20 can still be moved
///     by an allow-listed call, so the allow-list is the control there. Token-
///     denominated caps are ADR-XA-1 O-5.
contract AgentSessionKeyValidator is IValidator, IHook {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// The Kernel wallet entrypoint for executions: `execute(ExecMode, bytes)`.
    bytes4 internal constant EXECUTE_SELECTOR = 0xe9ae5c53;

    struct Session {
        address sessionKey;
        uint48 validUntil;
        uint256 spendCap;
        uint256 spent;
        bytes32 recipientsRoot;
    }

    // --- Errors ---
    error AlreadyInstalled(address smartAccount);
    error InvalidInstallData();
    error InvalidSessionKey();
    error InvalidSpendCap();
    error InvalidRecipientsRoot();
    error ExpiryInPast();

    // --- Events ---
    event SessionInstalled(
        address indexed kernel,
        address indexed sessionKey,
        uint48 validUntil,
        uint256 spendCap,
        bytes32 recipientsRoot
    );
    event SessionUninstalled(address indexed kernel, address indexed sessionKey, uint256 spent);
    /// Emitted on every accepted spend so an owner can reconstruct usage from logs
    /// without trusting the agent's own reporting.
    event SessionSpend(address indexed kernel, uint256 amount, uint256 totalSpent, uint256 spendCap);

    // --- Storage ---
    mapping(address smartAccount => Session) public sessionOf;

    // --- Install lifecycle ---

    /// `_data` packing (90 bytes):
    ///   sessionKey (20) | validUntil (6) | spendCap (32) | recipientsRoot (32)
    ///
    /// Every field is validated. In particular `recipientsRoot` may NOT be zero: an
    /// empty allow-list must mean "nothing is permitted", and a zero root would
    /// instead make every merkle proof trivially unsatisfiable in a way that reads
    /// like a misconfiguration rather than a deliberate deny. Refusing at install
    /// makes the operator fix it while they are looking.
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length != 90) revert InvalidInstallData();
        if (_isInitialized(msg.sender)) revert AlreadyInstalled(msg.sender);

        address sessionKey = address(bytes20(_data[0:20]));
        if (sessionKey == address(0)) revert InvalidSessionKey();

        uint48 validUntil = uint48(bytes6(_data[20:26]));
        if (validUntil <= block.timestamp) revert ExpiryInPast();

        uint256 spendCap = uint256(bytes32(_data[26:58]));
        if (spendCap == 0) revert InvalidSpendCap();

        bytes32 recipientsRoot = bytes32(_data[58:90]);
        if (recipientsRoot == bytes32(0)) revert InvalidRecipientsRoot();

        sessionOf[msg.sender] = Session({
            sessionKey: sessionKey,
            validUntil: validUntil,
            spendCap: spendCap,
            spent: 0,
            recipientsRoot: recipientsRoot
        });
        emit SessionInstalled(msg.sender, sessionKey, validUntil, spendCap, recipientsRoot);
    }

    /// Owner-signed revoke. Authority ends ON-CHAIN, not merely in the authority's
    /// database — which is the point: an off-chain revoke the validator never hears
    /// about would leave a live key.
    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        Session memory s = sessionOf[msg.sender];
        delete sessionOf[msg.sender];
        emit SessionUninstalled(msg.sender, s.sessionKey, s.spent);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return sessionOf[smartAccount].sessionKey != address(0);
    }

    // --- Views (owner/dashboard) ---

    /// Remaining spendable value under the cap. Zero once exhausted or expired.
    function remaining(address smartAccount) external view returns (uint256) {
        Session storage s = sessionOf[smartAccount];
        if (s.sessionKey == address(0)) return 0;
        if (block.timestamp > s.validUntil) return 0;
        return s.spent >= s.spendCap ? 0 : s.spendCap - s.spent;
    }

    /// The leaf a recipient allow-list must commit to.
    ///
    /// Double-hashed, which is the standard defence against a second-preimage
    /// attack on a merkle tree whose internal nodes are also 32 bytes: without it
    /// an attacker can present an internal node as though it were a leaf.
    function recipientLeaf(address target) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(target))));
    }

    // --- IValidator ---

    /// Signature envelope: `abi.encode(bytes rawSig, bytes32[][] proofs)`, with one
    /// merkle proof per execution in the UserOp, in order.
    ///
    /// abi.encode rather than hand-packed offsets on purpose — manual offset
    /// arithmetic in a validator is a classic source of parsing bugs, and a
    /// malformed envelope must fail rather than be misread.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        Session storage s = sessionOf[msg.sender];
        if (s.sessionKey == address(0)) return SIG_VALIDATION_FAILED_UINT;
        if (block.timestamp > s.validUntil) return SIG_VALIDATION_FAILED_UINT;

        bytes memory rawSig;
        bytes32[][] memory proofs;
        {
            // A signature that is not a well-formed envelope fails closed.
            (bool ok, bytes memory decoded) = _tryDecodeEnvelope(userOp.signature);
            if (!ok) return SIG_VALIDATION_FAILED_UINT;
            (rawSig, proofs) = abi.decode(decoded, (bytes, bytes32[][]));
        }

        if (!_signedBySessionKey(userOpHash, rawSig, s.sessionKey)) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        // Decode the wallet's execute() and total the native value, checking each
        // target against the allow-list as we go.
        (bool decodedOk, uint256 total) = _sumAndCheckTargets(userOp.callData, s.recipientsRoot, proofs);
        if (!decodedOk) return SIG_VALIDATION_FAILED_UINT;

        // THE cap check. Unchecked overflow is impossible: `total` is a sum of
        // uint256 values that individually fit, and the comparison happens before
        // any state write, so an overflowing sum reverts in _sumAndCheckTargets.
        uint256 newSpent = s.spent + total;
        if (newSpent > s.spendCap) {
            // This is acceptance A3: the N+1th spend is rejected HERE, by the
            // validator the EntryPoint consults, with no client cooperation.
            return SIG_VALIDATION_FAILED_UINT;
        }
        s.spent = newSpent;
        if (total > 0) emit SessionSpend(msg.sender, total, newSpent, s.spendCap);

        return SIG_VALIDATION_SUCCESS_UINT;
    }

    /// ALWAYS invalid — see the contract-level note. A session key must not be able
    /// to sign arbitrary off-chain payloads, or it could authorize value movement
    /// that never passes the cap.
    function isValidSignatureWithSender(address, bytes32, bytes calldata)
        external
        view
        override
        returns (bytes4)
    {
        return ERC1271_INVALID;
    }

    // --- IHook (no-op; validation is the control here) ---

    function preCheck(address, uint256, bytes calldata)
        external
        payable
        override
        returns (bytes memory)
    {
        return hex"";
    }

    function postCheck(bytes calldata) external payable override {}

    // --- internals ---

    /// Bounds-check the envelope before abi.decode so a truncated signature returns
    /// a failure code rather than reverting the whole bundle.
    function _tryDecodeEnvelope(bytes calldata sig) internal pure returns (bool, bytes memory) {
        if (sig.length < 128) return (false, hex"");
        return (true, sig);
    }

    function _signedBySessionKey(bytes32 userOpHash, bytes memory sig, address sessionKey)
        internal
        pure
        returns (bool)
    {
        if (sig.length != 65) return false;
        // Accept a raw signature over userOpHash OR an EIP-191 personal_sign of it,
        // matching CitrateECDSAValidator's tolerance so an agent signer built for
        // either convention works.
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, sig);
        if (err == ECDSA.RecoverError.NoError && recovered == sessionKey) return true;
        (address recovered2, ECDSA.RecoverError err2,) =
            ECDSA.tryRecover(userOpHash.toEthSignedMessageHash(), sig);
        return err2 == ECDSA.RecoverError.NoError && recovered2 == sessionKey;
    }

    /// Decode `execute(ExecMode, bytes)` and total native value, requiring every
    /// target to be merkle-proved against `root`.
    ///
    /// Returns `(false, 0)` — never reverts — for anything unrecognized, so an
    /// unexpected shape is a signature failure rather than a bundle-level revert.
    function _sumAndCheckTargets(bytes calldata callData, bytes32 root, bytes32[][] memory proofs)
        internal
        pure
        returns (bool, uint256)
    {
        if (callData.length < 4) return (false, 0);
        if (bytes4(callData[0:4]) != EXECUTE_SELECTOR) return (false, 0);

        ExecMode mode;
        bytes memory execData;
        {
            (bytes32 rawMode, bytes memory d) = abi.decode(callData[4:], (bytes32, bytes));
            mode = ExecMode.wrap(rawMode);
            execData = d;
        }

        CallType callType = CallType.wrap(bytes1(ExecMode.unwrap(mode)));

        if (CallType.unwrap(callType) == CallType.unwrap(CALLTYPE_SINGLE)) {
            if (execData.length < 52) return (false, 0);
            address target;
            uint256 value;
            // execData = target(20) | value(32) | callData
            assembly {
                let p := add(execData, 0x20)
                target := shr(96, mload(p))
                value := mload(add(p, 20))
            }
            if (proofs.length != 1) return (false, 0);
            if (!MerkleProof.verify(proofs[0], root, recipientLeaf(target))) return (false, 0);
            return (true, value);
        }

        if (CallType.unwrap(callType) == CallType.unwrap(CALLTYPE_BATCH)) {
            Execution[] memory execs = abi.decode(execData, (Execution[]));
            if (proofs.length != execs.length) return (false, 0);
            uint256 total;
            for (uint256 i; i < execs.length; ++i) {
                if (!MerkleProof.verify(proofs[i], root, recipientLeaf(execs[i].target))) {
                    return (false, 0);
                }
                // Reverts on overflow (checked arithmetic) — a wrapped total would
                // slip past the cap comparison, so overflowing must not be silent.
                total += execs[i].value;
            }
            return (true, total);
        }

        // CALLTYPE_DELEGATECALL and anything else: refused.
        return (false, 0);
    }
}
