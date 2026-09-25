// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

import {QuorumIdentity} from "../quorum/QuorumIdentity.sol";

/// @title TinaWorkpaperRegistry — DPF-13 TINA Form-1411 workpaper anchoring.
/// @notice Per planset 02_PROCUREMENT_AUTOMATION.md § 1. When a non-
///         competitive procurement exceeds the TINA threshold
///         ($2M FY2026), the automation engine spins up a workpaper
///         and registers it here.
///
/// @dev 4-state lifecycle (mirrors TinaWorkpaperLifecycle.tla):
///        0 = NotStarted (sentinel — workpaper doesn't exist)
///        1 = Pending    (drafted; threshold not yet met)
///        2 = Signed     (threshold met; terminal-positive)
///        3 = Expired    (deadline passed without threshold; terminal-negative)
///
/// @dev Signatures are tracked as a set of signer identities. Each
///      `addSignature(workpaper_id, signer)` is recorded once
///      (dedup via mapping). When sig_count >= threshold, anyone
///      can call `signWorkpaper(workpaper_id)` to flip to Signed.
///
/// @dev PBA-L2-014 (pre-bounty audit 2026-09-24; residual of CHAIN-B-C024):
///      a single recorder used to satisfy an M-of-N workpaper by naming M
///      arbitrary signer ids. Now (a) the recorder fixes the required-signer
///      set at draft time, (b) `signer` must be the caller's own
///      `QuorumIdentity.subjectKey(msg.sender)` and a member of that set, and
///      (c) no signature is accepted, and no Signed transition made, after
///      `expires_at_block`.
///
/// @dev Auto-expiry: anyone can call `expireWorkpaper(workpaper_id)`
///      when `block.number > expires_at_block`. The expiry is
///      permissionless to keep the cron tick simple.
///
/// Source: .agentile/sprints/active/2026-05-11-dpf-13-procurement-automation/SPRINT.md D-1
contract TinaWorkpaperRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error AlreadyDrafted(bytes32 workpaper_id);
    error NotPending(bytes32 workpaper_id);
    error AlreadySigned(bytes32 workpaper_id, bytes32 signer);
    error ThresholdNotMet(uint16 sig_count, uint16 threshold);
    error NotExpired(uint256 expires_at, uint256 block_number);
    error ZeroThreshold();
    error ZeroPoHash();
    // PBA-L2-014
    error SignerNotCaller(bytes32 signer, address caller);
    error NotRequiredSigner(bytes32 workpaper_id, bytes32 signer);
    error BadRequiredSigners(uint256 count, uint16 threshold);
    error DuplicateRequiredSigner(bytes32 signer);
    error WorkpaperLapsed(bytes32 workpaper_id, uint256 expires_at, uint256 block_number);

    // ── Types ──────────────────────────────────────────────────────────

    struct Workpaper {
        bytes32 workpaper_id;       // keccak256(po_hash || merkle_root)
        bytes32 po_hash;            // procurement PO hash
        bytes32 merkle_root;        // root over workpaper line items
        bytes32 form_1411_cid;      // IPFS CID of the rendered Form 1411 PDF
        bytes32 scope;              // tenant scope
        uint8   state;              // 1=Pending, 2=Signed, 3=Expired
        uint16  threshold;          // signature threshold (M-of-N)
        uint16  sig_count;          // sigs received so far
        uint256 drafted_at_block;
        uint256 expires_at_block;
        uint256 signed_at_block;    // 0 until Signed
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;

    mapping(address => bool) public is_recorder;

    /// @notice workpaper_id → record.
    mapping(bytes32 => Workpaper) public workpapers;

    /// @notice workpaper_id → exists flag (O(1) check).
    mapping(bytes32 => bool) public exists;

    /// @notice (workpaper_id, signer) → recorded flag (dedup).
    mapping(bytes32 => mapping(bytes32 => bool)) public hasSigned;

    /// @notice workpaper_id → signers (append-only).
    mapping(bytes32 => bytes32[]) public signersOf;

    /// @notice PBA-L2-014: workpaper_id → the identities allowed to sign it.
    mapping(bytes32 => mapping(bytes32 => bool)) public isRequiredSigner;
    mapping(bytes32 => bytes32[]) private _requiredSigners;

    /// @notice scope → workpaper_ids (append-only).
    mapping(bytes32 => bytes32[]) public workpapersByScope;

    /// @notice All workpaper_ids ever drafted.
    bytes32[] public allWorkpaperIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event Drafted(
        bytes32 indexed workpaper_id,
        bytes32 indexed po_hash,
        bytes32 indexed scope,
        uint16 threshold,
        uint256 expires_at_block
    );
    event SignatureAdded(
        bytes32 indexed workpaper_id,
        bytes32 indexed signer,
        uint16 sig_count
    );
    event WorkpaperSigned(bytes32 indexed workpaper_id, uint16 sig_count);
    event WorkpaperExpired(bytes32 indexed workpaper_id);

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = InitialAdmin.check(initialGovernance); // PBA-L2-002: never the CREATE2 factory
    }

    // ── Governance ─────────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Draft a new workpaper. workpaper_id is caller-chosen.
    function draftWorkpaper(
        bytes32 workpaper_id,
        bytes32 po_hash,
        bytes32 merkle_root,
        bytes32 form_1411_cid,
        bytes32 scope,
        uint16 threshold,
        uint256 expires_at_block,
        bytes32[] calldata required_signers
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (po_hash == bytes32(0)) revert ZeroPoHash();
        if (threshold == 0) revert ZeroThreshold();
        if (exists[workpaper_id]) revert AlreadyDrafted(workpaper_id);
        // PBA-L2-014: the M-of-N set is fixed here, by the recorder, before
        // any signature exists.
        if (required_signers.length < threshold || required_signers.length > 64) {
            revert BadRequiredSigners(required_signers.length, threshold);
        }
        for (uint256 i = 0; i < required_signers.length; ++i) {
            bytes32 r = required_signers[i];
            if (isRequiredSigner[workpaper_id][r]) revert DuplicateRequiredSigner(r);
            isRequiredSigner[workpaper_id][r] = true;
            _requiredSigners[workpaper_id].push(r);
        }

        workpapers[workpaper_id] = Workpaper({
            workpaper_id: workpaper_id,
            po_hash: po_hash,
            merkle_root: merkle_root,
            form_1411_cid: form_1411_cid,
            scope: scope,
            state: 1, // Pending
            threshold: threshold,
            sig_count: 0,
            drafted_at_block: block.number,
            expires_at_block: expires_at_block,
            signed_at_block: 0
        });
        exists[workpaper_id] = true;
        workpapersByScope[scope].push(workpaper_id);
        allWorkpaperIds.push(workpaper_id);

        emit Drafted(workpaper_id, po_hash, scope, threshold, expires_at_block);
    }

    /// @notice Add a signature to a Pending workpaper. Idempotent
    ///         per (workpaper_id, signer); duplicate signers revert.
    /// @dev PBA-L2-014: signed by the signer itself (not by a recorder on its
    ///      behalf), only by a required signer, and only before expiry.
    function addSignature(bytes32 workpaper_id, bytes32 signer) external {
        Workpaper storage w = workpapers[workpaper_id];
        if (w.state != 1) revert NotPending(workpaper_id);
        if (signer != QuorumIdentity.subjectKey(msg.sender)) revert SignerNotCaller(signer, msg.sender);
        if (!isRequiredSigner[workpaper_id][signer]) revert NotRequiredSigner(workpaper_id, signer);
        if (block.number > w.expires_at_block) {
            revert WorkpaperLapsed(workpaper_id, w.expires_at_block, block.number);
        }
        if (hasSigned[workpaper_id][signer]) revert AlreadySigned(workpaper_id, signer);

        hasSigned[workpaper_id][signer] = true;
        signersOf[workpaper_id].push(signer);
        w.sig_count = w.sig_count + 1;

        emit SignatureAdded(workpaper_id, signer, w.sig_count);
    }

    /// @notice Sign a workpaper. Anyone can call once threshold is met.
    function signWorkpaper(bytes32 workpaper_id) external {
        Workpaper storage w = workpapers[workpaper_id];
        if (w.state != 1) revert NotPending(workpaper_id);
        if (w.sig_count < w.threshold) {
            revert ThresholdNotMet(w.sig_count, w.threshold);
        }
        // PBA-L2-014: a lapsed workpaper is not signed (it can only expire).
        if (block.number > w.expires_at_block) {
            revert WorkpaperLapsed(workpaper_id, w.expires_at_block, block.number);
        }
        w.state = 2; // Signed
        w.signed_at_block = block.number;
        emit WorkpaperSigned(workpaper_id, w.sig_count);
    }

    /// @notice Expire a workpaper. Permissionless once block past
    ///         expires_at_block. Only Pending → Expired allowed.
    function expireWorkpaper(bytes32 workpaper_id) external {
        Workpaper storage w = workpapers[workpaper_id];
        if (w.state != 1) revert NotPending(workpaper_id);
        if (block.number <= w.expires_at_block) {
            revert NotExpired(w.expires_at_block, block.number);
        }
        w.state = 3; // Expired
        emit WorkpaperExpired(workpaper_id);
    }

    // ── Views ──────────────────────────────────────────────────────────

    function getWorkpaper(bytes32 workpaper_id) external view returns (Workpaper memory) {
        return workpapers[workpaper_id];
    }

    /// @notice All workpaper_ids drafted under a scope.
    function byScope(bytes32 scope) external view returns (bytes32[] memory) {
        return workpapersByScope[scope];
    }

    function requiredSigners(bytes32 workpaper_id) external view returns (bytes32[] memory) {
        return _requiredSigners[workpaper_id];
    }

    function signersList(bytes32 workpaper_id) external view returns (bytes32[] memory) {
        return signersOf[workpaper_id];
    }

    function allWorkpapers() external view returns (bytes32[] memory) {
        return allWorkpaperIds;
    }

    function workpaperCount() external view returns (uint256) {
        return allWorkpaperIds.length;
    }

    function countByScope(bytes32 scope) external view returns (uint256) {
        return workpapersByScope[scope].length;
    }
}
