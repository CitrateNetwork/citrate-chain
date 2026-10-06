// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title AnchorRegistry: RFC-CIT-AGENT-0001 §6.3 + planset
///        06_ON_CHAIN_SURFACE.md "AnchorRegistry" + planset
///        05_AUDIT_CHAIN.md "Anchor strategies".
///
/// Append-only registry of audit-chain commitments. Closes the
/// audit-chain loop: cit-agent computes the canonical CBOR + hash
/// of an audit record (or batch), commits the hash here, and a
/// later auditor can verify the off-chain log matches the on-chain
/// commitment.
///
/// Three anchor kinds matching `agent/core/src/audit/record.rs::AnchorKind`:
///   * PerCapsule: commit hash of each capsule-install record
///   * PerApproval: commit hash of each approval-resolution record
///   * NightlyMerkle: nightly Merkle root over the day's records
///
/// `anchor()` is append-anyone. Records are kept PER COMMITTER: each
/// `(committer, root)` pair is recorded once, so a committer's record
/// always names the sender of that committer's own transaction, and an
/// earlier anchor of the same root by another address neither blocks
/// nor relabels it (HUP-S7.1 redeploy version). Verifiers that tie a
/// commitment to an identity read `getAnchorBy(committer, root)` /
/// `isAnchoredBy(committer, root)`. `getAnchor(root)` / `isAnchored(root)`
/// keep their original meaning: the first record of `root` by anyone.
/// No multi-sig because revoking a commitment isn't a supported
/// operation (append-only).
contract AnchorRegistry {
    enum AnchorKind { PerCapsule, PerApproval, NightlyMerkle }

    struct Anchor {
        AnchorKind kind;
        bytes32 root;            // record hash (PerCapsule / PerApproval)
                                  // or Merkle root (NightlyMerkle)
        address committer;
        uint256 block_number;
        uint256 timestamp;
    }

    /// First record of each root, by any committer (the original read surface).
    mapping(bytes32 => Anchor) private _anchors;

    /// One record per (committer, root).
    mapping(address => mapping(bytes32 => Anchor)) private _anchorsBy;

    /// Per-kind: distinct roots in first-anchored order. Off-chain
    /// indexers walk this for time-ordered queries.
    mapping(AnchorKind => bytes32[]) private _rootsByKind;

    /// Per-committer, per-kind: that committer's roots in order.
    mapping(address => mapping(AnchorKind => bytes32[])) private _rootsByCommitter;

    error AlreadyAnchored();
    error AnchorNotFound();

    event Anchored(
        bytes32 indexed root,
        AnchorKind indexed kind,
        address indexed committer
    );

    /// Record `root` for `msg.sender`. Reverts `AlreadyAnchored` only when
    /// this sender has already anchored this root (under any kind).
    function anchor(AnchorKind kind, bytes32 root) external {
        if (_anchorsBy[msg.sender][root].block_number != 0) {
            revert AlreadyAnchored();
        }
        Anchor memory a = Anchor({
            kind: kind,
            root: root,
            committer: msg.sender,
            block_number: block.number,
            timestamp: block.timestamp
        });
        _anchorsBy[msg.sender][root] = a;
        _rootsByCommitter[msg.sender][kind].push(root);
        if (_anchors[root].block_number == 0) {
            _anchors[root] = a;
            _rootsByKind[kind].push(root);
        }
        emit Anchored(root, kind, msg.sender);
    }

    /// First record of `root` by any committer.
    function getAnchor(bytes32 root) external view returns (Anchor memory) {
        Anchor memory a = _anchors[root];
        if (a.block_number == 0) revert AnchorNotFound();
        return a;
    }

    /// True once any committer has anchored `root`.
    function isAnchored(bytes32 root) external view returns (bool) {
        return _anchors[root].block_number != 0;
    }

    /// `committer`'s own record of `root`.
    function getAnchorBy(address committer, bytes32 root) external view returns (Anchor memory) {
        Anchor memory a = _anchorsBy[committer][root];
        if (a.block_number == 0) revert AnchorNotFound();
        return a;
    }

    /// True once `committer` has anchored `root`.
    function isAnchoredBy(address committer, bytes32 root) external view returns (bool) {
        return _anchorsBy[committer][root].block_number != 0;
    }

    function rootCountByKind(AnchorKind kind) external view returns (uint256) {
        return _rootsByKind[kind].length;
    }

    function rootCountByCommitter(address committer, AnchorKind kind) external view returns (uint256) {
        return _rootsByCommitter[committer][kind].length;
    }

    /// Paginated slice of the kind's distinct roots. Returns at most
    /// `count` entries from `start`; an out-of-range `start` or a large
    /// `count` returns the available tail (never reverts).
    function rootsByKind(AnchorKind kind, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory)
    {
        return _page(_rootsByKind[kind], start, count);
    }

    /// Paginated slice of `committer`'s roots of `kind`, same rules.
    function rootsByCommitter(address committer, AnchorKind kind, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory)
    {
        return _page(_rootsByCommitter[committer][kind], start, count);
    }

    /// `start + count` is never computed, so no input overflows.
    function _page(bytes32[] storage all, uint256 start, uint256 count)
        private
        view
        returns (bytes32[] memory out)
    {
        uint256 n = all.length;
        if (start >= n) return new bytes32[](0);
        uint256 avail = n - start;
        uint256 len = count < avail ? count : avail;
        out = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = all[start + i];
        }
    }
}
