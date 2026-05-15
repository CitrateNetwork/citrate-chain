// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title AnchorRegistry — RFC-CIT-AGENT-0001 §6.3 + planset
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
///   * PerCapsule — commit hash of each capsule-install record
///   * PerApproval — commit hash of each approval-resolution record
///   * NightlyMerkle — nightly Merkle root over the day's records
///
/// `anchor()` is append-anyone — the value is in the public
/// commitment, not in who made it. The off-chain verifier ties
/// commitments to specific AgentSBT identities via the committer
/// field. No multi-sig because revoking a commitment isn't a
/// supported operation (append-only).
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

    /// Keyed by `root` (the committed value). Two callers cannot
    /// commit the same root twice — the second call reverts. This
    /// is the append-only property at the contract level.
    mapping(bytes32 => Anchor) private _anchors;

    /// Per-kind: list of all roots committed in order. Off-chain
    /// indexers walk this for time-ordered queries.
    mapping(AnchorKind => bytes32[]) private _rootsByKind;

    error AlreadyAnchored();
    error AnchorNotFound();

    event Anchored(
        bytes32 indexed root,
        AnchorKind indexed kind,
        address indexed committer
    );

    function anchor(AnchorKind kind, bytes32 root) external {
        if (_anchors[root].block_number != 0) {
            revert AlreadyAnchored();
        }
        _anchors[root] = Anchor({
            kind: kind,
            root: root,
            committer: msg.sender,
            block_number: block.number,
            timestamp: block.timestamp
        });
        _rootsByKind[kind].push(root);
        emit Anchored(root, kind, msg.sender);
    }

    function getAnchor(bytes32 root) external view returns (Anchor memory) {
        Anchor memory a = _anchors[root];
        if (a.block_number == 0) revert AnchorNotFound();
        return a;
    }

    function isAnchored(bytes32 root) external view returns (bool) {
        return _anchors[root].block_number != 0;
    }

    function rootCountByKind(AnchorKind kind) external view returns (uint256) {
        return _rootsByKind[kind].length;
    }

    /// Return a paginated slice of the kind's root list. `start +
    /// count` MUST be <= rootCountByKind(kind).
    function rootsByKind(AnchorKind kind, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory)
    {
        bytes32[] storage all = _rootsByKind[kind];
        if (start >= all.length) return new bytes32[](0);
        uint256 end = start + count;
        if (end > all.length) end = all.length;
        bytes32[] memory out = new bytes32[](end - start);
        for (uint256 i = 0; i < end - start; i++) {
            out[i] = all[start + i];
        }
        return out;
    }
}
