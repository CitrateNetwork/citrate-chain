// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title UsageReceipts: opt-in daily commitment to a member's local usage log
/// @notice AMC 0.5.3 planset 06 section 3; ADR-2026-10-26 P-7(d), P-12. Spec:
///         docs/amc/PROVIDER_GOVERNANCE_CONTRACTS.md. Not in r1006 or block 0.
///
///         Core writes a signed local record for every cloud call, with no prompt or reply
///         content. A member who opts in commits one Merkle root per closed UTC day, so they can
///         later prove chosen records to an org admin or auditor without publishing the rest.
///
///         On chain: the committer (msg.sender, the subject), the day, the root and a schema byte.
///         No count, no totals, no provider list (RT-4).
///
///         Leaf and tree (off chain, X-5): leaf_i = SHA-256("citrate.usage-receipts.v1\n" ||
///         salt_i || canonical(record_i)) with salt_i 32 random bytes kept only in the member's
///         sealed local salts file; the tree and inclusion proofs are RFC 6962, the same code as
///         citrate-agent-anchor. A reveal is {record, salt, proof}, checked against `rootOf`.
///
///         Backfill is bounded: a day older than `maxBackfillDays` before today is refused
///         (deploy profile 90, matching the local history retention; owner, 2026-10-26). This
///         limits what a stolen key can pre-empt for days the member has not committed.
///
///         Layout follows AnchorRegistry (committer namespacing, tail-clamped paging). Holds no
///         value; no governance; no external calls.
contract UsageReceipts {
    struct Receipt {
        bytes32 root;
        uint64 committedAt;
        uint64 blockNumber;
        uint8 schema;
    }

    /// The leaf / record schema core 0.5.3 writes. A verifier interprets other values per its
    /// own schema table; 0 is never valid.
    uint8 public constant SCHEMA_V1 = 1;

    /// Bounds on the backfill limit chosen at deployment; DEFAULT_MAX_BACKFILL_DAYS is the
    /// deploy-profile value (history retention).
    uint32 public constant DEFAULT_MAX_BACKFILL_DAYS = 90;
    uint32 public constant MIN_BACKFILL_DAYS = 1;
    uint32 public constant MAX_BACKFILL_DAYS = 366;

    /// @notice How many days back from today a closed day may still be committed.
    uint32 public immutable maxBackfillDays;

    mapping(address => mapping(uint32 => Receipt)) private _receipts;
    mapping(address => uint32[]) private _days;

    event ReceiptCommitted(address indexed committer, uint32 indexed day, bytes32 root, uint8 schema);

    error AlreadyCommitted();
    error DayNotClosed();
    error BadSchema();
    error ZeroRoot();
    error DayTooOld(uint32 oldestAllowed);
    error BadBackfill();

    constructor(uint32 maxBackfillDays_) {
        if (maxBackfillDays_ < MIN_BACKFILL_DAYS || maxBackfillDays_ > MAX_BACKFILL_DAYS) revert BadBackfill();
        maxBackfillDays = maxBackfillDays_;
    }

    /// @param day UTC day number (unix seconds / 86400). Only a closed day may be committed.
    function commit(uint32 day, bytes32 root, uint8 schema) external {
        uint256 today = block.timestamp / 1 days;
        if (uint256(day) >= today) revert DayNotClosed();
        if (uint256(day) + maxBackfillDays < today) revert DayTooOld(uint32(today - maxBackfillDays));
        if (root == bytes32(0)) revert ZeroRoot();
        if (schema == 0) revert BadSchema();
        Receipt storage r = _receipts[msg.sender][day];
        if (r.committedAt != 0) revert AlreadyCommitted();
        r.root = root;
        r.committedAt = uint64(block.timestamp);
        r.blockNumber = uint64(block.number);
        r.schema = schema;
        _days[msg.sender].push(day);
        emit ReceiptCommitted(msg.sender, day, root, schema);
    }

    /// @notice The committer's receipt for `day`; all zero when none was committed.
    function rootOf(address committer, uint32 day) external view returns (Receipt memory) {
        return _receipts[committer][day];
    }

    function isCommitted(address committer, uint32 day) external view returns (bool) {
        return _receipts[committer][day].committedAt != 0;
    }

    function dayCount(address committer) external view returns (uint256) {
        return _days[committer].length;
    }

    /// Days the committer has committed, in commit order. An out-of-range `start` or a large
    /// `count` returns the available tail (never reverts).
    function daysOf(address committer, uint256 start, uint256 count) external view returns (uint32[] memory out) {
        uint32[] storage all = _days[committer];
        uint256 n = all.length;
        if (start >= n) return new uint32[](0);
        uint256 avail = n - start;
        uint256 len = count < avail ? count : avail;
        out = new uint32[](len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = all[start + i];
        }
    }
}
