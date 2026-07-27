// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MeetingRegistry — citrate-quorum QRM-S6
///
/// The on-chain half of a ratified meeting. citrate-quorum composes minutes
/// locally, a human signs a BLAKE3 commitment to them through the
/// SignatureCeremony, and that commitment is registered here so a board member
/// — or an auditor with no access to the deployment — can verify the minutes
/// they were handed are the minutes that were signed.
///
/// ## What is stored, and what deliberately is not
///
/// Hashes and an optional content pointer. **Never content, never names.**
/// Planset decision D6: on-chain carries hashes/CIDs only, so content stays
/// erasable at source and the non-identifying commitment survives deletion.
/// That is also what keeps this compatible with data-residency and
/// export-control obligations — an ITAR-classified meeting can be registered
/// here because nothing recoverable about it is on a public ledger.
///
/// The tenant is a hash for the same reason: a raw tenant id is customer
/// structure ("Meridian Aero › Aerostructures › Wichita › Line-4"), which is
/// commercially sensitive even when the minutes are not.
///
/// Who ratified is recorded as the **signing key** (`msg.sender`), not a name.
/// A name is PII; a key is an on-chain identity that the off-chain record ties
/// back to a person through the tenant's own evidence chain.
///
/// ## Append-only, first-writer-wins
///
/// A `(tenant, meetingId)` pair can be registered exactly once and can never
/// be amended. Ratification is a human signature over a specific hash; a
/// record that could be rewritten afterwards would not be evidence of
/// anything. Amending minutes means holding another meeting, which gets its
/// own id — the same rule the local domain enforces (a ratified meeting is
/// immutable).
///
/// ## Permissionless, like AnchorRegistry
///
/// `register` is open to any caller and carries no governance parameter. The
/// value is in the commitment plus the key that made it, not in a gatekeeper:
/// a third party verifying minutes checks that the record's `ratifier` is the
/// key their counterparty told them to expect, exactly as they would check a
/// signature. Gating registration would add an administrator who could censor
/// a customer's own audit record without making any forgery harder — anyone
/// can already register hashes of a meeting they invented, and such a record
/// verifies against nothing.
contract MeetingRegistry {
    struct MinutesRecord {
        /// The agenda hash frozen when the meeting opened.
        bytes32 agendaHash;
        /// The content hash the human actually signed.
        bytes32 minutesHash;
        /// The key that registered it — the on-chain identity of the ratifier.
        address ratifier;
        /// Ratification time as the application recorded it. A *claim*: the
        /// registrant chooses it. `blockNumber` is the authoritative ordering.
        uint64 ratifiedAt;
        /// Block this record landed in. Set by the chain, not the caller.
        uint64 blockNumber;
        /// Optional content pointer (IPFS CID) for a deployment that pins its
        /// minutes. Empty when nothing is pinned — which is the default, and
        /// is not a degraded state.
        string cid;
    }

    /// `keccak256(tenant, meetingId)` → record.
    mapping(bytes32 => MinutesRecord) private _records;

    /// Per-tenant list of registered meeting ids, in registration order, so an
    /// indexer can enumerate without replaying every log.
    mapping(bytes32 => bytes32[]) private _meetingsByTenant;

    error AlreadyRegistered(bytes32 tenant, bytes32 meetingId);
    error NotRegistered(bytes32 tenant, bytes32 meetingId);
    error ZeroMinutesHash();

    event MinutesRegistered(
        bytes32 indexed tenant,
        bytes32 indexed meetingId,
        bytes32 indexed minutesHash,
        bytes32 agendaHash,
        address ratifier
    );

    /// The storage key for a meeting. Exposed so an off-chain verifier can
    /// compute it without reimplementing the encoding.
    function recordKey(bytes32 tenant, bytes32 meetingId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(tenant, meetingId));
    }

    /// Register the ratified minutes of one meeting.
    ///
    /// Reverts if this `(tenant, meetingId)` is already registered — the
    /// append-only property, enforced at the contract rather than trusted to
    /// the caller.
    function register(
        bytes32 tenant,
        bytes32 meetingId,
        bytes32 agendaHash,
        bytes32 minutesHash,
        uint64 ratifiedAt,
        string calldata cid
    ) external {
        // A zero minutes hash commits to nothing and would let a caller
        // occupy a key with an empty record, permanently blocking the real
        // registration of that meeting.
        if (minutesHash == bytes32(0)) revert ZeroMinutesHash();

        bytes32 key = recordKey(tenant, meetingId);
        if (_records[key].minutesHash != bytes32(0)) {
            revert AlreadyRegistered(tenant, meetingId);
        }

        _records[key] = MinutesRecord({
            agendaHash: agendaHash,
            minutesHash: minutesHash,
            ratifier: msg.sender,
            ratifiedAt: ratifiedAt,
            blockNumber: uint64(block.number),
            cid: cid
        });
        _meetingsByTenant[tenant].push(meetingId);

        emit MinutesRegistered(
            tenant, meetingId, minutesHash, agendaHash, msg.sender
        );
    }

    /// The full record. Reverts when the meeting was never registered, so a
    /// caller cannot mistake a zeroed struct for a real one.
    function getMinutes(bytes32 tenant, bytes32 meetingId)
        external
        view
        returns (MinutesRecord memory)
    {
        MinutesRecord memory r = _records[recordKey(tenant, meetingId)];
        if (r.minutesHash == bytes32(0)) revert NotRegistered(tenant, meetingId);
        return r;
    }

    function isRegistered(bytes32 tenant, bytes32 meetingId)
        external
        view
        returns (bool)
    {
        return _records[recordKey(tenant, meetingId)].minutesHash != bytes32(0);
    }

    /// The verification an auditor actually performs: does the chain agree
    /// that THIS hash is the ratified minutes of THIS meeting?
    ///
    /// Returns false for an unregistered meeting rather than reverting — "no
    /// record" and "a different record" are both answers to the same question,
    /// and a verifier wants a boolean, not two error paths.
    function verifyMinutes(
        bytes32 tenant,
        bytes32 meetingId,
        bytes32 minutesHash
    ) external view returns (bool) {
        if (minutesHash == bytes32(0)) return false;
        return _records[recordKey(tenant, meetingId)].minutesHash == minutesHash;
    }

    function meetingCount(bytes32 tenant) external view returns (uint256) {
        return _meetingsByTenant[tenant].length;
    }

    /// Paginated meeting ids for a tenant, in registration order.
    function meetingsByTenant(bytes32 tenant, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory)
    {
        bytes32[] storage all = _meetingsByTenant[tenant];
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
